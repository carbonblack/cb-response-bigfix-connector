import requests
import xml.etree.ElementTree as Et
import json
import threading
import datetime
from fletch.utils.loggy import Loggy
from fletch.data.events import VulnerableAppEvent, ImplicatedAppEvent


def _bigfix_lock_required(func):
    """
    Wrapper for functions requiring the bigfix manager lock
    """
    # TODO separate this into function that creates locks by name
    # TODO need three locks: cache data, dashboard, malware fixlet updates
    def wrapper(*args, **kwargs):
        # since this is actually operating on class methods
        # we still need the self attribute. Feels hacky, but it works
        self = args[0]
        self._manager_lock.acquire()
        try:
            result = func(*args, **kwargs)
        finally:
            self._manager_lock.release()
        return result
    return wrapper


class BigFixApi:

    # lock across all instances of this class
    _manager_lock = threading.RLock()

    def __init__(self, fletch_config):
        self._bigfix_host = fletch_config.ibm_bigfix.url
        self._auth = (fletch_config.ibm_bigfix.username,
                      fletch_config.ibm_bigfix.password)
        self._manager_lock = BigFixApi._manager_lock
        self._packaging_interval = fletch_config.ibm_bigfix.packaging_interval

        # we use this both as a template and also as a
        # temporary store for the dashboard XML structure
        with open('bigfix_plugin_api_post_template.xml') as temp_open:
            self._dashboard_data_xml = temp_open.read()

        # URL to get/post data to the bigfix asset dashboard
        self._dashboard_url = \
            'https://{0}/api/dashboardvariables/MVScan.ojo'.format(
                self._bigfix_host)

        # setup the logging infrastructure
        self.loggy = Loggy(__name__)
        self.loggy.setup_log_to_stdout(Loggy.DEBUG)
        self.logger = self.loggy.logger()

        # and setup our caching layer
        self._cache_array = list()

    def get_besid(self, cb_sensor_id):
        """
        Grabs the besid from the bigfix console that corresponds to
        the cb_sensor_id we have.
        :param cb_sensor_id: as you'd guess, the cb id number
        """

        # build and send the query
        query_string = 'ids of bes computers whose (value of result from' \
                       ' (bes property "Sensor ID") of it = "{0}" )'.format(
                        cb_sensor_id)

        payload = {'relevance': query_string}
        url = 'https://{0}/api/query'.format(self._bigfix_host)

        # need to manually
        req_result = requests.get(url, auth=self._auth, verify=False,
                                  params=payload,
                                  headers={"Accept-Encoding": "gzip"})

        # parse the XML answer
        xml_result = Et.fromstring(req_result.text)
        besid = xml_result.find('Query').find('Result').find('Answer').text
        # print besid
        return int(besid)

    def get_dashboard_data(self):
        """
        Pulls down the current dashboard data
        :return: Dashboard data in JSON format
        """
        self.logger.info('Pulling data from the BigFix dashboard')
        self._dashboard_data_xml = requests.get(self._dashboard_url,
                                                auth=self._auth,
                                                verify=False).text

        # TODO, is this still useful?  how we will pull data from bigfix?
        # parse the XML result, load the value as json, then do what we need
        xml_result = Et.fromstring(self._dashboard_data_xml)
        data = json.loads(xml_result.find('DashboardData').find('Value').text)
        self.logger.debug('Pulled the following data from BigFix: %s', data)
        return data

    def put_dashboard_data(self, json_data):
        """
        Pushes the provided json the dashboard.
        BigFix will handle any data merging that is needed.
        :param json_data: JSON data to post. This should be the array of
                          assets that bigfix expects.
        """

        # make the weird timestamp-as-name thing
        # bigfix expects this to show up as UTC
        # should look like: 20160720.175526.545
        # then the value for the name field: '20160720.175526.545.1 - Name'
        current_timestamp = datetime.datetime.utcnow()
        t_millisecond_str = str(current_timestamp.strftime('%f'))[0-2]
        t_time_string = current_timestamp.strftime('%Y%m%d.%H%M%S')
        time_name_string = "{0}.{1}".format(t_time_string, t_millisecond_str)
        name_string = "{0}.1 - Name".format(time_name_string)

        xml_result = Et.fromstring(self._dashboard_data_xml)
        xml_result.find('BESAPI').find('DashboardData')\
            .find('Name').text = name_string

        # construct the JSON wrapper around our data:
        json_wrapper = {
            'name': name_string,
            "timestamp": time_name_string,
            "vendor": "CarbonBlack",
            "version": "1",
            "assets": json_data
        }

        # dump the json to string, save it to the XML value
        # then post the XML.
        data_out = json.dumps(json_wrapper)
        xml_result.find('BESAPI').find('DashboardData')\
            .find('Value').text = data_out
        generated_xml = Et.tostring(xml_result)

        self.logger.info('Posting data to BigFix dashboard')
        self.logger.debug("XML post to Dashboard: {0}".format(generated_xml))

        requests.post(self._dashboard_url, auth=self._auth, verify=False,
                      data=generated_xml)

    @_bigfix_lock_required
    def _cache_json_data(self, json_data):
        """
        Cache the information that we need to provide to bigfix so that
        we can do it in a single huge push instead of doing a POST
        every time we get data in.
        :param json_data: the data to store. This function expects JUST the
                          'assets' list portion of the BigFix API spec.
        """

        # this is going to be extremely simple for now. We will just
        # collect json items as they come in and simply append them
        # to the list that we'll be sending to BigFix. Their job is to
        # deduplicate / merge in the data.
        for asset in json_data:
            self._cache_array.append(asset)

    @_bigfix_lock_required
    def _cache_pull_and_delete(self):
        """
        This function grabs the data from the cache and returns it.
        Nothing fancy here.
        :return:  json data for the 'assets' array within the BigFix spec
        """
        temp_data = self._cache_array
        self._cache_array = list()
        return temp_data

    def update_nvd_dashboard_data(self, event, bypass_cache=False):
        """
        Unpacks event data into the format required by the BigFix API.
        In essence we convert the Event object into some core json events
        and then store it in our cache layer. At a later point in time we
        will actually go through the motions of sending the data.
        :param event: Event object to upload data for
        :param bypass_cache: Use the cache, or send immediately to bigfix.
        """

        asset = dict()

        # confirm we received the right type of event here
        supported_events = [VulnerableAppEvent, ImplicatedAppEvent]
        if type(event) not in supported_events:
            self.logger.error(
                "Bad Event to BigFix. Got {0}.".format(type(event)))
            raise TypeError("Bad Event Type to BigFix API")

        # build the list of assets
        asset['fqdn'] = event.host.name
        asset['besid'] = event.host.bigfix_id
        asset['cves'] = list()
        for hit in event.threat_intel:
            asset['cves'].append({
                "id": hit.cve,
                "risk": hit.score,
                "implicated": 0
            })

        # send the asset json to the cache
        # unless we are bypassing the cache, then send immediately
        if bypass_cache:
            pass
        else:
            self._cache_json_data(asset)

# TODO have something here to handle banned files and push them to BigFix.
