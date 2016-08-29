import requests
import xml.etree.ElementTree as Et
import json
import threading
import datetime
import logging
import time
from data.events import VulnerableAppEvent, ImplicatedAppEvent, Host
from threading import Thread


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


class BannedFileFixletData(object):
    """
    Bigfix Helper Class to organize data around the banned files
    """
    def __init__(self, md5, actionscript="", relevance=""):
        self.md5 = md5
        self.actionscript = actionscript
        self.relevance = relevance


class BigFixApi:

    # lock across all instances of this class
    _manager_lock = threading.RLock()

    def __init__(self, fletch_config, switchboard):
        self._switchboard = switchboard
        self._bigfix_host = fletch_config.ibm_bigfix.url
        self._bigfix_protocol = fletch_config.ibm_bigfix.protocol
        self._auth = (fletch_config.ibm_bigfix.username,
                      fletch_config.ibm_bigfix.password)
        self._manager_lock = BigFixApi._manager_lock
        self._packaging_interval = fletch_config.ibm_bigfix.packaging_interval
        self._bigfix_ssl_verify = fletch_config.ibm_bigfix.ssl_verify
        self._bigfix_custom_site_name = fletch_config.ibm_bigfix.bigfix_custom_site_name

        # we use this both as a template and also as a
        # temporary store for the dashboard XML structure
        xml_template = 'src/statics/bigfix_plugin_api_post_template.xml'
        with open(xml_template) as temp_open:
            self._dashboard_data_xml = temp_open.read()

        # template for fixlets..
        xml_path = 'src/statics/bigfix_fixlet_template.xml'
        with open(xml_path) as temp_open:
            self._fixlet_creation_template = temp_open.read()

        # URL to get/post data to the bigfix asset dashboard
        self._dashboard_url = \
            '{0}://{1}/api/dashboardvariables/MVScan.ojo'.format(
                self._bigfix_protocol, self._bigfix_host)
        self._bigfix_query_api_url = \
            '{0}://{1}/api/query'.format(
                self._bigfix_protocol, self._bigfix_host)
        self._bigfix_fixlet_api_url = \
            '{0}://{1}/api/fixlet/custom/{2}'.format(
                self._bigfix_protocol, self._bigfix_host, self._bigfix_custom_site_name)
        self._bigfix_fixlets_api_url = \
            '{0}://{1}/api/fixlets/custom/{2}'.format(
                self._bigfix_protocol, self._bigfix_host, self._bigfix_custom_site_name)

        # setup the logging
        self.logger = logging.getLogger(__name__)

        # and setup our caching layer
        self._cache_enabled = fletch_config.ibm_bigfix.cache_enabled
        self._cache = dict()

        # finally kick off a thread responsible for sync'ing the
        # contents of our cache up to the bigfix server.
        # We make a new channel here so that we can capitalize on the
        # switchboard's built-in shutdown messaging to close our thread
        # when it is required
        self._cache_post_chan = self._switchboard.channel('BigFixCachePost')

        # start the listener
        Thread(target=self._cache_purging_loop,
               name="bigfix_api_cache_purging_timer").start()

    def _cache_purging_loop(self):
        """
        NOTE: Run this in a separate thread, it is a never ending loop
        unless a service shutdown is issued.
        This function will, on the configured interval, grab the data from
        the cache and send it over to bigfix.
        """
        while self._cache_post_chan.is_running():

            # self.logger.debug("Current channel status: {}".format(
            #     self._cache_post_chan.is_running()))

            # repeat the sleep here to give us a chance to break the loop
            for t in range(0, (self._packaging_interval*60/5) + 1):
                if not self._cache_post_chan.is_running():
                    break
                time.sleep(5)

            # send off the cached data
            cache_output = self._cache_pull_and_delete()
            if len(cache_output) > 0:
                self.logger.info("Posting {} items to BigFix from "
                                 "the local cache.".format(len(cache_output)))
                self.put_dashboard_data(cache_output)
            else:
                self.logger.debug("Skipping scheduled BigFix post, no data in "
                                  "the local cache.")

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

        # need to manually
        req_result = requests.get(self._bigfix_query_api_url, auth=self._auth,
                                  verify=self._bigfix_ssl_verify,
                                  params=payload,
                                  headers={"Accept-Encoding": "gzip"})

        # parse the XML answer
        xml_result = Et.fromstring(req_result.text)
        besid = xml_result.find('Query').find('Result').find('Answer').text
        # print besid
        return int(besid)

    def get_dashboard_data(self, return_metadata=False):
        """
        Pulls down the current dashboard data
        :param return_metadata:  Returns the full dict from the server which
                    which includes the timestamp and vendor metadata instead of
                    just the assets list that we usually only care about.
        :return: Dashboard data in JSON format
        """
        self.logger.info('Pulling data from the BigFix dashboard')
        self._dashboard_data_xml = requests.get(self._dashboard_url,
                                                auth=self._auth,
                                                verify=self._bigfix_ssl_verify
                                                ).text

        # parse the XML result, load the value as json, then do what we need
        xml_result = Et.fromstring(self._dashboard_data_xml)
        value_content = xml_result.find('DashboardData').find('Value').text

        if value_content is None or value_content.strip() is "":
            data = dict()
        else:
            data = json.loads(value_content)

        self.logger.debug('Pulled the following data from BigFix: %s', data)
        if return_metadata:
            return data
        else:
            return data['assets']

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
        t_millisecond_str = str(current_timestamp.strftime('%f'))[0:3]
        t_time_string = current_timestamp.strftime('%Y%m%d.%H%M%S')
        time_name_string = "{0}.{1}".format(t_time_string, t_millisecond_str)
        name_string = "{0}.1 - Name".format(time_name_string)

        xml_result = Et.fromstring(self._dashboard_data_xml)
        xml_result.find('DashboardData').find('Name').text = name_string

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
        xml_result.find('DashboardData').find('Value').text = data_out
        generated_xml = Et.tostring(xml_result)

        self.logger.info('Posting data to BigFix dashboard')
        self.logger.debug("XML post to Dashboard: {0}".format(generated_xml))

        requests.post(self._dashboard_url, auth=self._auth,
                      verify=self._bigfix_ssl_verify,
                      data=generated_xml)

    # TODO: need a cache purging function on some interval
    @_bigfix_lock_required
    def _cache_json_data(self, json_data):
        """
        Cache the information that we need to provide to bigfix so that
        we can do it in a single huge push instead of doing a POST
        every time we get data in.
        :param json_data: the data to store. This function expects JUST the
                          'assets' list portion of the BigFix API spec.
        """

        # this is going to be simple for now. We will merge all incoming
        # entries together so that bigfix can receive them. Their job is to
        # deduplicate / merge our data into their data store.
        for asset in json_data:
            if asset['besid'] not in self._cache:
                self._cache[asset['besid']] = asset
            else:
                cached_asset = self._cache[asset['besid']]

                # loop over all cves and ensure that the cve is cached
                # if the cve already existed, and the new cve now indicates
                # that it is implicated, set the cached version appropriately
                for cve in asset['cves']:
                    cve_found = False
                    for cached_cve in cached_asset['cves']:
                        if cve['id'] == cached_cve['id']:
                            cve_found = True
                            if cve['implicated'] == 1:
                                cached_cve['implicated'] = 1
                    if cve_found is False:
                        cached_asset['cves'].append(cve)

    @_bigfix_lock_required
    def _cache_pull_and_delete(self, return_type=list()):
        """
        This function grabs the data from the cache and returns it.
        Nothing fancy here.
        :param return_type: Defaults to a list, since that is what
                            bigfix wants, but also allows for return of
                            the original dict to make testing easier.
        :return:  json data for the 'assets' array within the BigFix spec
        """
        temp_data = self._cache
        self._cache = dict()

        if isinstance(return_type, list):
            return temp_data.values()
        elif isinstance(return_type, dict):
            return temp_data
        else:
            ValueError("Incorrect type requested")

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

        elif type(event) == ImplicatedAppEvent:
            implication_status = 1

        else:
            implication_status = 0

        # build the list of assets
        asset['fqdn'] = event.host.name
        asset['besid'] = event.host.bigfix_id
        asset['cves'] = list()
        for hit in event.threat_intel.hits:
            asset['cves'].append({
                # strip cve- off
                "id": hit.cve,
                "risk": hit.score,
                "implicated": implication_status
            })

        # send the asset json to the cache
        # unless we are bypassing the cache, then send immediately
        if bypass_cache or self._cache_enabled is False:
            self.put_dashboard_data([asset])
        else:
            self._cache_json_data([asset])

    def process_banned_file_event(self, event):
        """
        The main function for handling of banned files. This will do all the
        work for other functions.
        :param event: the Banned File Event
        """
        self.logger.debug('Processing Banned File {0}'.format(
            event.process.md5))
        fixlet_xml_string = self._get_remediation_fixlet(event.process.md5)

        # if were weren't able to find an existing fixlet, setup
        # the banned file data object ourselves
        if fixlet_xml_string is None:
            self.logger.debug('No existing fixlet, creating new one.')
            banned_file_data = BannedFileFixletData(md5=event.process.md5)
        else:
            self.logger.debug('Found existing fixlet, unpacking..')
            banned_file_data = self._unpack_remediation_fixlet(
                fixlet_xml_string)

        # if we have no updates to do, this will be set to None
        banned_file_data = self._build_fixlet_commands(event, banned_file_data)
        if banned_file_data is not None:
            self.logger.debug('Sending fixlet to BigFix.')
            self._put_remediation_fixlet(
                self._build_remediation_fixlet(banned_file_data),
                banned_file_data
            )
        else:
            self.logger.debug('Fixlet not updated, path already present.')

    def _build_remediation_fixlet(self, banned_file_data):
        """
        Using the fixlet template, put all the pieces together here.
        :param banned_file_data:  BannedFileData object
        :return:  returns the complete fixlet xml as a string
        """
        fixlet_xml = Et.fromstring(self._fixlet_creation_template)
        current_time = datetime.datetime.utcnow()
        fixlet_xml.find('Fixlet').find('Title').text = \
            'Banned File - md5={0}'.format(banned_file_data.md5)
        fixlet_xml.find('Fixlet').find('Relevance').text = \
            banned_file_data.relevance
        fixlet_xml.find('Fixlet').find('SourceReleaseDate').text = \
            current_time.strftime("%Y-%m-%d")
        fixlet_xml.find('Fixlet').find('MIMEField').find('Value').text = \
            current_time.strftime("%a, %d %b %Y %H:%M:%S +0000")
        fixlet_xml.find('Fixlet').find('DefaultAction').\
            find('ActionScript').text = banned_file_data.actionscript
        return Et.tostring(fixlet_xml)

    def _unpack_remediation_fixlet(self, xml):
        """
        A simple helper to extract the fields we alter from an existing
        fixlet. Helpful when we need to update the content.
        :param xml:  fixlet xml as a string
        :return  a construct BannedFileData object for use in other functions
        """
        fixlet_xml = Et.fromstring(xml)
        fixlet_elm = fixlet_xml.find('Fixlet')
        return BannedFileFixletData(
            md5=fixlet_elm.find('Title').text.split('=')[1],
            relevance=fixlet_elm.find('Relevance').text,
            actionscript=(
                fixlet_elm.find('DefaultAction').find('ActionScript').text
            )
        )

    def _get_remediation_fixlet_id(self, md5):
        # see if we already have a fixlet of this nature.
        query_string = \
            'ids of bes fixlets whose (name of site of' \
            ' it = "{0}" AND name of it as string' \
            ' as lowercase contains "{1}" as lowercase)'.format(
                self._bigfix_custom_site_name, md5)

        req_result = requests.get(
            self._bigfix_query_api_url,
            auth=self._auth,
            verify=self._bigfix_ssl_verify,
            params={'relevance': query_string, 'output': 'json'},
            headers={"Accept-Encoding": "gzip"})

        # if no existing fixlet found, return None
        result_json = json.loads(req_result.content)
        if len(result_json["result"]) == 0:
            return None
        else:
            return result_json["result"][0]

    # TODO build a delete fixlet function, would be helpful for testing

    def _get_remediation_fixlet(self, md5):
        """
        Grabs the XML of an existing fixlet from the BigFix server.
        :param md5: the md5 of the banned file to grab the fixlet of
        :return: returns the XML as as string or, None, is fixlet doesn't exist
        """
        fixlet_id = self._get_remediation_fixlet_id(md5)

        if fixlet_id is None:
            return None
        else:
            # do a query to grab the contents of the fixlet.
            # We only care about the first fixlet found
            # since there really should only ever be one.
            rest_query = "{0}/{1}".format(
                self._bigfix_fixlet_api_url,
                fixlet_id)
            req_result = requests.get(rest_query,
                                      auth=self._auth,
                                      verify=self._bigfix_ssl_verify)

            if req_result.status_code != 200:
                self.logger.warning(
                      "Error pulling fixlet from Bigfix:"
                      " {0}, API status code: {1}".format(
                        req_result.text,
                        req_result.status_code))
                return None
            else:
                return req_result.content

    def _put_remediation_fixlet(self, xml_string, banned_file_data):
        """
        Send our newly created/updated fixlet up to the bigfix server.
        :param xml_string:  XML (as str) of the fixlet
        :param banned_file_data:
        """

        fixlet_id = self._get_remediation_fixlet_id(banned_file_data.md5)

        # if no existing fixlet found, just make a new one
        if fixlet_id is None:
            put_result = requests.post(self._bigfix_fixlets_api_url,
                                       auth=self._auth,
                                       verify=self._bigfix_ssl_verify,
                                       data=xml_string)

            if put_result.status_code != 200:
                self.logger.warning(
                    "Error in fixlet POST to Bigfix: {0},"
                    " API status code: {1}".format(
                        put_result.text, put_result.status_code))

        # otherwise, update the existing one
        else:
            url = '{0}/{1}'.format(self._bigfix_fixlet_api_url, fixlet_id)
            put_result = requests.put(url,
                                      auth=self._auth,
                                      verify=self._bigfix_ssl_verify,
                                      data=xml_string)
            if put_result.status_code != 200:
                self.logger.warn("Error in fixlet PUT to Bigfix: {0},"
                                 " API status code: {1}".format(
                                  put_result.text, put_result.status_code))

    def _build_fixlet_commands(self, event, banned_file_data):
        # if we are updating an existing fixlet, then the functions
        # below will simply append the new string to the end of the
        # existing ones.
        # ALL events in event_list must relate to the same banned MD5!

        relevance_command = banned_file_data.relevance
        actionscript_command = banned_file_data.actionscript

        # right now we focus on windows
        # we'll just return nothing here to indicate no change required
        if event.host.os_type != Host.OS_TYPE_WINDOWS:
            self.logger.info('Not proceeding with Banned File Fixlet update '
                             'only Windows machines currently supported.')
            return None

        # else we build out the relevance commands for finding the file
        if relevance_command != "":
            relevance_command += " OR "

        filename = event.process.file_path.split('\\')[-1]
        folder_split = event.process.file_path.split('\\')[0:-1]
        folder = "\\".join(folder_split)

        # if we already have this path in the fixlet, we don't need to add it
        # again, skip the remaining part of this loop
        if event.process.file_path in actionscript_command:
            return None

        relevance_command += """
            (exists file "{0}" whose
                (md5 of it as lowercase = "{1}" as lowercase)
                    of folders "{2}")
            """.format(filename, event.process.md5, folder)

        # build the delete statements
        # WARNING: newlines are important here, don't
        # break up the if-statement so that we keep bigfix happy.
        actionscript_command += """
            if {{(exists file "{0}" whose (md5 of it as lowercase = "{1}" as lowercase) of folders "{2}")}}
                    delete "{3}"
            endif
            """.format(filename,
                       event.process.md5,
                       folder,
                       event.process.file_path)

        return BannedFileFixletData(
            md5=banned_file_data.md5,
            relevance=relevance_command,
            actionscript=actionscript_command
        )
