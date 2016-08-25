import requests
import xml.etree.ElementTree as Et
import json
import threading


def _bigfix_lock_required(func):
    """
    Wrapper for functions requiring the bigfix manager lock
    """
    # TODO: Handle exceptions and still release the lock
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

        # we use this both as a template and also as a
        # temporary store for the dashboard XML structure
        self._dashboard_data_xml = \
            """<?xml version="1.0" encoding="UTF-8"?>
                <BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd">
                <DashboardData Resource="https://bigfixcb.dnsalias.com:52311/api/dashboardvariable/qui.ojo/assets">
                <Dashboard>qui.ojo</Dashboard>
                <Name>assets</Name>
                <IsPrivate>false</IsPrivate>
                <Value>{}</Value>
                </DashboardData>
                </BESAPI>
            """

        # URL to get/post data to the bigfix asset dashboard
        self._dashboard_url = \
            'https://{0}/api/dashboardvariable/qui.ojo/assets'.format(
                self._bigfix_host)

    @_bigfix_lock_required
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

    @_bigfix_lock_required
    def get_dashboard_data(self):
        """
        Pulls down the current dashboard data
        :return: Dashboard data in JSON format
        """
        self._dashboard_data_xml = requests.get(self._dashboard_url,
                                                auth=self._auth,
                                                verify=False).text

        # parse the XML result, load the value as json, then do what we need
        xml_result = Et.fromstring(self._dashboard_data_xml)
        # print(req_result.text)
        data = json.loads(xml_result.find('DashboardData').find('Value').text)
        return data

    @_bigfix_lock_required
    def put_dashboard_data(self, json_data):
        """
        Puts the contents of the passed data to the dashboard.
        WARNING- will completely overwrite whatever is currently there.
        :param json_data: JSON data to post
        """

        # dump the json to string, save it to the XML value
        print("Sending JSON: {0}".format(json_data))
        data_out = json.dumps(json_data)
        xml_result = Et.fromstring(self._dashboard_data_xml)
        xml_result.find('DashboardData').find('Value').text = data_out

        generated_xml = Et.tostring(xml_result)
        requests.post(self._dashboard_url, auth=self._auth, verify=False,
                      data=generated_xml)

    @_bigfix_lock_required
    def update_nvd_dashboard_data(self, event):
        """
        Updates the BigFix console with the NVD data we've received from Cb.
        It is worth noting that we must download the existing data, then
        upload new data to preserve it's current contents.
        :param event: Event object to upload data for
        """
        data = self.get_dashboard_data()

        # if there is no data (empty object) add the assets tag
        if "assets" not in data:
            data['assets'] = []

        def update_asset_from_event(b_asset):
            """
            Given an asset from the bigfix dashboard, update it and then
            simply return it.
            :param b_asset: Asset to update
            :return:  Updated asset
            """
            b_asset['fqdn'] = event.host.name
            b_asset['besid'] = event.host.bigfix_id

            try:
                if b_asset['risk'] < event.threat_intel.phase2_patch_priority:
                    b_asset['risk'] = event.threat_intel.phase2_patch_priority
            except KeyError:
                b_asset['risk'] = event.threat_intel.phase2_patch_priority

            cve_exists = False
            try:
                for cve in b_asset['cves']:
                    if cve['id'] == event.threat_intel.cve:
                        cve_exists = True
            except KeyError:
                b_asset['cves'] = list()

            # print(cve_exists)

            if not cve_exists:
                b_asset['cves'].append({
                    "id": event.threat_intel.cve,
                    "risk": event.threat_intel.report_score
                })

            return b_asset

        # loop through the data to see if we have any data already
        # for this machine
        asset_index = -1
        for index, working_asset in enumerate(data['assets']):
            if working_asset['besid'] == event.host.bigfix_id:
                asset_index = index

        # if we found it already existing in the dashboard..
        if asset_index > -1:
            data['assets'][asset_index] = update_asset_from_event(
                data['assets'][asset_index])
        else:
            data['assets'].append(update_asset_from_event({}))

        self.put_dashboard_data(data)

   #
   #
   # # if there is no data (empty object) add the assets tag
   #      if "assets" not in data:
   #          data['assets'] = []
   #
   #      # loop through the data to see if we have any data already for this machine
   #      asset_found = False
   #      for asset in data['assets']:
   #          if asset['besid'] == str(besid):
   #              asset_found = True
   #              working_asset = asset
   #
   #              # update the values we have with the ones we were provided, just in case.
   #              for key in machine_info_dict:
   #                  working_asset[key] = machine_info_dict[key]
   #
   #              for addr in machine_addrs:
   #                  if addr not in working_asset['addrs']:
   #                      working_asset['addrs'].append(addr)
   #
   #              # since we only want one copy of this cve data for now,
   #              # this will drop anything that is a duplicate.
   #              existing_cves = list()
   #              for existing_cve_data in working_asset['cves']:
   #                  existing_cves.append(existing_cve_data['cve'])
   #              for cve_data in cve_data_dicts:
   #                  if cve_data['cve'] not in existing_cves:
   #                      working_asset['cves'].append(cve_data)
   #
   #      # if the asset wasn't found, simply plop our thing in and call it good.
   #      if not asset_found:
   #          working_asset = {}
   #          for key in machine_info_dict:
   #              working_asset[key] = machine_info_dict[key]
   #          working_asset['addrs'] = machine_addrs
   #          working_asset['cves'] = cve_data_dicts
   #          data['assets'].append(working_asset)
   #
   #      # dump the json to string, save it to the XML value
   #      data_out = json.dumps(data)
   #      xml_result.find('DashboardData').find('Value').text = data_out
   #
   #      generated_xml = Et.tostring(xml_result)
   #      requests.post(url, auth=self._auth, verify=False, data=generated_xml)
