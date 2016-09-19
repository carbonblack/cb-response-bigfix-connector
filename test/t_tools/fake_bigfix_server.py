"""
The goal of this class is to serve as a mini bounce location for HTTP requests
so that we can test the values of our internal data prior to BigFix being
ready for their new code.
"""

from flask import Flask, request
import xml.etree.ElementTree as Et
import json

# number of requests to accept before shutting down.
# if we are running test cases, leave this at 2 otherwise
# the testing will hang because of the blocking wait for HTTP requests
max_requests_before_shutdown = 2


class FakeBigFixData(object):

    def __init__(self):
        self._server_cache = dict()
        self._json_wrapper = {
            'name': '',
            "timestamp": '',
            "vendor": "CarbonBlack",
            "version": "1",
            "assets": list()
        }

        # grab the bigfix XML document template
        xml_template_path = 'src/statics/bigfix_plugin_api_post_template.xml'
        with open(xml_template_path) as temp_open:
            self._xml_template = temp_open.read()

    def empty_cache(self):
        self._server_cache = dict()

    def build_response(self, posted_xml=None):
        """
        Process any new XML stuff and then merge it into our in-memory cache.
        Spit out the XML the server should be returning.
        :param posted_xml:  (if any) new XML this fake server just received.
        :return:  XML to return to the client (if a GET request)
        """

        if posted_xml is not None:
            xml_result = Et.fromstring(posted_xml)
            new_content = xml_result.find('DashboardData').find('Value').text
            json_data = json.loads(new_content)

            # simple merge strategy to emulate what bigfix will do.
            for asset in json_data['assets']:

                if asset['besid'] not in self._server_cache:
                    self._server_cache[asset['besid']] = asset
                else:
                    cached_asset = self._server_cache[asset['besid']]

                    # loop over all cves and ensure that the cve is cached
                    # if the cve already existed, and the new cve now indicates
                    # that it is implicated, set the cached version likewise
                    for cve in asset['cves']:
                        cve_found = False
                        for cached_cve in cached_asset['cves']:
                            if cve['id'] == cached_cve['id']:
                                cve_found = True
                                if cve['implicated'] == 1:
                                    cached_cve['implicated'] = 1
                        if cve_found is False:
                            cached_asset['cves'].append(cve)

        # then, return our content as XML
        output_xml = Et.fromstring(self._xml_template)
        output_json = self._json_wrapper
        output_json['assets'] = self._server_cache.values()
        output_xml.find('DashboardData').find('Value').text = \
            json.dumps(output_json)
        output_string = Et.tostring(output_xml)
        return output_string


def request_tracker():
    global max_requests_before_shutdown

    max_requests_before_shutdown -= 1
    # have we handled enough requests to shutdown?
    if max_requests_before_shutdown == 0:
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()


app = Flask(__name__)


def init_fake_server(*args, **kwargs):
    app_data = FakeBigFixData()
    app_data.empty_cache()
    app.run(*args, **kwargs)


@app.route("/<path:path>", methods=['GET'])
def get(path):
    """
    :return: The last content that was posted to us.
    """
    request_tracker()
    return app_data.build_response()


@app.route("/<path:path>", methods=['POST'])
def post(path):

    print('Fake BigFix Received POST')
    request_tracker()
    app_data.build_response(request.data)
    return ''


if __name__ == "__main__":
    app.run()
