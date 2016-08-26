"""
This file is for loading in configuration information from the config file.
Decided against purely using a ConfigParser so that we can cast types in here
instead of only storing strings and requiring all uses of this data to cast.
"""

import ConfigParser
import json


def str2bool(string):
    if string in ['true', 't', 'True']:
        return True
    else:
        return False


def load_file_section(section, config_file_path):
    """
    Simple helper to load in a section of the config file
    :param section - name of section to load
    :param config_file_path - path to the config file to load
    """
    cp = ConfigParser.SafeConfigParser()
    if config_file_path is None:
        config_file_path = 'config.ini'
    cp.read([config_file_path])

    return cp.items(section)


class CbEventListener(object):
    """
    Configuration for connecting to the Cb Event Forwarder
    """
    def __init__(self, config_file_path):

        # name of channel to ship received JSON messages to
        self.sb_incoming_cb_events = "sb_incoming_cb_events"

        # TODO defaults init

        # load in the items from the config file
        for x in load_file_section('cb-event-forwarder', config_file_path):
            self.__dict__[x[0]] = x[1]

        # cast to int.. port to communicate with the cb-event-forwarder
        self.listen_port = int(self.listen_port)


class CbComms(object):
    """
    Configuration for the connection to the Cb Response server
    This is mainly for using the API on the server to do queries
    """
    def __init__(self, config_file_path):
        # API token to use
        self.api_token = ''

        # TODO defaults init
        # URL to connect to
        # must always end in a forward slash
        self.url = ''

        # load in the items from the config file
        for x in load_file_section('cb-enterprise-response', config_file_path):
            self.__dict__[x[0]] = x[1]

        # correct type to boolean
        self.ssl_verify = str2bool(self.ssl_verify)


class IbmBigfix(object):
    """
    Configuration for the connection to the IBM bigfix server
    """
    def __init__(self, config_file_path):
        self.url = ''
        self.username = ''
        self.password = ''

        # TODO defaults init
        self.bigfix_custom_site_name = 'Carbon Black'

        # load in the items from the config file
        for x in load_file_section('ibm-bigfix', config_file_path):
            self.__dict__[x[0]] = x[1]

        # correct type to an integer
        self.packaging_interval = int(self.packaging_interval)

        # correct type to boolean
        self.cache_enabled = str2bool(self.cache_enabled)
        self.ssl_verify = str2bool(self.ssl_verify)


class Config(object):
    """
    Class to hold our configuration data.
    Note: the values here can be overridden by the config.ini file
    """
    def __init__(self, config_file_path=None):

        self._config_file = config_file_path

        # Main Switchboard channels
        self.sb_feed_hit_events = "sb_feed_hit_events"
        self.sb_banned_file_events = "sb_banned_file_events"

        # Risk Scores
        self.risk_phase2_nvd = 5
        self.risk_phase2_nvd_and_iocs = 10

        # Banned file feed name
        self.banned_file_feed = 'cbbanning'

        # TODO defaults init

        # load in the items from the config file
        for x in load_file_section('integration-core', self._config_file):
            self.__dict__[x[0]] = x[1]

        # make the on/off switches actually booleans
        self.send_vulnerable_app_info = bool(self.send_vulnerable_app_info)
        self.send_implicated_app_info = bool(self.send_implicated_app_info)
        self.send_banned_file_info = bool(self.send_banned_file_info)

        # a list of tuples for the feeds we should look for and the
        # minimum score that must be achieve before we consider it a
        # vulnerable app process
        self.vulnerable_app_feeds = list()
        self._raw_vulnerable_app_feeds = load_file_section(
            'integration-vulnerable-app-feeds',
            self._config_file
        )

        # we need to convert all the scores from the config file into
        # integers here for later comparisons.
        for feed in self._raw_vulnerable_app_feeds:
            self.vulnerable_app_feeds.append(
                (feed[0], int(feed[1]))
            )

        # fix the watchlist list so that it isn't a string
        self.integration_implication_watchlists = json.loads(
            self.integration_implication_watchlists
        )

        # Load in the other option blocks
        self.cb_event_listener = CbEventListener(self._config_file)
        self.cb_comms = CbComms(self._config_file)
        self.ibm_bigfix = IbmBigfix(self._config_file)
