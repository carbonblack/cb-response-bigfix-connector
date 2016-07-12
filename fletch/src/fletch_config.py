"""
This file is for loading in configuration information from the config file.
Decided against purely using a ConfigParser so that we can cast types in here
instead of only storing strings and requiring all uses of this data to cast.
"""

import ConfigParser
import json


def load_file_section(section):
    """
    Simple helper to load in a section of the config file
    :param section - name of section to load
    """
    cp = ConfigParser.SafeConfigParser()
    cp.read(['config.ini', '../config.ini'])
    return cp.items(section)


class CbEventListener(object):
    """
    Configuration for connecting to the Cb Event Forwarder
    """
    def __init__(self):

        # name of channel to ship received JSON messages to
        self.sb_incoming_cb_events = "sb_incoming_cb_events"

        # load in the items from the config file
        for x in load_file_section('cb-event-forwarder'):
            self.__dict__[x[0]] = x[1]

        # cast to int.. port to communicate with the cb-event-forwarder
        self.listen_port = int(self.listen_port)


class CbComms(object):
    """
    Configuration for the connection to the Cb Response server
    This is mainly for using the API on the server to do queries
    """
    def __init__(self):
        # API token to use
        self.api_token = ''

        # URL to connect to
        # must always end in a forward slash
        self.url = ''

        # ssl verify, whether to check if TLS connection has valid certs
        self.ssl_verify = False

        # load in the items from the config file
        for x in load_file_section('cb-enterprise-response'):
            self.__dict__[x[0]] = x[1]


class IbmBigfix(object):
    """
    Configuration for the connection to the IBM bigfix server
    """
    def __init__(self):
        self.url = ''
        self.username = ''
        self.password = ''

        # load in the items from the config file
        for x in load_file_section('ibm-bigfix'):
            self.__dict__[x[0]] = x[1]


class Config(object):
    """
    Class to hold our configuration data.
    It is the plan to eventually read these things from a file.
    """
    def __init__(self):

        # Main Switchboard channels
        self.sb_feed_hit_events = "sb_feed_hit_events"

        # Risk Scores
        self.risk_phase2_nvd = 5
        self.risk_phase2_nvd_and_iocs = 10

        # load in the items from the config file
        for x in load_file_section('integration-core'):
            self.__dict__[x[0]] = x[1]

        # a list of tuples for the feeds we should look for and the
        # minimum score that must be achieve before we consider it a
        # vulnerable app process
        self.vulnerable_app_feeds = load_file_section(
            'integration-vulnerable-app-feeds'
        )

        # fix the watchlist list so that it isn't a string
        self.integration_implication_watchlists = json.loads(
            self.integration_implication_watchlists
        )

        # Load in the other option blocks
        self.cb_event_listener = CbEventListener()
        self.cb_comms = CbComms()
        self.ibm_bigfix = IbmBigfix()
