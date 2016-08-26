import logging
import argparse
import sys
from time import sleep

from cbapi import CbEnterpriseResponseAPI
from cbapi.response.models import Watchlist

from comms.bigfix_api import BigFixApi
from data.switchboard import Switchboard
from egress.bigfix import EgressBigFix
from fletch_config import Config
from fletch_config import FletchCriticalError
from ingress.cbforwarder.cb_event_handler import CbEventHandler
from ingress.cbforwarder.cb_event_listener import CbEventListener
from utils.loggy import Loggy


class CbBigFixIntegrator(object):

    def __init__(self, config_file_path):
        print("")
        print("Carbon Black - IBM Bigfix Integration Service")
        print("Release Version 1.0")
        print("")

        # load in all the configuration options
        self._config = Config(config_file_path)

        # setup logging
        # TODO respect the user configuration of log level
        self.loggy = Loggy(log_level=Loggy.DEBUG,
                           auto_config_flags=[Loggy.AC_STDOUT_DEBUG,
                                              Loggy.AC_FILE])
        self.logger = logging.getLogger(__name__)
        self.logger.debug('Powering Up...')

        # use the fake bigfix server:
        # if False:
        #     from test import tools as bigfix_server
        #     from threading import Thread
        #     self._config.ibm_bigfix.url = 'localhost:5000'
        #     self._config.ibm_bigfix.protocol = 'http'
        #     Thread(target=bigfix_server.app.run).start()

        # connect to the Carbon Black response server
        # and ensure the watchlists we need are in place
        cb = CbEnterpriseResponseAPI(
            url=self._config.cb_comms.url,
            token=self._config.cb_comms.api_token,
            ssl_verify=self._config.cb_comms.ssl_verify
        )
        for watchlist in self._config.integration_implication_watchlists:
            if watchlist not in [w.name for w in cb.select(Watchlist)]:
                self.logger.critical(
                    "Can't find watchlist {0}, exiting.".format(watchlist))
                exit(1)

        # establish our services
        self._sb = Switchboard()
        self._bigfix_api = BigFixApi(self._config, self._sb)
        self._cb_listener = CbEventListener(self._config, self._sb)
        self._cb_handler = CbEventHandler(self._config, self._sb,
                                          self._bigfix_api)
        self._bf_egress = EgressBigFix(self._config, self._sb,
                                       self._bigfix_api)
        self.logger.debug("All Services Up")

        try:
            while True:
                sleep(1000)

        # TODO handle shutdown signals here
        except KeyboardInterrupt:
            self._cb_listener.shutdown()
            self._sb.shutdown()
            print("Goodbye")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Cb Response, IBM Bigfix Integration Connector.')
    parser.add_argument('-c', '--config', metavar='c', nargs='?',
                        default='/etc/cb/integrations/bigfix/connector.config',
                        help='path to the configuration file')

    args = parser.parse_args()
    try:
        CbBigFixIntegrator(args.config)
    except FletchCriticalError as e:
        logging.critical(e.message)
        sys.exit(1)
    except Exception as e:
        logging.exception(e)
        sys.exit(2)

