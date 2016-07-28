from time import sleep
from cbapi.response.models import Watchlist
from cbapi import CbEnterpriseResponseAPI

from fletch.data.switchboard import Switchboard
from fletch.fletch_config import Config
from fletch.ingress.cbforwarder.cb_event_listener import CbEventListener
from fletch.ingress.cbforwarder.cb_event_handler import CbEventHandler
from fletch.egress.bigfix import EgressBigFix


class CbBigFixIntegrator(object):

    def __init__(self):
        print("")
        print("Carbon Black - IBM Bigfix Integration Service")
        print("Release Version 1.0")
        print("")

        # load in all the configuration options
        self._config = Config()

        # connect to the Carbon Black response server
        # and ensure the watchlists we need are in place
        cb = CbEnterpriseResponseAPI(
            url=self._config.cb_comms.url,
            token=self._config.cb_comms.api_token,
            ssl_verify=self._config.cb_comms.ssl_verify
        )
        for watchlist in self._config.integration_implication_watchlists:
            if watchlist not in [w.name for w in cb.select(Watchlist)]:
                print("Can't find watchlist {0}, exiting.".format(watchlist))
                exit(1)

        # establish our services
        self._sb = Switchboard()
        self._cb_listener = CbEventListener(self._config, self._sb)
        self._cb_handler = CbEventHandler(self._config, self._sb)
        self._bf_egress = EgressBigFix(self._config, self._sb)

        try:
            while True:
                sleep(1000)
        except KeyboardInterrupt:
            self._cb_listener.shutdown()
            self._sb.shutdown()
            print("Goodbye")

if __name__ == "__main__":
    CbBigFixIntegrator()
