import unittest
import logging
from cbapi import CbEnterpriseResponseAPI
from cbapi.response.models import Watchlist

from fletch_config import Config
from utils.loggy import Loggy

from test_config import test_config_file_path
from fletch_init import auto_create_vulnerability_watchlist


class TestFletchInit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        Loggy(log_level=Loggy.DEBUG,
              auto_config_flags=[Loggy.AC_STDOUT_DEBUG])
        cls._logger = logging.getLogger(__name__)
        cls._config = Config(test_config_file_path)

    def test_watchlist_auto_create_from_scratch(self):
        cb = CbEnterpriseResponseAPI(
            url=self._config.cb_comms.url,
            token=self._config.cb_comms.api_token,
            ssl_verify=self._config.cb_comms.ssl_verify
        )
        print(self._config.vuln_watchlist_name)
        auto_create_vulnerability_watchlist(
            cb,
            self._config.vuln_watchlist_name,
            self._config.vulnerable_app_feeds
        )
        # TODO develop checks here, right now this just run the code.


if __name__ == '__main__':
    unittest.main()
