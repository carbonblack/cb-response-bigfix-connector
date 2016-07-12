from unittest import TestCase, main as unittest_main
from time import sleep
import json

from src.fletch_config import Config
from src.comms.bigfix_api import BigFixApi


class TestEgressBigFix(TestCase):
    def test_get_besid(self):
        test_config = Config()
        bigfix = BigFixApi(test_config)

        besid = bigfix.get_besid(10)
        self.assertEqual(3634135, besid)

if __name__ == '__main__':
    unittest_main()
