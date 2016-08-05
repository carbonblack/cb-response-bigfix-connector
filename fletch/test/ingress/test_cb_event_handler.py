from unittest import TestCase, main as unittest_main
from time import sleep
import logging
import json

from src.data.switchboard import Switchboard
from src.fletch_config import Config
from src.ingress.cbforwarder.cb_event_handler import CbEventHandler
from src.utils.loggy import Loggy
import src.data.events as events

# from test.test_config import mutate_to_test_config


class TestCbEventHandler(TestCase):

    @classmethod
    def setUpClass(cls):
        Loggy(log_level=Loggy.DEBUG,
              auto_config_flags=[Loggy.AC_STDOUT_DEBUG])
        cls._logger = logging.getLogger(__name__)

    def cleanup_switchboard(self, sb):
        sb.shutdown()

    def test_add_get_channel(self):
        sb = Switchboard()
        self.addCleanup(self.cleanup_switchboard, sb)
        test_config = Config()

        CbEventHandler(test_config, sb)
        incoming = sb.channel(
            test_config.cb_event_listener.sb_incoming_cb_events)

        object_pass_back = {}

        # a tiny callback here to simply spit back the value
        # we were provided for further processing in this main thread
        def callback(feed_hit_event):
            object_pass_back['result'] = feed_hit_event

        sb.channel(test_config.sb_feed_hit_events)\
            .register_callback(callback)

        # WARN: many test failures come from this file.. usually because the
        # feed id number has changed. Update the JSON in the file to avoid
        # this.
        test_nvd_hit = "test/ingress/data/adobe_reader_9_3_4_nvd_hit.json"
        with open(test_nvd_hit) as json_file:
            hit_example = json.load(json_file)
            # print hit_example
        incoming.send(hit_example)

        sleep(1.5)
        object_pass_back = object_pass_back['result']

        # now verify the data was parsed correctly
        self.assertEqual(object_pass_back.host.name,
                         hit_example["hostname"])
        self.assertEqual(object_pass_back.host.bigfix_id,
                         3634135)
        self.assertEqual(object_pass_back.threat_intel.hits[0].cve,
                         hit_example["report_id"])
        self.assertEqual(object_pass_back.threat_intel.hits[0].score,
                         float(hit_example["report_score"])/10)

        # ugly way of grabbing just the first 5 chunks of id info
        unique_id = '-'.join(
            hit_example["docs"][0]["unique_id"].split('-')[0:5])
        self.assertEqual(object_pass_back.vuln_process.guid, unique_id)

    def test_watchlist_hit(self):
        """
        Send the JSON of a watchlist hit to the cb_event_handler and be sure
        that it constructs an accurate resulting event.
        NOTE: because this test cases requires the use of a live Cb server
        it is possible that the test will fail after some duration when
        the Cb server no longer has the process doc stored.
        """
        sb = Switchboard()
        self.addCleanup(self.cleanup_switchboard, sb)
        test_config = Config()

        cve_to_check_for = "CVE-2010-2883"

        CbEventHandler(test_config, sb)
        incoming = sb.channel(
            test_config.cb_event_listener.sb_incoming_cb_events)

        object_pass_back = {}

        # a tiny callback here to simply spit back the value
        # we were provided for further processing in this main thread
        def callback(feed_hit_event):
            object_pass_back['result'] = feed_hit_event

        sb.channel(test_config.sb_feed_hit_events)\
            .register_callback(callback)

        # WARN: many test failures come from this file.. likely means the
        # server has purged this particular process from its stored data
        test_watchlist_hit = "test/ingress/data/adobearm_implication_" \
                             "watchlist_hit.json"
        with open(test_watchlist_hit) as json_file:
            hit_example = json.load(json_file)
            # print hit_example
        self._logger.debug("Sending Implication JSON to Event Handler")
        incoming.send(hit_example)

        sleep(1.5)
        event = object_pass_back['result']

        # now verify the data was parsed correctly
        self.assertTrue(isinstance(event, events.ImplicatedAppEvent))
        self.assertEqual(event.implicating_watchlist_name,
                         hit_example['watchlist_name'])
        self.assertEqual(event.implicating_process.guid,
                         hit_example['docs'][0]['unique_id'])

        self.assertTrue(event.vuln_process.name, "acrord32.exe")

        # especially verify the right cve was found in there
        cves = [obj.cve for obj in event.threat_intel.hits]
        self.assertTrue(cve_to_check_for in cves)


if __name__ == '__main__':
    unittest_main()
