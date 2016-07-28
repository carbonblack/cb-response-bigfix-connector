from unittest import TestCase, main as unittest_main
from time import sleep
import json

from fletch.data.switchboard import Switchboard
from fletch.fletch_config import Config
from fletch.ingress.cbforwarder.cb_event_handler import CbEventHandler


class TestCbEventHandler(TestCase):
    def test_add_get_channel(self):
        sb = Switchboard()
        test_config = Config()

        CbEventHandler(test_config, sb)
        incoming = sb.channel(
            test_config.cb_event_listener.sb_incoming_cb_events)

        object_pass_back = {}

        # a tiny callback here to simply spit back the value
        # we were provided for further processing in this main thread
        def callback(feed_hit_event):
            object_pass_back['result'] = feed_hit_event

        sb.channel(test_config.sb_feed_hit_events).register_callback(callback)
        with open("ingress/data/adobe_reader_9_3_4_nvd_hit.json") as json_file:
            hit_example = json.load(json_file)
            # print hit_example
        incoming.send(hit_example)

        sleep(1)
        object_pass_back = object_pass_back['result']

        # now verify the data was parsed correctly
        self.assertEqual(object_pass_back.host.name,
                         hit_example["hostname"])
        self.assertEqual(object_pass_back.host.bigfix_id,
                         3634135)
        self.assertEqual(object_pass_back.threat_intel.cve,
                         hit_example["report_id"])
        self.assertEqual(object_pass_back.threat_intel.phase2_patch_priority,
                         5)
        self.assertEqual(object_pass_back.threat_intel.hits[0].
                         associated_process.guid,
                         hit_example["docs"][0]["unique_id"])

        sb.shutdown()

if __name__ == '__main__':
    unittest_main()

