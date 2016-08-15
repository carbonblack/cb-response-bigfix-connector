from unittest import TestCase, main as unittest_main
from time import sleep
import json

from src.egress.bigfix import EgressBigFix
from src.data.switchboard import Switchboard
from src.fletch_config import Config
from src.data.events import FeedHitEvent
from src.comms.bigfix_api import BigFixApi


class TestEgressBigFix(TestCase):
    def test_outbound_event_empty_state(self):
        self.outbound_event_helper(dict())

    def test_outbound_event_single_host_state(self):
        self.outbound_event_helper({
            "assets":
                [
                    {
                        "besid": 22413,
                        "fqdn": "WIN7",
                        "risk": 5,
                        "cves": [
                            {
                                "id": "TEST-0-0-0",
                                "risk": 100
                            }
                        ]
                    }
                ]
        })

    def outbound_event_helper(self, starting_state):
        sb = Switchboard()
        test_config = Config()
        bigfix = BigFixApi(test_config)

        # back up whatever used to be on the dashboard
        original_data = bigfix.get_dashboard_data()

        # clear the bigfix data
        bigfix.put_dashboard_data(starting_state)

        class TestValues:
            hostname = "TestWorkstation"
            cve = "TEST-0-0-0"
            besid = 22413
            ti_score = 100
            priority = 5

        try:
            EgressBigFix(test_config, sb)
            outgoing_channel = sb.channel(test_config.sb_feed_hit_events)
            feed_hit = FeedHitEvent()
            feed_hit.host.name = TestValues.hostname
            feed_hit.threat_intel.cve = TestValues.cve
            feed_hit.host.bigfix_id = TestValues.besid
            feed_hit.threat_intel.report_score = TestValues.ti_score
            feed_hit.threat_intel.phase2_patch_priority = TestValues.priority
            outgoing_channel.send(feed_hit)

            sleep(1)
            test_data = bigfix.get_dashboard_data()
            # print(test_data)

            self.assertEqual(
                test_data["assets"][0]["fqdn"], TestValues.hostname)
            self.assertEqual(
                test_data["assets"][0]["besid"], TestValues.besid)
            self.assertEqual(
                test_data["assets"][0]["risk"], TestValues.priority)
            self.assertEqual(
                test_data["assets"][0]["cves"][0]["id"], TestValues.cve)
            self.assertEqual(
                test_data["assets"][0]["cves"][0]["risk"], TestValues.ti_score)

            # object_pass_back = {}
            #
            # # a tiny callback here to simply spit back the value
            # # we were provided for further processing in this main thread
            # def callback(feed_hit_event):
            #     object_pass_back['result'] = feed_hit_event

        finally:
            bigfix.put_dashboard_data(original_data)
            sb.shutdown()

if __name__ == '__main__':
    unittest_main()
