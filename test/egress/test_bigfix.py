from unittest import TestCase, main as unittest_main
from time import sleep
from src.utils.loggy import Loggy

from src.egress.bigfix import EgressBigFix
from src.data.switchboard import Switchboard
from src.fletch_config import Config
from test.test_config import mutate_to_test_config
from src.data.events import VulnerableAppEvent, ThreatIntelHit
from src.comms.bigfix_api import BigFixApi


class TestEgressBigFix(TestCase):

    @classmethod
    def setUpClass(cls):
        # setup logging
        loggy = Loggy(log_level=Loggy.DEBUG,
                      auto_config_flags=[Loggy.AC_STDOUT_DEBUG])

    def test_outbound_event_empty_state(self):
        self.outbound_event_helper(list())

    def test_outbound_event_single_host_state(self):
        self.outbound_event_helper(
            [
                {
                    "besid": 22413,
                    "fqdn": "TEST-WORKSTATION-2",
                    "cves": [
                        {
                            "id": "TEST-0-0-1",
                            "risk": 10,
                            "implicated": 0
                        }
                    ]
                }
            ]
        )

    def outbound_event_helper(self, starting_state):
        sb = Switchboard()
        test_config = mutate_to_test_config(
            Config(),
            fake_bigfix_server_requests=5,
        )
        bigfix = BigFixApi(test_config, sb)

        # back up whatever used to be on the dashboard
        original_data = bigfix.get_dashboard_data()

        # clear the bigfix data
        bigfix.put_dashboard_data(starting_state)

        class TestValues:
            hostname = "WIN7"
            cve = "TEST-0-0-0"
            besid = 22414
            ti_score = 10
            implicated = 0

        try:
            _bigfix = BigFixApi(test_config, sb)
            EgressBigFix(test_config, sb, _bigfix)
            outgoing_channel = sb.channel(test_config.sb_feed_hit_events)
            vuln_event = VulnerableAppEvent()
            vuln_event_hit = ThreatIntelHit()
            vuln_event.threat_intel.hits.append(vuln_event_hit)

            vuln_event.host.name = TestValues.hostname
            vuln_event.host.bigfix_id = TestValues.besid

            vuln_event_hit.cve = TestValues.cve
            vuln_event_hit.score = TestValues.ti_score
            outgoing_channel.send(vuln_event)

            sleep(1)
            test_data = bigfix.get_dashboard_data()

            # locate the item we need by besid
            besid_to_index = [a['besid'] for a in test_data]
            test_index = besid_to_index.index(TestValues.besid)

            self.assertEqual(
                test_data[test_index]["fqdn"], TestValues.hostname)
            self.assertEqual(
                test_data[test_index]["besid"], TestValues.besid)
            self.assertEqual(
                test_data[test_index]["cves"][0]["id"], TestValues.cve)
            self.assertEqual(
                test_data[test_index]["cves"][0]["risk"], TestValues.ti_score)
            self.assertEqual(
                test_data[test_index]["cves"][0]["implicated"],
                TestValues.implicated)

        finally:
            bigfix.put_dashboard_data(original_data)
            sb.shutdown()

if __name__ == '__main__':
    unittest_main()
