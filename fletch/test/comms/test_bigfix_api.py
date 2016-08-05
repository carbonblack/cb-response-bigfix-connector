from unittest import TestCase, main as unittest_main
from time import sleep
from src.fletch_config import Config
from test.test_config import mutate_to_test_config
from src.comms.bigfix_api import BigFixApi
from copy import deepcopy as deepcopy
from tools.deep_compare import deep_compare as deep_compare
import src.data.events as events


class TestCommsBigFix(TestCase):
    def test_get_besid(self):
        test_config = Config()
        bigfix = BigFixApi(test_config)
        besid = bigfix.get_besid(10)
        self.assertEqual(3634135, besid)


class TestCommsBigFixCache(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_config = Config()
        cls.bigfix = BigFixApi(cls.test_config)

    def test_cache_layer_append(self):

        # test data
        computer1 = {"fqdn": "computer1", "besid": "456789", "cves": []}
        cve1 = {"id": "2016-1000", "risk": 1, "implicated": 0}
        cve2 = {"id": "2016-2000", "risk": 1, "implicated": 0}

        round1 = deepcopy(computer1)
        round2 = deepcopy(computer1)
        round1['cves'].append(cve1)
        round2['cves'].append(cve2)
        self.bigfix._cache_json_data([round1])
        self.bigfix._cache_json_data([round2])

        result = self.bigfix._cache_pull_and_delete(return_type=dict())
        cves = [a['id'] for a in result[computer1['besid']]['cves']]
        self.assertTrue(cve1['id'] in cves)
        self.assertTrue(cve2['id'] in cves)

    def test_cache_layer_implicated(self):

        # test data
        computer1 = {"fqdn": "computer1", "besid": "456789", "cves": []}
        cve1 = {"id": "2016-1000", "risk": 1, "implicated": 0}
        cve2 = {"id": "2016-1000", "risk": 1, "implicated": 1}

        round1 = computer1
        round1['cves'].append(cve1)
        round2 = computer1
        round2['cves'].append(cve2)
        self.bigfix._cache_json_data([round1])
        self.bigfix._cache_json_data([round2])

        result = self.bigfix._cache_pull_and_delete(return_type=dict())
        self.assertTrue(
            result[computer1['besid']]['cves'][0]['implicated'] == 1
        )


class TestCommsDashboard(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_config = mutate_to_test_config(
            Config(),
            fake_bigfix_server_requests=2
        )
        cls.bigfix = BigFixApi(cls.test_config)

    def test_dashboard_content_update(self):

        test_event = events.ImplicatedAppEvent()
        test_event.host.name = 'computer1'
        test_event.host.bigfix_id = '456789'

        test_event_hit = events.ThreatIntelHit()
        test_event_hit.cve = '2016-1000'
        test_event_hit.score = 1

        test_event.threat_intel.hits.append(
            test_event_hit
        )

        test_data = [{"fqdn": "computer1", "besid": "456789", "cves": [
            {"id": "2016-1000", "risk": 1, "implicated": 1}
        ]}]

        # post to the fake server, and confirm we resulted in an XML
        # document with our data inside.
        self.bigfix.update_nvd_dashboard_data(test_event, bypass_cache=True)
        dashboard_data = self.bigfix.get_dashboard_data()
        print(dashboard_data)
        self.assertTrue(deep_compare(test_data, dashboard_data))


class TestBannedFileFixlets(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_config = mutate_to_test_config(
            Config(),
            fake_bigfix_server_enable=False
        )
        cls.bigfix = BigFixApi(cls.test_config)

    def test_full_fixlet_creation(self):

        test_event = events.BannedFileEvent()
        test_event.host.name = 'computer1'
        test_event.host.bigfix_id = '456789'
        test_event.host.os_type = events.Host.OS_TYPE_WINDOWS

        test_event.process.file_path = 'C:\\Test\\Path'
        test_event.process.md5 = 'TEST12345678909876543212345890'

        self.bigfix.process_banned_file_event(test_event)

        sleep(.5)
        xml = self.bigfix._get_remediation_fixlet(test_event.process.md5)
        ban_data = self.bigfix._unpack_remediation_fixlet(xml)
        self.assertTrue(test_event.process.md5 == ban_data.md5)
        self.assertTrue(test_event.process.file_path in ban_data.actionscript)


if __name__ == '__main__':
    unittest_main()
