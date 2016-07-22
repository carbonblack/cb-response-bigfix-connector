from unittest import TestCase, main as unittest_main
from time import sleep
import json
import socket

from src.data.switchboard import Switchboard
from src.fletch_config import Config
from src.ingress.cbforwarder.cb_event_listener import CbEventListener


class TestCbEventListener(TestCase):

    def test_inbound_data_processing(self):
        """"
        For this, we'll let the Event listener power up like normal,
        then we'll connect to it over a socket, ship it JSON, and then
        confirm that it was put into the handler channel without loss of data.
        """

        sb = Switchboard()
        test_config = Config()
        print("Setup starting for EventListener")
        listener = CbEventListener(test_config, sb)
        print("Setup Complete")

        # hack to bring data within the callback function
        # back into this scope
        object_pass_back = {}

        # a tiny callback here to simply spit back the value
        # we were provided for further processing in this main thread
        def callback(network_json):
            object_pass_back['result'] = network_json

        sb.channel(test_config.cb_event_listener.sb_incoming_cb_events)\
            .register_callback(callback)

        # open up the JSON file and ship it over the network
        with open("ingress/data/adobe_reader_9_3_4_nvd_hit.json") as json_file:
            original_json = json.load(json_file)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((
                    'localhost',
                    test_config.cb_event_listener.listen_port
                ))
                s.send(json.dumps(original_json))
            finally:
                s.close()

        sleep(1)
        object_pass_back = object_pass_back['result']

        # now verify the data was parsed correctly
        self.assertTrue(original_json, object_pass_back)
        listener.shutdown()
        sb.shutdown()

    # tests for general feed hit abilities
    def test_inbound_data_processing_general_feed_hit(self):
        """"
        For this, we'll let the Event listener power up like normal,
        then we'll connect to it over a socket, ship it JSON, and then
        confirm that it was put into the handler channel without loss of data.
        """

        sb = Switchboard()
        test_config = Config()
        print("Setup starting for EventListener")
        listener = CbEventListener(test_config, sb)
        print("Setup Complete")

        # hack to bring data within the callback function
        # back into this scope
        object_pass_back = {}

        # a tiny callback here to simply spit back the value
        # we were provided for further processing in this main thread
        def callback(network_json):
            object_pass_back['result'] = network_json

        sb.channel(test_config.cb_event_listener.sb_incoming_cb_events)\
            .register_callback(callback)

        # open up the JSON file and ship it over the network
        j_path = "ingress/data/reader_sl_feed_hit_with_nvd_vuln_parent.json"
        with open(j_path) as json_file:
            original_json = json.load(json_file)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((
                    'localhost',
                    test_config.cb_event_listener.listen_port
                ))
                s.send(json.dumps(original_json))
            finally:
                s.close()

        sleep(1)
        object_pass_back = object_pass_back['result']

        # now verify the data was parsed correctly
        self.assertTrue(original_json, object_pass_back)
        listener.shutdown()
        sb.shutdown()

if __name__ == '__main__':
    unittest_main()
