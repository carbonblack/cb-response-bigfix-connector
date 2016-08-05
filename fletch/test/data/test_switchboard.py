from unittest import TestCase, main as unittest_main
from src.data.switchboard import Switchboard, Channel
from random import randint
from time import sleep


class TestSwitchboard(TestCase):
    def test_add_get_channel(self):
        sb = Switchboard()
        chan_from_test = sb.channel("from_test")
        self.assertTrue(isinstance(chan_from_test, Channel))

        get_chan_from_test = sb.channel("from_test")
        self.assertTrue(isinstance(chan_from_test, Channel))
        self.assertEqual(chan_from_test, get_chan_from_test)

        sb.shutdown()


class TestChannel(TestCase):
    def test_create_register_send_remove_shutdown(self):
        """
        Test to ensure that we can create a channel, register a callback
        and then actually receive a message with it.
        """

        def t_crs_callback(string_to_check, object_needing_true):
            object_needing_true['function_ran'] = True
            object_needing_true['string_to_check'] = string_to_check

        ch = Channel("test")
        obj_needing_true = {}
        subscription_id = ch.register_callback(t_crs_callback)
        send_string = "Hello World {0}".format(randint(0, 10000))
        ch.send(send_string, obj_needing_true)

        # do a pause here to wait for events to finish
        sleep(0.5)

        self.assertTrue(obj_needing_true['function_ran'])
        self.assertEqual(obj_needing_true['string_to_check'], send_string)

        # now remove the callback, ensure it has been properly deleted
        ch.remove_callback(subscription_id)
        obj_needing_false = {'function_ran': False}
        ch.send(send_string, obj_needing_false)

        # another pause to wait for events
        sleep(0.5)

        self.assertFalse(obj_needing_false['function_ran'])
        with self.assertRaises(KeyError):
            self.assertFalse(obj_needing_false['string_to_check'])

        ch.shutdown()

if __name__ == '__main__':
    unittest_main()