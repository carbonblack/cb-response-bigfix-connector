from src.comms.bigfix_api import BigFixApi


class EgressBigFix(object):

    def __init__(self, fletch_config, switchboard):
        self._feed_event_chan = switchboard.channel(
            fletch_config.sb_feed_hit_events)

        self._feed_event_chan.register_callback(self._handle_message)
        self._api = BigFixApi(fletch_config)

    def _handle_message(self, event):
        # print("Handling Egress through BigFix")
        self._api.update_nvd_dashboard_data(event)

