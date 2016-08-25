import logging
from src.comms.bigfix_api import BigFixApi


class EgressBigFix(object):

    def __init__(self, fletch_config, switchboard, bigfix_api):
        self._api = bigfix_api

        # Register for vulnerable and implicated events
        self._feed_event_chan = switchboard.channel(
            fletch_config.sb_feed_hit_events)
        self._feed_event_chan.register_callback(self._handle_message)

        # Register for banned file events
        self._feed_event_chan = switchboard.channel(
            fletch_config.sb_banned_file_events)
        self._feed_event_chan.register_callback(
            self._handle_banned_file_events)

        self.logger = logging.getLogger(__name__)

    def _handle_message(self, event):
        # print("Handling Egress through BigFix")
        self.logger.debug("Dispatching Dashboard Update")
        self._api.update_nvd_dashboard_data(event)

    def _handle_banned_file_events(self, event):
        self.logger.debug("Dispatching Banned File Fixlet Update")
        self._api.process_banned_file_event(event)

