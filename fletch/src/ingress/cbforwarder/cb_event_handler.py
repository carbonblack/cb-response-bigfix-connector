import logging

import src.data.events as events
from src.comms.bigfix_api import BigFixApi
from cbapi import CbApi


class CbEventHandler(object):

    def __init__(self, fletch_config, switchboard):
        self._switchboard = switchboard
        self._core_event_chan = self._switchboard.channel(
            fletch_config.sb_feed_hit_events)
        self._cb_url = fletch_config.cb_comms.url

        self._bigfix_api = BigFixApi(fletch_config)
        self._logger = logging

        # setup an (old) cbapi connection
        self._old_cbapi = CbApi(
            self._cb_url,
            token=fletch_config.cb_comms.api_token,
            ssl_verify=False
        )

        # grab our risk settings
        self._nvd_risk = fletch_config.risk_phase2_nvd
        self._iocs_nvd_risk = fletch_config.risk_phase2_nvd_and_iocs

        # grab the vulnerability feed settings
        self.vuln_feeds_entries = fletch_config.vulnerable_app_feeds
        self.vuln_feed_names = [feed[0] for feed in self.vuln_feeds_entries]

        # grab the banned file feed name
        self.banned_file_feed = fletch_config.self.banned_file_feed

        # grab the implication 'detection' watchlists
        self.implication_watchlists = \
            fletch_config.integration_implication_watchlists

        # grab the on/off switches
        self.send_vulnerable_app_info = fletch_config.send_vulnerable_app_info
        self.send_implicated_app_info = fletch_config.send_implicated_app_info
        self.send_banned_file_info = fletch_config.send_banned_file_info

        # register our callback
        self._switchboard.channel(
            fletch_config.cb_event_listener.sb_incoming_cb_events
        ).register_callback(self.handle_incoming_event)

    def handle_incoming_event(self, json_object):
        """
        This function is designed to be a callback by a switchboard channel
        We'll handle the data sent in by the CbEventListener class.
        :param json_object:  JSON from the cb-event-forwarder
        """

        try:
            if 'feed_name' in json_object:

                # match on vulnerable binary feeds
                if self.send_vulnerable_app_info:
                    if json_object['feed_name'] in self.vuln_feed_names:
                        self._process_nvd_hit(json_object)

                # match on process banned feeds
                if self.send_banned_file_info:
                    if json_object['feed_name'] in self.banned_file_feed:
                        self._process_banned_files(json_object)

                # match on implication watchlists:
                # TODO match on watchlists NOT on feeds
                if self.send_implicated_app_info:
                    if json_object['feed_name'] in self.implication_watchlists:
                        self._process_general_feed_hit(json_object)

        except Exception as e:
            self._logger.exception(e)

    def _process_nvd_hit(self, json_object):
        """
        When we notice an NVD feed hit come over the wire, process the data
        into FeedHitEvent objects and ship over to the main event stream for
        output processing
        :param json_object: JSON received from cb-event-forwarder
        """
        feed_hit_event = events.FeedHitEvent()
        feed_hit_event.feed_name = json_object['feed_name']

        feed_hit_event.host.name = json_object['hostname']
        feed_hit_event.host.cb_sensor_id = json_object['sensor_id']
        feed_hit_event.host.bigfix_id = int(self._bigfix_api.get_besid(
            json_object['sensor_id']))

        feed_hit_event.threat_intel.\
            report_score = json_object["report_score"]
        feed_hit_event.threat_intel.\
            cve = json_object["report_id"]
        feed_hit_event.threat_intel.\
            phase2_patch_priority = self._nvd_risk

        # dig into the docs provided from the feed
        # and pull out the interesting detail.
        for doc in json_object["docs"]:
            th = events.ThreatIntelHit()

            th.associated_process.md5 = doc["process_md5"]
            th.associated_process.timestamp = doc["last_update"]
            th.associated_process.name = doc["process_name"]
            th.associated_process.cb_analyze_link = "{0}/{1}/1".format(
                self._cb_url, doc['unique_id'])
            th.associated_process.guid = doc["unique_id"]
            th.alliance_nvd_link = doc["alliance_link_{0}".format(
                feed_hit_event.feed_name)]

            feed_hit_event.threat_intel.hits.append(th)

        self._core_event_chan.send(feed_hit_event)

    def _process_general_feed_hit(self, json_object):
        """
        When we notice a generic feed hit come over the wire, process the data
        and trace it back in CarbonBlack to see if it has a parent with NVD
        hits.  If not, discard the notice.  If so, send a FeedHitEvent object
        with additional data so bigfix can show a higher priority for whatever
        vulnerability it was.
        :param json_object: JSON received from cb-event-forwarder
        """
        print("Saw implication feed hit, investigating..")

        # for some reason all feeds have alliance as a prefix..
        # since the configuration takes in just the feed name we need to
        # prepend this prefix so that we can do a string match.
        feed_prefix = "alliance_score_"

        process_json = self._old_cbapi.process_events(
                            json_object["process_id"],
                            json_object["segment_id"]
                        )["process"]
        while "parent_unique_id" in process_json:

            # check to see if we have come across something with registered
            # NVD hits.  If so, we stop processing here and toss the result
            # over to the queue for posting to bigfix.
            for feed in self.vuln_feeds_entries:
                feed_name = feed[0]  # name of feed
                feed_min_score = feed[1]  # min score to proceed with match

                full_feed_key = feed_prefix + feed_name

                # check whether the key exists, and if so,
                # confirm the score is high enough to continue.
                if (full_feed_key in process_json) and \
                        (feed_min_score < process_json[full_feed_key]):

                    # TODO: clean this up...
                    # TODO: needs updates when new BigFix api is released
                    print "\tgold! implicating process '{}'".format(
                        process_json["process_name"]
                    )
                    iocs_nvd_hit = events.FeedHitEvent()
                    iocs_nvd_hit.host.name = process_json["hostname"]
                    iocs_nvd_hit.host.bigfix_id = int(
                        self._bigfix_api.get_besid(
                            json_object['sensor_id']
                        )
                    )
                    iocs_nvd_hit.feed_name = "TODO"
                    # CVE
                    # hostname
                    # besid
                    # count
                    process_json = dict()
                    break

                else:
                    # separate the id and segment ids out
                    parent_id_split = \
                        process_json["parent_unique_id"].split("-")
                    parent_id = "-".join(parent_id_split[0:-1])
                    parent_segment = parent_id_split[-1]
                    print("\tChasing id-segment: {} (unique-id: {})".format(
                        parent_id + '-' + parent_segment,
                        process_json["parent_unique_id"]))

                    # grab the parent process and do the loop over again
                    process_json = \
                        self._old_cbapi.process_events(
                            parent_id, parent_segment)["process"]

    def _process_banned_files(self, json_object):
        """
        For every banned file that is detected as attempted to execute,
        we need to inform BigFix of it's presence. This will be done
        through the creation/update of a fixlet within the bigfix server.
        :param json_object:  the json from the cb-event-forwarder
        """

        # TODO parse the json output and grab the file path, md5, and host
        # TODO integrate some modules from punisher codebase to update bigfix
        # TODO logging output.

        pass