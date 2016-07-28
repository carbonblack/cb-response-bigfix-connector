import logging

import fletch.data.events as events
from fletch.comms.bigfix_api import BigFixApi
from cbapi import CbApi
from cbapi import CbEnterpriseResponseAPI
from cbapi.response.models import ThreatReport


class CbEventHandler(object):

    def __init__(self, fletch_config, switchboard):
        self._switchboard = switchboard
        self._core_event_chan = self._switchboard.channel(
            fletch_config.sb_feed_hit_events)
        self._cb_url = fletch_config.cb_comms.url

        self._bigfix_api = BigFixApi(fletch_config)
        self._logger = logging

        # setup an (old) cbapi connection
        # TODO fix ssl_verify to use configuration file!
        self._old_cbapi = CbApi(
            self._cb_url,
            token=fletch_config.cb_comms.api_token,
            ssl_verify=False
        )

        # setup a new cbapi-python connection
        # TODO fix ssl_verify to use configuration file!
        self._cb = CbEnterpriseResponseAPI(
            url=self._cb_url,
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
        self.banned_file_feed = fletch_config.banned_file_feed

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
            # watch for feed events so we can inspect processes
            if json_object['type'] == 'feed.storage.hit.process':

                # match on vulnerable binary feeds
                if self.send_vulnerable_app_info:
                    if json_object['feed_name'] in self.vuln_feed_names:
                        self._process_vuln_hit(json_object)

                # match on process banned feeds
                if self.send_banned_file_info:
                    if json_object['feed_name'] in self.banned_file_feed:
                        self._process_banned_files(json_object)

            # Observe for watchlist hits that we should process
            elif json_object['type'] == 'watchlist.hit.process':

                # match on implication watchlists:
                if self.send_implicated_app_info:
                    if json_object['watchlist_name'] in \
                            self.implication_watchlists:
                        self._process_watchlist_hit(json_object)

        except Exception as e:
            self._logger.exception(e)

    def _process_vuln_hit(self, json_object):
        """
        When we notice a feed hit from one of our vulnerability feeds
        come over the wire, process the data into VulnerableAppEvent objects
        and ship over to the main event stream for output processing
        :param json_object: JSON received from cb-event-forwarder
        """
        event = events.VulnerableAppEvent()
        feed_id = json_object['feed_id']
        feed_name = json_object['feed_name']

        # host information
        event.host.name = json_object['hostname']
        event.host.cb_sensor_id = json_object['sensor_id']
        event.host.bigfix_id = int(self._bigfix_api.get_besid(
            json_object['sensor_id']))

        # process information, or at least, whatever we can fill in
        event.vuln_process.guid = json_object['process_id']
        event.vuln_process.timestamp = json_object['timestamp']
        event.vuln_process.cb_analyze_link = "{0}/{1}/1".format(
                self._cb_url, event.vuln_process.guid)

        # watch for more than one document, wasn't a case this was built for
        # since I'm not sure if it even exists?
        if len(json_object['docs']) > 1:
            self._logger.warning('More than one doc in feed report??')

        # store all the threat intel now
        for doc in json_object["docs"]:
            data_key = "alliance_data_{0}".format(feed_name)
            intel_data_ids = doc[data_key]

            # if we get a string back, just stuff it into an array for
            # processing. Not sure why it's possible to get different types
            # back from the same data element.. but there you go.
            if isinstance(intel_data_ids, str):
                intel_data_ids = [intel_data_ids]

            for report in intel_data_ids:
                th = events.ThreatIntelHit()
                th.feed_name = feed_name

                select_string = "{0}:{1}".format(feed_id, report)
                report = self._cb.select(ThreatReport, select_string)

                # the cb score is out of 100, instead of out of 10 like CVSS
                # assumption: the CVSS score was just multiplied by 10
                th.score = float(report['score']) / 10

                # assume some structure here.. we need the CVE tag
                # and I think the only way to do that is to extract it from
                # the title (UGH).
                # Expected title format:  CVE<id> description
                # We only care about what is before the first space.
                th.cve = report['title'].split(' ')[0]
                self._logger.debug('Vuln Hits: Built Intel Hit:{}'.format(th))

                # intentionally skipping the alliance link variable
                # it isn't reliable enough in this instance
                # (one link for 'n' number of threat hits..)

                event.threat_intel.hits.append(th)

        self._core_event_chan.send(event)

    def _process_watchlist_hit(self, json_object):
        """
        When we notice a watchlist hit come over the wire, process the data
        and trace it back in CarbonBlack to see if it has a parent with NVD
        hits.  If not, discard the notice.  If so, send a ImplicatedAppEvent
        object with additional data so bigfix can show a higher priority
        for whatever vulnerability it was.
        :param json_object: JSON received from cb-event-forwarder
        """
        self._logger.debug("Saw implication feed hit for process: {}".format(
            json_object["process_id"]
        ))

        # for some reason all feeds have alliance as a prefix..
        # since the configuration takes in just the feed name we need to
        # prepend this prefix so that we can do a string match.
        feed_prefix = "alliance_score_"

        process_json = self._old_cbapi.process_events(
                            json_object["process_id"],
                            json_object["segment_id"]
                        )["process"]

        # since we will be re-writing the process_json every loop
        # let's save the start point so we can come back to it later
        implicating_process_json = process_json

        # start parent hunting
        while "parent_unique_id" in process_json:

            # some helping data structure for all the data we are
            # about to process. This is a pain because of how we need to
            # get feed hit information out of the cb api documents
            all_threat_hits = list()

            # check to see if we have come across something with registered
            # NVD hits.  If so, we stop processing here and toss the result
            # over to the queue for posting to bigfix.
            for feed in self.vuln_feeds_entries:
                feed_name = feed[0]  # name of feed
                feed_min_score = feed[1]  # min score to proceed with match

                full_feed_key = feed_prefix + feed_name

                # check whether the key exists
                if full_feed_key in process_json:

                    # collect all the information on this feed's hits
                    for hit in process_json['alliance_hits']:
                        hit_contents = process_json['alliance_hits'][hit]
                        hit_feed_name = hit_contents['feedinfo']['name']
                        if hit_feed_name.lower() == feed_name.lower():
                            for report in hit_contents['hits']:
                                report_value = hit_contents['hits'][report]

                                th = events.ThreatIntelHit()
                                th.feed_name = hit_feed_name.lower()
                                th.score = float(report_value['score'])/10

                                # again, assumed title format:
                                # Expected title format:  CVE<id> description
                                th.cve = report_value['title'].split(' ')[0]

                                # only add it to the list if the score is high
                                if feed_min_score < report_value['score']:
                                    all_threat_hits.append(th)

            # Inspect to see if we have any entries in the hit list that
            # are relevant to this process.
            if len(all_threat_hits) > 0:

                event = events.ImplicatedAppEvent()

                # host information
                event.host.name = implicating_process_json['hostname']
                event.host.cb_sensor_id = implicating_process_json['sensor_id']
                event.host.bigfix_id = int(self._bigfix_api.get_besid(
                    implicating_process_json['sensor_id']))

                event.implicating_watchlist_name = \
                    json_object['watchlist_name']

                # TODO add in rest of implicating process information
                event.implicating_process.guid = \
                    implicating_process_json["process_id"]

                # TODO add in implicating process threat intel

                # the vulnerable process information
                event.vuln_process.md5 = process_json['md5']
                event.vuln_process.guid = process_json['process_id']
                event.vuln_process.file_path = process_json['path']
                event.vuln_process.name = process_json['process_name']
                event.vuln_process.cb_analyze_link = "{0}/{1}/1".format(
                    self._cb_url, event.vuln_process.guid)

                # the vulnerable process threat info, we can just take our
                # list and stick it right into a threat intel report
                event.threat_intel = all_threat_hits
                self._logger.info(
                    'Found Vulnerable Process {} from Implication {}'.format(
                        event.vuln_process.guid, event.implicating_process.guid
                    ))

                # escape the while loop
                break

            # if no relevant hits, then we need to grab the parent process
            # and keep going up the chain.
            else:

                # separate the id and segment ids out
                parent_id_split = \
                    process_json["parent_unique_id"].split("-")
                parent_id = "-".join(parent_id_split[0:-1])
                parent_segment = parent_id_split[-1]

                self._logger.debug("\tChasing id-segment: {0}".format(
                    parent_id + '-' + parent_segment))

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