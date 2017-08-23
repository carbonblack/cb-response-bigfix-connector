from requests.exceptions import HTTPError
from cbapi import CbApi
from cbapi import CbEnterpriseResponseAPI
from cbapi.response.models import Process as cbapiProcess
import data.events as events
import logging


class CbEventHandler(object):

    def __init__(self, fletch_config, switchboard, bigfix_api):
        self._switchboard = switchboard
        self._core_event_chan = self._switchboard.channel(
            fletch_config.sb_feed_hit_events)
        self._banned_file_chan = self._switchboard.channel(
            fletch_config.sb_banned_file_events)

        self._cb_url = fletch_config.cb_comms.url

        self._bigfix_api = bigfix_api
        self.logger = logging.getLogger(__name__)

        # setup an (old) cbapi connection
        self._old_cbapi = CbApi(
            self._cb_url,
            token=fletch_config.cb_comms.api_token,
            ssl_verify=fletch_config.cb_comms.ssl_verify
        )

        # setup a new cbapi-python connection
        self._cb = CbEnterpriseResponseAPI(
            url=self._cb_url,
            token=fletch_config.cb_comms.api_token,
            ssl_verify=fletch_config.cb_comms.ssl_verify
        )

        # grab our risk settings
        self._nvd_risk = fletch_config.risk_phase2_nvd
        self._iocs_nvd_risk = fletch_config.risk_phase2_nvd_and_iocs

        # grab the vulnerability feed settings
        self.vuln_feeds_entries = fletch_config.vulnerable_app_feeds
        self.vuln_feed_names = [feed[0] for feed in self.vuln_feeds_entries]
        self.vuln_watchlist_name = fletch_config.vuln_watchlist_name

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
            "sb_incoming_cb_events"
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

                # match on process banned feeds
                if self.send_banned_file_info:
                    if json_object['feed_name'] in self.banned_file_feed:
                        self.logger.debug("Dispatching Process Banned Event")
                        self._process_banned_files(json_object)

            # Observe for watchlist hits that we should process
            elif json_object['type'] == 'watchlist.storage.hit.process':

                # match on vulnerable app launch watchlist
                if self.send_vulnerable_app_info:
                    if json_object['watchlist_name'] == \
                            self.vuln_watchlist_name:
                        self.logger.debug("Dispatching Vulnerable App Event")
                        self._process_vuln_hit(json_object)

                # match on implication watchlists:
                if self.send_implicated_app_info:
                    if json_object['watchlist_name'] in \
                            self.implication_watchlists:
                        self.logger.debug("Dispatching Implication Event")
                        self._process_watchlist_hit(json_object)

        except Exception as e:
            self.logger.exception(e)

    def _process_vuln_hit(self, json_object):
        """
        Note: this function was rewritten from processing feed hit events
        into processing watchlist events as part of adapting to the discovery
        that in Cb Response 5.1/5.2 modloads of vulnerable binaries does NOT
        trigger a feed hit.

        When we notice a watchlist hit from our auto-generated watchlist (based
        upon the names of the feeds we are supposed to monitor), process the
        data into VulnerableAppEvent objects and ship over to the main event
        stream for output processing.

        :param json_object: JSON received from cb-event-forwarder
        """

        event = events.VulnerableAppEvent()
        process_id = json_object['process_id']
        process_doc = self._cb.select(cbapiProcess, process_id)

        # host information
        event.host.name = process_doc.hostname
        event.host.cb_sensor_id = process_doc.sensor_id

        # TODO: we probably shouldn't be looking up bes id's here. Leave that
        # TODO: up to the bigfix later on in the processing chain.
        event.host.bigfix_id = int(self._bigfix_api.get_besid(
            event.host.cb_sensor_id))

        # process information, or at least, whatever we can fill in
        event.vuln_process.guid = process_id
        event.vuln_process.timestamp = json_object['timestamp']
        event.vuln_process.cb_analyze_link = process_doc.webui_link

        # now we need to loop through the process document information
        # and extract all interesting items from the alliance hits
        # portion.
        for feed_triggered in process_doc.alliance_hits:
            feed_data = process_doc.alliance_hits[feed_triggered]

            feed_name = feed_data['feedinfo']['name'].lower()
            if feed_name in self.vuln_feed_names:
                for feed_hit in feed_data['hits']:
                    hit_data = feed_data['hits'][feed_hit]

                    th = events.ThreatIntelHit()
                    th.feed_name = feed_name

                    # the cb score is out of 100, instead of
                    # out of 10 like CVSS.
                    # Assumption: the CVSS score was just multiplied by 10
                    th.score = float(hit_data['score']) / 10

                    # assume some structure here.. we need the CVE tag
                    # and I think the only way to do that is to extract it from
                    # the id (and then chop of the 'CVE-' part of the string)
                    # Expected title format:  CVE-<id> description
                    # We only care about what is after the CVE- part.
                    th.cve = hit_data['id']
                    th.cve = th.cve[4:]  # remove 'CVE-' from the string
                    self.logger.debug(
                        'Vuln Hits: Built Intel Hit:{}'.format(th))

                    # including the threat report link
                    th.alliance_link = hit_data['link']

                    event.threat_intel.hits.append(th)

        self._core_event_chan.send(event)

    def _process_watchlist_hit(self, json_object):
        """
        NOTE: This function processes IMPLICATION watchlists hits.
        When we notice a watchlist hit come over the wire, process the data
        and trace it back in CarbonBlack to see if it has a parent with NVD
        hits.  If not, discard the notice.  If so, send a ImplicatedAppEvent
        object with additional data so bigfix can show a higher priority
        for whatever vulnerability it was.
        :param json_object: JSON received from cb-event-forwarder
        """
        self.logger.debug("Saw implication feed hit for process: {}".format(
            json_object["process_id"]
        ))

        # for some reason all feeds have alliance as a prefix..
        # since the configuration takes in just the feed name we need to
        # prepend this prefix so that we can do a string match.
        feed_prefix = "alliance_score_"

        # separate the id and segment ids out
        # unfortunately this some stuffed into a 'doc' entry.
        # warn if we have more than one since we don't account for it
        if len(json_object['docs']) != 1:
            self.logger.warning("More than one 'doc' received??")

        id_split = json_object["docs"][0]["unique_id"].split("-")
        unique_id = "-".join(id_split[0:-1])
        segment_id = int(id_split[-1])  # convert to int to drop extra 0's

        process_json = self._old_cbapi.process_events(
                            unique_id, str(segment_id))["process"]

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

                                # get rid of the 'CVE' part of the title,
                                # just want the id.
                                th.cve = th.cve[4:]

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
                    implicating_process_json["unique_id"]

                # TODO add in implicating process threat intel

                # the vulnerable process information
                event.vuln_process.md5 = process_json['process_md5']
                event.vuln_process.guid = process_json['unique_id']
                event.vuln_process.file_path = process_json['path']
                event.vuln_process.name = process_json['process_name']
                event.vuln_process.cb_analyze_link = "{0}/{1}/{2}".format(
                    self._cb_url, event.vuln_process.guid,
                    process_json["segment_id"])

                # the vulnerable process threat info, we can just take our
                # list and stick it right into a threat intel report
                event.threat_intel.hits = all_threat_hits
                self.logger.info(
                    'Found Vulnerable Process {} from Implication {}'.format(
                        event.vuln_process.guid, event.implicating_process.guid
                    ))

                # send our message and escape the while loop
                self._core_event_chan.send(event)
                break

            # if no relevant hits, then we need to grab the parent process
            # and keep going up the chain.
            else:

                # separate the id and segment ids out
                parent_id_split = \
                    process_json["parent_unique_id"].split("-")
                parent_id = "-".join(parent_id_split[0:-1])
                parent_segment = int(parent_id_split[-1])  # convert: drop 0's

                self.logger.debug("Chasing id-segment: {0} - {1}".format(
                    parent_id, parent_segment))

                # grab the parent process and do the loop over again
                try:
                    process_json = \
                        self._old_cbapi.process_events(
                            parent_id, parent_segment)["process"]
                except HTTPError:
                    self.logger.info("Stopping the process hunt, can't find "
                                      "the parent process")
                    break  # stop the search

    def _process_banned_files(self, json_object):
        """
        For every banned file that is detected as attempted to execute,
        we need to inform BigFix of it's presence. This will be done
        through the creation/update of a fixlet within the bigfix server.
        :param json_object:  the json from the cb-event-forwarder
        """

        ban_event = events.BannedFileEvent()
        ban_event.host.name = json_object["hostname"]

        # assuming only a single doc again here
        if len(json_object['docs']) != 1:
            self.logger.warning("More than one doc received??")

        # TODO: we probably shouldn't be looking up bes id's here. Leave that
        # TODO: up to the bigfix later on in the processing chain.
        ban_event.host.bigfix_id = int(self._bigfix_api.get_besid(
            json_object['sensor_id']))

        # TODO correct test case, it wasn't properly checking os type
        ban_event.host.cb_sensor_id = json_object['sensor_id']
        if json_object['docs'][0]["os_type"].lower() == "windows":
            ban_event.host.os_type = events.Host.OS_TYPE_WINDOWS

        ban_event.process.file_path = json_object["ioc_attr"]["hit_field_path"]
        ban_event.process.md5 = json_object["ioc_attr"]["hit_field_md5"]
        ban_event.timestamp = json_object["timestamp"]
        # ban_event.process.cb_analyze_link = "{0}/{1}/{2}".format(
        #    self._cb_url, ban_event.process.guid, json_object["segment_id"])

        self._banned_file_chan.send(ban_event)
