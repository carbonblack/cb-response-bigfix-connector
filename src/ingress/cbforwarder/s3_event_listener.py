"""
Data input service to poll for event forwarder files off S3 bucket,
and placing it into the right event processing channels.

Overall data path:

-> cb-event-forwarder
 -> s3 bucket
  -> CbEventListener
   -> Channel("incoming_cb_events")
    -> CbEventHandler
     -> Channel("core_event_stream")

From the core event stream the output plugins can do whatever they'd like
to the data and ship it to where it needs to go.
"""

import logging
from threading import Thread
import boto3
from json import loads as json_loads
import time
from datetime import datetime
from dateutil.tz import tzutc
from dateutil import parser


S3_STATE_FILE = "/var/run/cb/integrations/cb-response-bigfix-connector/s3-last-modified"


class S3EventListener(object):
    def __init__(self, fletch_config, switchboard):
        """
        Establishes an interface to pull events from the Cb Response Event Forwarder via S3.
        Does not remove the files on the S3 bucket; instead we track the most recent last modified
        date that we've processed, and use that as a trigger
        """
        self._s3_bucket_name = fletch_config.s3_event_listener.bucket_name
        self._s3_profile_name = fletch_config.s3_event_listener.profile_name
        self._switchboard = switchboard
        self._shutdown = False
        self.logger = logging.getLogger(__name__)

        self._last_modified = datetime(2001, 1, 1, tzinfo=tzutc())

        # create our channels in the switchboard
        self._incoming_chan = self._switchboard.channel("sb_incoming_cb_events")

        #
        # Connect to S3
        #
        session = boto3.Session(profile_name=self._s3_profile_name)
        s3 = session.resource('s3')
        self._bucket = s3.Bucket(self._s3_bucket_name)

        # start the listener
        Thread(target=self._s3_poll_loop,
               name="s3_event_listener_server").start()

    def shutdown(self):
        self._shutdown = True

    def _process_events(self, body):
        for json_string in body:
            json_object = json_loads(json_string)

            # TODO test case of sending watchlist hit through here
            accepted_message_types = [
                "feed.storage.hit.process",
                "watchlist.storage.hit.process"
            ]

            # assume keys are present, fetch what we need
            # (errors will be caught anyhow by the try-except wrapper)
            object_type = json_object.get("type")

            if object_type in accepted_message_types:
                self.logger.debug("Received message of type: {0}".format(
                    json_object['type']
                ))
                self._incoming_chan.send(json_object)

            elif not object_type:
                self.logger.debug("Skipping unrelated object without 'type' field")
            else:
                self.logger.debug("Skipping unrelated object: {0}".format(
                    json_object["type"]))

    def _read_progress(self):
        self._last_modified = parser.parse(open(S3_STATE_FILE, "r").readline())

    def _save_progress(self):
        self.logger.debug("Last modified time is now {}".format(self._last_modified))
        open(S3_STATE_FILE, "w").write(self._last_modified.isoformat())

    def _s3_poll_loop(self):
        """
        Main loop to poll the S3 bucket for incoming events.

        IMPORTANT: This will never return until a shutdown is called.
        Start this function as a target of a thread.
        """
        processed_list = set()
        max_last_modified_time = self._last_modified

        while not self._shutdown:
            for obj in self._bucket.objects.all():
                if obj.last_modified > self._last_modified:
                    if obj.last_modified > max_last_modified_time:
                        max_last_modified_time = obj.last_modified

                    self.logger.debug("Processing file: {}".format(obj.key))
                    body = obj.get()["Body"].read()
                    self._process_events(body)

            self._last_modified = max_last_modified_time
            self._save_progress()

            # sleep for 1 minute
            time.sleep(60)

