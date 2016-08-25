"""
These class exist solely for allowing consistent (and readable) structures
for holding our data as we process it through the system.  Other classes
can write translation functions from whatever data they are bringing in
and/or sending out.
"""


class Host(object):
    """
    data about the hosting machine
    """
    name = ""
    ipv4_addresses = []
    ipv6_addresses = []
    bigfix_id = -1
    cb_sensor_id = -1


class Process(object):
    """
    data about the process with the threat hit
    """
    md5 = ""
    guid = ""
    timestamp = ""
    name = ""
    cb_analyze_link = ""


class ThreatIntelHit(object):
    associated_process = Process()
    alliance_nvd_link = ""


class ThreatIntel(object):
    """
    data about the threat info
    """
    hits = []   # of ThreatIntelHits
    report_score = 0
    cve = ""
    phase2_patch_priority = -1


class Event(object):
    """
    A class for being consistent in how we are storing data between
    collecting it from the cb-event-forwarder and shipping it to
    BigFix.
    """

    def __init__(self):
        self.host = Host()
        self.threat_intel = ThreatIntel()


class FeedHitEvent(Event):
    """
    A class for being consistent in how we are storing data between
    collecting it from the cb-event-forwarder and shipping it to
    BigFix.
    """

    def __init__(self):
        self.feed_name = ""
        super(FeedHitEvent, self).__init__()



