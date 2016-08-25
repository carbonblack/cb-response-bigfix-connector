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

    OS_TYPE_WINDOWS = 0

    def __init__(self):
        self.name = ""
        self.bigfix_id = -1
        self.cb_sensor_id = -1
        self.os_type = None


class Process(object):
    """
    data about the process involved in the event
    """
    def __init__(self):
        self.md5 = ""
        self.guid = ""
        self.file_path = ""
        self.timestamp = ""
        self.name = ""
        self.cb_analyze_link = ""


class ThreatIntel(object):
    """
    data about the threat info
    """
    def __init__(self):
        self.hits = list()   # list of ThreatIntelHits
        self.overall_score = -1


class ThreatIntelHit(object):
    def __init__(self):
        self.feed_name = ""
        self.score = -1
        self.alliance_link = ""
        self.cve = ""


##############################################################################
# __ Event Superstructures __
# These are for storing data consistently across otherwise independent modules.

class Event(object):
    """
    A class for being consistent in how we are storing data between
    collecting it from the cb-event-forwarder and shipping it to
    BigFix.
    """

    def __init__(self):
        self.host = Host()


class VulnerableAppEvent(Event):
    """
    This class represents when a binary has been detected as vulnerable.
    """

    def __init__(self):
        self.vuln_process = Process()
        self.threat_intel = ThreatIntel()
        super(VulnerableAppEvent, self).__init__()


class ImplicatedAppEvent(Event):
    """
    This class represents when a binary has been detected as vulnerable AND
    a detection event has occurred that implies bad behavior from
    the vulnerable app.
    """

    def __init__(self):
        self.vuln_process = Process()
        self.threat_intel = ThreatIntel()

        self.implicating_watchlist_name = ""
        self.implicating_process = Process()
        self.implicating_process_threat_intel = ThreatIntel()

        super(ImplicatedAppEvent, self).__init__()


class BannedFileEvent(Event):
    """
    Though Cb Response reports banned file as a feed hit, we separate it out
    here since it really is a different type of thing.
    """

    def __init__(self):
        self.process = Process()
        super(BannedFileEvent, self).__init__()