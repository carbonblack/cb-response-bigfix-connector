from cbapi.response import *
from cbapi.live_response_api import LiveResponseError
import cbfeeds
import time
import os
import hashlib


# ---- SETUP ----
# Compile the golang project and get its hash
os.chdir("vulnerable_binary")
os.system("GOOS=windows go build")

filehash = hashlib.md5(open("vulnerable_binary.exe", "rb").read()).hexdigest()

# Create a new feed with the hash of our "vulnerable_binary" in it
# - this will be our "vulnerable software" feed
feed_info = cbfeeds.CbFeedInfo(name="bigfixTestVulnerableSoftware", display_name="Test feed for BigFix integration",
                               summary="Test feed for BigFix integration", tech_data="Not for release",
                               provider_url="http://localhost")
feed_report = cbfeeds.CbReport(iocs={"md5": [filehash]}, timestamp=int(time.time()), link="http://localhost",
                               title="test vulnerable application", id="a", score=100)

new_feed = cbfeeds.CbFeed(feedinfo=feed_info, reports=[feed_report])
open("feed.json", "w").write(new_feed.dump())

print("Make sure that the feed 'feed.json' is copied to the Cb Response server.")
input("Press enter when the feed is copied: ")

# Create a new watchlist with a query of "process_name:ping.exe"
# - this will be our "implicated event" watchlist, which will be triggered by our "vulnerable binary" above
c = CbResponseAPI()
if len(c.select(Watchlist).where("name:VulnBin")) == 0:
    new_watchlist = c.create(Watchlist, data={"name": "VulnBin",
                                              "index_type": "events",
                                              "query": "process_name:ping.exe"})
    new_watchlist.save()

# ---- TESTS ----
# Test 1: Run the "vulnerable" binary and make sure that it triggers the "vulnerable software" feed

# - Copy the "vulnerable binary" via Live Response to a sensor connected to the Cb Response server
# - (?) Validate that we get a hit in the BigFix connector
hostname = "WIN10BIGFIX60"
sensor = c.select(Sensor).where("hostname:{}".format(hostname)).one()
while sensor.status.lower() != "online":
    print("Make sure that host {} is online before proceeding.".format(hostname))
    input("Press enter when the host {} is online: ".format(hostname))
    sensor = c.select(Sensor).where("hostname:{}".format(hostname)).one()

with sensor.lr_session() as session:
    try:
        session.delete_file(r"c:\vulnerable_binary.exe")
    except LiveResponseError as e:
        if e.decoded_win32_error == "ERROR_FILE_NOT_FOUND":
            pass

    session.put_file(open("vulnerable_binary.exe", "rb"), r"c:\vulnerable_binary.exe")

    # - Run the "vulnerable binary" without any arguments
    session.create_process(r"c:\vulnerable_binary.exe")

# Test 2: Run the "vulnerable" binary and make sure that it triggers the "implicated" feature
# - Copy the "vulnerable binary" via Live Response to a sensor connected to the Cb Response server
# - Run the "vulnerable binary" with one command line argument (anything)
# - (?) Validate that we get a hit in the BigFix connector
    session.create_process(r"c:\vulnerable_binary.exe do_implicated")

print("Test complete. Validate that there are two hits in the BigFix console")

