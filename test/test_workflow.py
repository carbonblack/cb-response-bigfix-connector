from cbapi.response import *
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


# Create a new watchlist with a query of "process_name:ping.exe"
# - this will be our "implicated event" watchlist, which will be triggered by our "vulnerable binary" above
c = CbResponseAPI()
new_watchlist = c.create(Watchlist)

# ---- TESTS ----
# Test 1: Run the "vulnerable" binary and make sure that it triggers the "vulnerable software" feed

# - Copy the "vulnerable binary" via Live Response to a sensor connected to the Cb Response server
# - Run the "vulnerable binary" without any arguments
# - (?) Validate that we get a hit in the BigFix connector

# Test 2: Run the "vulnerable" binary and make sure that it triggers the "implicated" feature

# - Copy the "vulnerable binary" via Live Response to a sensor connected to the Cb Response server
# - Run the "vulnerable binary" with one command line argument (anything)
# - (?) Validate that we get a hit in the BigFix connector


