'''
.DESCRIPTION
    Simulates beaconing techniques for training
.EXAMPLE
    .\Fake-Beacon.py www.sans.org 3 30
.NOTES
    Interval time is in seconds
    TotalTime is in seconds
'''

import sys
import os
import time
import requests


if len(sys.argv)!=4:
    print('Usage: fakeBeacon.py <website> <interval> <totaltime>')
    sys.exit(0)

Website = (sys.argv[1])
Interval = int(sys.argv[2])
TotalTime = int(sys.argv[3])
# proxies = {"http": "http://<proxy ip>"}


def stopwatch(Website, Interval, TotalTime):
    start = time.time()
    time.clock()
    elapsed = 0
    while elapsed < TotalTime:
        try:
            elapsed = time.time() - start
            requests.get(("http://" + Website))
            #requests.get(("http://" + Website), proxies=proxies)
            print("[+]  " + (time.strftime("%d-%m-%Y")) +"   " + (time.strftime("%H:%M:%S")) + "  ----  " + Website + "  ----  Status: Beacon is alive.")

            time.sleep(Interval)
        except KeyboardInterrupt:
            print("Exiting...")
            sys.exit(0)
    # sys.stdout.write(RED)
    print("[+]  " + (time.strftime("%d-%m-%Y")) +"   " + (time.strftime("%H:%M:%S")) + "  ----  " + Website + "  ----  Status: Beacon is dead.")

stopwatch(Website, Interval, TotalTime)
