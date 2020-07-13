'''
.DESCRIPTION
    Simulates beaconing techniques for training
.EXAMPLE
    .\fakeBeacon.py www.sans.org 3 30
.NOTES
    Interval time and total time is in seconds
'''

import sys
import os
import time
from urllib3 import ProxyManager


http = ProxyManager("http://10.10.10.10:80")

Website = (sys.argv[1])
Interval = int(sys.argv[2])
TotalTime = int(sys.argv[3])

def fakeBeacon(Website, Interval, TotalTime):
    start = time.time()
    time.clock()
    elapsed = 0
    while elapsed < TotalTime:
        try:
            elapsed = time.time() - start
            r = http.request('GET', ("http://" + Website))
            print("[+]  " + (time.strftime("%m-%d-%Y")) + "  " + (time.strftime("%H:%M:%S")) + "  ----  " + Website + "  ----  Status: Beacon is alive.")

            time.sleep(Interval)
        except KeyboardInterrupt:
            print("Exiting...")
            sys.exit(0)
    # sys.stdout.write(RED)
    print("[+]  " + (time.strftime("%d-%m-%Y")) +"   " + (time.strftime("%H:%M:%S")) + "  ----  " + Website + "  ----  Status: Beacon is dead.")

fakeBeacon(Website, Interval, TotalTime)
