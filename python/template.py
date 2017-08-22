#!/bin/python

from socket import *
import sys

def usage():
    print "scriptname.py <file>"

argc = len(sys.argv)
if(argc < 2 or argc > 2):
    usage()
    sys.exit(0)
