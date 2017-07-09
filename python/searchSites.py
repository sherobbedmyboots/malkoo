#!/usr/bin/python
import socket
import requests
import os
import sys
import colors
import re

if len(sys.argv)==3:
    term = sys.argv[1]
    filename = sys.argv[2]
    if not os.path.isfile(filename):
        print(colors.red("[-] "+filename+" does not exist."))
        exit(0)
    if not os.access(filename, os.R_OK):
        print(colors.red("[-] "+filename+" access denied."))
        exit(0)
    print("\r\n[*] Using file: "+filename)
else:
    print('Usage: searchSites.py <term> <filename>')
    sys.exit(0)


with open(filename) as f:
    sites = f.read().splitlines()


def webreq(site):
    try:
        data = requests.get('http://'+site).text
        return data
    except:
        return

def main():
    print("[*] Searching term: "+term+"\r\n")
    for site in sites:
        try:
            page = webreq(site)
            if page:
                if (term in page):
                    # print (colors.green("[+] String '"+term+"' found on site "+site))
                    version = re.search(r"(?i)wordpress.{0,10}[\'|\"]", page).group(0)
                    #print("[+] "+site+" contained the string: '"+version+"'")
                    print(colors.green("[+] "+'{:40s} {:40s}'.format(site,version)))
                else:
                    print (colors.red("[+] "+'{:40s} {:40s}'.format(site,"Not found")))
            else:
                print (colors.red("Page not retrieved"))
        except:
            print("[-] Error")
    print("\r\n\r\n")
main()
