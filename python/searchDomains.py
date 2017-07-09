#!/usr/bin/python
import socket
import requests
import os
import sys
import colors
import re
import whois
from tabulate import tabulate


if len(sys.argv)==2:
    filename = sys.argv[1]
    if not os.path.isfile(filename):
        print(colors.red("[-] "+filename+" does not exist."))
        exit(0)
    if not os.access(filename, os.R_OK):
        print(colors.red("[-] "+filename+" access denied."))
        exit(0)
    print("\r\n[*] Using file: "+filename)
else:
    print('Usage: searchSuspDomains.py <sitename-file>')
    sys.exit(0)

with open(filename) as f:
    sites = f.read().splitlines()

def main():
    print("[*] Gathering WHOIS data...\r\n")
    table =[]
    for site in sites:
        try:
            i = whois.whois(site)
            if i:
                d = i["domain_name"]
                r = i["registrar"]
                c = i["creation_date"]
                c = c[0].strftime('%Y/%m/%d')
                e = i["emails"]
                e = e[1]
                table += [[d,r,c,e]]
        except:
            return
    headers = ["Domain Name", "Registrar", "Creation Date", "Email"]
    print(tabulate(table, headers, tablefmt="pipe"))
    print("\r\n\r\n")
main()
