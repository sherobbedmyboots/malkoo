#!/usr/bin/env python
import hashlib
import hmac
import json
import requests
import sys, os
import datetime
import urllib
import email

def loadConfig(urlPath):
    with open('credentials.json') as creds:
	    credentials = json.load(creds)
    public_key = credentials['public']
    private_key = credentials['private']
    accept_header = 'application/json'
    accept_version = '2.5'
    time_stamp = email.utils.formatdate(localtime=True)
    string = urlPath + accept_version + accept_header + time_stamp
    key = bytearray()
    key.extend(map(ord, private_key))
    hashed = hmac.new(key, string.encode('utf-8'), hashlib.sha256)
    global proxy 
    proxy = {
        'http':'http://10.10.10.10:80',
        'https':'http://10.10.10.10:80',
    }
    global headers 
    headers = {  
        'Host':'api.isightpartners.com:443',
        'Proxy-Connection':'keep-alive',
        'Accept': accept_header,
        'Accept-Version': accept_version,
        'X-Auth': public_key,
        'X-Auth-Hash': hashed.hexdigest(),
        'Date': time_stamp,
        'User-Agent':'xxxxxxx',
    }

def HTTPSProxyRequest(method, host, url, proxy, header=None, proxy_headers=None, port=443):
    https = urllib.request.http.client.HTTPSConnection(proxy[0], proxy[1])
    https.set_tunnel(host, port, headers=headers)
    https.connect()
    https.request(method, url, headers=headers)
    response = https.getresponse()
    return response.read(), response.status

def checkIndicator(urlPath):
    r = HTTPSProxyRequest('GET','api.isightpartners.com',urlPath, ('10.10.10.10',80))
    if r[1] == 200:
        json_data = json.loads(r[0])
        return json_data
    elif r[1] == 204:
        print("RESULT: Indicator not found")
        exit()
    else:
        print("ERROR: HTTP Code: "+str(r[1]))
        exit()

def printResults(data):
    actors = []
    families = []
    categories = []
    pubinds = data['message']['publishedIndicators']
    for i in pubinds:
        act = i.get('actor','None')
        if act is not None:
            actors.append(act)
        fam = i.get('malwareFamily','None')
        if fam is not None:
            families.append(fam)
        cat = i.get('ThreatScape', 'None')
        if cat is not None:
            categories.append(cat)
    print("Related indicators: " + str(len(pubinds)))
    print("Associated actors: " + ', '.join(set(actors))) 
    print("Associated malware families: " + ', '.join(set(families)))
    print("Associated threat categories: " + ', '.join(set(categories)))

def formatUrlPath(ENDPOINT, type, indicator):
    if type == 'fileName':
        indicator = indicator.split('%5C')[-1].lower()
    if type == 'url':
        urlPath = '/' + ENDPOINT + '/' + type + '?value=' + indicator
    else:
        urlPath = '/' + ENDPOINT + '/' + type + '/' + indicator
    return urlPath

def main():
    urlPath = formatUrlPath(sys.argv[1], sys.argv[2], sys.argv[3])
    loadConfig(urlPath)
    data = checkIndicator(urlPath)
    printResults(data)

main()


