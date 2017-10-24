#!/usr/bin/env python
import hashlib
import hmac
import email
import json
import requests
import sys
import csv
from colored import fore, style
import os
import subprocess
import datetime
import re
import fileinput


class APIRequestHandler(object):

    def __init__(self):
        self.URL = 'https://api.isightpartners.com'
        credentials = loadCreds()
        self.public_key = credentials['public']
        self.private_key = credentials['private']
        self.accept_version = '2.5'

    def run(self, type, indicator):
        time_stamp = email.utils.formatdate(localtime=True)
        
        # For url types, modify query
        if type == 'url':
            ENDPOINT = '/pivot/indicator/' + type + '?value=' + indicator
        else:
            ENDPOINT = '/pivot/indicator/' + type + '/' + indicator
        
        # For filePath types, take only filename 
        if type == 'filePath':
            type = 'fileName'
            indicator = indicator.split('%5C')[-1]

        # For fileName types, make lower
        if type == 'fileName':
            indicator = indicator.lower()

        accept_header = 'application/json'
        new_data = ENDPOINT + self.accept_version + accept_header + time_stamp
        # print(new_data)
        print(fore.GREEN + "[+] " + style.RESET + "Checking " + type + " " + indicator)
        key = bytearray()
        key.extend(map(ord, self.private_key))
        hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)

        headers = {
            'Accept': accept_header,
            'Accept-Version': self.accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }
        try:
            r = requests.get(self.URL + ENDPOINT, headers=headers)
            status_code = r.status_code
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        if status_code == 200:
            json_data = json.loads(r.text)
            pubinds = json_data['message']['publishedIndicators']
            actors = []
            families = []
            categories = []
            for x in pubinds:
                if x['actor'] not in actors:
                    if x['actor'] is not None:
                        actors.append(str(x['actor']))
                if x['malwareFamily'] not in families:
                    if x['malwareFamily'] is not None:
                        families.append(str(x['malwareFamily']))
                if x['ThreatScape'] not in categories:
                    if x['ThreatScape'] is not None:
                        categories.append(str(x['ThreatScape']))
            if not actors:
                actors.append('None')
            if not families:
                families.append('None')
            if not categories:
                categories.append('None')
            return actors, families, categories
        
        # Indicator not found
        elif status_code == 204:
            g = []
            g.append('None')
            return g, g, g
        
        # Error
        else:
            print(fore.RED + "[-] " + fore.YELLOW + indicator + style.RESET + " caused a " + fore.YELLOW + str(status_code) + style.RESET)
            h = []
            h.append('Unknown')
            return h, h, h

    def test(self, endpoint, type, indicator):
        time_stamp = email.utils.formatdate(localtime=True)
        if type == 'url':
            ENDPOINT = '/pivot/indicator/' + type + '?value=' + indicator
        else:
            ENDPOINT = '/pivot/indicator/' + type + '/' + indicator
        accept_header = 'application/json'
        new_data = ENDPOINT + self.accept_version + accept_header + time_stamp
        print(fore.GREEN + "[+] " + style.RESET + "Querying indicator: " + fore.YELLOW + indicator + style.RESET)
        key = bytearray()
        key.extend(map(ord, self.private_key))
        hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)

        headers = {
            'Accept': accept_header,
            'Accept-Version': self.accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }

        try:
            r = requests.get(self.URL + ENDPOINT, headers=headers)
            status_code = r.status_code
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        if status_code == 200:
            json_data = json.loads(r.text)
            pubinds = json_data['message']['publishedIndicators']
            print(fore.GREEN + "[+] " + style.RESET + "Related indicators: " + fore.YELLOW + str(len(pubinds)) + style.RESET)
            with open('data.json', 'w') as outfile:
                json.dump(json_data, outfile)
            actors = []
            families = []
            categories = []
            for x in pubinds:
                if x['actor'] not in actors:
                    if x['actor'] is not None:
                        actors.append(x['actor'])
                if x['malwareFamily'] not in families:
                    if x['malwareFamily'] is not None:
                        families.append(str(x['malwareFamily']))
                if x['ThreatScape'] not in categories:
                    if ['ThreatScape'] is not None:
                        categories.append(str(x['ThreatScape']))
            if not actors:
                actors.append("None")
            print(fore.GREEN + "[+] " + style.RESET + "Associated actors: " + fore.YELLOW + ', '.join(actors) + style.RESET) 
            if not families:
                families.append("None")
            print(fore.GREEN + "[+] " + style.RESET + "Associated malware families: " + fore.YELLOW + ', '.join(families) + style.RESET)
            if not categories:
                categories.append("None")
            print(fore.GREEN + "[+] " + style.RESET + "Associated threat categories: " + fore.YELLOW + ', '.join(categories) + style.RESET) 
        
        # Indicator not found
        elif status_code == 204:
            print(fore.YELLOW + "[+] " + style.RESET + "Indicator not found" + style.RESET)
        
        # Error
        else:
            if r.content:
                ejson = r.json()
                error = ejson['message']['error']
                descr = ejson['message']['description']
                print(fore.RED + "[-] " + style.RESET + str(status_code) + " -- " + error + " -- " + descr)
            else:
                print("No content")


def searchForPdfs():
    print(fore.YELLOW + "[+] " + style.RESET + "Searching current directory for PDFs")
    pdfs = os.popen('ls *.pdf').read()
    pdflist = pdfs.split('\n')
    pdflist.pop()
    pdfcount = len(pdflist)
    return pdflist, pdfcount

def parseWithIocp(pdfcount):
    print(fore.YELLOW + "[+] " + style.RESET + str(pdfcount) + " PDFs being parsed by IOCParser")
    os.system('for x in $(ls *.pdf);do iocp -i pdf -o csv $x -d > $x.csv;done')

def extractDates(pdflist):
    dates = []
    for p in pdflist:
        cmd = "pdf2txt.py " + p + " | grep 'Earliest Event\|First Occurrence' | grep -oP '[\d]{4}-[\d]{2}-[\d]{2}|[\d]{2}/[\d]{2}/[\d]{4}'"
        d = os.popen(cmd).read()
        dates.append(d)
    return dates

def formatDates(dates):
    print(fore.YELLOW + "[+] " + style.RESET + "Formatting dates list")
    newdates = []
    dates = list(map(str.strip, dates))
    for s in dates:
        # if SEN then 2017-01-01 format
        if s.startswith('20'):
            s = datetime.datetime.strptime(s, '%Y-%m-%d')
            s = s.strftime('%Y-%m-%d')
            newdates.append(s)
        elif s.startswith('1') or s.startswith('0'):
            s = datetime.datetime.strptime(s, '%m/%d/%Y')
            s = s.strftime('%Y-%m-%d')
            newdates.append(s)
        else:
            s = '0000-00-00'
            newdates.append(str(s))
    return newdates

def searchForCsv():
    print(fore.YELLOW + "[+] " + style.RESET + "Searching current directory for CSVs")
    csvs = os.popen('ls *.csv').read()
    csvlist = csvs.split('\n')
    csvlist.pop()
    csvcount = len(csvlist)
    return csvlist, csvcount

def addDateColumn(newdates, csvlist):
    print(fore.YELLOW + "[+] " + style.RESET + "Writing dates, removing pages, creating 'combined.csv'")
    combined = './combined.csv'
    with open(combined, 'w', newline='') as csvoutput:
        for d, c in zip(newdates, csvlist):
            with open(c, 'r', newline='') as csvinput:
                writer = csv.writer(csvoutput, delimiter=',', quotechar='"', lineterminator = '\n')
                reader = csv.reader(csvinput, delimiter=',', quotechar='"', lineterminator = '\n')
                for r in reader:
                    writer.writerow( (d, r[0], r[2], r[3]) )

def removeBadRegex(infile):
    print(fore.YELLOW + "[+] " + style.RESET + "Removing bad regex from 'combined.csv'" )
    for l in fileinput.input(infile, inplace = True):
        if not re.search(r'10\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}', l) and not re.search(r'(\.dhs$)|(\.ice$)|(\.hq$)|(\.fema$)|(\.gov$)', l):
            print(l, end = "")

def removeBadNames(infile):
    print(fore.YELLOW + "[+] " + style.RESET + "Removing bad names from 'combined.csv'")
    for n in fileinput.input(infile, inplace = True):
        if not re.search(r'(virustotal\.com)|(sophos\.com)|(malwr\.com)|(outlook\.com)|(malware\-traffic\.com)|(bluecoat\.com)', n):
            print(n, end = "")

def normalizeData(infile, outfile):
    print(fore.YELLOW + "[+] " + style.RESET + "Normalizing data.....creating 'normalized.csv'")
    findlist =  (',Host,', ',Email,', ',Filepath,', ',URL,', ',SHA256,', ',SHA1,', ',MD5,', ',Registry,', ',IP,', ',Filename,', ',CVE,', '@', ':', "\\", '/', 'hxxp', '[.]', '[d]', '#', '"', '[dot]')
    replacelist = (',domain,', ',emailName,', ',filePath,', ',url,', ',sha256,', ',sha1,', ',md5,', ',registryKey,', ',ip,', ',fileName,', ',cve,', '%40', '%3A', '%5C', '%2F', 'http', '.', '.', '%23', '%22', '.')
    with open(infile, 'r', newline='') as csvinput: 
        with open(outfile, 'w', newline='') as csvoutput:
            for line in csvinput:
                for item, replacement in zip(findlist, replacelist):
                    line = line.replace(item, replacement)
                csvoutput.write(line)

def queryIsight(infile):
    print(fore.YELLOW + "[+] " + style.RESET + "Checking indicators against iSight")
    indlist = []
    actors = []
    families = []
    categories = []
    with open(infile, 'r', newline='') as csvinput:
        reader = csv.reader(csvinput, delimiter=',', quotechar='"', lineterminator='\n')
        for row in reader:
            indlist.append([row[2], row[3]])
    for x, y in indlist:
        a, f, c = request_handler.run(x, y)
        actors.append(a)
        families.append(f)
        categories.append(c)
    return actors, families, categories

def writeNewCsv(list, infile, outfile):
    with open(infile, 'r', newline='') as csvinput:
        with open(outfile, 'w', newline='') as csvoutput:
            writer = csv.writer(csvoutput, delimiter=',', quotechar='"', lineterminator = '\n')
            reader = csv.reader(csvinput, delimiter=',', quotechar='"', lineterminator='\n')
            all = []
            for x in list:
                row = next(reader)
                row.append(', '.join(x))
                all.append(row)
            writer.writerows(all)

def getGoodRegex(infile):
    print(fore.YELLOW + "[+] " + style.RESET + "Extracting analysis URLs from 'combined.csv'")
    for n in fileinput.input(r'./combined.csv', inplace = True):
        if re.search(r'URL', n):
            if re.search(r'(virustotal\.com)|(malwr\.com)|(malware\-traffic\-analysis\.net)|(hybrid-analysis\.com)|(reverse\.it)', n):
                print(n, end = "")

def extractLinks():    
    pdflist, pdfcount = searchForPdfs()
    parseWithIocp(pdfcount)
    dates = extractDates(pdflist)
    newdates = formatDates(dates)
    csvlist, csvcount = searchForCsv()
    addDateColumn(newdates, csvlist)
    getGoodRegex('./combined.csv')
    print('./combined.csv')

def loadCreds():
    with open('credentials.json') as creds:
        credentials = json.load(creds)
        return credentials

def showHelp():
    print('\n' + fore.GREEN + "CSV_MODE:" + style.RESET + '\t\t' + "Usage:         python3 pdf2trend.py")
    print('\t\t\t' + "Description:   Extract indicators from PDFs, run against iSight API, store in CSV" + '\n')
    print(fore.GREEN + "SAMPLE_MODE:" + style.RESET + '\t\t' + "Usage:         python3 pdf2trend.py sample")
    print('\t\t\t' + "Description:   Extract malware sample URLs, store in CSV" + '\n')
    print(fore.GREEN + "SINGLE_QUERY mode:" + style.RESET + '\t' + "Usage:         python3 pdf2trend.py [endpoint] [indicator type] [indicator]")
    print('\t\t\t' + "Description:   Query iSight API endpoint for a single indicator and type"+ '\n')
    print('\t\t\t' + "Example:       python3 pdf2trend.py /pivot/indicator ip 10.10.10.10" + '\n')
    print("Put " + fore.GREEN + "public and private API keys " + style.RESET + "in a json file named " + fore.GREEN + "'credentials.json'" + style.RESET + ":" + '\n')
    print("$ python3" + '\n' + ">>> import json" + '\n' + ">>> credentials = {'public': 'xxxxxxx',")
    print("... 'private': 'xxxxxxx'}" + '\n' + ">>> with open('credentials.json','w') as f:")
    print("...    json.dump(credentials,f,ensure_ascii-False)" + '\n' + "..." + '\n' + ">>> exit()" + '\n')

if __name__ == '__main__':
    if len(sys.argv) == 2:
        if sys.argv[1] == 'sample':
            print(fore.GREEN + "[+] " + style.RESET + "Using SAMPLE_LINK_EXTRACT mode")
            extractLinks()
        elif sys.argv[1] == '-h':
            showHelp()

    elif len(sys.argv) == 4:
        print(fore.GREEN + "[+] " + style.RESET + "Using SINGLE_QUERY mode")
        request_handler = APIRequestHandler()
        request_handler.test(sys.argv[1], sys.argv[2], sys.argv[3])

    elif len(sys.argv) != 1:
        showHelp()
        
    else:
        request_handler = APIRequestHandler()
        pdflist, pdfcount = searchForPdfs()
        parseWithIocp(pdfcount)
        dates = extractDates(pdflist)
        newdates = formatDates(dates)
        csvlist, csvcount = searchForCsv()
        addDateColumn(newdates, csvlist)
        removeBadRegex('./combined.csv')
        removeBadNames('./combined.csv')
        normalizeData('./combined.csv', './normalized.csv')
        actors, families, categories = queryIsight('./normalized.csv')

        print(fore.YELLOW + "[+] " + style.RESET + "Writing actor column.....creating 'actors.csv'")
        writeNewCsv(actors, './normalized.csv','./actors.csv')

        print(fore.YELLOW + "[+] " + style.RESET + "Writing family column.....creating 'families.csv'")
        writeNewCsv(families, './actors.csv', './families.csv')

        print(fore.YELLOW + "[+] " + style.RESET + "Writing category column.....creating 'categories.csv'")
        writeNewCsv(categories, './families.csv', './categories.csv')