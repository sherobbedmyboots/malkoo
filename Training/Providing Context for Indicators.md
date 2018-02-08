# Providing Context for Indicators

When we obtain an indicator, either during incident response or from a third party, 
the next step is to use it to find, alert on, and
respond to the threat it is associated with.  In order to do this, we
almost always need more context.  Commercial and open-source feeds,
platforms, reports, and tools can be used to provide this context,
"enriching" our indicators to give us a better overview of the threat
and how it operates.  The more we know about the threat, the better we
can identify the systems that are at risk, hunt for related activity,
set up automated alerting, and validate and respond to the alerts.


- [Indicators and TTPs](#indicators-and-ttps)
- [Indicator Research](#threat-indicator-research)
- [Using Maltego](#using-maltego)

## Indicators and TTPs

Indicators are things that could indicate the possibility of an
attack/compromise and range from atomic indicators (IPs and domain
names) to tools used (Sdelete, Mimikatz) to host and network artifacts
(PCAPs, Registry keys, Event Logs).  TTPs are the tactics, techniques,
and procedures used by adversaries in order to accomplish their goals. 
Together, all of these can be used to enhance incident detection,
analysis, and response.

This is a diagram called the [Pyramid of
Pain](http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html). 
It shows common indicator types and the relative "pain level" for
adversaries when denying the use of each one.

![](images/Researching%20Threat%20Indicators/image001.png)


This does a great job of reminding us that adversaries can easily change
hash values, IP addresses, and domain names in order to continue their
operation without being detected.  However, when defenders are aware
of/searching for TTPs, tools, and host/network artifacts, it is more
difficult for adversaries to achieve their objectives.  So generally
when we are researching indicators, we are trying to "move up" the
Pyramid of Pain to gather higher-quality information and a better
overview of the threat.

Here are general descriptions and examples of each type:


|Indicator|Description|Example|
|-|-|-|
|Tactics|The art or skill of employing available means to accomplish an end|Spear phishing, credential theft, drive-by downloads|
|Techniques|The unique ways or methods used to perform functions|Passwords used, commands used, exploits used|
|Procedures|A series of actions done in a specific order|Obtaining persistence, then downloading tools, then deleting logs|
|Tools|The tools used to complete an objective|PSExec, Nmap, WCE, DNScat, Sdelete, etc.|
|Host & Network Artifacts|Artifacts created by tools and TTPs used|Network traffic, log events, registry entries|
|Atomic indicators|Mostly context-less strings of data and metadata|IP address, domain name, hash value, email address|

[This diagram](http://ryanstillions.blogspot.com/2014/04/on-ttps.html)
is similar to the first and shows how each type fits into the big
picture:

![](images/Researching%20Threat%20Indicators/image002.jpg)


Here is an example of how these types can be used to distinguish between
two attacks that have many similarities, but are very different in terms
of how to best hunt/detect/respond:

|Indicator|Scenario 1|Scenario 2|
|-|-|-|
|Tactics|Client-side attack via phishing|Client-side attack via phishing|
|Techniques|IE buffer overflow|HTA file, macro|
|Procedures|`whoami`, `ipconfig`, `net user`|PS scripts, scanning, remote services|
|Tools|`pscp.exe`, `bd.exe`|Cobalt Strike, Bloodhound, PowerSploit|
|Host/Network Artifacts|TCP reverse shell, 4688 events|DNS, HTTP, HTTPS, 4625/4656 events|
|Domain Names|N/A|-|
|IP Addresses|-|-|
|Hash Values|N/A|N/A|


In most cases we're provided hash values, IP addresses, or domain names
as indicators of malicious activity.  We search for these indicators
across our environment and if any are found they help us quickly
identify the attack traffic and compromised systems.

- If a known bad file is sitting on a host, it can be detected by
    endpoint agents/enterprise search and the compromised host is
    quickly identified

- In the browser exploit exercise the file is not known---but
    knowledge of the malicious IP address allows us to quickly find the
    attack traffic

- In both scenarios, IPs changed---but knowledge of the malicious
    domain name allowed us to quickly find the attack traffic

But what happens if the hashes, IP addresses, and domain names being
used have been changed?  How do we find the malicious traffic on our
network?

- Use external sources to provide more context on the indicators we
    have

- Pivot to obtain higher quality indicators such as Host and Network
    artifacts, Tools, and TTPs (moving up the Pyramid of Pain)

## Threat Indicator Research

These are common sites used to gather information when indicators have
been provided but more information is needed:

What is it?

- [Robtex](https://www.robtex.com/)
- [DomainTools](https://whois.domaintools.com/)
- [Dazzlepod](http://dazzlepod.com/ip)
- [Network-Tools](http://network-tools.com/)
- [DNSstuff](http://www.dnsstuff.com/)

Has it been reported as being involved in malicious activity?

- [VirusTotal](https://www.virustotal.com/)
- [Urlvoid](http://www.urlvoid.com/)
- [IPvoid](http://www.ipvoid.com/)
- [SiteReview](https://sitereview.bluecoat.com/sitereview.jsp)
- [MalwareDomainList](https://www.malwaredomainlist.com/mdl.php)

By this point we now more context, such as the type of threat associated
with the indicators, and can pivot to other sites that focus on a single
type of threat:

Malware
- [Malwr](https://malwr.com/)
- [PayloadSecurity](https://www.hybrid-analysis.com/)
- [ThreatExpert](http://www.threatexpert.com/)

Ransomware                    
- [RansomwareTracker](https://ransomwaretracker.abuse.ch/tracker/)   

Website                               
- [Urlquery](http://urlquery.net/)
- [ThreatGlass](http://www.threatglass.com/)

Phishing                              
- [Phishtank](https://www.phishtank.com/)

Various Attacks                
- [BlockList](http://www.blocklist.de/en/search.html)

Additional research then allows more follow-on searches that hopefully
result in higher-quality indicators. 

Now, there is an easier way of accomplishing the same thing---instead of
hopping from portal to portal searching the indicators we have, we can
use a threat data aggregator such as [Active Trust
Dossier](https://platform.activetrust.net/) that collects current threat
data from multiple sources (Whois, DNS, CrowdStrike, iSight, OpenPhish,
etc.) directly into one platform.

For example:

Back when the Scenario 2 activity was first detected, initial research 
 with [Robtex](https://www.robtex.com/),
[DomainTools](https://whois.domaintools.com/),
[Dazzlepod](http://dazzlepod.com/ip),
[Network-Tools](http://network-tools.com/),
[DNSstuff](http://www.dnsstuff.com/) revealed the IP address, Whois
data, and basic infrastructure details.  Individual searches for the
domain in [VirusTotal](https://www.virustotal.com/),
[Urlvoid](http://www.urlvoid.com/), [IPvoid](http://www.ipvoid.com/),
[SiteReview](https://sitereview.bluecoat.com/sitereview.jsp), and
[MalwareDomainList](https://www.malwaredomainlist.com/mdl.php) did not
(and still do not) return any malicious reports.  Googling the domain
and searching through the results did yield some interesting information
but there's a better, faster way to tap into threat data that's already
been collected about a domain.

[Active Trust Dossier](https://platform.activetrust.net/) queries
multiple threat data sources and allows easy pivoting to ones that
contain data related to an indicator.  Using it to search the domain gives us several interesting results:


The **SECURE DOMAIN FOUNDATION** feature shows previous malware/phishing
from this domain:



The **PASSIVE DNS** feature shows another IP address used with this
domain:


Pivoting on this new IP address shows it has the worst possible
reputation score (100):


The **GOOGLE CUSTOM SEARCH** feature shows several malware samples
associated with this domain:


Pivoting to a
[Reverse.it](https://www.reverse.it/sample/)
link reveals another malicious HTA file served from
the domain:


Pivoting to one of the
[PayloadSecurity](https://www.hybrid-analysis.com/)
links reveals a malicious HTA file served from host " " on the
domain:


And this shows how the file uses `mshta.exe` to invoke a hidden, encoded
PowerShell process:


And finally, pivoting to this
[PayloadSecurity](https://www.hybrid-analysis.com/)
link shows another HTA file which again utilizes `mshta.exe`, making
hundreds of DNS requests to the domain:


After just a few minutes, we already have a good amount of **context** for
our initial indicator ** ** :

- The domain has been previously used for phishing and malware
    distribution

- The domain has been associated with another IP address reported as
    malicious

- The domain has served three different HTA files that were reported
    as malicious


As well as some **TTPs**:

- These are client-side phishing attacks directed at what looks to be
    government agencies

- HTA files opened with `mshta.exe` are being used to deliver payloads
    to the victim hosts

- When successful, the attacks launch a hidden, encoded PowerShell
    process on the victim host

- Hundreds of DNS requests to the domain appear to be the method of C2


A little more research would reveal the tool being used and some common
host and network artifacts resulting from its use on the network.  By
obtaining additional indicators and TTPs, if these adversaries now began
using different IP addresses and domain names, we would still have ways
to search for and detect this kind of activity in our environment. 
Having this additional information also allows faster scoping,
containment, and remediation of compromised hosts.  Understanding more
about how the adversaries operate improves monitoring as well as efforts
to avoid reinfections.

Here are some open-source threat data aggregators that are also very
good:

- [ThreatMiner](https://www.threatminer.org/) aggregates data from open source tools and feeds (malwr, VT,
PayloadSecurity, OTX) providing context and data enrichment for improved
analysis

- [Passive Total](https://passivetotal.org/) pulls
pDNS, WHOIS, SSL, malware, OSINT data, great at showing timeline of DNS
resolutions and allowing pivots to OSINT/hashes/other DNS names

- [Threat Crowd](https://www.threatcrowd.org/) uses
open source data (Whois, DNS, VirusTotal, Malwr) to provide information
on IPs, domains, hashes, email addresses, and AV detections

The following, commonly referred to as Threat Intelligence Platforms
(TIPs), are also great tools to use for research but are more geared
towards managing and collaborating on threat data across an
organization, a group of organizations, or the entire community.

Commercial versions:
 
- [ThreatConnect](https://www.threatconnect.com/)
- [ThreatQuotient](https://www.threatq.com/)
- [Anomali](https://www.anomali.com/)
- [CentripetalNetworks](http://www.centripetalnetworks.com/)

Here are some open-source platforms---the
exchange networks are another valuable source of information when
researching indicators:

- [IBM X-Force
Exchange](https://exchange.xforce.ibmcloud.com/new) is a cloud-based threat intelligence platform for sharing and collaborating

- [AlienVault
OTX](https://otx.alienvault.com/browse/pulses/) is used to research threat data, follow contributors, and subscribe to pulses that
provide a summary of each threat with IOCs and targeted software

- [Blueliv Threat Exchange
Network](https://community.blueliv.com/#!/discover) is an indicator sharing and collaboration site

- [CRITS](https://crits.github.io/) is used to manage and share indicator sets within and across organizations in a
standardized format

- [MISP](https://github.com/MISP/MISP) is a repository for sharing, storing, and correlating IOCs of targeted
attacks

- [threat_note](https://github.com/defpoint/threat_Note) is a lightweight investigation notebook with integrated VirusTotal enrichment

## Using Maltego

[Maltego](https://www.paterva.com/web7/) is a link analysis tool that
locates, aggregates, and organizes data from a wide range of external
sources.  By using transforms, Maltego queries a source (Whois,
NewsLink, PeopleMon, HaveIBeenPwned, etc.) for an entity (Name, Email
address, Company Name) returning related links and data.  This allows
pivoting while also creating a visual picture of the relationships
between all entities.

This helps gather new information and build out a bigger picture of
people, organizations, and infrastructure involved.  Here are some
examples of entity types you can use:

|Type|Example|
|-|-|
|People|Names, Phone numbers, Email addresses, Aliases, Social groups, Organizations, Companies, Usernames, User IDs|
|Groups|Company, School, Institution, Online Group, Organization, Political Movement|
|Infrastructure|Domains, DNS names, Netblocks, IP addresses, AS, MX Record, NS Record, URL, Website, MAC Addresses|
|Location|City, Country, Region, Home, Office|
|Social Networks|Affiliations, Tweets, Hashtags, LinkedIn, Facebook|
|Events|Conversations, Chats, Meetings, Incidents, Emails|
|Devices|Desktop, Device, Mobile Computer, Smartphone, Mobile phone|
|Documents|Hashes, Notes, Images, Phrases, Files|


A version of Maltego is already installed on the SIFT-REMnux VM:

- Open a terminal and type `maltego_tungsten_ce`

- When prompted with the welcome message, click Next

- Click on Register Here in order to create an account

- After account is created, enter username, password, and captcha

- After account details are displayed, Click Next

- Leave Maltego box checked and Click Next again

- When wizard is finished, leave "Start a Machine Option" checked and
    click Finish

- When prompted, check the option "Footprint L2" and click Next

- Enter domain name ` ` and click Finish

- At the prompt, click OK

- Uncheck the name servers and click Next

- Find ` ` and click once on it to select it

Scroll down to see that it resolves to an IP which belongs to a Netblock
 /24) and an AS ( ).

Right click on the IP address and run the following transforms:

`Run Transform -> IP owner detail -> All in this set`

This gives us a location, a phone number and an email
address:   

On the AS, run:

`Run Transform -> All Transforms -> To Company [Owner]`

This gives us the owning company and the
telecommunications carrier:   

On the ` ` domain, run:

`Run Transform -> Domain owner detail -> All in this set`

Notice the contact info is privacy protected, location
is Panama, PA

`Run Transform -> Other Transfers -> To DNS Name [using DB]`

Now we can see subdomains such as  .

You should now have a graph that looks similar to this:

 
Version 4 adds a ton of new features including transforms for
VirusTotal, PassiveTotal, ThreatCrowd, Shodan, ThreatMiner and more
which I will add to the VM soon. 

Using Maltego to aggregate and organize open-source threat data is
another way to add context to indicators and move up the Pyramid of
Pain.  It takes some practice getting used to navigating the tool---the
threat data aggregators are definitely more user-friendly.  But once you
get used to it the tool is great, especially if visualizing
organizations, infrastructure, and miscellaneous data is the goal.  Try
it out the next time you're researching a suspicious domain or IP
address and see if you like it. 

FYI - Here is a great collection of threat intelligence resources:  
<https://github.com/hslatman/awesome-threat-intelligence>
