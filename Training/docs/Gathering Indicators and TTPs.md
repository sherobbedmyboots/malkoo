# Gathering Indicators and TTPs

Adversaries regularly take advantage of the fact that an attack on one
organization can be effective against thousands.  The extraction,
fusion, and sharing of threat indicators is used to counter this so that
instead of each organization fighting off adversaries individually, they
can work together using the knowledge and experience that already exists
in the community. 

Indicators are unique pieces of information that have some type of
intelligence value.  Here are the most common categories and their
descriptions:

|Category|Description|Example|
|-|-|-|
|IP|a valid IP Address, either IPv4 or IPv6|10.0.0.1|
|Email|a valid email address|emailaddress@gmail.com|
|File|a unique file hash or series of hashes|b7c380f0c33143d5042b699c0e2710a5|
|Host|a valid hostname, which is also referred to as a domain|[www.google.com](http://www.google.com)|
|URL|a valid URL, including protocol|https://www.google.com:443/?gws_rd=ssl|
|ASN|Autonomous System Numbers uniquely identify each network on the Internet|15169|
|CIDR|Classless Inter-Domain Routing identifies a block of network IP addresses|10.0.0.0/8|
|Mutex|a synchronization primitive that can be used to identify malware files/families|`\Sessions\1\BaseNamedObjects\53c044b1f7ebc1cbf2bff088c95b30`|
|Registry Key|a node in Windows registry|`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`|
|User Agent|software agent string used when operating in a network protocol|Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/55555 Firefox/53.0|


## Gathering Indicators

Three common ways to gather indicators and TTPs:

- [Collecting from Threat Data Feeds and Reports](#collecting-from-threat-data-feeds-and-reports)
- [Extracting from Malware and Artifacts](#extracting-from-malware-and-artifacts)
- [Pivoting on Known Indicators](#pivoting-on-known-indicators)


### Collecting from Threat Data Feeds and Reports

Nearly every attack you will see has most likely already been written
about or encountered before by numerous individuals.  Commercial and
open-source feeds, platforms, reports, and tools can provide a good
collection of indicators that are associated with a given threat. 

Finding, using, and sharing information on a threat's capabilities,
infrastructure, motives, goals, and resources is key for improving
detection, analysis and response.  Threat Intelligence Platforms (TIPs)
such as [ThreatConnect](https://threatconnect.com/sans/) allow you to
download multiple indicators and TTPs associated with a specific
incident that can be used to search across our environment.

                            

![](images/Gathering%20Indicators%20and%20TTPs/image001.png)


Other TIPs include:

- [ScoutVision](https://lgss.lgscout.com/) - Sharing and collaboration platform for consuming DHS threat data,
Internet topology mapping, aggregated threat indicator feeds

- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/new) - Cloud-based threat intelligence platform for sharing and collaborating

- [AlienVault OTX](https://otx.alienvault.com/browse/pulses/) - Research threat data, follow contributors, and subscribe to pulses
that provide a summary of each threat with IOCs and targeted software

- [Blueliv Threat Exchange Network](https://community.blueliv.com/#!/discover) - Indicator sharing and collaboration site

You shouldn't find any threat indicators related to our example scenario
in any of these TIPs since their purpose is collecting indicators for
actual incidents/attacks.

But you may find yourself in a similar situation if you're investigating
an incident that involves a fairly new or unknown attack.  In these
cases, if we have a sample, we can still obtain indicators and TTPs from
various stages of malware analysis.

### Extracting from Malware and Artifacts

Malware analysis is an extremely valuable source of indicators and TTPs
and usually consists of the following stages:

![](images/Gathering%20Indicators%20and%20TTPs/image002.png)


#### Fully Automated                              

Automated tools scan for common characteristics and techniques in a sandbox environment

Some reasons we may want to avoid automated sandbox solutions:

- Need full examination and reverse engineering

- Keep analysis in house

- Potential privacy violations

#### Static                                                    

Examineing metadata and other file attributes to perform triage and
determine next course of action


#### Interactive                                         

Running malware in a lab environment to observe its interactions with network,
files, processes, registry

#### Code Reversing                                

Using disassembly, decoding, and special tools to understand malware's inner workings

As we've seen in many of our previous exercises, different indicators
and TTPs are discovered during different stages of malware analysis.  In
the last two scenarios we obtained indicators from the file itself and
then used memory analysis to see what files, processes, and network
connections resulted from an infected host.  But we still only scratched
the surface... there are many more opportunities to extract additional
indicators and TTPs associated with this incident.


For example, this quick walkthrough shows how to use a tool called
CapLoader to carve out all network activity contained in a memory image
into a pcap file for analysis in wireshark, NetworkMiner, etc.

1. Copy the image `VM-USER-PC-2017-05-02-202227.raw` onto your Windows VM

2. Go to http://www.netresec.com/?page=CapLoader#trial and click on
    "Download Free Trial"

3. Download the `CapLoader_TRIAL.zip` file and extract its contents

4. Start the application and go to File --> Open File(s)

5. Select the memory image and click `Open`

6. When prompted to carve packets from the file, click `Yes`

7. Leave default options checked and click `Start`

We now have a summary of discovered flows, services, and hosts along
with full packet captures of the network activity that was contained in
the memory image:

![](images/Gathering%20Indicators%20and%20TTPs/image003.png)


Go to the Hosts tab, select 34.208.205.97, then right click on the PCAP
icon in the upper right-hand corner and save the PCAP to your desktop.

Using Wireshark, we can extract the TLS certificate used by the malware:

1. Open the pcap in Wireshark

2. Find the Server Hello message from the C2 server (there are several
    to choose from)

3. Find the "Secure Sockets Layer" field and expand its contents

4. Find the "TLSv1 Record Layer: Handshake Protocol: Certificate" field
    and expand its contents

5. Find the "Handshake Protocol: Certificate" field and expand its
    contents

6. Find the "Certificates (1305 bytes)" field and expand its contents

7. Right click on the "Certificate:
    30820512308203faa0030201020212031bb7058c792db28d...
    (id-at-commonName=unioncentralorchids.com)" field and  choose
    "Export Packet Bytes"

8. Save to Desktop as a .der file (`evilcert.der`)

9. Open a PowerShell prompt and navigate to Desktop

10. Get the sha1 fingerprint of the certificate by typing `certutil -hashfile .\evilcert.der`

11. Get the sha256 fingerprint of the certificate by typing `certutil -hashfile .\evilcert.der SHA256`

Now let's look at some of the indicators and TTPs we've obtained so far
from the `mnemonic1.exe` file and memory image:

|Exercise|Category|Indicator|
|-|-|-|
|Analyzing Packed Executables|TTP|Spear phishing|
||TTP|UPX-packed executable|
||TTP|PowerShell payload|
||URL|https://unioncentralorchids[d]com:443/index.asp|
||Host|unioncentralorchids\[d\]com|
||md5|b7c380f0c33143d5042b699c0e2710a5|
|Memory-based Attack Techniques|IP|34.208.205.97|
||IP|172.31.1.217|
||TTP|Reflective DLL Injection|
|Gathering Indicators and TTPs|sha1|a97496080b00097703d1bb58e7dd9742cad7dcf7|
||sha256|0a18aa47e2118608ba83ee799d27fbcc34efc2fc607cf8d6d2312bd37f16fc56|


This is a great start, but more can be obtained from pivoting with the
Diamond Model.

## Pivoting on Known Indicators

In addition to the Kill Chain model, there is another model that is used
for intrusion analysis called the [Diamond
Model](http://www.activeresponse.org/the-diamond-model/).  Using its
four elements (Adversary, Capability, Infrastructure, and Victim),
analysts can pivot to discover related evidence which helps correlate
and piece together data across intrusions.

The four elements are:

|Element|Description|
|-|-|
|Adversary|Actor/organization responsible, malware author/operator, intruder, etc|
|Capability|Tools, techniques used, exploits, malware samples, C2|
|Infrastructure|Structures used to deliver capability, domains, IPs, email addresses, proxies|
|Victim|Target of the attack/capability|

This figure shows an example of an analyst pivoting between elements to
discover new indicators:

1. Malware sample is found and examined

2. Domain name is discovered in malware

3. IP address is discovered from domain name

4. Firewall logs show that IP has been contacted by other systems in the environment

5. Owner/registration info discovered from IP address

![](images/Gathering%20Indicators%20and%20TTPs/image004.png)


This pivoting revealed additional victims, the C2 infrastructure being
used, and adversary information as well as opportunities to discover
even more indicators:

6. Discover other domains that resolve/have resolved to that IP address

7. Discover malware samples that have been associated with those domains

8. Discover other IP addresses that these additional domains resolve to/have resolved to in the past

9. Discover additional victims that have contacted these additional domains and IPs

10. Discover additional malware that was delivered to victims from these domains and IPs

And you can see how the pivoting can be repeated over and over each time
new indicators are discovered.

We can plug our indicators into this ThreatConnect diagram and apply the
Diamond Model to our `mnemonic1.exe` incident:

![](images/Gathering%20Indicators%20and%20TTPs/image005.png)


WHOIS and passive DNS data are two valuable resources to use while
pivoting for indicators.  A number of different sites and tools use this
data---here are a few screenshots of different tools providing different
indicators:

Here is [ThreatCrowd](https://www.threatcrowd.org/) showing a new IP
address and the email address which registered the
**unioncentralorchids.com** domain:

![](images/Gathering%20Indicators%20and%20TTPs/image006.png)

Searching the new IP address in
[ScoutVision](https://lgss.lgscout.com/account/login?referer=%2F) gives
us the last two IP addresses associated with host
unioncentralorchids.com:   

![](images/Gathering%20Indicators%20and%20TTPs/image007.png)

With [Hurricane Electric Internet Services](http://bgp.he.net/) we can
get the ASNs and see that all three IPs belong to Amazon:

![](images/Gathering%20Indicators%20and%20TTPs/image008.png)

![](images/Gathering%20Indicators%20and%20TTPs/image009.png)

Searching the email address in [PassiveTotal](https://passivetotal.org/)
shows another domain was registered using the same email address:

![](images/Gathering%20Indicators%20and%20TTPs/image010.png)

And also shows two new hosts now resolving to the **35.163.126.190**
address:

![](images/Gathering%20Indicators%20and%20TTPs/image011.png)

As well as a new TLS certificate:

![](images/Gathering%20Indicators%20and%20TTPs/image012.png)

Here is [Active Trust Dossier](https://platform.activetrust.net/)
showing the created, updated, and expires dates along with the name of
the registrant:

![](images/Gathering%20Indicators%20and%20TTPs/image013.png)

Here is
[Censys](https://censys.io/), a
search engine for hosts and networks on the Internet, showing
information on the related X.509 certificates:  


![](images/Gathering%20Indicators%20and%20TTPs/image014.png)

![](images/Gathering%20Indicators%20and%20TTPs/image015.png)

Let's say you scan the environment for any hosts that have communicated
with these new IPs and domains and find two:  **192.168.2.20** and
**192.168.2.44**.

After analysis of these hosts you find one was infected with a
custom-packed executable which uses encrypted payloads and .NET
functions.

Now let's look at our updated list of indicators:

|Incident|Category|Indicator|
|-|-|-|
|Mnemonic1.exe|TTP|Spear phishing|
||TTP|UPX-packed executable|
||TTP|PowerShell payload|
||URL|https://unioncentralorchids[d]com:443/index.asp|
||Host|unioncentralorchids\[d\]com|
||md5|b7c380f0c33143d5042b699c0e2710a5|
||IP|34.208.205.97|
||IP|172.31.1.217|
||TTP|Reflective DLL Injection|
||sha1|a97496080b00097703d1bb58e7dd9742cad7dcf7|
||sha256|0a18aa47e2118608ba83ee799d27fbcc34efc2fc607cf8d6d2312bd37f16fc56|
||email|sherobbedmyboots19@gmail.com|
||IP|34.210.28.254|
||IP|35.163.126.190|
||ASN|AS16509|
||Host|sadeyedlady\[d\]com|
||Host|colddistance\[d\]com|
||Host|outside.colddistance\[d\]com|
||sha1|a9752ec9520777ad50cccc0e1a616afdf96f5b42|
||TTP|Custom-packed EXEs|
||TTP|Encrypted payloads|
||TTP|.NET functions|


And the updated Diamond diagram:

![](images/Gathering%20Indicators%20and%20TTPs/image016.png)


We've already doubled the list of indicators with five or six quick
pivots.  And we only pivoted on a fraction of the indicators we
currently have... 

You can imagine how big the list can get depending on the type of
incident and the number of victims and suspicious IPs/domains/hosts
involved.

Next, we'll go over ways to organize, store, and share indicators and
TTPs so that they can be fed into a tool or easily and quickly shared
with another analyst, component, or organization.
