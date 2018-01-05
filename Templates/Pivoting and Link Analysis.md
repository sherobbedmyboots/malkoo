# Pivoting and Link Analysis
  
Pivoting describes the process of using the knowledge obtained during an investigation to discover related information.  Link analysis is the process of analyzing relationships between these pieces of information.  They are used together to provide a better understanding of attacks, intrusions, and adversary tradecraft.
 
Infrastructure and capabilities are the most common pivot points we see during investigations.  You can use open source tools to pivot on a domain or malware sample and find hundreds, possibly thousands of “related” pieces of information—but only proper link analysis will determine what is actually relevant to our investigation and what is important for us as analysts and incident responders.  Just like indicators, relationships need context to have value.
 
This will review:
 
- Common Opportunities to Pivot
- Manual Pivoting and Link Analysis
- Pivoting and Visualization with Maltego
 
 
## Common Opportunities to Pivot
 
We should already be familiar with the Diamond Model and how we use it to identify new information about infrastructure, capabilities, victims, and adversaries.  This will review two elements from the model—Infrastructure and Capabilities—and some common pivot points for each.
 
 
### Key Questions
 
Here are some common questions about infrastructure we need to answer in many investigations:
 
1.       When was the domain registered?
2.       What email address was used to register it?
3.       What other domains did this email address register?
4.       Has the domain been associated with a known incident, campaign, or threat actor?
5.       What subdomains does the domain have?
6.       What IPs hosted the domain after it was registered by adversary?
7.       Which of those IPs are most likely dedicated to the adversary?
8.       What other domains were hosted on the same IP at same time as initial domain?
9.       What email addresses were used to register these domains?
10.   Was the malware using a TLS certificate?
11.   How many other IPs have been seen using that certificate?
12.   What time was the certificate seen on the suspect IP address?
13.   What were the expiration dates of the certificate, not before, not after, etc.?
14.   Were the certificates self-signed, free (Let’s Encrypt, WooSign), or paid?
 
 
And capabilities:
 
1.       What domains and IPs was the samples associated with?
2.       When were they observed there?
3.       What URLs did the samples use?
4.       What filenames did the samples have?
5.       Were the samples associated with a TLS/SSL certificate?
6.       Were the samples observed using a mutex?
7.       Was the sample associated with an email address?
8.       Has the sample been associated with a known incident, campaign, or threat actor?
 
 
Each of these questions is a possible pivot point.  We may discover the answer during domain/sample analysis or we may search a number of tools trying to find the answer.
 
When queries or analysis provides us these answers, we need to consider the source, the technique used to obtain it, and how it can help our investigation.
 
 
### Maintaining Context
 
While pivoting and discovering new relationships, keep in mind some of the following scenarios regarding context:
 
- Malicious domains and IPs frequently get taken over and pointed to a sinkhole.  Although OSINT tools may report relationships between this data point and others, the infrastructure hosting the sinkhole and the other “related” domains pointing to the same sinkhole are not relevant to our investigation
 
- IP addresses belonging to VPNs and VPSs are constantly being shared by millions of different users every day.  Attempting to pivot to samples or infrastructure “related” to one of these IPs will almost always be a waste of time
 
- IP addresses that belong to hosting services and reverse proxies are a similar problem—multiple tools will find relationships between an IP and the thousands of domains it is hosting, but these are not the types of pivots that will lead to related infrastructure and samples
 
- Third party domain registrars like GoDaddy, Hover, and DreamHost manage reservations of domain names for many different users.  If the adversary uses one of these services, we cannot pivot to other users of the service or other domain names registered using the service as they are in no way related to our investigation
 
- If Dynamic DNS is being used and a domain is pointing at multiple different IP addresses in a short period of time, pivoting on the IP addresses won’t give us the information we’re after.  Also, the registrant information will belong to the DDNS providers
 
- Compromised legitimate sites being used for Delivery, C2, and Exfil will also have registrant information that is not related to the adversary
 
- Information discovered about IPs and domains that were determined to be malicious in the past may not hold true today.  Some infrastructures change owners/operators frequently which means we must understand the historical context of the information we find
 
 
 
## Manual Pivoting and Link Analysis
 
 
Using ss as an example, we started out with a suspicious email reported by an end user.  We then:
 
- Used dynamic analysis to obtain:
 
	- Delivery domain sudebnii-advokat[.]ru
	- Sample Canada Post Notice Card.doc
 
- Used Dynamic Analysis of Canada Post Notice Card.doc to obtain:
 
	- Delivery domain tehnospas74[.]ru
	- Delivery domain tekflagman[.]ru
	- Delivery domain telecomserv[.]ru
	- Delivery domain telerad[.]ru
	- Delivery domain telexon[.]ru
	- C2 IP address 176.31.22[.]17
	- Sample 23.exe
	- Sample 23.vbs
 
- Used analysis of 176.31.22[.]17 to obtain:
 
	- Delivery domain yaded[.]ru
	- Delivery domain uk-sv[.]ru
	- Sample 9b57.exe
	- Sample 1fug.exe
 
- Used Dynamic Analysis of sample 9b57.exe to obtain:
 
	- Sample 799157431
	- Sample System.dll
	- C2 domain manrovm[.]gdn
	- C2 domain lemanva[.]gdn
 
- Used OSINT (PassiveTotal) for manrovm[.]gdn and lemanva[.]gdn to obtain:
 
	- 20 different samples associated with these domains
	- Common TTPs used
 
 
From here we could keep pivoting on each of the 20 samples or from any of the other samples and domains looking for related information. 
 
But we can find much of this same information, and create visualizations with it, using Maltego.
 
 
 
## Pivoting and Visualization with Maltego
 
Maltego is a tool that can performing some of this pivoting and link analysis by leveraging the APIs of multiple free and commercial online investigation tools. 
 
It is also great at giving a visualization of the data points discovered and the relationships between them.
 
To use it, open a terminal in REMnux and type maltego-community
 
Sign up for a free account, login in, and use the button in the top left to open a new graph.
 
If prompted to update, go ahead and update and restart.  If asked for the version, we want Maltego CE.
 
On the left menu, click on Entity Palette, and drag the IP address icon into the center of the graph.
 
Double click it to enter in an IP address.
 
 
 
### Infrastructure
 
Starting with the C2 IP address we discovered during analysis, we can use the following transform to pivot to related information:
 
IP Address To ():
 
- Domain                           ThreatMiner IP to Domain
- Sample                           ThreatMiner IP to Samples
- SSL Certificate                  ThreatMiner IP to SSL Certificate
- URI                              ThreatMiner IP to URI
- WHOIS data                       ThreatMiner IP to Whois Details
 
 
Here we’re using the IP address to obtain WHOIS data, associated domains, and a SHA256 hash of our sample:
 
![](./images/image046.png)     

cid:image008.png@01D34674.E7DFF080
 
 
We also have a DNS name which was involved in the Delivery phase of this SEN which we can use to pivot.
 
Domain Name To ():
 
- IP Address
- Sample
- SSL cert
 
 
Here we use the Delivery DNS name to obtain an IP address along with SSL certs and a sample SHA256 hash seen at that IP:
 
cid:image009.png@01D34674.E7DFF080
 
 
 
Each entity we discover is another possible pivot opportunity allowing us to learn more about the adversary’s infrastructure and capabilities.
 
 
 
### Capabilities
 
Pivoting off a sample can also be used to obtain related information such as filenames, URLs, and other infrastructure.
 
Sample To ():
 
- Filename                                             ThreatMiner Malware to Filename
- URL                                                        ThreatMiner Malware to URL
- Domain                                                ThreatMiner Malware to Domain
 
 
Here we used the SHA256 hash of our sample to get the associated filename and URL:
 
cid:image010.png@01D34674.E7DFF080
 
 
The same pivot is now performed on the new sample to get its filename, domain, and URL:
 
cid:image011.png@01D34674.E7DFF080
 
 
 
At some point you may perform a transform that doesn’t provide useful information:
 
cid:image004.png@01D34719.82325ED0
 
 
In that case, use Ctrl+z to undo each of the transforms that were performed.
 
As your graph gets larger you’ll need to move around to different areas which you can do by clicking and dragging the graph with the right mouse button.
 
 
 
### Pivoting to Find Relationships
 
As we continue gathering information on the DNS name, a domain name is discovered.
 
In this case, the ThreatMiner transforms don’t provide any additional information for domain name tehnospas74[d]ru, so we’ll try another transform.
 
Selecting ALL transforms from the VirusTotal Public API connects the tehnospas74[d]ru domain with the 176.31.22[d]17 C2 address using our 23.exe malware sample:
 
cid:image012.png@01D34674.E7DFF080
 
 
 
 
 
### Adding Entities From External Sources
 
You may have domains, files, and other entities you’ve gathered during analysis that you want to add to the graph.
 
 
The following domains were discovered in the PowerShell script executed by the Word macro:
 
cid:image006.png@01D34719.82325ED0
 
 
And we discovered two additional domains and samples by visiting the C2 page:
 
cid:image018.png@01D3433B.801C5BF0
cid:image007.png@01D34719.82325ED0
 
 
 
We can manually add these domains and samples to our graph by selecting the appropriate icons from the entity palette and dragging them into the graph.
 
Double click the icon to modify its properties.
 
To create a relationship manually, left click on an entity and drag the cursor to another entity creating an arrow, or relationship.
 
You can also double click the arrows to edit the properties of the relationship.
 
 
 
 
### Creating Your Own Entities
 
You can create your own entities by going to the Entities tab on the top and clicking New Entity Type.
 
Here you can enter the name, description, icon and other properties you wish to use.
 
Select or create a category for the entity and any other settings you want, then click Finish.
 
Now your entity should be available in the Entity Palette on the left, use the search box at the top if you can’t find it scrolling.
 
In this example I created an entity for TTPs being used.
 
 
 
### Visualizations
 
We can now use a combination of what we’ve learned through malware analysis and OSINT pivoting to show multiple phases of the attack:
 
 
cid:image013.png@01D34804.8157F290
 
 
 
 
 