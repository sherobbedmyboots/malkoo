# Pivoting and Link Analysis
  
Pivoting describes the process of using the knowledge obtained during an investigation to discover related information.  Link analysis is the process of analyzing relationships between these pieces of information.  They are used together to provide a better understanding of attacks, intrusions, and adversary tradecraft.
 
Infrastructure and capabilities are the most common pivot points we see during investigations.  You can use open source tools to pivot on a domain or malware sample and find hundreds, possibly thousands of “related” pieces of information—but only proper link analysis will determine what is actually relevant to our investigation and what is important for us as analysts and incident responders.  Just like indicators, relationships need context to have value.
 
This will review:
 
- [Common Opportunities to Pivot](#common-opportunities-to-pivot)
- [Manual Pivoting and Link Analysis](#manual-pivoting-and-link-analysis)
- [Pivoting and Visualization with Maltego](#pivoting-and-visualization-with-maltego)
 
 
## Common Opportunities to Pivot
 
We should already be familiar with the Diamond Model and how we use it to identify new information about infrastructure, capabilities, victims, and adversaries.  This will review two elements from the model—Infrastructure and Capabilities—and some common pivot points for each.
 
 
### Key Questions
 
Here are some common questions about infrastructure we need to answer in many investigations:
 
- When was the domain registered?
- What email address was used to register it?
- What other domains did this email address register?
- Has the domain been associated with a known incident, campaign, or threat actor?
- What subdomains does the domain have?
- What IPs hosted the domain after it was registered by adversary?
- Which of those IPs are most likely dedicated to the adversary?
- What other domains were hosted on the same IP at same time as initial domain?
- What email addresses were used to register these domains?
- Was the malware using a TLS certificate?
- How many other IPs have been seen using that certificate?
- What time was the certificate seen on the suspect IP address?
- What were the expiration dates of the certificate, not before, not after, etc.?
- Were the certificates self-signed, free (Let’s Encrypt, WooSign), or paid?
 
 
And capabilities:
 
- What domains and IPs was the samples associated with?
- When were they observed there?
- What URLs did the samples use?
- What filenames did the samples have?
- Were the samples associated with a TLS/SSL certificate?
- Were the samples observed using a mutex?
- Was the sample associated with an email address?
- Has the sample been associated with a known incident, campaign, or threat actor?
 
 
Each of these questions is a possible pivot point.  We may discover the answer during domain/sample analysis or we may search a number of tools trying to find the answer.
 
When queries or analysis provides us these answers, we need to consider the source, the technique used to obtain it, and how it can help our investigation.
 
 
### Maintaining Context
 
While pivoting and discovering new relationships, keep in mind some of the following scenarios regarding context:
 
- Malicious domains and IPs frequently get taken over and pointed to a sinkhole.  Although OSINT tools may report relationships between this data point and others, the infrastructure hosting the sinkhole and the other “related” domains pointing to the same sinkhole are not relevant to our investigation
 
- IP addresses belonging to VPNs and VPSs are constantly being shared by millions of different users every day.  Attempting to pivot to samples or infrastructure “related” to one of these IPs will almost always be a waste of time
 
- IP addresses that belong to hosting services and reverse proxies are a similar problem—multiple tools will find relationships between an IP and the thousands of domains it is hosting, but these are not the types of pivots that will lead to related infrastructure and samples
 
- Third party domain registrars like GoDaddy, Hover, and DreamHost manage reservations of domain names for many different users.  If the adversary uses one of these services, we cannot pivot to other users of the service or other domain names registered using the service as they are in no way related to our investigation
 
- If Dynamic DNS is being used and a domain is pointing at multiple different IP addresses in a short period of time, pivoting on the IP addresses won’t give us the information we’re after.  Also, the registrant information will belong to the DDNS providers
 
- Compromised legitimate sites being used for Delivery, C- and Exfil will also have registrant information that is not related to the adversary
 
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
	- C2 IP address 176.31.22[.]- - Sample 23.exe
	- Sample 23.vbs
 
- Used analysis of 176.31.22[.]- to obtain:
 
	- Delivery domain yaded[.]ru
	- Delivery domain uk-sv[.]ru
	- Sample 9b57.exe
	- Sample 1fug.exe
 
- Used Dynamic Analysis of sample 9b57.exe to obtain:
 
	- Sample 7991574- - Sample System.dll
	- C2 domain manrovm[.]gdn
	- C2 domain lemanva[.]gdn
 
- Used OSINT (PassiveTotal) for manrovm[.]gdn and lemanva[.]gdn to obtain:
 
	- Different samples associated with these domains
	- Common TTPs used
 
 
From here we could keep pivoting on each of the samples or from any of the other samples and domains looking for related information. 
 
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
 
 
Here we’re using the IP address to obtain WHOIS data, associated domains, and a SHA2- hash of our sample:
 
![](./images/Pivoting_and_Link_Analysis/image001.png)     

We also have a DNS name which was involved in the Delivery phase of this SEN which we can use to pivot.
 
Domain Name To ():
 
- IP Address
- Sample
- SSL cert
 
 
Here we use the Delivery DNS name to obtain an IP address along with SSL certs and a sample SHA2- hash seen at that IP:
 
![](./images/Pivoting_and_Link_Analysis/image002.png) 

Each entity we discover is another possible pivot opportunity allowing us to learn more about the adversary’s infrastructure and capabilities.
 
 
 
### Capabilities
 
Pivoting off a sample can also be used to obtain related information such as filenames, URLs, and other infrastructure.
 
Sample To ():
 
- Filename                      ThreatMiner Malware to Filename
- URL                           ThreatMiner Malware to URL
- Domain                        ThreatMiner Malware to Domain
 
 
Here we used the SHA2- hash of our sample to get the associated filename and URL:
 
![](./images/Pivoting_and_Link_Analysis/image003.png) 

The same pivot is now performed on the new sample to get its filename, domain, and URL:
 
![](./images/Pivoting_and_Link_Analysis/image004.png)

At some point you may perform a transform that doesn’t provide useful information:
 
![](./images/Pivoting_and_Link_Analysis/image005.png) 
 
 
In that case, use Ctrl+z to undo each of the transforms that were performed.
 
As your graph gets larger you’ll need to move around to different areas which you can do by clicking and dragging the graph with the right mouse button.
 
 
 
### Pivoting to Find Relationships
 
As we continue gathering information on the DNS name, a domain name is discovered.
 
In this case, the ThreatMiner transforms don’t provide any additional information for domain name tehnospas74[d]ru, so we’ll try another transform.
 
Selecting ALL transforms from the VirusTotal Public API connects the tehnospas74[d]ru domain with the 176.31.22[d]- C2 address using our 23.exe malware sample:
 
![](./images/Pivoting_and_Link_Analysis/image006.png) 

### Adding Entities From External Sources
 
You may have domains, files, and other entities you’ve gathered during analysis that you want to add to the graph.
 
 
The following domains were discovered in the PowerShell script executed by the Word macro:
 
![](./images/Pivoting_and_Link_Analysis/image007.png) 
 
 
And we discovered two additional domains and samples by visiting the C2 page:
 
![](./images/Pivoting_and_Link_Analysis/image008.png) 
![](./images/Pivoting_and_Link_Analysis/image009.png) 
 
 
 
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
 
 
![](./images/Pivoting_and_Link_Analysis/image010.png) 