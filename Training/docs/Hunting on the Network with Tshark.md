# Hunting on the Network with TShark

Hunting is searching for adversaries without a particular indicator.  When hunting on the network, that means looking for payload deliveries, C2, lateral movement, exfil, etc.---any traffic that could indicate an attack or compromise.

Hunting requires that you learn and understand who the adversaries are, how they operate, and the specific capabilities they bring to the table.  It also forces you to gain a better understanding of your environment so that you can more accurately distinguish abnormal events from normal operations.  As we hunt, learn, and document our findings, we can develop more effective detections and responses and even discover gaps in our tools and infrastructure along the way.

This document will review:

- [Process and Tools](#process-and-tools)
	- [PCAP to HTTPS Connection Logs](#pcap-to-https-connection-logs)
	- [PCAP to HTTP Connection Logs](#pcap-to-http-connection-logs)
	- [PCAP to DNS Logs](#pcap-to-dns-logs)
	- [PCAP to Flow Logs](#pcap-to-flow-logs)
	- [PCAP to SSL/TLS Certificate Info](#pcap-to-ssl-tls-certificate-info)
- [Techniques](#techniques)
    - [Frequency Analysis](#frequency-analysis)
    	- [HTTPS Server Name](#https-server-name)
		- [HTTP Host and Referrer](#http-host-and-referrer)
		- [HTTP User Agent](#http-user-agent)
    - [Link Analysis](#link-analysis)
    	- [Identifying C2 Technique Used](#identifying-c2-technique-used)
    - [Time Series Analysis](#time-series-analysis)
    	- [Abnormal Browsing](#abnormal-browsing)
		- [Searching for the Payload](#searching-for-the-payload)
	- [Combining Techniques](#combining-techniques)
		- [Searching for Persistence](#searching-for-persistence)

The PCAP can be found here:

	/CSIRT/Sample-Files/CSIRT-pcap-7.pcapng
	


## Process and Tools

No matter what tools we're using, the following process applies to hunting on the network:

|Step|Description|
|-|-|
|Acquire and Format|Have a searchable format---most times this is Splunk logs but in this case we're producing connection logs, flow logs, DNS logs, and SSL/TLS Cert information from a PCAP|
|Reduce and Analyze|Find ways to isolate potentially abnormal traffic from the rest|
|Investigate Artifacts|As we discover interesting files, domains, payloads, certificates, etc. we can examine using additional analysis tools|
|Pivot to Related Artifacts|Use the artifacts we discover for follow-on searches and research|


Tshark comes with Wireshark and is a great tool to use for PCAP analysis.  A PCAP can be used to produce several different log and data sources:

- [PCAP to HTTPS Connection Logs](#pcap-to-https-connection-logs)
- [PCAP to HTTP Connection Logs](#pcap-to-http-connection-logs)
- [PCAP to DNS Logs](#pcap-to-dns-logs)
- [PCAP to Flow Logs](#pcap-to-flow-logs)
- [PCAP to SSL/TLS Certificate Info](#pcap-to-ssl-tls-certificate-info)

To ensure the Wireshark directory is in your path type:

```powershell
$env:PATH
```

If it's not in your path, add it with:

```powershell
$env:PATH += ';C:\Program Files\Wireshark'
```

### PCAP to HTTPS Connection Logs

HTTPS is a good way for adversaries to avoid detection on the network.... everything except the handshake is encrypted.

In the handshake is the server name of the destination server for each HTTPS connection.  We can extract these with TShark:

```powershell
tshark -r .\c2-pcap.pcapng -Y 'ssl.handshake.type==1' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e ssl.handshake.extensions_server_name -E separator="," -E quote=d -E header=y -E occurrence=a > names.csv
```

This pulls the fields we need and places them in a CSV file which we can then put in a variable:

```powershell
$https = gc names.csv | ConvertFrom-Csv
```

Now every HTTPS connection in the PCAP is represented by an object.  

This command is needed to format the time property:

```powershell
$https | %{$_.'frame.time' = ($_.'frame.time' -split(" "))[4].substring(0,8)}
```

The first object is an HTTPS connection to www.amazon.com:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image001.PNG)


### PCAP to HTTP Connection Logs

We can do the same thing with HTTP connections, extracting all the HTTP requests:

```powershell
tshark -r .\c2-pcap.pcapng -Y 'http' -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.host -e http.user_agent -e http.referer -E separator="," -E quote=d -E header=y -E occurrence=a > http.csv
```

Put them into a variable and format the time:

```powershell
$http = gc http.csv | ConvertFrom-Csv
$http | %{$_.'frame.time' = ($_.'frame.time' -split(" "))[4].substring(0,8)}
```

And the first object is a GET request to www.jimpress.co\[d\]uk for the latestnews.html page:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image002.PNG)


### PCAP to DNS Logs

A basic DNS log has the following properties:

- Time
- Hostname Queried
- IP Address

Extract them from the PCAP with this command:

```powershell
tshark -r c2-pcap.pcapng -2 -R "dns.a" -T fields -e frame.time -e dns.resp.name -e dns.a -E header=y -E separator="," -E quote=d -E occurrence=f > dns.csv
```

Put them into a variable and format the time:

```powershell
$dns = gc dns.csv | ConvertFrom-Csv
$dns | %{$_.'frame.time' = ($_.'frame.time' -split(" "))[4].substring(0,8)}
```


The first object represents a DNS request for www.amazon.com which resolved to 54.230.6.218:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image003.PNG)


### PCAP to Flow Logs

A basic flow contains the following properties:

- Time 
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol

Extract these fields from the PCAP with this command:

```powershell
tshark -r c2-pcap.pcapng -2 -R "ip" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.proto -E header=y -E separator="," -E quote=d -E occurrence=f > flow.csv
```

Put them into a variable and format the time:

```powershell
$flow = gc flow.csv | ConvertFrom-Csv
$flow | %{$_.'frame.time' = ($_.'frame.time' -split(" "))[4].substring(0,8)}
```

The first packet happens to be a DNS request to the router at 10.0.0.1:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image004.png)


### PCAP to SSL TLS Certificate Info

SSL/TLS certificates are a good way to track HTTPS traffic.  Certs have many properties that can be used for analysis but for this example we'll just look at two:

- Root CA - the CA at the top of the chain of trust
- Subject - who the certificate was issued to

To extract this information, use this command:

```powershell
tshark -r .\c2-pcap.pcapng -2 -R 'ssl.handshake.type==11' -T fields -e frame.time -e ip.src -e x509sat.printableString -e x509sat.uTF8String -e x509sat.CountryName -E separator="," -E quote=d -E header=y -E occurrence=a -E aggregator=";" > certs.csv
```

Put into a variable and format two of the properties:

```powershell
$certs = gc certs.csv | ConvertFrom-Csv
$certs | %{$_.'frame.time' = ($_.'frame.time' -split(" "))[4].substring(0,8)}
$certs | %{ $_ | Add-Member CA ($_ | select -exp x509sat.printableString).split(';')[-1]}

```

## Techniques

Since we're hunting without indicators, we'll need ways to differentiate normal network activity from abnormal network activity.

Here are three techniques commonly used to do this:

|Technique|Description|
|-|-|
|[Frequency Analysis](#frequency-analysis)|comparing data characteristics to identify anomalies and interesting events or indicators|
|[Link Analysis](#link-analysis)|Relationships between nodes, events, Odd systems, related traffic|
|[Time Series Analysis](#time-series-analysis)|Data points across time intervals, Beaconing, Unique events/sequences|



### Frequency Analysis   

Frequency Analysis is comparing different characteristics of data to identify anomalies and interesting events.  This is a very effective technique when searching large sets of data and can be used to spot newly observed/registered domains, external services, and unusual port and protocol usage.

For example, if an attacker is actively controlling a victim machine over the network, there will likely be a high number of connections.  Therefore if we find an unusually high number of connections to a server in relation to its function or reputation, it warrants further investigation.

The following searches attempt to compare, or "stack" different characteristics of traffic:

- [HTTPS Server Name](#https-server-name)
- [HTTP Host and Referrer](#http-host-and-referrer)
- [HTTP User Agent](#http-user-agent)

#### HTTPS Server Name

The command `$https | measure` shows us we have over 1600 connections to examine.

This command stacks the server names for all HTTPS connections and shows only those with more a count more than ten:

```powershell
$https | group 'ssl.handshake.extensions_server_name' -NoElement | ? count -gt 10 | sort -desc count | ft -auto
```

Right away this narrows it down to a few interesting server names:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image005.PNG)


Most of these hostnames are well-known and affiliated with ad delivery and content delivery so a high number of connections to them isn't unusual.

But it does seem unusual that what looks to be a regular web page (sadeyedlady\[d\]com) would gets that many visits by one system in such a short time.

For further comparison, look at the top three sites on PassiveTotal.com

- [dt.adsafeprotected.com](https://community.riskiq.com/search/dt.adsafeprotected.com) has 450 subdomains, 192 resolutions, and consistent WHOIS ownership info
- [images-na.ssl-images-amazon.com](https://community.riskiq.com/search/images-na.ssl-images-amazon.com) has 16 subdomains, 2,000 resolutions, and consistent WHOIS ownership info

Compare those two to this one:

- [sadeyedlady\[d\].com](https://community.riskiq.com/search/sadeyedlady.com) only has 2 subdomains, 5 resolutions, has changed ownership recently, and has changed IP addresses multiple times in the last week.


Extracting and inspecting the TLS certificate shows it was acquired from Let's Encrypt, another indication this could be a C2 server designed to blend in with normal HTTPS web traffic:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image006.png)


#### HTTP Host and Referrer

We can do the same thing with HTTP traffic using the host header and referer fields.  Normal web browsing utilizes the host header to identify the endpoint the client is connecting to and the referer field to identify the site or page that referred the client there.

By stacking these together, we can see the most common hosts visited along with the sites that referred them:

```powershell
$http | ? http.request.method -eq GET | group -NoElement http.host,http.referer | sort -desc count | ? count -gt 20 | ft -auto
```

The top result has an unusual hostname with no values in the referer field: 

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image007.PNG)

The host is an Amazon CloudFront web distribution.  These are used to deliver static and dynamic content for websites hosted by Amazon.  When an HTTP request is sent to a distribution, the website it is hosting content for should be in the referer field.  There is an unusually large amount of HTTP requests to this distribution with no referers.


#### HTTP User Agent

Another way we can use this technique is to stack the different user agents observed.  Normal HTTP browsing should use a few common user agent strings depending upon which browsers are installed on the system.

This shows the system was sending traffic using two different user agents:

```powershell
$http | group -NoElement http.user_agent | ft -auto
```

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image011.PNG)


And this command will give us the hosts that were contacted using each user agent:

```powershell
$http | ? http.user_agent -match MSIE | group http.host -NoElement | ft -auto
```

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image012.PNG)

This could just mean a different browser was used for this particular traffic.

Let's take a closer look...



### Link Analysis

Link Analysis is using the relationships between nodes or events to locate anomalies, outliers, or related traffic.

- [Identifying C2 Technique Used](#identifying-c2-technique-used)


#### Identifying C2 Technique Used

Let's look at the relationship between the victim system and the Amazon Cloudfront distribution.

This command shows the unique IP addresses used for connections to the distribution:

```powershell
$http | ? http.host -eq d2xx82w00xgkht.cloudfront.net | select -Unique ip.dst
```


Then we can check our dns logs to see what domains resolved to these IP addresses:

```powershell
$dns | ? dns.a -match '13.33.78.140|13.33.78.53'
```

The results show that the system got these IP addresses by sending DNS queries for the cdn.az\[d\]gov domain:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image009.PNG)


So the client queried cdn.az\[d\]gov to get its IP address, then sent traffic to the IP which was destined for the d2xx82w00xgkht.cloudfront\[d\]net host, each time not being referred by another page or site.

Based on the relationships of the domains, IPs, and events we've identified, we can conclude that a C2 technique known as "domain fronting" is being used.

We can verify this is still possible with `nslookup`:

```powershell
nslookup -debug cdn.az.gov
```

The results of this command shows that cdn.az\[d\]gov is a CNAME record pointing to another Cloudfront distribution:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image010.PNG)

We can also see this in the packet capture which contains the DNS response received by the system after it queried cdn.az\[d\]gov:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image016.png)


So when cdn.az\[d\]gov is queried by the victim:

- The record points to `d1ioko8gurp5my.cloudfront.net` and its IP address is provided
- The system sends traffic to the IP with `d2xx82w00xgkht.cloudfront.net` in the host header
- The IP, which is owned by Amazon, sees the intended host is another Amazon distribution and forwards the traffic to it
- All responses from `d2xx82w00xgkht.cloudfront.net` are forwarded back to `d1ioko8gurp5my.cloudfront.net` and back to the victim

In this scenario, both distrubutions act as pointers to different domains or IP addresses.  What makes this attractive to adversaries is that:

- If tools or analysts aren't inspecting the host header, it looks like cdn.az\[d\]gov is the actual destination
- Even if domain fronting is detected, we have no way of seeing what `d2xx82w00xgkht.cloudfront.net` points to
- This can be done using HTTPS so that all traffic is encrypted

Looking at the HTTP payloads in Wireshark confirms it is not normal browsing as some payloads are encrypted and some return a default page of a web server reporting it has no content.


### Time Series Analysis

Time Series Analysis looks at patterns of data points across time intervals such as beaconing and other unusual events or sequences.

- [Abnormal Browsing](#abnormal-browsing)
- [Searching for the Payload](#searching-for-the-payload)


#### Abnormal Browsing

This command shows all the requests that were made to the Amazon Cloudfront distribution over the duration of the packet capture:

```powershell
$http | ? http.host -eq d2xx82w00xgkht.cloudfront.net | select frame.time,http.request.method,http.request.uri
```

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image008.PNG)

Here we see more unusual activity:

- GETs and POSTs that use the same parameters
- Multiple "searches" for the same terms that are repeated
- Connections are always 2 to 3 seconds apart unlike normal browsing

Looking at several of these events individually wouldn't necessarily reveal suspicious activity, but looking at all the events over time shows the sequence of connections to this host is not consistent with normal browsing behavior.


#### Searching for the Payload

Another thing we can look at in a time series is the connections to the first suspicious domain.

This command shows the time of each HTTPS connection:

```powershell
$https | ? ssl.handshake.extensions_server_name -eq sadeyedlady.com | ft
```

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image013.png)

The HTTPS requests occurred 2 - 5 times per minute for almost seven minutes.

Looking at the sites that were visited just before the first communication to sadeyedlady\[d\]com at 14:38:38 gives us some leads of what might have initiated the traffic:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image014.png)

After investigating several of these, the payload is discovered to be a link displayed on colddistance\[d\]com which leads to a shortcut file hosted on sadeyedlady\[d\]com:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image015.png)

                        


With the information we have so far, we can establish a potential C2 timeline:

|Time|Domain|Protocol|Interval|Function|
|-|-|-|-|-|
|14:38:38 - 14:45:01|sadeyedlady\[d\]com|HTTPS|2 - 5 connections per minute|Payload|
|14:43:43 - 14:53:46|cdn.az\[d\]gov|HTTP|20 - 25 connections per minute|Operations|
|?|?|?|?|Persistence|


### Combining Techniques

#### Searching for Persistence

Since the payload delivery was successful, and the domain fronting activity indicates the adversary had around ten minutes of interactive access with the victim, it is very likely that long-term persistence was installed on the victim.  

We can use what we've discovered about the frequency, relationships, and time properties of the payload and operations C2 to narrow our search for persistence C2:

- A connection or series of connections that occurs a very low number of times
- A connection that may have characteristics related to other malicious traffic discovered
- A connection that occurred after interactive operations ended at 14:53:46


We could start out searching for suspicious HTTPS connections as the adversary has used encryption in some form or another in both C2 channels we've discovered.

This search returns domains that had less than five HTTPS connections for our time frame:

```powershell
$https | ? frame.time -gt 14:53:46 | group -NoElement ssl.handshake.extensions_server_name | ? count -lt 5 | sort -desc count | ft -auto
```

This gives almost 200 results which will take a while to sort through.


Another option is searching for destination hosts with certificates signed by the same CA that signed sadeyedlady\[d\] com:  Let's Encrypt

This command searches for all HTTPS connections in our time frame with certs issued by Let's Encrypt:

```powershell
$certs | ? frame.time -gt 14:53:46 | ? CA -match 'Encrypt' | select frame.time,x509sat.printableString
```

This returns two unique hosts:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image017.png)


One of the domains has the same ownership information as both colddistance\[d\]com and sadeyedlady\[d\]com:

![](images/Hunting%20on%20the%20Network%20with%20Tshark/image018.png)






