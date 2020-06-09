# Tor Alerts in Splunk

Tor is an anonymity network made up of many different volunteer-operated
systems that work together to prevent surveillance and traffic
analysis.  This network of relay nodes and exit nodes creates a virtual
tunnel for users allowing them to prevent identification of their
traffic's true destination.  

Normally, when a user makes a connection to a destination server,
someone monitoring the traffic can identify the true destination of the
traffic.  When a user makes a connection using the Tor network, the
user's traffic is routed first through a Node 1, a Node 2, an Exit Node,
and then to the destination server.  In this situation, it would appear
to someone monitoring the user's traffic that Node 1 is the traffic's
true destination.  Likewise, to someone monitoring the destination
server's traffic, it would appear that the traffic is originating from
the Exit Node instead of the user.

There are four system roles in a Tor circuit:

|||
|-|-|
|Client|directs traffic to a Relay Node|
|Relay Node|listens for traffic, and passes any received Tor traffic on to other relays|
|Exit Node|the last relay, routes traffic to its final destination on the Internet|
|Destination server|receives traffic from Exit Node|

An asset involved in Tor traffic could be a client, a Relay Node, an
Exit Node, or a destination server.  The two most likely scenarios we
would see are:

1. Asset as a client (DHS user attempting to evade surveillance)

2. Asset as a destination server (external entity attempting to
    access our network anonymously)

The Tor alert in Splunk currently looks for **any activity to or
from** the IP addresses of all publicly listed Tor relays. 
Therefore it's important to know what true Tor traffic looks like and be
able to determine if the traffic that alerted indicates one of these
scenarios.

In this case, we had a user browsing to an IP address that is publicly
listed as an Exit Node.

Here's what the alert returns:

![](images/Tor%20alerts%20in%20Splunk/image001.png)


To see a more complete timeline of the user's browsing activity just
before visiting the site, use a search like this:

![](images/Tor%20alerts%20in%20Splunk/image002.png)


Now we want to see the `cs_Referer` fields for all traffic to all barnband\[d\]com hosts:

![](images/Tor%20alerts%20in%20Splunk/image003.png)


Searches for information on the destination:

- [URL Query](http://urlquery.net/report.php?id=1457094719954) - Scans the url, inspects requests, responses, files, redirects, scripts, recent reports

- [Robtex](https://www.robtex.com/en/advisory/dns/45/79/184/114/) - Shows DNS info, name records, Whois, blacklist info


This site maintains a list of active Tor nodes:

- <https://www.dan.me.uk/tornodes>

The site lists the system as an exit node (Has the "E" flag):

![](images/Tor%20alerts%20in%20Splunk/image004.png)


Scan the system using [Dazzlepod](http://dazzlepod.com/ip) to see what services it
is providing:

![](images/Tor%20alerts%20in%20Splunk/image005.png)


This server is running nginx 1.9.5 web server software on port 443, not
the Tor software.

Here's an example of a system that serves as both a Relay node and an
Exit node.  Note the Tor service listening on port 443:

![](images/Tor%20alerts%20in%20Splunk/image006.png)


Here are the indicators identifying this as non-Tor traffic:

- User connected to an Exit Node instead of a Relay Node.

- User connected to nginx web software on port 443, not the Tor
    software

- User was redirected to the site which indicates normal browsing. 
    Tor software keeps a list of active Relay nodes so clients can
    connect directly.


Here are some indicators of true Tor Traffic:

**Asset as a client (user attempting to evade surveillance)**

- Tor browser installed on the asset

- Traffic is destined for a Relay node

- Relay node is running the Tor service on the port in which the client connected


**Asset as a destination server (external entity attempting to access our network anonymously)**

- Traffic is originating from an Exit node

- Traffic is destined for one of our assets
