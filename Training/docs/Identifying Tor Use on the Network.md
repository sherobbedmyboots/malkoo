# Identifying Tor Use on the Network

In this example, a user is suspected of using the Tor network to bypass content filtering.  The user's workstation was examined and did not
reveal any artifacts indicating Tor use, however a full packet capture
of the user's traffic from the day in question is available for review. 
Using the packet capture, determine if the traffic indicates the user
accessed the Tor network from his workstation.  The packet capture is
located on the OOB at:

    pcap-5.pcap

## Tor Review

Tor is an anonymity network made up of many different volunteer-operated
systems that work together to prevent surveillance and traffic
analysis.  This network of relay nodes and exit nodes creates a virtual
tunnel for users allowing them to prevent identification of their
traffic's true destination.  

Normally, when a user makes a connection to a destination server,
someone monitoring the traffic can identify the true destination of the
traffic.  When a user makes a connection using the Tor network, the
user's traffic is routed through a relay \#1, a relay \#2, an then an
Exit Node before finally arriving at the destination server.  In this
situation, it would appear to someone monitoring the user's traffic that
relay \#1 is the traffic's true destination.  Likewise, to someone
monitoring the destination server's traffic, it would appear that the
traffic is originating from the Exit Node.

There are four system roles in a Tor circuit:

|Role|Description|
|-|-|
|Client|Directs traffic to a Relay/Bridge|
|Relay/Bridge|Listens for traffic, and passes any received Tor traffic on to other relays|
|Exit Node|The last relay, routes traffic to its final destination on the Internet|
|Destination server|Receives traffic from Exit Node|

<br>
The Tor browser makes the following connections:

- TLS connection \#1 to Tor relay \#1

- TLS connection \#2 to Tor relay \#2  (tunneled inside TLS \#1)

- TLS connection \#3 to Tor exit node  (tunneled inside TLS\#1 and TLS \#2)

This creates a tunnel through the three Tor nodes between the client and
all browsing destinations.  Web traffic is directed through this
triple-encrypted tunnel, passing through both relays and the exit node,
and arrives at its destination appearing to have originated from the
exit node's IP address.

## Detecting Tor Use

Monitoring a Tor client's traffic will only reveal the TLS connection to
the first relay and nothing else since the connection is encrypted and
everything is tunneled through it.  However, there are two major ways to
tell that this TLS connection is Tor related:

- [Address Blocking](#address-blocking) - Identifying communication with the Tor infrastructure

- [Content Blocking](#content-blocking) - Identifying signatures unique to Tor

### Address Blocking

Public directories of Tor node IP addresses are used to detect by
destination.  Network monitoring tools such as the Blue Coats keep an
updated list of these IPs and any connections to them are flagged as
potential Tor traffic.

To get around this, Tor uses "bridges" which are relays that are not
listed publicly.  The IP addresses of the bridges are carefully
distributed so that it's easy for a client to learn a few bridges, but
difficult for someone to enumerate them all and make a Tor bridge
blacklist.

Still, with enough effort, many of the bridges can be enumerated
preventing a Tor client from accessing the Tor network.  To bypass this,
a user can stand up his own private bridge on a cloud service (Amazon
Web Services, Google Cloud Engine, etc.), making connections to the Tor
network appear to be connections to an unknown instance hosted on the
cloud provider's infrastructure.

In these cases, when the destination of the traffic is unknown (bridge,
private instance, proxy, etc.), unique characteristics of Tor traffic
can be used for detection.

### Content Blocking

After a client joins the Tor Network via a TLS-encrypted connection to a
bridge or relay, the traffic looks almost identical to a normal HTTPS
browsing session.  But the content contained in the TLS handshake used
to set up the Tor connection has several unique characteristics that can
be used to identify it as a Tor TLS connection. 

In a normal HTTPS connection, the client and the server complete the
three-way handshake (SYN/SYN-ACK/ACK) and then the client sends the
server a Client Hello message.  This message contains the protocol
version it supports, a list of cipher suites supported, and the
destination hostname as the Server Name Indication (SNI). 

At first, Tor Client Hello messages had a unique set of cipher suites
that could be used to identify it as a Tor TLS connection.  To counter
this, Tor changed its cipher suite list to match Mozilla Firefox's and
additional changes were made in an attempt to make Client Hello messages
from Tor browsers look more like Client Hello messages from normal
browsers. 

One thing that is still used to identify Tor traffic is the SNI.  Modern
servers that host different domains at the same IP address expect an SNI
from the client to identify the resource that is being requested.  This
is so the server can provide the correct certificate to the client's
browser for validation.  A Tor client connecting to a Tor server doesn't
need to specify an SNI---all it wants to do is set up TLS to encrypt the
connection.  However, if the Tor browser didn't provide a server name it
would stand out from all the other browsers that consistently do.  For
this reason, Tor browsers include a randomly generated hostname in the
SNI field that looks like this:

[www.skcygkltjuskg\[d\]com](http://www.skcygkltjuskg[d]com)

The Tor server then replies with a randomly generated server name of its
own.  These are bogus hostnames and will not resolve to an IP address
but it is more difficult to detect this than not providing anything at
all in these fields which would immediately identify it as Tor traffic. 

An example of these bogus hostnames can be seen below:

## Obfuscation Plugins

Improvements in identifying Tor signatures and infrastructure led to the
creation and use of Tor Obfuscation Plugins.  These avoid detection by
tools (Blue Coats, NetWitness, IDS, etc.) that examine data in traffic
for static signatures.  There are two general strategies used:

- [Look like something the tool allows](#looking-like-allowed-traffic)

- [Look unlike anything the tool blocks](#looking-unlike-blocked-traffic)


### Looking Like Allowed Traffic

Plugins that utilize this include:

|Plugin|Description|
|-|-|
|Format-Transforming Encryption (FTE)|Encodes data so that it matches specific regular expressions commonly found in normal HTTP traffic|
|Meek|Uses domain fronting to hide Tor traffic in legitimate HTTPS connections to well-known services (Amazon, Azure, etc.). Tor stream is transferred in a series of HTTP POST requests inside the TLS connection with the trusted domain|


### Looking Unlike Blocked Traffic

Plugins that utilize this include:

|Plugin|Description|
|-|-|
|obfs2|Obfuscates TLS handshake parameters via a weak key exchange (no longer used)|
|obfs3|Obfuscates TLS handshake parameters with a Diffie-Hellman key exchange, encodes the public keys, but does not hide packet sizes and timing (no longer used)|
|obfs4|Randomizes the size and timing of packets. Requires client to present a secret key shared out of band. Stream looks like random noise with no plaintext components, not even in the handshake and key exchange|



## OOB Exercise

Open the packet capture in Wireshark, Tcpdump, or your network traffic
analysis tool of choice.

Here are three techniques to use:

- [Look for Random Hostnames](#look-for-random-hostnames)
- [Look for Known Tor IPs](#look-for-known-tor-ips)
- [Look for TLS Without Handshake](#look-for-tls-without-handshake)



### Look for Random Hostnames

Use Wireshark to look for random hostnames in the TLS Handshake.

All Tor traffic uses TLS to set up an encrypted connection.  Use the filter `ssl.handshake.type == 1` to look at all Client Hello messages.

Inspect each Client Hello message for possible Tor traffic



### Look for Known Tor IPs

Use Tcpdump to look for IPs reported as Tor infrastructure.

Several sites provide a list of public Tor nodes. Download this list to a file by typing:

```bash
wget https://www.dan.me[d]uk/torlist/
```

See how many IPs are in the list by typing `cat index.html | wc -l  ` Should be around 7,000.

Extract a list of destination IP addresses from the pcap by typing:

```bash
tcpdump -r CSIRT-pcap-6-pcapng -n | cut -d ' ' -f5 | cut -d '.' -f 1-4 | sort -u > destips.txt
```

Check list of Tor nodes for IPs found in pcap by typing:

```bash
for p in $(cat destips.txt); do grep $p index.html; done
```

You should now have several IP addresses that are present in both the pcap and the list of Tor nodes.

Now use Wireshark with the Client Hello filter from before combined with `ip.addr == <ip address>` filters for each of the Tor nodes found in `index.html`.

So final filter will resemble this:  

`ssl.handshake.type == 1 && (ip.addr == <ip address> || ip.addr == <ip address> || ip.addr == ... )`  including all the ip addresses found.

You should now have several Client Hello messages.
 
Check the SNI field in each for any random hostnames.


### Look for TLS Without Handshake

Now use Wireshark to look for port 443 traffic that has does not have a proper TLS handshake.

Search for TLS connections not containing a Client Hello message with:

`(ip.src==192.168.2.116 && tcp.flags.syn==1 && tcp.port==443) || (tcp.port==443 && ssl.handshake.type==1)`

This will show the initial SYN and Client Hello message
sent to each destination IP address.  A SYN without a Client Hello
message should be investigated as a possible Tor relay.

               

## Questions

1. How many times did the user access the Tor network?

2. What obfuscation plugins, if any, were used each time?

3. Were you able to determine the Tor relays/bridges used?

4. Are there any connections to Tor relay nodes that are non-Tor traffic?
