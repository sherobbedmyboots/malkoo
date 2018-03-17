# Gathering Information on a Rogue System

Here are three tools that we can use to obtain information about a rogue
system that has been detected on our network:

- [Splunk](#splunk)
- [Wireshark](#wireshark)
- [Nmap](#nmap)


## Splunk

When a system joins the network, if it's configured for DHCP it will
request an IP address using the following sequence:

|||
|-|-|
|DHCPDISCOVER|Host notifies network it needs an IP address|
|DHCPOFFER|DHCP server offers an IP address to the host|
|DHCPREQUEST|Host requests the IP address that was offered|
|DHCPACK|DHCP acknowledges the host's new IP address|  
  


This sequence is logged by Infoblox:

Infoblox then creates a forward and reverse map for the IP address and
hostname:

After this, the host begins renewing its lease with a DHCPREQUEST and
each time Infoblox responds with a DHCPACK:

When the lease expires, Infoblox reports a DHCPEXPIRE and the forward
and reverse maps are removed:

While on the network, any DNS queries the host makes will be captured
by Infoblox. 

This shows the rogue system queried domains that are used by Firefox
and Chrome browsers for updating their block lists:

And although it queried two hosts, the proxy logs show no traffic from
that IP:

Had we seen any traffic, the logs of the web requests could be mined
for more information such as the host's [user agent
strings](https://browscap.org/ua-lookup).

Also with Splunk, we can query our `networks` lookup to get a
location of the subnet of the rogue system:

So just from Splunk we've obtained the following information:

|||
|-|-|
|Hostname:|Ragnar|
|IP Address:|\<ip-address\>|
|MAC Address:|\<mac-address\>|
|DNS:|Firefox and Chrome browser-related queries|
|Web:|No traffic indicates host did not know/locate the Proxy address|
|Location:|\<location\>|


## Wireshark

Using a different rogue system event in this example, a packet capture
of the host's traffic can be very useful if it is available.

Looking at the DHCP process in this packet capture gives us a vendor
identifier: `WYSE-1000`

Also look for other systems trying to access the rogue
system who could be the system's owners. 

Below we see \<ip-address\> trying to connect with the rogue system on port
80:

And here we see \<ip-address\> trying to
RDP to the rogue system, failing, and then performing a `traceroute`:

And when the TTLs are large enough to reach the rogue
system (11), it replies with a TTL of its own (64):

A table of common starting TTLs for different operating systems indicates this is a Linux or Mac host:

|TTL|OS|
|-|-|
|64|Linux, Mac, BSD, Nmap|
|128|Windows, Novell|
|255|Solaris, iOS, PalmOS, TMOS|


Looking at who the rogue host was trying to contact can
reveal potential targets:

Looking at these two systems more closely we can see the
rogue host is repeatedly querying \<host\>, connecting to it on port 443.

A closer look shows the 3-way handshake completes and
then our capture seems to be missing some packets:

We can't say exactly what the problem is, but this
pattern indicates some type of connectivity problem or else the rogue
system would not need to query the host and complete the 3-way handshake
over and over again.

So from using Wireshark, we've obtained the following information:

|||
|-|-|
|Device:|Vendor class indicates a WYSE Dell Thin Client|
|Hostname:|\<hostname\>|
|OS:|Starting TTL indicates Linux, most likely ThinOS which runs on WYSE thin clients|
|Owners:|Possibly \<ip-address\> who is trying to access it on port 80|
||Possibly \<ip-address\> who is trying to access it on port 3389 and troubleshooting with `traceroute`|
|Targets:|\<host\>, which it is completing the 3-way handshake, but cannot keep connectivity|

## Nmap

Nmap is a tool used for network mapping, port scanning, and active
OS/service fingerprinting.  Nmap can get information about the rogue
host by sending various packet types and measuring system responses to
determine what type of platform and services the system is running.

Before you start, check to see if `nmap` is in your path:

If not, add to your path by typing:

```powershell
$env:PATH += ";<path-to-nmap-folder>"
```

Nmap uses the following format for its commands:

```powershell
nmap <options> -p <ports> <target>
```

Here are the options we will use:

|Option|Description|
|-|-|
|`-p`|use `-p <firstport>-<lastport>` for a range or `-p <port1>,<port2>,<port3>` for multiple ports|
|`-sV`|VersionNmap uses a a database of probes and responses expected by various applications to determine service versions|
|`-sO`|Nmap tries to fingerprint and guess the targets OS|
|`-sL`|Lists DNS name of the IP address|
|`-Pn`|No pingNmap does not ping the host first and assumes that the host is online|
|`-sS`|TCP SYN scan|
|`-sU`|UDP scan|


First let's use the `-sL` switch to get the hostname:


Fully Qualified Domain Name (FQDN):    

**\<fqdn\>**

Now let's scan all TCP and UDP ports to see if any are
listening:

The service values given are the services commonly known
to listen on that particular port, that's all. 

We do not know for sure that TFTP is really listening on port 69.

So let's do a Service Version scan (`-sV`) to see if nmap
can confirm any of the services listening on these ports:

Notice the VERSION column is empty for each service so
Nmap cannot confirm the version of any of the services.

Now let's do an OS detection scan with the `-O` switch:

Nmap guesses it is a load balancer running Linux 2.6. 

Load balancers typically have a starting TTL of 255 so we will ignore
this guess.

Using Nmap, we've found the following information:

|||
|-|-|
|FQDN|\<fqdn\>|
|Open TCP Ports|80, 4000|
|Open UDP Ports|69, 1718, 1719|

## Summary

Although we weren't able to confirm the OS or the service versions, the
information we've gathered allows further research.

A few Google queries on these devices supports the theory that this is a
WYSE device.  WYSE documentation shows several default ports and their
purpose:

Found in WYSE reference manuals:

|Protocol|Port|Function|
|-|-|-|
|TFTP|69|Download bootable image to enable management processing|
|HTTP|80|Communicate with the Web Service regarding actions and status of current task|


ThinPrintEnable={yes, no} - Set to no to disable the thinprint client. 
\[Port=port number\] -  The option Port sets the port of thinprint.  The default is 4000.

Found from multiple sources:

1718 and 1719 are the gateway ports used for H.323 connectivity (VOIP
and audio/video streaming)

               
