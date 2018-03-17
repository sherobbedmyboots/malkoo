# Traffic Analysis with Wireshark

Here is a quick introduction to Wireshark and some of its basic
features.  For the examples, use the following packet capture:

`wireshark_exercise.pcapng`


This document will review:

- [TCP/IP Communications Model](#tcp-ip-communications-model)
- [Wireshark Operation](#wireshark-operation)
- [Analyzing Different Protocols](#analyzing-different-protocols)
- [Analyzing an Incident](#analyzing-an-incident)


## TCP/IP Communications Model

The TCP/IP model aligns very closely with the way Wireshark organizes
network traffic.  Each layer has a different purpose and contains
different information.

|Layer|Description|
|-|-|
|Application|HTTP, DNS, SMTP data|
|Transport|TCP, UDP segments|
|Internet|IP packets|
|Link|Ethernet frames|


### Application Layer

- Interacts with the user
- Data used by the application
- HTTP, HTTPS, DNS, FTP, NTP, SSH, SMTP, SNMP, etc.
- Depends on all other layers for delivery


### Transport Layer

- TCP, UDP
- Contains the port

TCP is connection-oriented
- Sets up session between one source one destination
- optimizes flow
- uses sequence numbers for reliability
- SYN/SYN_ACK/ACK
- RST/ACK, FIN/ACK

UDP is connectionless
- Does unicast, broadcast, multicast
- Very efficient, no flow control or reliability


### IP Layer

- ipv4, ipv6, icmp
- Communicate using ip addresses and packets
- Uses DNS to do address translation

- Options for
  - Hops - ttl
  - Fragmentation - first, last, or other fragment
  - Protocol - TCP or UDP
  - checksums - if checksum fails packet is dropped

ICMP has no ports, uses message types and codes

- Used to send error conditions and information messages
- Reports on problems like fragmentation needed, unreachable ports or
    hosts
- No client/server, no reliability built in, can be broadcast


### Link Layer

- 802.3 Ethernet, 802.11 Wireless
- Communicate using MAC addresses and frames
- ARP is not routable protocol so needs to talk to IP


### Bits

- Binary digits
- Can have two possible values: 1 or 0
- Used to represent code (CPU commands) or data (documents)
- 8 bits make a "byte" or two hex characters (ff)
- 4 bits make a "nibble" or one hex value (f)

Each layer depends on the next: 
- Application data depends on TCP/UDP for delivery
- TCP/UDP depends on IP for network
- IP packets depend on Ethernet for link
- Ethernet frames are transferred between devices in bits and bytes
- IP packets are delivered by Ethernet
- TCP/UDP is delivered by IP packets
- Application data is delivered by TCP/UDP


When an application on host A wants to communicate to an application on
host B, data is encapsulated and passed down the layers until it travels
across the network in bits:

![](images/Traffic%20Analysis%20with%20Wireshark/image001.jpg)


Wireshark captures these bits as they are passed across the network and
organizes them by layer. 

You can expand each layer and see its contents:

**Application Layer**

![](images/Traffic%20Analysis%20with%20Wireshark/image002.png)


**Transport Layer**

![](images/Traffic%20Analysis%20with%20Wireshark/image003.png)


**Internet Layer**

![](images/Traffic%20Analysis%20with%20Wireshark/image004.png)


**Link Layer**

![](images/Traffic%20Analysis%20with%20Wireshark/image005.png)


Wireshark will also show exactly which bits make up each field. 

For example, selecting the User-Agent field highlights the 128 bytes in
the frame that correspond to that field's value:

![](images/Traffic%20Analysis%20with%20Wireshark/image006.png)


Wireshark has interpreted each field in the HTTP request.

Selecting the "GET" field in the web request highlights the three hex
values, or "nibbles" that correspond to the characters G, E, and T:

![](images/Traffic%20Analysis%20with%20Wireshark/image007.png)


We could do this manually by converting each nibble to its character
value:

![](images/Traffic%20Analysis%20with%20Wireshark/image008.png)


Or convert all three hex values to characters to create the "GET"
string:

![](images/Traffic%20Analysis%20with%20Wireshark/image009.png)


But Wireshark automates this for us as it recognizes thousands of
different protocols and field values. 

This allows analysts to quickly drill down into packets, interpret the
information present in each layer, and understand the nature of the
traffic.

## Wireshark Operation

### Columns

When you first open Wireshark, set the format of the columns:

- Right click on `Time` and select Column Preferences

- Click the `+` button to add a field

  - Add src port (unresolved)

  - Add dest port (unresolved)

- Double click on `Time` field to bring up a drop down menu

  - Select `Absolute date, as YYY-MM-DD, and time`

- Click `OK`


### Operators

These are the most common operators you will use:

|||
|-|-|
|`\|\|`|OR|
|`==`|EQUAL|
|`!`|NOT|
|`&&`|AND|


### Filters

Three effective ways to isolate and filter traffic are by system, by
protocol, and by port.

#### System

```
ip.addr == <ip address>
ip.src == <ip address>
ip.dst == <ip address>
```

![](images/Traffic%20Analysis%20with%20Wireshark/image010.png)


#### Protocol

`<protocol>`

![](images/Traffic%20Analysis%20with%20Wireshark/image011.png)


#### Port

```
<transport>.port == <port number>
<transport>.srcport == <port number>
<transport>.dstport == <port number>
```

![](images/Traffic%20Analysis%20with%20Wireshark/image012.png)


## Analyzing Different Protocols

Try each the following filters using `wireshark_exercise.pcapng`:

### ARP

Link Layer Communication

|Filter|Description|
|-|-|
|`arp`|see all arp|
|`arp && eth.src==00:0c:29:ef:a6:74`|see arp traffic from 00:0c:29:ef:a6:74|

### DHCP

Used to Obtain an IP address on the Network

|Filter|Description|
|-|-|
|`udp.dstport==67`|see all DHCP traffic to 67|
|`boot.hw.mac_addr==08:00:27:4f:01:91`|see DHCP traffic from 08:00:27:4f:01:91|

### DNS

Used for Host-to-IP Resolution

|Filter|Description|
|-|-|
|`dns`|see all DNS traffic|
|`dns && ip.src==192.168.2.237`|see all .237's DNS traffic|
|`dns && ip.src==192.168.2.237 && dns.qry.type=0x0001`|see all .237's A record queries|
|`dns && dns.flags.rcode==3`|see all "No Such Name" DNS responses|


### HTTP

Web Traffic

|Filter|Description|
|-|-|
|`http`|see all HTTP traffic|
|`http && http.request.method==GET`|see all GET requests|
|File  -->  Export Objects --> HTTP (Save As)|carve out a file transferred over HTTP|
|Statistics  -->  Conversation List  -->  IPv4 (sort by Packets)|see which hosts are most active|
|Right click  -->  Apply as Filter  -->  Selected  -->  `A -> B`|see what traffic top host was sending|

### SMB/CIFS

Used for file-oriented operations

|Filter|Description|
|-|-|
|`smb`|see all SMB traffic|
|`smb.path == "\\\\192.168.2.237\\IPC$"`|see all SMB traffic to .237's IPC$ Share|
|Right click -->  Follow TCP Stream|see commands and output from SMB session|


## Analyzing an Incident

When investigating a PCAP, it helps to first get a good overview of the
traffic.

- Use statistics overview to see protocols and conversations

  Statistics --> Conversations --> `Sort by Packets/Bytes`

- Examine conversations

  Right click on top conversation --> Apply as Filter --> Selected --> `A<->B`

- Filter out unwanted traffic

  Select a \[TCP Retransmission\] packet and select the value of \[This frame is a (suspected) retransmission\]

  Right click --> Apply as Filter --> `...and not Selected`

  Select a \[TCP Dup ACK XXXX\#X\] packet and select the value of \[This is a TCP duplicate ack\]

  Right click --> Apply as Filter --> `...and not Selected`

- Put together a timeline of events

  Review the actions of the attacking machine and responses of the victim machine

  Create a summary of events in chronological order
