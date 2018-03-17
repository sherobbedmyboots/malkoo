# Intrusion Analysis Using the Kill Chain

The [Kill Chain
model](http://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf)
is a framework used to understand the steps an adversary typically takes
in a successful intrusion.  By separating an adversary's steps into
phases, defenders can more easily map phase-specific indicators to
specific response actions.  In other words, the more you know about what
the adversary is doing---and is most likely trying to do next---the
quicker you can react and implement the most effective countermeasures. 
This model is also useful in post-mortem analysis by allowing defenders
to identify patterns in each phase, extract indicators, and use them to
improve defensive courses of action.

This exercise simulates an attacker compromising a server via a
vulnerable web application, escalating privileges, pivoting to another
host, and performing data exfiltration.

    pcap-4.pcap

### NetworkMiner Setup

#### On the SIFT-REMnux:

1. Open Network Miner by opening a terminal and typing `NetworkMiner`

2. Click File --> Open, Select the PCAP and click `Open`

3. After the PCAP is loaded you will see tabs along the top (Hosts,
    Files, Images, DNS, etc.)

## Analysis

Here are the general steps the attacker took for each phase of the Kill
Chain---try to answer the questions for each one:

- [Reconnaissance](#reconnaissance)
- [Weaponization](#weaponization)
- [Delivery](#delivery)
- [Exploitation](#exploitation)
- [Installation](#installation)
- [Command and Control](#command-and-control)
- [Actions on Objectives](#actions-on-objectives)


### Reconnaissance

Gathering information about the target

Attacker performed an arp scan, port scan, and service enumeration

- Did the victim host respond to the arp scan?

- Which ports on the victim host responded to the port scan?

- Name two services the attacker enumerated after the port scan.

- What vulnerability did the attacker discover?

- What information was the attacker able to obtain from this
    vulnerability?

Wireshark Filters

- `arp`

- `ip.src == <victim ip address> && tcp.flags.ack ==1`

- `ip.src == <victim ip address> && (tcp.port == <port> || tcp.port == <port>)`


### Weaponization

Creation of a malicious payload  (This is done on the attacker's side)

- What payloads did the attacker create?

- What were their associated filenames?



Wireshark Filters

- `ip.addr == <victim ip address> && ip.addr == <attacker ip address>`


NetworkMiner

- Browse the files extracted from the PCAP under the "Files" tab


### Delivery 

Sending the malicious payload

- How did the attacker deliver each payload?

- Where on the victim host was each payload placed?



Wireshark Filters

- `ip.addr == <victim ip address> && ip.addr == <attacker ip address>`


NetworkMiner

- Select interesting files under the "Files" tab

- Right Click and Open to view contents


### Exploitation

Execution of the exploit
              

- What application(s) were exploited to run the payloads?

- How did the attacker use the results of the exploited application(s)?


Wireshark Filters

- `http.request || http.response`

- `ip.src == <attacker ip address>`


### Installation 

Malware is installed on the computer

- Did the attacker install any malware on the victim host?

- What were the attackers first actions after successfully exploiting
    the victim?


Wireshark

- Identify and examine C2 channels to determine the attacker's
    actions


### Command and Control 

Remote control of the compromised system

- Name the two different C2 methods that were used by the
    attacker.            

- What ports and protocols were used for each?

- Was each method synchronous or asynchronous?



Wireshark

- `ip.src == <victim ip address> && ip.addr == <attacker ip
    address>`

NetworkMiner

- Examine interesting sessions under the "Sessions" tab


### Action on Objectives

Privilege escalation, persistence, pivoting, data exfiltration, etc.

- What did the attacker use to escalate privileges?

- How did the attacker transfer what was needed to the victim system?

- What system(s) did the attacker pivot to?

- What file(s) did the attacker steal?


Wireshark

- Identify and examine C2 channels to determine the attacker's
    actions
