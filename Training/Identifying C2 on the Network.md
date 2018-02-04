# Identifying C2 on the Network

Command and Control (C2) refers to remote access to a system over the
network---the way an attacker interacts with and controls a victim
machine.  Techniques can include the use of encrypted communications,
covert channels, legitimate web services, multiple domains and IPs,
multiple protocols, changing check-in intervals, and peer-to-peer
communications in order to avoid detection.  One common characteristic
is that it must traverse a network's points of presence (POP) /
chokepoints to reach the Internet so the majority of monitoring will
focus primarily on web proxy and DNS logs.  For us this means using
Splunk, but other tools can be used to find C2 activity as well such as
IDS, NetWitness, and FireEye.


## C2 Techniques

C2 can attempt to blend in with normal traffic on the network or attempt
to hide by obfuscation, use of uncommon ports, tunneling protocols,
encryption, etc.  Data can be transferred using user agent strings,
URLs, hostnames, and unusual fields/places in packets.  Encryption and
obfuscation is also frequently used to evade IDS and DLP tools. 
Multiple C2 servers add another layer of protection to avoid initial
detection and also to maintain communications if one or more C2 IP
addresses or domains is blocked on the victim's network.

Some common techniques (see
[here](https://attack.mitre.org/wiki/Command_and_Control) for a full
list):

- Commonly Used Port
- Uncommonly Used Port
- Multi-Stage Channels
- Fallback Channels
- Multiband Communication
- Multi-hop Proxy
- Multilayer Encryption
- Data Encoding
- Data Obfuscation


## Persistence and Shell Access

Controlling a system over the network with modern C2 consists of a
reliable communication channel between the attacker and victim and a
persistent process on the victim that receives commands from the
attacker and carries them out using the victim OS.  The most basic
example of this is PSEXEC and SSH used to administer Windows and Linux
systems remotely.  Backdoors and other remote access tools have been
used in a similar way to bypass normal security controls and access
systems for years.  They have now evolved into full-featured
post-exploitation tools called implants, capable of using many different
modules for covert communication, system enumeration, pivoting,
scanning, credential access, etc.---all while avoiding detection by
host-based tools. 

Just as implants have become stealthier, more capable, and more
persistent, C2 methods have also made improvements in evading network
security monitoring tools searching for patterns, signatures, and
anomalous traffic.  Implants that provide interactive shell access
(i.e., Meterpreter) are very noisy on the network and can be identified
by a steady connection between the attacker and victim host.  Because of
this, modern implants use an asynchronous (intermittent communications)
model and can be configured to communicate only at certain times and
intervals using multiple different protocols. 

Another problem with traditional interactive shell access is that if the
connection drops or the implant fails or is detected/deleted, an
attacker would no longer have access to the system.  For the attacker,
this would require gaining access to the network again, repeating an
exploit, or finding another successful exploit that will restore access
to the victim system.  For this reason, one of the first things an
attacker will do upon compromising a system is establish some form of
persistence.  Common methods are using registry run keys, logon scripts,
scheduled jobs, modifying service binaries, and WMI subscriptions.

These two problems have caused a shift towards separating persistence
from shell access.  Using this strategy, a small implant with only
essential elements for low-and-slow, asynchronous communications would
be a preferred payload rather than the actual full-featured implant when
compromising a system.  This is much more difficult to detect on the
host as well as over the network.  Once an attacker is ready for
interactive operations, the implant is tasked to pull down individual
modules depending on what capabilities are needed for that particular
system or network.  Implants have also made other OPSEC improvements
such as running in memory and utilizing modules that are designed to
avoid touching disk to leave little or no evidence of the intrusion.

Here are some example C2 implementations and tools that can mimic the
type of malware C2 in order of louder/larger to smaller/more
OPSEC-focused:

|Technique|Tool|
|-|-|
|Interactive Shell Access over HTTP/HTTPS|Meterpreter, Reverse TCP shells|
|Interactive Shell Access over DNS|Dnscat2|
|Asynchronous over DNS|Cobalt Strike|
|Asynchronous over HTTP/HTTPS|Cobalt Strike, Empire|
|Asynchronous over HTTP/HTTPS to Multiple servers |Throwback, Empire|


## C2 Identification

Things to consider:

- Is the site suspicious?  (site reputation, OOB inspection)

- Does it look like normal behavior for the application?  (browser, dns, etc)

- Is the actual traffic suspicious or unusual?  (check associated process, packet contents)


The following examples were simulated on the network:


### Interactive Shell Access over HTTP/HTTPS

TCP connection is established providing command-line access to attacker

Examples:

- Reverse https meterpreter shell  (putty.exe)

- Reverse tcp shell  (pcap-1.pcapng)

Meterpreter is an implant that uses reflective DLL injection for
specialized command-line access.  It runs inside the exploited process
instead of creating a separate one and provides access purely by
manipulating memory and never touches disk.  It uses its own set of
commands instead of using executables on the target machine, and it can
load new modules, dynamically changing its functionality while still
inside the memory of the exploited process.  It can communicate using
TLS to avoid detection over the network and has many additional features
such as spawning a command shell, clearing all events from Application,
System, and Security logs, dumping password hashes from the registry,
screenshots, etc.

### Interactive Shell Access over DNS

TCP connection is tunneled over DNS providing command-line access to
attacker

Examples:

- Reverse TCP shell   

Dnscat2 is a server and client that tunnels encrypted data over DNS
queries to the same domain.  The client encrypts a chunk of the data,
sends it in a DNS query to the authoritative DNS server (the dnscat2
server) appearing to request the IP address of the fake hostname.  The
fake DNS server decrypts the data, one hostname at a time, and returns
encrypted data back through the tunnel over what appear to be normal DNS
replies where the client receives it, and decrypts it, one hostname at a
time. 

### Asynchronous over DNS

Implant checks in for tasking in a DNS query, C2 server provides task to implant in a DNS response.

Implant provides task results in a DNS query, C2 server acknowledges with DNS response.

Examples:

- Cobalt Strike Beacon

Beacon is Cobalt Strike's covert C2 payload that is used to simulate
specific threat actors or campaigns.  It is implemented as a reflective
DLL and can be delivered with social engineering packages, client-side
exploits, and session passing and can migrate to another process
immediately after staging.  All characteristics can be changed to
disguise the C2 traffic as some other type of normal traffic such as
google web bugs, Pandora streaming, amazon browsing, etc.

- Agents can be configured to use random intervals using changing protocols (DNS, SMB, HTTP, HTTPS)

- URIs can be configured to have multiple C2 servers to get around any IP/domain blocking

- User agent, metadata/ID format, and headers of both the client and the server interactions are configurable

### Asynchronous over HTTP/HTTPS

Implant checks in for tasking with a GET request, C2 server provides task to implant in a 200 OK response.

Implant reports task results with a GET or POST request, C2 server acknowledges with a 200 OK response.

Examples:

- Empire (pcap-2.pcapng, CurrentSalariesReview2017.docx)

- Cobalt Strike Beacon

Empire is a pure PowerShell and Python implant which offers many
OPSEC-focused features, a secure and flexible C2 architecture, and a
large collection of memory-only post-exploitation modules for evading
endpoint detection.  Like Meterpreter, it can migrate to other processes
by injecting itself into the process's memory space.  It can be
configured to check in at odd times and intervals using HTTP/S making it
difficult to detect over the network.

- Has settings for DefaultDelay, DefaultLostLimit, KillDate, WorkingHours, DefaultJitter anti-beaconing

- When delivered through browser/flash exploit, PowerShell is never started as process, but injected into same memory space as browser

- Delivery via MS Office, Adobe Reader PDF exploit, macro, executable, USB, etc. will start new PowerShell process

### Asynchronous over HTTP/HTTPS to Multiple C2 Servers

Implant communicates to C2 server using HTTP requests and responses to different servers which act as redirectors and are changed/rotated as needed.

Examples:

- Throwback 

- Empire

Throwback is a stealthy HTTP/HTTPS beaconing backdoor and C2 server
created by Silent Break Security.  Slingshot is their full-featured
payload which uses reflective DLL injection for interactive
post-exploitation.  Multiple apache servers host php files that collect
callback data from the implants which can be configured to check in for
tasks every 1, 4, 8, 12 hours in case the interactive shell drops.
