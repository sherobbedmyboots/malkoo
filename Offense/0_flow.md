# Flow

- [Reconnaissance](#reconnaissance)
- [Remote Enumeration](#remote-enumeration)
- [Construct Attack Sequence](#construct-attack-sequence)
- [Remote Exploits & Privilege Escalation](#remote-exploits-&-privilege-escalation)
- [Local Enumeration Scripts](#local-enumeration-scripts)
- [Local Exploits & Privilege Escalation](#local-exploits-&-privilege-escalation)
- [Persistence](#persistence)
- [Root Loot Scripts](#root-loot-scripts)
- [Cleanup](#cleanup)



## Reconnaissance

Scan network to get IP's and OS's

```
arp-scan –l
netdiscover –i eth0 –r $range
nmap -Pn -F -sSU -o sweep-$range $range | grep -v 'filtered|closed'
```

Responder

responder.py

ID DNS and do Zone xfer

for x in $(host -t ns $site|cut -d “ “ -f4); do host -l $site $x |grep “has address”;done

Zone Transfer

```
dig $site -t axfr
```

```
dnsrecon.py -a -d $site
```

Reverse DNS Lookup

```
dig -x $ip
```

DNS Recon

dig $site -t any
dnsrecon.py -d $site

Forward Brute Force

dnsrecon.py -t brt -d $site -D /opt/dnsrecon/namelist.txt

for x in $(cat subs.txt); do host $x.megacorpone.com;done


Reverse (PTR) Scan

```
use auxillary/gather/dns_reverse_lookup
```

```
dnsrecon.py -r $range
```

```
nmap -sL $range | grep \)
```

```
for x in $(seq 1 128); do host 10.10.10.$x; done | grep -v “not found”
```

## Remote Enumeration

Fingerprint and gather information from each port, enumerate SMB shares, user IDs, SNMP details, FTP banners, OS versions etc

Port Scanning (UDP + TCP)

### TCP

nmap -Pn -p1-65535 -o tcp-$ip $ip | grep -v 'filtered|closed'

### UDP

nmap -Pn -sU -p1-65535 -o udp-$ip $ip | grep -v 'filtered|closed'

Service Profiling

for p in $(grep open tcp-$ip | cut -d "/" -f 1); do nmap -Pn -sV -p$p| grep open >> ver-$ip; done

for p in $(grep open udp-$ip | cut -d "/" -f 1) ; do nmap -Pn -sV -p$p| grep open >> ver-$ip; done


Server Profiling (Software and Versions)
     
nmap -sO $ip

Service-Specific Enumeration

nmap --script=http-robots.txt $site

## Construct Attack Sequence

Kali "searchsploit" with the service/software version of each port

### Search exploitdb

grep -i OSVDB-397 /usr/share/exploitdb/files.csv

Compile

~/.wine/drive_c/MinGW/bin/wine gcc.exe ~/Downloads/1911.c -o ~/1911

*** if you are unable to get direction loop it back to Enumeration step



## Remote Exploits & Privilege Escalation

Perform sequence of exploits for specific vendor, version,
Remote exploits, FTP brute-force, HTTP directory brute force, SNMP brute force, active exploits against open services, etc

-php shell

*** Review exploit for any changes needed
*** Try different local ports



## Local Enumeration Scripts

Enumerate system getting as much information as possible.
Interesting files, bash history, cmd history, environment settings, memory, running services, directory permissions, service permissions, scheduled jobs, weak permissions etc

enumeration of the box to see what processes are running, what are running as root, config files, etc.

structure all your scripts and pre-compile your most used local privilege escalation exploits



## Local Exploits & Privilege escalation

Escalate to full root/system level access

UAC bypass, elevation scripts, local exploits, brute forcing, etc

*** use the linux or windows exploit suggesters
*** "searchsploit kernel x.x"
*** search for common weaknesses



## Persistence

Install backdoors to secure our access
- Add local administrator accounts
- Set service to start automatic on boot
- Put a pinhole in the firewall service


## Root Loot scripts

Search the whole system with system/root access for interesting data
- Steal hashes from LSA
- Configuration scripts
- SAM/shadow database
- Cracking MD5 and NTLM
- Checking currently connected users
- Checking relationship between this host and other hosts

*** Desktop, Documents, Program files, Temp folders, Recent files, etc.
*** Get usernames and passwords for all applications/processes on box (MySQL? VNC? xyz)
*** Print screen as you go, copy and paste konsole/terminal output


## Cleanup

Scrub logfiles, clean exploits, hide backdoors

Update maps and diagrams, and move to another system
