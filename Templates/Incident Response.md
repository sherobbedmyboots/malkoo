# Incident Response	

- Evaluate environment for presence of attacker activity or compromise																								
- Rapidly detect incidents and analyze incident-related data and respond quickly and effectively																	
- Scope, investigate, contain, and resolve security incidents minimizing loss and destruction																			
- Decrease response time and reduce impact of the security incident																								
- Mitigate weaknesses that were exploited																								

## Preparation	

Get team ready to handle incidents, Understand organization's risk profile and security posture, position to resist intrusions or counter weaknesses being exploited by ongoing intruder activity

### Policy

- Define roles and responsibilities, creating buy-in and garnering support from upper management and data-owning business units																								
- Identify ownership and responsibility for all systems (including data) in the enterprise																								
- Have written procedures and policy in place so personnel know what to do when an incident occurs																								
- Policies for computers the organization does not own, remote computers belonging to employees, business partners, contractors, and other non full-time employees																								
- Explicitly define the organization's policy on the presumption of privacy	

- Evaluate information security program to improve security posture and reduce risk																								
- Incident Handling plan should include hooks to your DR and BCP																								


### Tools & Staffing	

- Endpoint security (HIDS, AV, HBF) for detection, reporting, and protection against malicious software and activity																								
- IDS and IPS (Snort) for signature and anomaly-based alert data for alerting on and/or blocking real-time traffic in transit																								
- Log Collection & Correlation (OSSEC) for collecting and synthesizing separate indicator sources (system/device logs, tools, reputation data)																								
- Network flow collection (SiLK) collection of connection and session metadata for anomaly detection and retrospective analysis																								
- Network framework analysis (Bro) for collecting connection/specific application data and alerting on anomalies																								
- Full Packet Capture (tcpdump) for full content data including header and payload for session reconstruction and analysis																								
- Strictly control outgoing traffic using proxies wherever possible, internet white-listing, network traffic decryption and inspection, sufficient sensor placement																								
- Synchronize the clocks on all systems and network equipment

- Aggregate and index all system logs, alert data, flow data, and packet data ensuring all sources are searchable																								
- Integrate high-quality threat intelligence and reputation data to provide context																								
- Ensure proper IRT staffing	

- Implement hunt teaming searching for long URLs, weird user-agent strings, long durations, concurrent logins, blacklisted DNS entries, beaconing, odd services/exe's																								
### Training & Planning	

- Constantly train and assess the workforce on protecting the enterprise, test quarterly and track improvements and deficiencies																								
- Provide users with policy, procedures, training and convenient reporting and response capabilities such as phone, email, or website																								
- Harden the technical environment with configuration and vulnerability management and automated countermeasures such as firewalls, AV, DLP, and white-listing																								
- Develop and improve SOC and IRT capabilities by implementing a proactive, mission-focused program aligned with business requirements																								
- Test enterprise security posture using the same tools, techniques, and procedures (TTPs) as current, advanced attackers																								
- Funding and resources to perform extended investigations to allow continued IR work throughout sustained response																								
- In house capability or contracts with business partner for IR, Forensic Investigation, and Malware RE																								
### Response Strategies	

- Organizational response strategies should be discussed and decided with senior management and the legal team																								
- Interface with CIRTs, local, state, and federal law enforcement through local chapters of InfraGard, HTCIA, or ECTF																								
- Policy should specify to notify public, law enforcement, etc for breaches, threats to public safety or health, other types of incidents																								
- SOPs should define responses for each scenario, methodology for deviating from SOPs, notification and justification of planned deviations, contain/clear or watch/ learn																								
- Authorization, circumstances, and protocols for incident handlers accessing and responding to all systems in enterprise, especially critical systems																								
## Identification	

Maintain SA of indications, warnings, intelligence, fuse or correlate information																								
### Capture, Analyze, and Interpret Traffic and Events	

- Centralize Network perimeter, Host perimeter, System-level, and Application-level logs and work to identify all data from machines over all application																								
- Unknown web pages, PDFs, email attachments, etc. sent to a sandbox system, executed in organization's normal OS/app environment, malicious traffic is tagged and blocked at the gateway	

- Identify RATs, C&C, Encrypted communications, Covert channels, HIDS/NIDS alerts																								
### Network Analysis

- 1. Netflow analysis – Look at POP/chokepoints (web proxy, dns cache, connection logs) for what, where, when, how often, how much data																								
	- DNS – short TTLs, find cached malicious domains with dns-blacklists.py and Malware Domain List																								
	- Web Proxy – Long URLs, weird user agent strings, blacklisted domains																								

	- Connection Data – Beaconing, Scanning, Long durations, blacklisted IP addresses, Concurrent logins to high numbers of systems																								
- 2. Network connections – ports, protocols, socket creation times

- 3. Processes - What they are tied to, what they are doing, times started, locations, DLLs, parent processes, command arguments, SIDs running under																								
- 4. Files – strings, behavior, origin, reputation		

- 5. Relationships – with hostile systems, other internal systems

### Assess & Determine if an Incident	

- Knowing where to look to determine what happened, identify attacking hosts, malware C2, data exfiltration
																								
- Maintain notes recording all actions with timestamps																								

### Assign IR Team, use OOB and Encrypted Comms	

- Notify correct members using correct methods including press team, legal team, provide updates as new information comes to light																								
- On-site response team within 90 min. with checklists, jump bags, contact lists with owner and technical POCs for each system, set up command post to collect and analyze data		

- Create secure telephone bridge, password-protected real-time chat room, method for exchanging encrypted files via PGP, GnuPG, S/MIME (not primary email/chat)																								
- Send urgent notice to affected parties via encrypted communications on how to join phone bridge and chat room																								
- Real-time reporting identifying victim systems and data to coordinate containment actions and countermeasures to mitigate data loss, alteration, DoS, etc																								
### Establish Chain of Custody	

- Documents showing seizure, custody, control, storage, transfer, and analysis of physical and electronic evidence																								
- Include all dates, timestamps on items seized, records of serial numbers IAW procedures																								
- Sign and seal each piece of evidence as it is collected, all transfers of custody require signed itemized list of all contents																								
- Process must be fully auditable, verifiable, and repeatable

- Obtain hash, store in safe location with digital signature, copy evidence file to external media, validate copy by running hash on external media and comparing to good hash			

### Contain/Clear or Watch/Learn?	

- Does victim contain sensitive information?	

- Can information taken lead to other intrusions?	

- Any accounts that can be used to log on other systems?

- Are business partners or customers at risk?		


## Containment	

FIRST AID – Prevent attacker from getting deeper, spreading to other systems

### System Backup	

### Data Collection

### Memory Acquisition	

- Hardware - PCI card, Firewire	

- Software - Programs		

- Other - VM suspend, crashdump, hibernation file, cold boot attack	

### Live Data Collection	

- Memory is a snapshot of current physical memory, can contain malicious code from an infection and evidence of which system resources were allocated by and used in support of the malicious code.   	

- For data exfiltration, memory can contain encryption keys and passwords, plain-text contents of files before they were encrypted, full content network packets.																								
- Full Disk Encryption - extract AES keys to allow decryption, bypass packers, binary obfuscators, rootkits (including kernel mode) and other hiding tools																								
- Rootkit Analysis - identify processes trying to run undetected, network connections , running processes, open files, memory only chats, decrypted malware, windows cmd line history, better understand an event through correlation - memory, disk, network																								
- 1. If VM, pause/snapshot, clone, host disk, introspection  (most will not include network connection data)																								
- 2. If host not running, try hibernation file, page file(s), crash dumps																								
	- Convert hiberfil.sys with Volatility		

	- Convert hiberfil.sys with MoonSols hibr2bin

	- Convert dump file with MoonSols dmp2bin		

- 3. If running, and have root, use software-based utility

	- Local - dump to USB, ESATA, or Firewire drive - Dump memory to an external drive or to a listener on a remote machine.  If possible, do not save evidence to the local disk because it would overwrite unallocated disk space that could be helpful during disk forensics																								
	- Remote - push tools with Psexec or copy them to C$ or Admin$ via SMB, then schedule a task or install service that runs tools and sends physical memory to netcat listener	

		- 1.)  Create a temp admin account with access to only target system																								
		- 2.)  Disable after acquisition is complete, monitor for use of credentials																								
		- 3.)  Compute integrity hashes before and after the transfer																								
		
		- 4.)  Send via encrypted means if possible (CryptCat, F-Response, KnTDD)																								
- Open Source - Winpmem, Linpmem, FTK Imager, RAM capturer, DumpIt, RAM Capture, Memoryze, MDD, dc3dd																								
- Commercial - Dumpit, KnTDD, WinEn, WindowsSCOPE, HBGary FastDump, F-Response, EnCase																								
- LINUX - dc3dd and memdump for 2.4, LMG, LiME, linpmem, fmem for 2.6 and later																								
- 4. If not root, obtain exploit/brute force password	

- 5. If not, use Direct Memory Access (DMA)	

- Gather Live System State and Artifacts - Firewire (less than 4GB) or PCI	

- Obtain live system state and send to /mnt/usb/live:  `for cmd in 'uname -a'  ifconfig; do echo $cmd >> /mnt/usb/live && $command >> /mnt/usb/live 2>&1;done`																								
- Gather other Linux artifacts	

- Get Image of File System	

- Collect disk image - Stop services/apps && Minimize network traffic && install write blocker && collect with dd, dc3dd, FTK Imager,																								
- Make MD5/SHA256 hashes of all artifacts																								

### Memory Analysis	

- Running processes and services	parent directory, cmd line arguments, mispelled name, start time																							
- Unpacked/decrypted executables	injected code	

- Memory-only chat and P2P programs			

- Network communications and listening ports	

- Encryption keys and cleartext passwords	

- Private browsing data			

- Evidence of Rootkit Subversion	

- Volatile registry keys, open files, hardware & software configuration		

- Data and files not flushed to disk				

- Persistence - Run keys, scheduled tasks, malware as service, startup folder, DLL load order hijacking, image path hijacking																								
### Characterize Incident	Assign Category, Severity, and Sensitivity - Prioritize by functional impact, informational impact, and recoverability																								
- Which networks, systems, or applications are affected			

- Who or what originated the incident, how the incident is occurring

- What tools or attack methods are being used, what vulnerabilities are being exploited																								
- Any characteristics/techniques of the adversary including vectors, files, system calls, processes, ports, IPs, hostnames																								
- Update NIDS/HIDS/HIPS to assess assets in environment and identify additional affected systems																								
- Inspect Pcap and host data to determine what was stolen, assess damage	

- Identify legal ramifications such as PCI, HIPAA, California HR (SB 1386), European data breach requirements, etc																								
### Short-Term Containment	

- Notify Management and Officials	

- Enter in incident tracking system	

- Assign and Deploy Team		

- Coordinate with ISP and system owners	

- Contact person/group who makes the business decision about taking down a system, examines the system, isolates the system at network level? The ISP level?																								
- Notify public, US-CERT, partners, customers, and those identified by Industry requirements (DIB, Medical, SOC, GLB)																								
### Stop Attack Progress	

- Close network vectors of exfiltration	

- Disable certain functions		

- Isolate to honey network or containment VLAN	

- Change DNS name to point to different IP		

- Isolate with local firewall rule	

- Implement acl, routing change, firewall or proxy block

- Isolate or shut down switch port			

- Disconnect network cable	

- Put in hibernate mode		

- Shut down system		

### System Back-up (mem/nw/FS)	

- Filesystem: Use removable media with binaries, set path to run programs from media, create with dd, make original image (1), copy (2), and analysis starts on image (3)
																							
- Memory: Pause/snapshot VM, if root push software tool, if not consider exploit/bruteforce, if not use Direct Memory Access via Firewire or PCI																								
- Network Artifacts: Preserve pcap & network info IAW SOPs, make MD5 and SHA256 hash of stored pcap																								
### Determine Risk of Continuing Operations

- Review logs and neighboring systems

- Contain-and-Clean or Watch-and-Learn?																								

### Long-Term Containment	

- If system is critical, keep in production while building a clean one

- Remove accounts used by attacker, change passwords, shut down backdoor processes, alter any trust relationships																								
- Patch system, null-route all but essential ip addresses, deploy in-line Snort/IPS																								
## Eradication	

Determine cause, symptoms, and vector of attack and make corrections																								


### Identify root cause/symptoms

### Scrub/Remove malware OR Wipe/reformat/rebuild	

- Risks of not wiping/rebuilding

- OS & patches, apps & patches, then data																								

### Improve defenses	

- Filters, null route IPs, change IP and DNS names, patch and harden system	

### Perform vulnerability analysis																									

### Look for similar attacks																									

### Eliminate repeat occurrences																									


## Recovery	

Validate system, safely return to production, and monitor																								

### Validate system	

- Verify normal operation and all needed patches and controls IAW procedures, Have business units perform end user validation testing																								
- Return to production safely, have system owners decide when to restore systems, Coordinate restore operation time with business unit																								
- Monitor for repeat events	Use IPS/IDS and daily scripts to detect presence of repeat symptoms																								
## Lessons Learned	

Document what happened, improve capabilities																								

### Analysis/Technical Report	

- Initial vector of infection, How privileged credentials were obtained, Which systems were involved, What was searched and why, What was taken and how																								
- Extent of compromise and Remediation Plan	

- Get signature on follow up recommendations

### Meeting within 2 weeks	

- Process improvement, IH team and procedures effectiveness, Policy or organizational problems encountered that require management's consideration																								
### Create action plan to respond to operational issues that arose from this incident, Characterize adversary, Counter-intelligence strategies such as Kill Chain, Recategorize and revalue assets in light of incident																								
Apply approved fixes 	to process, technology, IR capabilities																								
- Move critical data to more restricted area, implement increased auditing																								
- Counsel/train/discipline any individuals who accidentally or purposefully aided the adversary																								
- Additional training required for new skills or using current tools more effectively																								
- Additional staff to aid in response																								
- New software or hardware to help prevent future incident																								
- Forms and incident management systems																								
- Consider adding a forensics capability for better evidence collection or IR/awareness																								
Attack Steps																									
Reconnaissance	names, phone numbers, postal addresses, IP addresses, and DNS servers																								
Remote Enumeration	Fingerprint and gather information from each port, enumerate shares, user IDs, SNMP, banners, OS versions, etc																								
Construct Attack Sequence																									
Remote Exploits & PrivEsc	Perform sequence of exploits against open services for specific vendor, version, password attacks																								
Local Enumeration	Interesting files, cmd history, environment settings, memory, running services, directory permissions, service permissions, scheduled jobs, weak permissions etc																								
Local Exploits & PrivEsc	Escalate to full root/system level access with UAC bypass, elevation scripts, local exploits, brute forcing, etc																								
Persistence																									
Root Loot	Search the whole system with system/root access for interesting data, Steal hashes from LSA, configuration scripts, SAM/shadow database, cracking MD5 and NTLM, checking currently connected users, checking relationship between this host and other hosts, etc																								
Update Attack Sequence	Update attacks with new information																								
Commands																									
Linux																									
Windows																									
Technologies																									
Endpoint IR	GRR, OSQuery, Tanium, Carbon Black, MIR, EnCase Enterprise, F-Response Enterprise, FireEye HX, osquery/Envdb, MIG, Kansa, Crowdstrike Response																								
Cloud	EC2, GCE, Azure																								
SIEM	Qradar, ArcSight, Spark? , Solar Winds, Trustwave, Tenable, MozDef?																								
Logging	Sysmon with ELK/Splunk, Syslog-NG, Beats, RELP																								
Analysis/Repository	Moloch, Hadoop																								
Case Management	CERT's FIR, CRITs, Jira, ArcSight, RSA Archer																								
Hunting/Threat Analytics	RITA, SOF-ELK, Cisco Talos, FireEye TAP, MTA																								
Web Proxy	Squid with DansGuardian, NGINX, Apache, Bluecoat, Forefront TMG, Barracuda, Websense																								
Enhanced Aggregation	Logstash (ELK), ELSA, Splunk, Cisco OpenSOC																								
Netflow	SiLK, Nfcapd																								
Vulnerability Scanning	Find holes in network, wireless, phone before attackers   Supplement with pentesting to verify results  CONS: false positives, unverified vulnerabilities																								
HIDS	Unencrypted, UA changes, FIC, resource misuse, OSSEC, Tiger, Samhain  CONS: deployment/maint/updates, tunnel vision, needs centralization, cost  USE: monitor changes at application level (web/dns/mail), networking devices 																								
NIDS	insight into network, assists quick response, auditing, Snort, PSAD   CONS: topology, encryption, signature quality/quantity, performance, cost   USE: Well-trained analysts, SIEM, integrate with VA for profiling/prioritization																								
HIPS	HIDS + ability to stop known & unknown attacks   CONS: false positives + same as HIDS  USE: Centrally manage and test software & updates, don't rely solely on																								
NIPS	NIDS + ability to stop known & unknown attacks   CONS: false positives, throughput, less-extensive rule base, false negatives   USE: trained analysts & engineers																								
Firewalls	Filter based on content, perform NAT, Encrypt for VPN   CONS: Application-layer, VPN, dial-up, extranet attacks may get through   USE: Default Deny on packet filter, stateful inspection or Proxy/App Gateway																								
Honeypots	Insight into TTP, reduces false alarms   CONS: improper deployments, use against org, resource burden, legal liability   USE: deploy/monitor secure, low-interaction, in unused address space																								
Integrity Checkers	Integrit, Tripwire, Aide, Samhain, Verisys																								
Boot	Boot sector, MBR, BIOS code integrity   BitLocker used with TPM, UEFI Secure Boot (Win 8 & later)																								
Endpoint	ClamAV, Comodo, AVG, Avira, BitDefender, SE/Windows Defender, Malwarebytes, CarbonBlack																								
Web Application Firewall	ModSecurity, ModEvasive, ModSecurity, WebKnight																								
Rootkit Detection	chrootkit, rkhunter. Anti-Rootkit, Rootkit Detective, and Rootkit Revealer																								
Memory/BO protection	PaX, Pro Police, EMET																								
Brute force blockers	Fail2Ban, DenyHosts, Cyberarms, Syspeace, RdpGuard																								
Data Loss Prevention	MyDLP, Bluecoat, Websense																								
AppWhite-listing/MAC	AppArmor, SELinux, Grsecurity, SRP, AppLocker, DeviceGuard																								
Cached malicious domains	Dns-blacklists.py, Malware Domain List																								
Encryption																									
Data in Transit	VPNs (Client & Site-to-Site)	Confidentiality over public networks, quick set up, low cost, CONS: no dedicated bandwidth, not recommended for time-critical comms																							
- IPsec (uses IKE)	mutual authentication, provides CIA and replay attack prevention																							
- SSL	fastest growing, compatibility, less problems, CONS: open fw ports (80/443), app vulns, authentication, browser attack surface																							
Data at Rest	Disk Encryption	LUKS, VeraCrypt, LibreCrypt, or   BitLocker, VeraCrypt, CipherShed	Full disk (on-the-fly) or volumes, drives, containers, files																						
- File encryption	Gpg4win, gpg, EncFS, eCryptfs, 7zip, EFS, AxCrypt																							
- Email encryption	Gpg4win, gpg																							
Key Management	PKI	simplifies authorized access, allows secure web, email, disk encryption, code/driver signing, IPSEC & VPN, NAC, wireless, digital sigs, general user authentication	competing/incomplete standards, certification of CAs, extensive planning																						
- SSL/TLS for web traffic	prevents eavesdropping/tampering																							
Steganography	S-Tools for (Win)	hides/retrieves data inside BMPs, GIFs, WAVs																							
- Invisible Secrets (Win)	hides/retrieves data inside JPEG, PNG, BMP, HTML, WAV																							
Wireless																									
VOIP																									
IPv6 over IPv4	6to4  (IPv6 sites talking via IPv4)	Gateway adds/removes IPv4 header (Proto type 41)	10.10.10.10 --> 2002:0a0a:0a0a::																						
- Teredo  (IPv6 hosts using UDP)	"IPv6 hosts talk via IPv4 P2P UDP
run automatically, wrapped in UDP, uses bubbles (keep-alives)"	"Use to be 3FFE:831F::/32
RFC 4380 Changed to 2001::/32"	"Host sends IPv4 UDP to a teredo relay
Relay forwards/receives traffic to IPv6 host
Relay returns traffic to host via IPv4 UDP"																					
- GRE (IPv6 over IPv4)	Tunnel software adds/removes IPv4 headers																							
Client Controls																									
Hosts file	hostsfile.mine.nu/downloads/updatehosts.sh.txt	winhelp2002.mvps.org/hosts.htm																							
Adblocking software	Adblock Plus	Adblock Plus																							
JS/Flash execution	NoScript, Ghostery, BetterPrivacy	NoScript, Ghostery, BetterPrivacy																							
Private data security	SafeHistory, ClickClean, SafeCache	SafeHistory, ClickClean, SafeCache																							
Phishing defense	Web of Trust																								
Anonymous surfing	Tor, privoxy, hidemyass	Tor, privoxy, hidemyass																							
Encryption	HTTPSEverywhere, HTTP Finder, OpenVPN	HTTPSEverywhere, HTTP Finder, OpenVPN																							
Config Mgmt, Backup/Recovery																									
stand up server	kickstart, SCCM																								
Software/version inventory	RCS, CVS, SVN, bro, SCCM, wmic, Kansa																								
Configuration assessment	CIS CAT, Lynis, SCA																								
Backups/Restore	dd, bacula, System Restore																								
config mgmt	chef, puppet, salt, ansible, cfengine, SCCM																								
Package deployment	SCCM, munki, casper, apt, yum																								
server monitoring 	nagios, cacti, munin, zabbix, spiceworks																								