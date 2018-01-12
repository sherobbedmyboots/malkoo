# Incident Response	

- Evaluate environment for presence of attacker activity or compromise																								
- Rapidly detect incidents and analyze incident-related data and respond quickly and effectively																	
- Scope, investigate, contain, and resolve security incidents minimizing loss and destruction																			
- Decrease response time and reduce impact of the security incident																								
- Mitigate weaknesses that were exploited																								
      


- [Preparation](#preparation)
	- [Policy](#policy)
	- [Tools and Staffing](#tools-and-staffing)
	- [Training and Planning](#training-and-planning)
	- [Response Strategies](#response-strategies)
- [Identification](#identification)
	- [Capture Analyze and Interpret Traffic and Events](#capture-analyze-and-interpret-traffic-and-events)
	- [Network Analysis](#network-analysis)
	- [Assess and Determine if Incident](#assess-and-determine-if-incident)
	- [Assign IR Team and Use OOB and Encrypted Comms](#assign-ir-team-and-use-oob-and-encrypted-comms)
	- [Establish Chain of Custody](#establish-chain-of-custody)
	- [Contain and Clear or Watch and Learn](#contain-and-clear-or-watch-and-learn)
- [Containment](#containment)
	- [Memory Acquisition](#memory-acquisition)
	- [Live Data Collection](#live-data-collection)	
	- [Memory Analysis](#memory-analysis)
	- [Characterize Incident](#characterize-incident)
	- [Short-Term Containment](#short-term-containment)
	- [Stop Attack Progress](#stop-attack-progress)
	- [System Backup](#system-backup)
	- [Determine Risk of Continuing Operations](#determine-risk-of-continuing-operations)
	- [Long-Term Containment](#long-term-containment)
- [Eradication](#eradication)
	- [Identify Root Cause and Symptoms](#identify-root-cause-and-symptoms)
	- [Remove Malware or Wipe Reformat Rebuild](#remove-malware-or-wipe-reformat-rebuild)
	- [Improve Defenses](#improve-defenses)
	- [Perform Vulnerability Analysis](#perform-vulnerability-analysis)
	- [Look for Similar Attacks](#look-for-similar-attacks)
	- [Eliminate Repeat Occurrences](#eliminate-repeat-occurrences)
- [Recovery](#recovery)
	- [Validate System](#validate-system)
	- [Return to Production Safely](#return-to-production-safely)
	- [Monitor for Repeat Events](#monitor-for-repeat-events)
- [Lessons Learned](#lessons-learned)
	- [Analysis and Technical Report](#analysis-and-technical-report)
	- [Meeting Within 2 Weeks](#meeting-within-2-weeks)
	- [Create Action Plan](#create-action-plan)
	- [Apply Approved Fixes](#apply-approved-fixes)

	



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


### Tools and Staffing	

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
### Training and Planning	

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

- Netflow analysis – Look at POP/chokepoints (web proxy, dns cache, connection logs) for what, where, when, how often, how much data																								
	- DNS – short TTLs, find cached malicious domains with dns-blacklists.py and Malware Domain List																								
	- Web Proxy – Long URLs, weird user agent strings, blacklisted domains																								

	- Connection Data – Beaconing, Scanning, Long durations, blacklisted IP addresses, Concurrent logins to high numbers of systems																								
- Network connections – ports, protocols, socket creation times

- Processes - What they are tied to, what they are doing, times started, locations, DLLs, parent processes, command arguments, SIDs running under																								
- Files – strings, behavior, origin, reputation		

- Relationships – with hostile systems, other internal systems

### Assess & Determine if an Incident	

- Knowing where to look to determine what happened, identify attacking hosts, malware C2, data exfiltration
																								
- Maintain notes recording all actions with timestamps																								

### Assign IR Team and Use OOB and Encrypted Comms	

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

### Contain and Clear or Watch and Learn	

- Does victim contain sensitive information?	

- Can information taken lead to other intrusions?	

- Any accounts that can be used to log on other systems?

- Are business partners or customers at risk?		


## Containment	

FIRST AID – Prevent attacker from getting deeper, spreading to other systems

### Memory Acquisition	

- Hardware - PCI card, Firewire	

- Software - Programs		

- Other - VM suspend, crashdump, hibernation file, cold boot attack	

### Live Data Collection	

- Memory is a snapshot of current physical memory, can contain malicious code from an infection and evidence of which system resources were allocated by and used in support of the malicious code.   	

- For data exfiltration, memory can contain encryption keys and passwords, plain-text contents of files before they were encrypted, full content network packets.																								
- Full Disk Encryption - extract AES keys to allow decryption, bypass packers, binary obfuscators, rootkits (including kernel mode) and other hiding tools																								
- Rootkit Analysis - identify processes trying to run undetected, network connections , running processes, open files, memory only chats, decrypted malware, windows cmd line history, better understand an event through correlation - memory, disk, network																								
- [If VM, pause/snapshot, clone, host disk, introspection]()  (most will not include network connection data)																								
- [If host not running, try hibernation file, page file(s), crash dumps]()

	- Convert hiberfil.sys with Volatility		

	- Convert hiberfil.sys with MoonSols hibr2bin

	- Convert dump file with MoonSols dmp2bin		

- [If running, and have root, use software-based utility]()

	- Local - dump to USB, ESATA, or Firewire drive - Dump memory to an external drive or to a listener on a remote machine.  If possible, do not save evidence to the local disk because it would overwrite unallocated disk space that could be helpful during disk forensics																								
	- Remote - push tools with Psexec or copy them to C$ or Admin$ via SMB, then schedule a task or install service that runs tools and sends physical memory to netcat listener	

	1. Create a temp admin account with access to only target system	

	2. Disable after acquisition is complete, monitor for use of credentials																								
	3. Compute integrity hashes before and after the transfer																								
		
	4. Send via encrypted means if possible (CryptCat, F-Response, KnTDD)

- Open Source - Winpmem, Linpmem, FTK Imager, RAM capturer, DumpIt, RAM Capture, Memoryze, MDD, dc3dd																								
- Commercial - Dumpit, KnTDD, WinEn, WindowsSCOPE, HBGary FastDump, F-Response, EnCase																								
- LINUX - dc3dd and memdump for 2.4, LMG, LiME, linpmem, fmem for 2.6 and later																								
- [If not root, obtain exploit/brute force password]()	

- [If not possible, use Direct Memory Access (DMA)]()

- Gather Live System State and Artifacts - Firewire (less than 4GB) or PCI	

- Obtain live system state and send to /mnt/usb/live:  

```
for cmd in 'uname -a'  ifconfig; do echo $cmd >> /mnt/usb/live && $command >> /mnt/usb/live 2>&1;done
```			

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
### Characterize Incident	

- Assign Category, Severity, and Sensitivity - Prioritize by functional impact, informational impact, and recoverability																								
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

### System Backup 

- Backup filesystem, memory, and network artifacts	

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

### Identify Root Cause and Symptoms

### Remove Malware or Wipe Reformat Rebuild	

- Risks of not wiping/rebuilding

- OS & patches, apps & patches, then data																								

### Improve defenses	

- Filters, null route IPs, change IP and DNS names, patch and harden system	

### Perform Vulnerability Analysis																									

### Look for Similar Attacks																									

### Eliminate Repeat Occurrences																									


## Recovery	

Validate system, safely return to production, and monitor																								

### Validate System	

- Verify normal operation and all needed patches and controls IAW procedures, Have business units perform end user validation testing																								
- Return to production safely, have system owners decide when to restore systems, Coordinate restore operation time with business unit																								
- Monitor for repeat events	Use IPS/IDS and daily scripts to detect presence of repeat symptoms																								
## Lessons Learned	

Document what happened, improve capabilities																								

### Analysis and Technical Report	

- Initial vector of infection, How privileged credentials were obtained, Which systems were involved, What was searched and why, What was taken and how																								
- Extent of compromise and Remediation Plan	

- Get signature on follow up recommendations

### Meeting Within 2 Weeks	

- Process improvement, IH team and procedures effectiveness, Policy or organizational problems encountered that require management's consideration																								
### Create Action Plan 

- To respond to operational issues that arose from this incident

- Characterize adversary using counter-intelligence strategies such as Kill Chain, Diamond Model

- Recategorize and revalue assets in light of incident		

### Apply Approved Fixes 	

- To IR process, technology, and capabilities	

- Move critical data to more restricted area, implement increased auditing	

- Counsel/train/discipline any individuals who accidentally or purposefully aided the adversary																								
- Additional training required for new skills or using current tools more effectively																								
- Additional staff to aid in response		

- New software or hardware to help prevent future incident	

- Forms and incident management systems				

- Consider adding a forensics capability for better evidence collection or IR/awareness																			