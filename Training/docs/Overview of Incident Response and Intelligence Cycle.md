# Overview of Incident Response and Intelligence Cycles

With the traditional [Incident Response Cycle](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final), the focus is on decreasing response time, reducing the impact of the security incident, and ensuring systems are safely returned to the production environment.  The weaknesses that were exploited are mitigated and capabilities are improved, however not much focus is given to building a complete picture of adversary operations:  

|Step|Description|
|-|-|
|Preparation |Understand organization's risk profile and security posture, position to resist intrusions or counter weaknesses being exploited by ongoing intruder activity|
|Identification|Maintain SA of indications, warnings, intelligence, fuse or correlate information, Evaluate environment for presence of attacker activity or compromise, Detect incidents and analyze incident-related data to respond quickly and effectively, Scope, investigate|
|Containment|FIRST AID – Prevent attacker from getting deeper, spreading to other systems, resolve incidents while minimizing loss and destruction|
|Eradication|Determine cause, symptoms, and vector of attack and Mitigate the weaknesses that were exploited|
|Recovery|Validate system, safely return to production, and monitor|
|Lessons Learned|Document what happened, improve capabilities|

<br>

The [Intelligence Cycle](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/books-and-monographs/analytic-culture-in-the-u-s-intelligence-community/chapter_4_systems_model.htm) is used to identify relationships between different pieces of information and draw correlations for improved decision-making.  By using this process, we improve our understanding of adversary operations and can use it to prepare for the most likely attack scenarios and predict how and when they are most likely to occur.  This entails collecting raw data and using it to create actionable intelligence: 

|Step|Description|
|-|-|
|Planning and Direction|Establishing requirements, what to do and how to do it|
|Collection|Gathering raw data from an operational environment|
|Processing|Collected data is converted to information analysts can use|
|Analysis and Production|Analysis of processed intelligence shows implications and patterns|
|Dissemination|The report is delivered to and consumed by decision makers|

<br>

Combining these two cycles together is known as Intelligence-Driven Incident Response and a great description of implementing it with the F3EAD process can be found [here](https://medium.com/@sroberts/intelligence-concepts-f3ead-964a0653be13).  The article describes how the Operations and Intelligence functions are used together to anticipate and predict adversary operations.  

In the F3EAD process, **Operations** directs the **Intelligence** effort which in turn provides **Operations** with information necessary for improving network defenses for future attacks.  The goal for defenders is to use this process to plan and execute operations against the adversary faster than the adversary can react:

|Function|Phase|Description|
|-|-|-|
|Find         |[Monitoring and Hunting](#monitoring-and-hunting)			|Detect using alerts, analytics, endpoint interrogation  			 			|
|Fix          |[Triage](#triage)                                        	|Make decisions on prioritization, remediation, countermeasures      			|
|Finish       |[Incident Response](#incident-response)                  	|Scope incidents, contain and eradicate threats  	     			 			|
|Exploit      |[Threat Research](#threat-research)                      	|Obtain data from artifacts and adversary tradecraft for intelligence purposes  |
|Analyze      |[Operationalize Intelligence](#operationalize-intelligence)  |Produce actionable intelligence for decision advantage 			 			|
|Disseminate  |[Disseminate Intelligence](#disseminate-intelligence)       	|Feed intelligence to partners, analysts, tools, processes 			 			|

<br>

Let's look at each function, its purpose, and some of the tasks involved.

### Monitoring and Hunting

Evaluate the environment for the presence of attacker activity or compromise.  Monitor and search for unusual configurations, baseline variations, behavioral TTPs, and indicators with the goal of discovering malicious activity.

**Key Requirements:**

- Understand organization's risk profile and security posture
- Access to the current state of all systems and historical data (event logs, network data)
- Use of analysis processes that defeat anti-forensics (centralized logging, memory analysis)
- Centralize and aggregate alert data and all logs (network/system/application) to be searchable
- Monitor for IOCs, hunt for tactics, methods, and types of infrastructure used by adversary

**Examples:**

- Netflow analysis – Look at POP/chokepoints (web proxy, dns cache, connection logs) for what, where, when, how often, how much data, Identify RATs, C&C, Encrypted communications, Covert channels, HIDS/NIDS alerts
- DNS – short TTLs, queries for blacklisted domains
- Web Proxy – Long URLs, weird user agent strings, blacklisted domains
- Connection Data – Beaconing, Scanning, Long durations, blacklisted IP addresses, Concurrent logins to high numbers of systems
- Network connections – ports, protocols, socket creation times
- Processes - What they are tied to, what they are doing, times started, locations, DLLs, parent processes, command arguments, SIDs running under, odd services/exe's
- Files – strings, behavior, origin, reputation
- Relationships – with hostile systems, other internal systems

**Related Tasks:**

|Task|Description|
|-|-|
|[Hunting with Volatility](Hunting%20on%20the%20Endpoint%20with%20Volatility.md)|Unpacked/unencrypted form, Injected code not on disk, Hidden/exited processes, Closed connections/sockets, Cached/deleted files|
|[Hunting with TShark](Hunting%20on%20the%20Network%20with%20Tshark.md)|Looking for payload deliveries, C2, lateral movement, exfil, etc.|
|[Hunting with Splunk](Filtering%20Expected%20Web%20Traffic%20in%20Splunk.md)|Eliminating Whitelisted Sites/Tools, Cert checks, Ads/Analytics, Safebrowsing, Connectivity checks, Google/MS services from results|
|[Hunting in AWS](Review%20of%20Amazon%20Web%20Services.md)|Compute (EC2, Beanstalk, Lambda), Networking/Storage (VPC, Route 53, S3), Access Control (IAM), Logging (CloudTrail, S3 Access)|
|[Verifying Digital Signatures](Verifying%20Digital%20Signatures%20of%20PE%20Files.md)|Embedded (inside the PE), Catalog (hash of the PE is listed in catalog file)|
|[Examining Code Signing Certificates](Code%20Signing%20Certificates.md)|Hash and digital signature confirms file wasn't altered and identity of the software publisher|
|[Identifying C2 Channels](Identifying%20C2%20on%20Network.md)|Interactive shell access, long-haul access, asynchronous over DNS/HTTP/HTTPS|
|[Profiling Rogue Systems](Gathering%20Information%20on%20Rogue%20System.md)|Using Splunk, Wireshark, and Nmap to gather information on an unknown system|
|[Identifying Web Application Attacks](Identifying%20Web%20Application%20Attacks.md)|Path Traversal, LFI, RFI, OS Command Injection, SQL Injection, Cross-Site Scripting|
|[Using a Threat-based Approach For Detection](Using%20a%20Threat-based%20Approach%20For%20Detection.md)|Learning about adversary tradecraft and developing matching detections and responses|
|[Authentication Using Smart Cards and Public Key Kerberos](Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos.md)|Review of authentication process and the roles of PKI, Smart Cards, Kerberos, and Active Directory|



<br>

### Triage

Responding to suspicious events, determining if a security incident took place, and deciding the required response actions and priority for each system involved based on the severity of compromise.  

**Key Requirements:**

- Know where to look to collect data and determine what happened
- Identify attacking hosts, malicious processes and C2, data exfiltration
- Perform memory analysis, log analysis, file analysis, infrastructure analysis
- Analyze incident-related data and respond quickly and effectively

**Examples:**

- Form theories that would explain the indications that caused the detection
- Gather historical and contextual evidence and artifacts that support or disprove theories
- Use artifacts to establish facts, answer key questions, and provide analysis
- Prioritize systems by functional impact, informational impact, and recoverability
- Provide accurate, actionable information to management so they can make time-sensitive decisions to defend systems

**Related Tasks:**

|Task|Description|
|-|-|
|[Moving From Detection To Containment](Moving%20From%20Detection%20To%20Containment.md)|Get a clear picture of the incident, the systems involved, and a plan to stop the progress of the attack|
|[Privileged Account Usage](Windows%20Authentication%20and%20Lateral%20Movement.md)|No Interactive Logons, Disable Delegation, Enforce Kerberos Network Authentication|
|[Endpoint Interrogation with PowerShell 1](Endpoint%20Interrogation%20PowerShell%201.md)|Gathering info that can help answer key questions during an initial assessment|
|[Endpoint Interrogation with PowerShell 2](Endpoint%20Interrogation%20PowerShell%202.md)|Gathering info that can help answer key questions during an initial assessment|
|[Analyzing Malicious Office Documents](Analyzing%20Excel%20Doc%20Macros.md)|Examining VBA macros, Embedded OLE objects, Exploits with embedded shellcode|
|[Analyzing Malicious PowerShell](Analyzing%20Malicious%20PowerShell%20Commands.md)|Offensive uses of PowerShell such as encoding, obfuscation, in memory execution, payload delivery|
|[Analyzing Malicious VBScript](Analyzing%20Malicious%20VBScript.md)|Examining files containing malicious VBScript such as HTA and VBE|
|[Analyzing Malicious Scripts](Review%20of%20Windows%20Scripting%20Technologies.md)|Batch Files (CLI), VBScript/JScript (COM, .NET, WinAPI), VBA (COM, .NET, WinAPI), PowerShell (CLI, COM, .NET, WinAPI)|
|[Analyzing Malicious Websites](Analyzing%20Malicious%20Websites%20with%20Thug.md)|Examining Phishing, Malware via Social Engineering, Malware via Exploit|
|[Analyzing Malicious PDFs](Analyzing%20PDFs%20with%20REMnux.md)|JavaScript, embedded documents, ActionScript via Flash/HTML, Multimedia, launching commands, connecting to URI |
|[Examining Firewall Logs](Windows%20Firewall%20Rules%20Profiles%20Logging.md)|Retrieve logs from hosts as objects for easy sorting and filtering|

<br>

### Incident Response

Scoping, investigating, containing, and resolving security incidents while minimizing loss and destruction.

**Key Requirements:**

- Fill in knowledge gaps and focus approach
- Determine scope, cause, symptoms, and vector of attack
- Determine mitigations and remediations to deny, disrupt, degrade adversary actions
- Implement containment and eradication strategy
- Improve defenses to eliminate repeat occurrences
- Validate system, safely return to production, and monitor
- Monitor for repeat events	and symptoms

**Examples:**

- Use [Diamond Model](http://www.activeresponse.org/the-diamond-model/) to discover artifacts and events related to the incident
- Identify accounts, files, sensitive information accessed
- Identify networks, systems, and applications affected
- Identify tools or attack methods being used, what vulnerabilities are being exploited
- Identify incident category, severity, and sensitivity  
- Inspect network and host data to determine what was stolen, assess damage
- Disable certain functions, accounts, infrastructure 
- Isolate victim systems using ACL, firewall rules, or containment VLAN
- Close network vectors of C2/exfil using DNS blackholes, null route IPs, proxy blocks 
- Wipe and re-image systems

**Related Tasks:**

|Task|Description|
|-|-|
|[Interpreting Bits, Bytes, and Encoding](Bits%20Bytes%20and%20Encoding.md)|Interpreting bytes correctly when analyzing packet captures, malicious programs, shellcode, etc.|
|[Traffic Analysis with Wireshark](Traffic%20Analysis%20with%20Wireshark.md)|Using Wireshark to interpret traffic|
|[Automating with PowerShell](Using%20PowerShell%20for%20Efficiency.md)|Files, Logs, GPO, DNS Prefetching, Related Webpages, Releated Domains, Passive DNS data|
|[Using PowerShell Script Modules](Working%20with%20PowerShell%20Script%20Modules.md)|Load multiple functions into memory, easily shared, automatically import using PowerShell profile|
|[Pivoting and Link Analysis](Pivoting%20and%20Link%20Analysis.md)|Using knowledge obtained to discover related information, analyze relationships between these pieces of information|
|[Leveraging AWS API](Web%20Authentication%20and%20Session%20Management.md)|Interact with AWS resources using scripting and automation|
|[Common Functions and Data Sources in Splunk](Common%20Functions%20and%20Data%20Sources%20in%20Splunk.md)| Using core functions in Splunk to identify important information during an incident|

<br>


### Threat Research      

Collect and evaluate data from past incidents, known adversary malware and TTPs, offensive tools and exploits, and technical reports that can be used to prevent and detect adversary operations. 

This can be divided into three areas:

- [Intrusion Analysis](#intrusion-analysis) - Examine files, logs, network data and extract information to be used for intelligence purposes
- [Malware Analysis](#malware-analysis) - Reverse binaries/scripts, malicious infrastructure, memory analysis to determine malware capabilities
- [Threat Emulation](#threat-emulation) - Research adversary tradecraft, replicate TTPs against tools/environment, identify any gaps

### Intrusion Analysis

Examining files, traffic, and events to provide technical analysis and obtain knowledge about actors and the threat landscape.

**Key Requirements:**

- Identify artifacts related to initial vector of infection, credential theft, exfil, etc.
- Examine all artifacts and extract indicators
- Pivot on indicators to discover related evidence
- Identify context of all indicators
- Use analysis to characterize the incident and adversary

**Examples:**

- Use the [Kill Chain](http://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf) model to categorize indicators and provide context with their associated phase
- Use [Kill Chain](http://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf) model to identify patterns in each phase
- Use the [Diamond Model](http://www.activeresponse.org/the-diamond-model/) to discover related events, artifacts, incidents, victims, etc.

**Related Tasks:**

|Task|Description|
|-|-|
|[Intrusion Analysis using Kill Chain](Intrusion%20Analysis%20Using%20Kill%20Chain%20Solution.md)|Analysis of a simulated intrusion using the Kill Chain model|
|[Walkthrough](Walkthrough.md)|Analysis of artifacts and techniques used during exercise|
|[Understanding Adversary Tactics and Techniques](Overview%20of%20Common%20Adversary%20Tactics%20and%20Techniques.md)|Get limited user access, get admin/root access, pivot, get domain admin|
|[Postmortem Forensics with SIFT Workstation](Postmortem%20Forensics%20with%20SIFT%20Workstation.md)|Using SIFT to examine and extract data from a powered down laptop|

<br>

### Malware Analysis

Profiling the static and behavorial characteristics of malware and malicious infrastructure to assess and predict its capabilities.

**Key Requirements:**

- Determine the intended use of the malware/infrastructure and fully map capabilities
- Extract as much information as possible for the purpose of intelligence
- Use sample to determine tools and techniques used by the adversary

**Examples:**

- Perform automated analysis to get a quick look at APIs called, dropped files, connections, SSL certs, mutexes
- Perform static analysis using AV/Hash checks, strings, metadata, imports
- Perform dynamic analysis using tools to inspect File/Registry/Process/Network activity
- Perform static code analysis to discover how the program operates without running its code
- Perform dynamic code analysis to interact with malware, modify its execution, fully map its capabilities, and extract indicators & TTPs
- Perform memory analysis to examine how samples interact with system memory
- Develop tools to interact with the malware, automate parts of analysis, simulate it

**Related Tasks:**

|Task|Description|
|-|-|
|[Analysis Steps](Analysis%20of%20a%20Phishing%20Email.md)|Automated, Static, Dynamic, Static Code, Dynamic Code|
|[Gathering Indicators and TTPs](Gathering%20Indicators%20and%20TTPs.md)|Using threat data feeds/reports, extracting from malware/artifacts, pivoting on known indicators|
|[JavaScript Analysis with NodeJs/DevTools](JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools.md)|Tools and analysis techniques for JavaScript files that utilize obfuscation|
|[Deploying/Using Cuckoo](Deploying%20and%20Using%20Cuckoo%20Sandbox.md)|Stand up sandbox for file/URL analysis|
|[PE Static Analysis](Static%20Analysis%20of%20a%20Windows%20PE.md)|Hex Editors, Binary Format Tools (Characteristics, Reputation, Behavior), Dissassemblers|
|[Create Analysis/Sandbox VMs](Creating%20Analysis%20and%20Sandbox%20VMs.md)|Creating VM, tuning, customizing, and packaging for reuse|
|[Memory Analysis with Volatility](Memory%20Analysis%20with%20Volatility.md)|Walkthrough analysis of two infected systems using only a memory image|
|[Searching, Chopping, Joining, Replacing](Analysis%20of%20a%20Phishing%20Email.md)|Increasing efficiency and reducing the time required to perform complex tasks|
|[Debugging Windows Executables](Debugging%20a%20Windows%20Program.md)|Control program execution and allows us to analyze malware while it’s running on a system|
|[Dynamic Analysis](Dynamic%20Analysis%20Walkthrough.md)|Determine how malware interacts with its environment|
|[REMnux Tools](REMnux%20Refresher.md)|Useful tools that help us perform static, dynamic, and code analysis|
|[Extracting Shellcode from PDFs](Extracting%20Shellcode%20from%20PDF.md)|PDFs that use heavily obfuscated JavaScript to deliver shellcode|
|[Windows Processes in Memory](Windows%20Processes%20and%20Memory%20Analysis.md)|Using Volatility to examine processes running on an infected Windows host|
|[Building Analysis VMs](Building%20Analysis%20VMs.md)|Using Vagrant, Packer, Malboxes to create analysis VMs|
|[Memory Analysis Steps](Hunting%20on%20the%20Endpoint%20with%20Volatility.md)|Processes, DLLs/Handles/Threads, Network Activity, Code Injection, Rootkit Behavior, Dump Processes/Modules|
|[Analysis of Fareit Malware](Analysis%20of%20Fareit%20Malware.md)|Examining the different capabilities of Fareit/Pony sample|

<br>

### Threat Emulation

Researching and replicating malware and adversary tradecraft to test tools/analysts and identify gaps in mitigation and detection.

**Key Requirements:**

- Research and practice adversary tradecraft
- Replicate adversary TTPs to test enterprise security posture
- Simulate past incidents to test and evaluate new tools, signatures, hunting techniques

**Examples:**

- Simulate application whitelisting bypasses and check endpoint detection capabilities
- Simulate exploit on a system to produce logs and conditions that would allow detection
- Generate benign C2 traffic using different techniques to test tools and analysts
- Perform lateral movement using authenticated RCE techniques to examine logs and create search content

**Related Tasks:**

|Task|Description|
|-|-|
|[WMI Event Subscriptions](Persistence%20Using%20WMI%20Event%20Subscriptions.md)|Event Filters, Event Consumers, Filter-Consumer Bindings used for persistence|
|[Application Whitelisting Bypasses](Application%20Whitelisting%20Bypasses.md)|Path Rules, Publisher Rules, Leveraging Trusted Programs|
|[Windows Privilege Escalation Techniques](Privilege%20Escalation%20in%20Windows.md)|Unquoted Service Paths, DLL Order Hijacking, Auto-Elevation|
|[MacOs Privilege Escalation Techniques](Privilege%20Escalation%20in%20macOS.md)|Sudo Commands, SUID/SGID Permissions, Wildcards|
|[Lateral Movement by RCE](Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE.md)|WMI, SCM, WinRm, Remote Registry, Remote File Access, Task Scheduler, RDP, MMC20.Application DCOM|
|[Windows API Access](Phishing%20To%20Injection%20Techniques.md#windows-api-access)|Built-In Programs, Compiled Programs, COM Objects, Dynamic DotNet Assemblies, P/Invoke, PSReflect|
|[JavaScript Evasion](JavaScript%20Evasion%20Techniques.md)|Encoding, Obfuscation (Control Flow, Identifiers, Dead Code, Object Notations, Locking, Encryption, Different Contexts)|
|[Malicious JavaScript](JavaScript%20and%20Browser-Based%20Malware.md)|Session Hijacking, CSRF, Profiling/Probing, Redirecting Browser, Cryptomining, Man in the Browser|
|[Memory Injection Techniques](Phishing%20To%20Injection%20Techniques.md#memory-injection-techniques)|Shellcode Injection, RDI, Memory Module, Process Hollowing, Module Overwriting|
|[Memory-Based Attack Techniques](Memory-based%20Attack%20Techniques.md#memory-based-attack-techniques)|Process Hiding with DKOM, PEB Unlinking, Code/DLL Injection, RDI, Process Hollowing|
|[Memory-Only Payloads](Phishing%20To%20Injection%20Techniques.md)|VBA Code Injects into Created Process, COM Object Injects into PowerShell Process, COM Object to DotNet Injects into Created Process|
|[Malicious PowerShell](Analyzing%20Malicious%20PowerShell%20Commands.md#analysis)|Container (xls/doc/hta), Script (JS/VBS/Batch), Command (IEX), Payload (Implant/Downloader)|
|[Advanced C2 Techniques](Advanced%20C2%20Techniques.md)|Asynchronous, Indirect, Irregular intervals, encrypted, tunneled, allowed protocols, signed certificates, reputable domains|
|[Drive-by Downloads](Drive-By%20Downloads.md)|Delivering exploit kits via malvertising or compromised sites|
|[Simulating Malware/TTPs](Introduction%20to%20Kali%20Linux.md)|Using Kali Linux to simulate adversary TTPs and support investigations|
|[Trojaned Executables](Identifying%20Trojan%20Executables.md)|Determine if the file is legitimate or malicious|
|[Domain Fronting](Analyzing%20Domain%20Fronting%20Malware.md)|Use of high-reputation domains to forward and hide the true destinations of traffic|
|[Persistence Techniques](Identifying%20Persistence%20Techniques.md)|Autoruns, Tasks, Accessibility features, new/modified services, shortcuts, default file associations|
|[Using Docker on Windows](Using%20Docker%20on%20Windows.md)|Explore different ways Docker can be used to bypass security controls or evade monitoring|
|[Evasion Techniques on the Network](Evasion%20Techniques%20on%20the%20Network.md)|Understand how a user can evade network monitoring|
|[Evasion Techniques on Disk](Evasion%20Techniques%20on%20Disk.md)|Understand how a user can evade endoint monitoring and forensics|



<br>

### Operationalize Intelligence

Organize data and develop into intelligence that can be leveraged for decision advantages.  Build detections, mitigations, and remediations to prepare for similar attacks and predict how, why, and when they are most likely to occur.

**Key Requirements:**

- Organize observed malware and adversary intent, objectives, and TTPs
- Develop mitigations for weaknesses that were exploited
- Develop detections for attacks, malware, and exploits used
- Develop remediations to prevent repeat incidents

**Examples:**

- Building alerts based on firewall/proxy traffic
- Creating signatures for IDS, EDR, YARA rules
- Developing hunting strategy for post-exploitation activity
- Creating technical reports for threat assessments and trending
- Build improved configuration baseline/GPO to counter silmilar attacks/malware 

**Related Tasks:**

|Task|Description|
|-|-|
|[Develop TTP-based Responses](Developing%20TTP-based%20Responses.md)|Gathering Information, Identifying TTPs, Find Common Techniques, Determine Best Responses|
|[Malware Evasion Techniques](Obfuscation%20Encryption%20Anti-Analysis%20Techniques.md)|Packers compress, Crypters obfuscate/encrypt, Protectors uses anti-analysis techniques to prevent reversing/analysis|
|[Detecting Unmanaged PowerShell](Detecting%20Unmanaged%20Powershell.md)|Detecting .NET assemblies (EXE/DLL) used as custom PowerShell runspace to execute PowerShell in any process|
|[Detecting Lateral Movement](Detecting%20Lateral%20Movement%20with%20Splunk.md)|Detecting lateral movement via file copies, WMI, WinRM, PsExec|
|[Detecting Tor Use](Identifying%20Tor%20Use%20on%20the%20Network.md)|Address Blocking uses Tor infrastructure, Content Blocking uses signatures unique to Tor|

<br>

### Disseminate Intelligence

Disseminating knowledge of adversary capabilities, infrastructure, motives, goals, and resources in useful formats to provide a more focused approach for defense.

**Key Requirements:**

- Provide actionable intelligence that will support improved defense
- Ensure content is relevant and meets the needs of consumer
- Tailor the format to the consumer
- Distribute efficiently and share in accordance with SOPs
- Gather consumer feedback to make improvements

**Examples:**

- Creation of new/improved hunting and monitoring techniques and content
- Provide tools with new/improved detection capabilities
- Provide analysts with actionable information
- Provide analysis reports on incidents/campaigns, trending, and attack forecasting
- Provide technical reports and analysis walk-throughs on malware samples

**Related Tasks:**

|Task|Description|
|-|-|
|[Using Indicators for Detection](Using%20Indicators%20For%20Detection.md)|Operationalize data using Splunk, FireEye HX, Rekall, and Yara|
|[Using Yara Rules](Improved%20Detections%20YARA%20rules.md)|Search files, pcaps, and memory space for specific adversary techniques|
|[Indicator Lifecycle](Indicator%20Context%20and%20Pivoting.md)|Obtain from IR/Intrusion Analysis, Use for Detection, Response/Analysis, and Planning|
|[Intel Storage and Sharing](Indicator%20Storage%20Sharing%20Visualization.md)|Indicators and detections can be stored, reviewed, fed to tools, or shared with third parties|
|[Windows Mitigations and Defenses](Windows%20Mitigations%20and%20Defenses.md)|Common tactics and techniques for hardening Windows systems|
|[AWS IAM Best Practices](AWS%20IAM%20Best%20Practices.md)|Review of Identity and Access Management (IAM) best practices in AWS environments|

<br>

## Summary

Knowledge of adversary actions improves detection, response, and planning.  Better detection, response, and planning improves our overall security posture.  Intelligence-driven incident response is applying the traditional intelligence cycle---using information collection and analysis to provide guidance for decisions---to enterprise security.  Monitoring the network and investigating incidents give us many opportunities to obtain intelligence, which in turn provides us with information necessary to accomplish our mission.  The more we learn about how the adversary operates, the better we will be able to detect and counter them.