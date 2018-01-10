# Overview of Common Adversary Tactics and Techniques
 
 
 
As defenders, we need to understand the goals of adversaries and the tactics and techniques they use to reach their objectives.  There are many resources that deal with this such as the Mitre ATT&CK Matrix, the Kill Chain Model, and others… We often dive deep into one technique and examine how it works but at times it’s good to get an overview of what the tactics and techniques are being used to accomplish.  Let’s review the most basic steps that are taken when an enterprise network is compromised.
 
Adversaries can range from financially motivated criminals to state-sponsored groups focused on data collection to hacktivists and insiders with various end goals.  Each adversary will most likely have their own objectives and different ways to reach them, but here is a very high level view of the steps most adversaries will use to accomplish their overall mission:
 
|Step|Description|Goal|
|-|-|-|
|1. Get limited user access|(Foothold, short term persistence)|Control a low privilege account that can make limited changes to one system|
|2. Get admin/root access|(Privilege Escalation)|Control a privileged account that can make many changes to one system|
|3. Get control of additional hosts|(Pivoting)|Control additional systems and the information they contain|
|4. Get domain admin|(Dominance, long term persistence)|Control a privileged account that can make many changes to many systems|
 
 
Also keep in mind that Command and Control is required for each of these stages to control the compromised accounts from outside of/within the network.
 
 
## 1. Get Limited User Access
 
The first step is to get an initial foothold on a system and have control of a low privilege account.
 
### Outside the network

| | | |
|-|-|-|
|Server exploit|External service compromised by external entity|E-Verify, WPaaS, AWS, etc.|
|Client-side exploit|Client application is exploited by external entity|Browser, Java, PDF reader, Flash, or MS Office|
|User-driven attack|User is tricked into running malicious code|Java applet, Office macro, zip file, executable, HTA, script, etc.|               
 
### Inside the Network

| | | |
|-|-|-|
|Server exploit|Internal service is compromised by rogue host|ICAM, Swimlane, Nessus|
|Client-side exploit|Client application is exploited by rogue host|ARP poisoning, DNS cache poisoning, WPAD,|
|User-driven attack|User is tricked into running malicious code|Program, script, UNC path|
 
### On Premises

| | | |
|-|-|-|
|Physical items|Device is used to execute malicious code|USB devices, CDs, external drives|
|Physical access|Adversary/Insider executes malicious code|Unlocked computers, unsecured devices|
 
 
 
## 2. Get admin/root Access
 
After obtaining control of a low privilege account, privilege escalation techniques are used to gain control of an admin/root account.
 
### Windows

| | |
|-|-|
|File system|Path interception, DLL Hijack, modify service, new service|
|Registry|AlwaysInstallElevated, autologons, autoruns|
|Configurations|Modify task, new task|
|Discover credentials|User files, installation/configuration files|
|Password attack|Guess or brute force local admin password|
|Local exploit|OS or application|
 
### MacOS

| | |
|-|-|
|File system|Setuid and Setgid, Dylib hijacking, modify plist, startup items/launch daemons|
|Configurations|Sudo commands, wildcards, modify job, new job|
|Discover credentials|User files, installation/configuration files|
|Password attack|Guess or brute force local admin password|
|Local exploit|OS or application|
 
 
 
## 3. Get Control of Additional Hosts / Lateral Movement
 
Compromised admin accounts can be used to abuse existing trusts in many different ways in order to obtain rights on remote systems.
 
| | | |
|-|-|-|
|Remote session|Use stolen or created credentials to create session|PS Remote, PSExec, RDP, Pass-the-Hash/Pass-the-Ticket, VNC, SSH|
|Remote code execution|Use stolen or created credentials to execute code|Invoke-Command, WMIC, Psexec, at, schtasks, sc|
|Remote file copy|Use stolen or created credentials to copy files|scp, rsync, ftp, cifs, sftp, Logon scripts/hooks, Admin shares, shared drives, DLL preloading, shortcut hijacks|
|Removable media|Execute code via USB, CD, other external media|Rubber Ducky/HID, autorun|
|Third-party software|Use a tool account’s privileges to access a remote host|Nessus, Mcafee, FireEye, SCCM|

 
 
 
## 4. Get Domain Admin
 
Lateral movement and privilege escalation are used to compromise domain admin accounts which frequently have unlimited privileges.

| | | |
|-|-|-|
|Steal token/hash/ticket|Keylog or dump credentials from DA logins (RunAs, RDP)|Mimikatz, Windows Credential Editor|
|Logon DC with other admin account|Dump all domain credentials|Mimikatz, Task Manager, NTDS.dit|
|Forge token/hash/ticket|Create fake/forged credentials|MS14-068|
|Password attack|Offline cracking|Kerberoast|
|Discover credentials|Installation/configuration files|SYSVOL, GPP|
 
 
  
 
## Exercise

Our goal is to become familiar with and able to recognize APT-level tactics and techniques in order to use this knowledge to detect and investigate this type of activity in our environment.
 
Start by picking one APT group from this list and document the techniques they’ve been observed using which we can then use to build targeted detections.  

[MITRE’s full list of techniques](https://attack.mitre.org/wiki/All_Techniques) is a great resource to use.
 

  
Here are two examples:
 
 
## APT 28

- Russian-based threat actor, which has been active since mid 2000s, known to attempt to masquerade as hacktivists or whistleblowers
- Focus is on espionage, intelligence on defense and geopolitical issues
- Also known as Pawn Storm, Sednit, Fancy Bear, Sofacy, STRONTIUM


### Tools:
| | |
|-|-|
|XTUNNEL|VPN-like network proxy tool that relays commands between C2 and internal hosts and encapsulates in TLS|
||can retrieve IE proxy configs to use proxy|
|SOURFACE /CORESHELL|downloader, obtains second stage backdoor from C2 server|
||uses HTTP POST requests which have data encrypted then encoded with Base64|
|EVILTOSS|AKA Sedreco, AZZY, xagent, NETUI|
|second stage backdoor capable of credential theft, recon, shellcode execution|
|||
|CHOPSTICK|AKA Xagent, webhp, SPLM|
|modular implant which communicates with C2 using SMTP or HTTP GET/POST requests|
|GAMEFISH|AKA Sednit, Seduploader, Sofacy|
|backdoor|


### Tactics:
| | |
|-|-|
|Social Engineering|Spearphishing, Doppelganger Domains, Shortened URLs|
||Exploit|Watering Hole Attack, Exploit of Vulnerability|
|Defense Evasion|Data Obfuscation, Timestomp, Indicator Removal on Host|
||Lateral Movement|Pass the Hash, Remote File Copy, Valid Accounts|
||Command and Control|Connection Proxy|


### Techniques:
| | |
|-|-|
|Spearphishing|a link that delivers malicious document or a web-based exploit that installs malware|
||a malicious attachment that installs malware (office macro, rtf w/ flash)|
||a link to fake login page to obtain credentials to read email (owa, gmail)|
||a link to give OAuth privileges to a malicious application to read email|
|Watering Hole Attack|inject malcode or iframe in compromised site which redirects victim to malicious site that profiles user|
|Users that match a specific profile are served an exploit which installs malware|
|Doppelganger Domains|domain names that mimic legitimate news, webmail, government, NGO websites|
||Shortened URLs|used to trick potential victims into visiting malicious/phishing sites|
|Exploitation of Vulnerability|compromise Internet-facing servers or software|
|Data Obfuscation|Runtime checks for analysis tools, use of obfuscated strings and junk code to hinder static analysis|
||Timestomp|resetting timestamps of files|
||Indicator Removal on Host|periodic event log clearing (via wevtutil cl System and wevtutil cl Security commands)|
|Pass the Hash|Authentication to a remote system without having user’s cleartext password|
|Remote File Copy|Files copied using legitimate tools, powershell, wmi, psexec|
|Valid Accounts|Legitimate credentials used to maintain access to victim network|
|Exfil via local network resources such as the victim organization’s mail server|
||Connection Proxy|Xtunnel network tunneling tool used to execute remote commands|
 
### References:
 
https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf
https://www2.fireeye.com/rs/848-DID-242/images/APT28-Center-of-Storm-2017.pdf
https://documents.trendmicro.com/assets/wp/wp-two-years-of-pawn-storm.pdf
https://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part-2.pdf
 
### Samples:
http://contagiodump.blogspot.com/2017/02/russian-apt-apt28-collection-of-samples.html
 
 
 
 
 
 
## APT 29

- Russian-based threat actor with a focus on espionage and intelligence on defense and geopolitical issues
- Also known as COZY BEAR, Cozy Duke, The Dukes


### Tools:

| | |
|-|-|
|SEADUKE|written in Python, a cross platform backdoor which communicates over HTTP(S)|
|HAMMERTOSS|uses Twitter, Github, and cloud storage services for C2 using image files for obfuscation|
|POSHSPY|a backdoor using PowerShell and WMI to store malicious code and execute for persistence|


### Tactics:|Persistence|WMI Event Subscription, Scheduled Task, Registry Run Keys / Start Folder|

| | |
|-|-|
|Command and Control|Encrypted C2, Domain Fronting, Connection Proxy|
|Lateral Movement|Pass the Hash|
|Defense Evasion|Software Packing, Scripting|


### Techniques:

| | |
|-|-|
|WMI Event Subscription|obtain persistence by using WMI events|
|Scheduled Task|obtain persistence by using the task scheduler to execute malware|
|Registry Run Keys/Start Folder  obtain persistence by using the Windows registry or start up folder to execute malware|
|Encrypted C2|used to conceal command and control and data exfiltration|
|Domain Fronting|using high reputation domains to redirect and conceal C2 traffic|
|Connection Proxy|Tor hidden services used to redirect and conceal C2 traffic|
|Pass the Hash|using password hashes and Kerberos tickets for lateral movement|
|Software Packing|packing files assists in anti-analysis by AV and IDS|
|Scripting|native scripting engines are used to bypass monitoring tools|




### References:

https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html
https://www2.fireeye.com/rs/848-DID-242/images/rpt-apt29-hammertoss.pdf

 
 
