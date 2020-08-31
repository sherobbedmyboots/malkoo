## Isolate Admins	
	Have dedicated admin machines
 	Restrict inbound connections to remote admin sources
	Block admin accounts from internet and email
	Mark privileged accounts “sensitive and cannot be delegated”
	Safely log on remotely without placing credentials on target machine
	Deny privilege accounts from authenticating to lower trust systems
	
## Code allow-listing	
	Allow-list batch scripts, vbscript/javascript, java, block VBA macros
 	Lock down powershell
	Bit9/Kapersky/Applocker…. Allow-lists
	
 	
## External	
| | |
|-|-| 	
|External server attack (web/sqli exploit, pw attack)|Web application auditing, web restrictions, DB user privs|
|Client-side exploit (Java, PDF readers, Office, Browsers via Exploit Kits)|VM isolation of vulnerable apps, DEP, ASLR, EMET, SEHOP, Allow-list Java, Allow-list web, secure webapp coding/patching|
|Social Engineering (Java applet, macros, executables via email or website)|Disable macros, Allow-list Java, exe’s, DLL’s, and scripts with AppLocker, SRP, Bit9|
|Physical Item Drop (thumb drives, CDs, lnk files or exe’s, HID-spoofing, RD)|Disable USB mass storage, train users|
|Physical access (Unlocked laptops, hard drive access, hardware backdoors)|Physical security, Full disk encryption|
	
## Internal Network	Internal server-side exploits/PXE attacks à Local Admin
 	Internal web attack, guessed password à Internal Server
 	
## Internal Server	Internal client-side attacks – ARP poison, WPAD à Local User, Domain Admin
	
## Limited User	
| | |
|-|-| 	
|Weak file/service/reg permissions (Upnp, HP PML)|Weak permission vuln scanning, remediation|
|Find plain text passwords (scripts, registry, documents, GPP)|Mandatory smart cards, train users/admins, Disable local admins|
|Local exploit (task scheduler, win32k, ntvdm)|Use latest OS, patch OS, VM isolation|
|Guess or BF local admin password, runas|Disable secondary logon, strong password policies|
|Find system current user is local admin on, find user group in admin group|Deny local admin group network/RDP logon rights, audit admin groups|
|Internal server-side exploit (web, sqli, pw, smb)|Audit internal sites like external, patch, use modern OS, restrict web, DB user perms|
|Relay NTLM (SMB or HTTP)|Disable NTLM, only Kerberos, block HTTP NTLM by policy and on proxy or IPS|
|Shares (DLL preload, sh-cut hijacks, script inf, exe’s w/ doc icons, writable shares)|Stop windows file shares, use web CMS’s to share files, only allow admin-writeable or user-private shares|
	
## Lateral Movement	
| | |
|-|-| 	
|Pass local hashes|Deny local admin net/RDP logons, mandatory smart cards, disable NTLM|
|Spread links via shares, email||
 	
## Local Admin	
| | |
|-|-|  	
|Dump cached active password (wdigest, mimikatz, meterpreter)|Mandatory smart cards, disable NTLM, type3 logons or restricted admin mode RDP/OTP RDP|
|Hijack token, hash, ticket (mimikatz, WCE)|Mandatory smart cards, disable NTLM, type3 logons or restricted admin mode RDP/OTP RDP|
|Find plain test password (saved logon pws, unattended.xml)|Mandatory smart cards, user/admin training—no pw saved or in scripts|
|Keylog or capture password|Mandatory smart cards, disable NTLM, type3 logons or restricted admin mode RDP/OTP RDP|
|Crack domain cached credentials (BF salted hashes)|Mandatory smart cards, disable cached credentials|
|Deobfuscate LSA secrets (pw to service/batch logon accounts)|Do not save credentials, use S4U login, deny RDP/net logon rights to accounts with saved pw|
 	
	
## Malicious Communications	
| | |
|-|-|  	
|Direct TCP/IP|Block direct connections out from internal hosts, force proxy use|
|HTTP/S to dynamic DNS or malicious domains, TOR|Allow-list, categorically block at proxy|
|DNS-based channels|Allow-list DNS domains at DNS server|
|USB drives|Disable USB mass storage, train users|
|Webmail, data-sharing sites|Categorical block of file sharing, pasting, social media|
|Compromised sites (comments used for C2)|No good defenses except air gap|
|Shares Block inter-workstation / ARP-spoofing|
|FTP/HTTP/HTTPS|Allow-list web/ftp|