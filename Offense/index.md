# Offense

- [Flow](./0_flow.md)
- [Enumerate Services](./1_enum-svc.md)
- [Web](./2_web.md)
- [Web Applications](./3_webapp.md)
- [Construct Attacks](./4_construct.md)
- [Password Attacks](./5_pw.md)
- [Transfer Files](./6_transfer-files.md)
- [Linux Privilege Escalation](./7_privesc-linux.md)
- [Windows Privilege Escalation](./7_privesc-win.md)


## Attack Steps																									
|Step|Description|
|-|-|
|Reconnaissance|Names, phone numbers, postal addresses, IP addresses, and DNS servers|
|Remote Enumeration|Fingerprint and gather information from each port, enumerate shares, user IDs, SNMP, banners, OS versions, etc|
|Construct Attack Sequence||
|Remote Exploits & PrivEsc|Perform sequence of exploits against open services for specific vendor, version, password attacks|
|Local Enumeration|Interesting files, cmd history, environment settings, memory, running services, directory permissions, service permissions, scheduled jobs, weak permissions|
|Local Exploits & PrivEsc|Escalate to full root/system level access with UAC bypass, elevation scripts, local exploits, brute forcing|
|Persistence||
|Root Loot|Search the whole system with system/root access for interesting data, Steal hashes from LSA, configuration scripts, SAM/shadow database, cracking MD5 and NTLM, checking currently connected users, checking relationship between this host and other hosts, etc|
|Update Attack Sequence |pdate attacks with new information|
