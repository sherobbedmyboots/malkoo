## Network Security Monitoring

| |Ubuntu|Windows|
|-|-|-|
|Web Content Filtering/Internet White-listing|Squid with DansGuardian|Bluecoat, Websense|
|Application White-listing/MAC|AppArmor, SELinux, Grsecurity|SRP, AppLocker|
|Connection data/threat analytics|Pfsense, RITA|Microsoft Threat Analytics, FireEye TAP, Kansa|
|Cached malicious domains|Dns-blacklists.py, Malware Domain List ||
|Lockdown Firewalls/Admin-net white-list|UFW, iptables|Windows Advanced Firewall|
|Remote system logging|Syslog-NG|Syslog-NG|

## Defense Tools
| |Ubuntu|Windows|
|-|-|-|
Endpoint|ClamAV, Comodo, AVG, Avira, BitDefender|SE/Windows Defender, Malwarebytes, CarbonBlack|
HIDS|OSSEC, Tiger, Samhain|OSSEC|
NIDS|Snort, PSAD|Snort|
Web Application Firewall|ModSecurity, ModEvasive|ModSecurity, WebKnight|
Rootkit Detection|chrootkit, rkhunter|Anti-Rootkit, Rootkit Detective, and Rootkit Revealer|
Memory/BO protection|PaX, Pro Police|EMET|
Brute force blockers|Fail2Ban, DenyHosts|Cyberarms, Syspeace, RdpGuard|
Data Loss Prevention|MyDLP|Bluecoat, Websense|
Boot sector, MBR, BIOS code integrity||BitLocker used with TPM, UEFI Secure Boot (Win 8 & later)|
File Integrity|Integrit, Tripwire, Aide, Samhain|Tripwire, Verisys|

## Encryption
| |Ubuntu|Windows|
|-|-|-|
Disk Encryption|LUKS, VeraCrypt, LibreCrypt|BitLocker, VeraCrypt, CipherShed|
Filesystem-level Encryption|EncFS, eCryptfs, 7zip|EFS, 7zip, AxCrypt|
Encrypted communications|GnuPG|GnuPG|

## Configuration Mgmt Backup and Recovery
| |Ubuntu|Windows|
|-|-|-|
|Stand up server|kickstart|SCCM|
|Software inventory/Version control|RCS, CVS, SVN, bro|SCCM, wmic, Kansa|
|Configuration assessment|CIS CAT, Lynis|SCA, CIS CAT|
|Configuration deployment|puppet, chef, ansible, saltstack, cfengine|SCCM|
|Backups|dd, bacula|wbadmin.exe, bacula|
|Restore|dd|System Restore|

## Browser Security
| |Ubuntu|Windows|
|-|-|-|
|Hosts file|hostsfile.mine.nu/downloads/updatehosts.sh.txt|winhelp2002.mvps.org/hosts.htm|
|Adblocking software|Adblock Plus|Adblock Plus|
|Control execution of all javascript/flash|NoScript, Ghostery, BetterPrivacy|NoScript, Ghostery, BetterPrivacy|
|Private data security|SafeHistory, ClickClean, SafeCache|SafeHistory, ClickClean, SafeCache|
|Phishing defense| | |
|Anonymous surfing|Tor, privoxy, hidemyass|Tor, privoxy, hidemyass|
|Encryption|HTTPSEverywhere, HTTP Finder, OpenVPN|HTTPSEverywhere, HTTP Finder, OpenVPN|

## Technologies	
| | | | |
|-|-|-|-|	
|Endpoint IR|GRR, OSQuery, Tanium, Carbon Black, MIR, EnCase Enterprise, F-Response Enterprise, FireEye HX, osquery/Envdb, MIG, Kansa, Crowdstrike Response||
|Cloud|EC2, GCE, Azure||
|SIEM|Qradar, ArcSight, Spark? , Solar Winds, Trustwave, Tenable, MozDef?||
|Logging|Sysmon with ELK/Splunk, Syslog-NG, Beats, RELP||
|Analysis/Repository|Moloch, Hadoop||
|Case Management|CERT's FIR, CRITs, Jira, ArcSight, RSA Archer||
|Hunting/Threat Analytics|RITA, SOF-ELK, Cisco Talos, FireEye TAP, MTA||
|Web Proxy|Squid with DansGuardian, NGINX, Apache, Bluecoat, Forefront TMG, Barracuda, Websense||
|Enhanced Aggregation|Logstash (ELK), ELSA, Splunk, Cisco OpenSOC||
|Netflow|SiLK, Nfcapd||
|Vulnerability Scanning|Find holes in network, wireless, phone before attackers|CONS: false positives, unverified vulnerabilities|USE:Supplement with pentesting to verify results|
|HIDS|Unencrypted, UA changes, FIC, resource misuse, OSSEC, Tiger, Samhain|CONS: deployment/maint/updates, tunnel vision, needs centralization, cost|USE: monitor changes at application level (web/dns/mail), networking devices ||
|NIDS|insight into network, assists quick response, auditing, Snort, PSAD|CONS: topology, encryption, signature quality/quantity, performance, cost|USE: Well-trained analysts, SIEM, integrate with VA for profiling/prioritization||
|HIPS|HIDS + ability to stop known & unknown attacks|CONS: false positives + same as HIDS|USE: Centrally manage and test software & updates, don't rely solely on||
|NIPS|NIDS + ability to stop known & unknown attacks|CONS: false positives, throughput, less-extensive rule base, false negatives|USE: trained analysts & engineers||
|Firewalls|Filter based on content, perform NAT, Encrypt for VPN|CONS: Application-layer, VPN, dial-up, extranet attacks may get through|USE: Default Deny on packet filter, stateful inspection or Proxy/App Gateway||
|Honeypots|Insight into TTP, reduces false alarms|CONS: improper deployments, use against org, resource burden, legal liability|USE: deploy/monitor secure, low-interaction, in unused address space||
|Integrity Checkers|Integrit, Tripwire, Aide, Samhain, Verisys||
|Boot|Boot sector, MBR, BIOS code integrity|BitLocker used with TPM, UEFI Secure Boot (Win 8 & later)||
|Endpoint|ClamAV, Comodo, AVG, Avira, BitDefender, SE/Windows Defender, Malwarebytes, CarbonBlack||
|Web Application Firewall|ModSecurity, ModEvasive, ModSecurity, WebKnight||
|Rootkit Detection|chrootkit, rkhunter. Anti-Rootkit, Rootkit Detective, and Rootkit Revealer||
|Memory/BO protection|PaX, Pro Police, EMET||
|Brute force blockers|Fail2Ban, DenyHosts, Cyberarms, Syspeace, RdpGuard||
|Data Loss Prevention|MyDLP, Bluecoat, Websense||
|AppWhite-listing/MAC|AppArmor, SELinux, Grsecurity, SRP, AppLocker, DeviceGuard||
|Cached malicious domains|Dns-blacklists.py, Malware Domain List||	

## Encryption			
| | | | |
|-|-|-|-|
|Data in Transit|VPNs (Client & Site-to-Site)|Confidentiality over public networks, quick set up, low cost|CONS: no dedicated bandwidth, not recommended for time-critical comms|
| |IPsec (uses IKE)|mutual authentication, provides CIA and replay attack prevention||
| |SSL|fastest growing, compatibility, less problems|CONS: open fw ports (80/443), app vulns, authentication, browser attack surface|
|Data at Rest|Disk Encryption|LUKS, VeraCrypt, LibreCrypt, or BitLocker, VeraCrypt, CipherShed|Full disk (on-the-fly) or volumes, drives, containers, files|
| |File encryption|Gpg4win, gpg, EncFS, eCryptfs, 7zip, EFS, AxCrypt||
| |Email encryption|Gpg4win, gpg||
|Key Management|PKI|simplifies authorized access, allows secure web, email, disk encryption, code/driver signing, IPSEC & VPN, NAC, wireless, digital sigs, general user authentication|CONS: competing/incomplete standards, certification of CAs, extensive planning|
| |SSL/TLS for web traffic|prevents eavesdropping/tampering||
|Steganography|S-Tools for (Win)|hides/retrieves data inside BMPs, GIFs, WAVs||
| |Invisible Secrets (Win)|hides/retrieves data inside JPEG, PNG, BMP, HTML, WAV||
|Wireless| | | |
|VOIP| | | |
|IPv6 over IPv4|6to4 (IPv6 sites talking via IPv4)|Gateway adds/removes IPv4 header (Proto type 41)|10.10.10.10 --> 2002:0a0a:0a0a::|
| |Teredo (IPv6 hosts using UDP)|IPv6 hosts talk via IPv4 P2P UDP, run automatically, wrapped in UDP, uses bubbles (keep-alives), Host sends IPv4 UDP to a teredo relay,
 Relay forwards/receives traffic to IPv6 host, Relay returns traffic to host via IPv4 UDP|Use to be 3FFE:831F::/32, RFC 4380 Changed to 2001::/32|
| |GRE (IPv6 over IPv4)|Tunnel software adds/removes IPv4 headers||







Commands|
Linux|
Windows|
Technologies|
Endpoint IR|GRR, OSQuery, Tanium, Carbon Black, MIR, EnCase Enterprise, F-Response Enterprise, FireEye HX, osquery/Envdb, MIG, Kansa, Crowdstrike Response|
Cloud|EC2, GCE, Azure|
SIEM|Qradar, ArcSight, Spark? , Solar Winds, Trustwave, Tenable, MozDef?|
Logging|Sysmon with ELK/Splunk, Syslog-NG, Beats, RELP|
Analysis/Repository|Moloch, Hadoop|
Case Management|CERT's FIR, CRITs, Jira, ArcSight, RSA Archer|
Hunting/Threat Analytics|RITA, SOF-ELK, Cisco Talos, FireEye TAP, MTA|
Web Proxy|Squid with DansGuardian, NGINX, Apache, Bluecoat, Forefront TMG, Barracuda, Websense|
Enhanced Aggregation|Logstash (ELK), ELSA, Splunk, Cisco OpenSOC|
Netflow|SiLK, Nfcapd|
Vulnerability Scanning|Find holes in network, wireless, phone before attackers   Supplement with pentesting to verify results  CONS: false positives, unverified vulnerabilities|
HIDS|Unencrypted, UA changes, FIC, resource misuse, OSSEC, Tiger, Samhain  CONS: deployment/maint/updates, tunnel vision, needs centralization, cost  USE: monitor changes at application level (web/dns/mail), networking devices |
NIDS|insight into network, assists quick response, auditing, Snort, PSAD   CONS: topology, encryption, signature quality/quantity, performance, cost   USE: Well-trained analysts, SIEM, integrate with VA for profiling/prioritization|
HIPS|HIDS + ability to stop known & unknown attacks   CONS: false positives + same as HIDS  USE: Centrally manage and test software & updates, don't rely solely on|
NIPS|NIDS + ability to stop known & unknown attacks   CONS: false positives, throughput, less-extensive rule base, false negatives   USE: trained analysts & engineers|
Firewalls|Filter based on content, perform NAT, Encrypt for VPN   CONS: Application-layer, VPN, dial-up, extranet attacks may get through   USE: Default Deny on packet filter, stateful inspection or Proxy/App Gateway|
Honeypots|Insight into TTP, reduces false alarms   CONS: improper deployments, use against org, resource burden, legal liability   USE: deploy/monitor secure, low-interaction, in unused address space|
Integrity Checkers|Integrit, Tripwire, Aide, Samhain, Verisys|
Boot|Boot sector, MBR, BIOS code integrity   BitLocker used with TPM, UEFI Secure Boot (Win 8 & later)|
Endpoint|ClamAV, Comodo, AVG, Avira, BitDefender, SE/Windows Defender, Malwarebytes, CarbonBlack|
Web Application Firewall|ModSecurity, ModEvasive, ModSecurity, WebKnight|
Rootkit Detection|chrootkit, rkhunter. Anti-Rootkit, Rootkit Detective, and Rootkit Revealer|
Memory/BO protection|PaX, Pro Police, EMET|
Brute force blockers|Fail2Ban, DenyHosts, Cyberarms, Syspeace, RdpGuard|
Data Loss Prevention|MyDLP, Bluecoat, Websense|
AppWhite-listing/MAC|AppArmor, SELinux, Grsecurity, SRP, AppLocker, DeviceGuard|
Cached malicious domains|Dns-blacklists.py, Malware Domain List|
Encryption|
Data in Transit|VPNs (Client & Site-to-Site)|Confidentiality over public networks, quick set up, low cost, CONS: no dedicated bandwidth, not recommended for time-critical comms|
- IPsec (uses IKE)|mutual authentication, provides CIA and replay attack prevention|
- SSL|fastest growing, compatibility, less problems, CONS: open fw ports (80/443), app vulns, authentication, browser attack surface|
Data at Rest|Disk Encryption|LUKS, VeraCrypt, LibreCrypt, or   BitLocker, VeraCrypt, CipherShed|Full disk (on-the-fly) or volumes, drives, containers, files|
- File encryption|Gpg4win, gpg, EncFS, eCryptfs, 7zip, EFS, AxCrypt|
- Email encryption|Gpg4win, gpg|
Key Management|PKI|simplifies authorized access, allows secure web, email, disk encryption, code/driver signing, IPSEC & VPN, NAC, wireless, digital sigs, general user authentication|competing/incomplete standards, certification of CAs, extensive planning|
- SSL/TLS for web traffic|prevents eavesdropping/tampering|
Steganography|S-Tools for (Win)|hides/retrieves data inside BMPs, GIFs, WAVs|
- Invisible Secrets (Win)|hides/retrieves data inside JPEG, PNG, BMP, HTML, WAV|
Wireless|
VOIP|
IPv6 over IPv4|6to4  (IPv6 sites talking via IPv4)|Gateway adds/removes IPv4 header (Proto type 41)|10.10.10.10 --> 2002:0a0a:0a0a::|
- Teredo  (IPv6 hosts using UDP)|"IPv6 hosts talk via IPv4 P2P UDP
run automatically, wrapped in UDP, uses bubbles (keep-alives)"|"Use to be 3FFE:831F::/32
RFC 4380 Changed to 2001::/32"|"Host sends IPv4 UDP to a teredo relay
Relay forwards/receives traffic to IPv6 host
Relay returns traffic to host via IPv4 UDP"|
- GRE (IPv6 over IPv4)|Tunnel software adds/removes IPv4 headers|
Client Controls|
Hosts file|hostsfile.mine.nu/downloads/updatehosts.sh.txt|winhelp2002.mvps.org/hosts.htm|
Adblocking software|Adblock Plus|Adblock Plus|
JS/Flash execution|NoScript, Ghostery, BetterPrivacy|NoScript, Ghostery, BetterPrivacy|
Private data security|SafeHistory, ClickClean, SafeCache|SafeHistory, ClickClean, SafeCache|
Phishing defense|Web of Trust|
Anonymous surfing|Tor, privoxy, hidemyass|Tor, privoxy, hidemyass|
Encryption|HTTPSEverywhere, HTTP Finder, OpenVPN|HTTPSEverywhere, HTTP Finder, OpenVPN|
Config Mgmt, Backup/Recovery|
stand up server|kickstart, SCCM|
Software/version inventory|RCS, CVS, SVN, bro, SCCM, wmic, Kansa|
Configuration assessment|CIS CAT, Lynis, SCA|
Backups/Restore|dd, bacula, System Restore|
config mgmt|chef, puppet, salt, ansible, cfengine, SCCM|
Package deployment|SCCM, munki, casper, apt, yum|
server monitoring |nagios, cacti, munin, zabbix, spiceworks|