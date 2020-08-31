# Recommendations

- [Device Inventory](#device-inventory)
- [Software Inventory](#software-inventory)
- [Secure Configurations](#secure-configurations)
- [Vuln Scans and Patching](#vuln-scans-and-patching)
- [Administrative Privileges](#administrative-privileges)
- [Log Monitoring](#log-monitoring)
- [Web and Email Clients](#web-and-email-clients)
- [Malware Defenses](#malware-defenses)
- [Network Ports](#network-ports)
- [Backups](#backups)
- [Network Devices](#network-devices)
- [Perimeter Defense](#perimeter-defense)
- [Data Protection](#data-protection)
- [Access Control](#access-control)
- [Wireless Access Control](#wireless-access-control)
- [Account Monitoring and Control](#account-monitoring-and-control)
- [Training and Evaluation](#training-and-evaluation)
- [Application Security](#application-security)
- [Incident Response](#incident-response)
- [Pentesting and Redteaming](#pentesting-and-redteaming)


## Device Inventory	
- Use an automated asset discovery tool to inventory all organization systems and detect rogue systems connected to the network
- Implement DHCP server logging to track inventory and detect unknown systems
- Ensure inventory is automatically updated when new authorized devices are connected to the network
- Maintain an asset inventory of all systems in the network including system/device details, type, and ownership information
- Implement  802.1x network authentication supported by inventory data to control which devices can be connected to the network
- Implement client certificates to validate and authenticate systems prior to connecting to the private network
## Software Inventory	
- Maintain a list of software and versions authorized for each type of server, workstation, network device in the organization
- Implement application allow-listing to prevent execution of unauthorized software on all systems
- Deploy software inventory system to track OS version and installed applications installed on all assets
- Isolate and run higher risk appliations in a virtual or air-gapped environment
## Secure Configurations	
- Create standardized, hardened images of all OS and application configurations to be used in the organization and update them on a regular basis
- Use secure images to build all new systems and reimage compromised systems in the enterprise
- Protect and monitor secure images using offline machine storage and integrity checking tools
- Use secure protocols and encrypted channels (TLS or IPSEC) for system administration of all enterprise systems and devices
- Protect and monitor critical system files with file integrity checking tools
- Use an automated configuration monitoring tool to detect unauthorized changes to network connections, services, or policy objects
- Use and automated configuration management tool such as Active Directory GPO or Puppet to enforce and redeploy configuration settings to enterpise systems at regularly scheduled intervals
## Vuln Scans and Patching	
- Perform weekly vulnerability scans and report by priority, criticality, and risk
- Integrate scanning results with SIEM for event correlation and improved identification of vulnerable targets on the network
- Implement authenticated scans via local agent or administrative credentials
- Regularly update scanning tools and utilize vulnerability intelligence services to monitor emerging security exposures
- Use automated patch management tools for OS and applications on all systems in the organization
- Monitor logs associated with any scanning activity and associated administrator accounts to ensure that this activity is limited to the timeframes of legitimate scans.  
- Patch by risk rating and work to minimize impact to the organization.  Verify remediation of all vulnerabilities via patching, compensating controls, or risk acceptance
## Administrative Privileges	
- Limit administrative accounts, only use them when they are required, and monitor them for unusual behavior or unauthorized use
- Implement logging for additions, deletions, modifications, and unsuccessful logins of administrator accounts and groups
- For all administrative access, require multi-factor authentication via smart cards,certificates, One Time Password tokens, biometrics, or long, 14 characters or more passwords if MFA not available
- Use sudo and RunAs to implement administrative privileges
- For all administrative tasks or tasks requiring elevated access, use a dedicated machine with no Internet or email access that is isolated from the primary network
## Log Monitoring	
- Configure all systems and devices to synchronize with time sources on a regular basis so that timestamps in logs are consistent
- Validate audit log settings on every system and device to ensure logs included sufficient information and are in standardized format
- Ensure adequate storage space for logs and proper log rotation configurations on all systems.  Archive and digitally sign on a periodic basis
- Have security personnel and/or system administrators run biweekly reports that identify anomalies in logs. They should then actively review the anomalies, documenting their findings.
- Configure network boundary devices, including firewalls, network-based IPS, and inbound and outbound proxies, to verbosely log all traffic (both allowed and blocked) arriving at the device.
- Aggregate and consolidate logs from multiple systems and devices for log correlation and analysis with a SIEM
## Web and Email Clients	
- Allow-list approved web browsers and email clients, keep up to date, implement application / URL allow-listing for pligins and add-on applications
- Control use of languages such as ActiveX and JavaScript
-  from each of the organization's systems, whether onsite or a mobile device, in order to identify potentially malicious activity and assist incident handlers with identifying potentially compromised systems.
- Create two separate browser configurations for each system---one with limited functionality for general web browsing and one for specific websites that require the use of such functionality
- Log all URL requests, maintain and enforce network based URL filters, update categorization services regularly, block uncategorized by default
- Implement the Sender Policy Framework (SPF) to mitigate spoofed emails by deploying SPF records in DNS and enabling receiver-side verification in mail servers
- Use e-mail content filtering and web content filtering, scan and block all e-mail attachments containing malicious code or unnecessary file types at the gateway
## Malware Defenses	
- Deploy automated tools and countermeasures such as anti-virus, anti-spyware, HIPS, personal firewalls, DLP, and allow-listing.
- Centralize the management of tools, ensure adequate event logging, and keep signatures and file reputations updated regularly
- Monitor and limit the use of external devices and configure all systems to automatically scan removable media for malware when inserted, c
- Disable auto-run functionality on all systems for all types of removable media including USB drives, external hard drives, CDs and DVDs, other external devices and mounted network shares.
- Deploy Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), Enhanced Mitigation Experience Toolkit (EMET), and virtualization/containerization.
- Identify executables in network traffic and use techniques other than signature-based detection to identify and filter out malicious content before it arrives at the endpoint.
- Monitor network traffic to detect anomalies and known malicious executables, and monitor DNS logs to detect name resolution queries for known malicious C2 domains.
## Network Ports	
- For each system, close all ports and disable all services that do not have a validated business requirement.
- Firewalls and host-based firewalls should include default-deny rules that drop all traffic that is not destined for explicitly allowed ports and services.
- Port scan all systems with automated tools and compare to an approved, known-good baseline to find unauthorized open ports and services.
- Verify any server that is visible from the Internet or an untrusted network, and if it is not required for business purposes, move it to an internal VLAN and give it a private address.
- Operate critical services on separate physical or logical host machines, such as DNS, file, mail, web, and database servers.
- Use application firewalls for critical servers and block all unauthorized traffic
## Backups	
- Configure automatic backups on all systems of OS, application software, and data for once or more a week.
- Maintain multiple backup versions to allow restoration to a specific timeframe.
- Protect all backups via physical security and encryption when at rest and in transit
- All backup policies should be compliant with any regulatory or official requirements.
- Conduct data restoration drills to ensure that the backup process is functioning correctly
- Maintain backups for key systems on systems/devices not continuously accessible by the system to mitigate ransomware attack risks
## Network Devices	
- Check firewall, router, and switch configurations against baseline configurations reviewed and approved by the organization's change control board.
- Document all device changes in organization's configuration management system with details, duration, and business requirement.
- Automate detection of device configurations and reporting of deviations from standard configuration of network devices.
- Ensure timely security updates and use two-factor authentication and encrypted sessions when managing devices
- Use a dedicated machine, isolated from primary network, for all administrative tasks or tasks requiring elevated access.
- Use dedicated network connections (either physical or separate VLANs) to manage the network devices and infrastructure.
## Perimeter Defense	
- Implement domain and IP addresss blacklisting or allow-listing and test frequently to ensure proper functionality
- Capture full packet header and payloads of the traffic to and from Internet and DMZ and feed to SIEM for log correlation and analysis.
- Deploy network-based IDS sensors on Internet and extranet DMZ systems and networks that look for unusual attack mechanisms and detect compromise of these systems. These network-based IDS sensors may detect attacks through the use of signatures, network behavior analysis, or other mechanisms to analyze traffic.
- Deploy NIPS to provide automation for blocking known bad traffic detected via virtual machine or sandbox-based tools
- Control outgoing Internet traffic with an enterprise-wide application layer proxy capable of decrypting network traffic, and implementing URL, domain name, and IP address blacklisting and whitlisting.
- Require 2FA for all remote login access including Citrix, VPN, and dial-up.
- Publish minimum security standards for third-party devices accessing the enterprise network and perform a security scan before allowing access.
- Periodically scan for back-channel unauthorized connections to the Internet or to other networks that bypass normal traffic routes
- Deploy NetFlow collection and analysis to DMZ network flows to detect anomalous activity.
- Identify TCP sessions that last an unusually long time to detect covert channels exfiltrating data through a firewall.
## Data Protection	
- Perform a sensitive data assessment to identify sensitive information that requires protection by encryption and integrity controls.
- Deploy approved hard drive encryption software to mobile devices and systems that hold sensitive data.
- Deploy network-based DLP solutions on network perimeters to detect and block unauthorized attempts to exfiltrate data across network boundaries.
- Automate periodic scans of systems to detect presence of sensitive data in clear text.
- Control read, write, and execute permissions of all removable media according to business requirements and inventory and track all authorized systems/media devices.
- Monitor all traffic leaving the organization to detect and terminate all unauthorized uses of encryption.
- Block access to known file transfer and e-mail exfiltration websites.
- Deploy host-based DLP to enforce ACLs even when data is copied off a server implementing ACLs.
## Access Control	
- Segment the network by classification level of the information stored on the servers. Create separate VLANS with firewall filtering for systems that contain sensitive information to allow access by only authorized individuals.
- Encrypt all sensitive information entering or traversing networks with lower trust levels.
- Enable Private VLANs for workstation networks to prevent client-to-client connections that can be used by an intruder for lateral movement.
- Use access control lists on all file systems, network shares, applications, and databases to prevent unauthorized access.
- Encrypt sensitive data at rest and require a secondary, non-OS authentication mechanism be used to access the information.
- Enforce detailed audit logging for access to nonpublic data and special authentication for sensitive data.
- Remove archived data sets and systems not regularly accessed by the organization from the organization's network.
## Wireless Access Control	
- Check wireless device configurations against baseline configurations and profiles reviewed and approved by the organization's change control board.
- Regularly scan to detect rogue devices and assess security of authorized wireless access points connected to the wired network.
- Deploy WIDS to identify rogue wireless devices and detect attack attempts and successful compromises.
- Where a specific business need for wireless access has been identified, configure wireless access on client machines to allow access only to authorized wireless networks. For devices that do not have an essential wireless business purpose, disable wireless access in the hardware configuration (basic input/output system or extensible firmware interface).
- Use AES encryption for all wireless traffic with at least Wi-Fi Protected Access 2 (WPA2) protection.
- Utilize protocols such as Extensible Authentication Protocol-Transport Layer Security (EAP/TLS) to provide credential protection and mutual authentication.
- Disable peer-to-peer wireless network capabilities on wireless clients.
- Disable wireless peripheral access of devices (such as Bluetooth), unless such access is required for a documented business requirement.
- Deploy a separate VLAN for BYOD systems or other untrusted devices. Internet access from this VLAN should go through at least the same border as corporate traffic. Enterprise access from this VLAN should be treated as untrusted and filtered and audited accordingly.
## Account Monitoring and Control	
- Review all system accounts and disable any account that cannot be associated with a business process and owner.
- Ensure that all accounts have an expiration date that is monitored and enforced.
- Disable accounts immediately upon termination of an employee or contractor.
- Regularly monitor the use of all accounts, automatically logging off users after a standard period of inactivity.
- Configure screen locks on systems to limit access to unattended workstations.
- Monitor account usage to identify and disable accounts that are not assigned to valid workforce members.
- Use and configure account lockouts such that after a set number of failed login attempts the account is locked for a standard period of time.
- Monitor attempts to access deactivated accounts through audit logging.
- Configure access for all accounts through a centralized point of authentication such as Active Directory or LDAP.
- Require MFA such as smart cards, certificates, OTP tokens, or biometrics, for all user accounts that have access to sensitive data or systems.
- Enforce use of long passwords on systems (longer than 14 characters) where MFA is not supported.
- Encrypt all account usernames and authentication credentials that are transmitted across networks.
- Encrypt or hash all authentication files to prevenet access without root or administrator privileges.  Audit all access to password files in the system.
## Training and Evaluation	
- Perform gap analysis to identify workforce deficiencies and needed skills.  Build a baseline training and awareness roadmap for all employees. 
- Deliver training via more senior staff or outside teachers utilizing training conferences or online training to fill the gaps.
- Implement, require of all employees, and frequently update a security awareness program
- Regularly test employees on common attack scenarios and provide targeted training to those who fall victim to the exercise.
- Measure skills mastery with  hands-on, real-world examples for each of the mission-critical roles to identify skills gaps.
## Application Security	
- Ensure all application software is the most current version and install all relevant patches and vendor security recommendations.
- Deploy WAFs to detect and block cross-site scripting, SQL injection, command injection, and directory traversal attacks.
- Perform error checking on software developed in-house analyzing all input, including for size, data type, and acceptable ranges or formats.
- Regularly test in-house-developed and third-party-procured web applications using automated remote web application scanners.
- Do not display system error messages to end-users (output sanitization).
- Maintain separate environments for production and nonproduction systems.
- Ensure that all software development personnel receive training in writing secure code for their specific development environment.
- Ensure that in-house software development artifacts are not included in production software or accessible in the production environment.
## Incident Response
- Develop IR procedures that define phases of IH process and define roles of personnel handling incidents.
- Assign job titles and duties for handling computer and network incidents to specific individuals.
- Define management personnel who will support the incident handling process by acting in key decision-making roles.
- Develop organization-wide standards for how and when to report anomalous events to the IH team and the kind of information that should be included in the incident notification. Notify CERT IAW all legal or regulatory requirements for involving that organization in computer incidents.
- Assemble and maintain information on third-party contact information to be used to report a security incident.
- Publish to all employees and contractors rules for reporting events and incidents to the IH team. Include in routine employee awareness activities.
- Regularly run incident scenario sessions for IH team members to ensure current threats and risks, and responsibilities are understood.
## Pentesting and Redteaming	
- Regularly conduct internal/external pentests to identify vulnerabilities and attack vectors that can be used to exploit enterprise systems successfully.
- Control and monitor pentest team accounts, systems, and services and remove when no longer needed.
- Perform periodic Red Team exercises to test organizational readiness to identify and stop attacks or to respond quickly and effectively.
- Include tests for the presence of unprotected system information and artifacts that would be useful to attackers, including network diagrams, configuration files, older penetration test reports, e-mails or documents containing passwords or other information critical to system operation.
- Simulate objectives and TTPs used by current attackers to create a realistic assessment of security posture and risk to critical assets.
- Integreate vulnerability scanning with penetration testing tools to guide and focus penetration testing efforts.
- Document and score all Red Team results so that results can be compared over time.
- Use a test bed simulating a production environmentto test attacks against supervisory control and data acquisition and other control systems.