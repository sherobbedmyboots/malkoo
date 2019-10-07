# Intrusion Analysis Using the Kill Chain Solutions

This example simulated an attacker compromising a server via a
vulnerable web application, escalating privileges, pivoting to another
host, and performing data exfiltration.  Here is a timeline of events
and the answers to the questions:

- [Timeline of Events](#timeline-of-events)
- [Reconnaissance](#reconnaissance)
- [Weaponization](#weaponization)
- [Delivery](#delivery)
- [Exploitation](#exploitation)
- [Installation](#installation)
- [Command and Control](#command-and-control)
- [Actions on Objectives](#actions-on-objectives)


## Timeline of Events:

|TIme|Event|
|-|-|
|19:55:00|Attacker joins the network|
|19:56:03|Arp scans the network|
|19:56:20|Port scans the victim|
|19:56:46|Enumerates HTTP and FTP|
|19:57:30|Browses HTTP|
|19:58:14|Creates a new user account on the application|
|19:59:34|Finds SQL injection vulnerability and extracts user, version, emails, usernames and passwords|
|20:01:26|Uses credentials to log in to FTP server and upload backdoor (`bd`)|
|20:02:20|Uses SQLI to upload a PHP web shell (`ws.php`)|
|20:02:50|Runs `hostname`, `id`, `uname -a`, `whoami` commands using web shell|
|20:03:36|Uses SQLI to execute `bd` on the victim|
|20:04:09|Connects to backdoor with netcat|
|20:04:22|Changes to `tmp` directory|
|20:05:05|Downloads and runs privilege escalation tool|
|20:08:17|Retrieves chosen exploit code and executes it on victim|
|20:09:20|Runs `whoami` to confirm attacker is root|
|20:09:44|Looks through victim machine files and directories|
|20:14:37|Steals \<account\> account's entire profile|
|20:15:53|Pivots to \<host\> using tag's credentials|
|20:18:46|Steals data|


## Reconnaissance 

Attacker performed an arp scan, port scan, and service enumeration

- Did the victim host respond to the arp scan?              

`Yes`

- Which ports on the victim host responded to the port scan?

`80, 21`

- Name two services the attacker enumerated after the port scan.

`FTP and HTTP`

- What vulnerability did the attacker discover?

`SQL Injection`

- What information was the attacker able to obtain from this vulnerability?

`Usernames, password hashes, email addresses, database version`


## Weaponization 

Creation of a malicious payload  (This is done on the attacker's side)

- What payloads did the attacker create?

`PHP web shell`

`Bind shell`

- What were their associated filenames?

`ws.php`

`bd`


## Delivery

Sending the malicious payload

- How did the attacker deliver each payload?

`Web shell was delivered via SQL Injection`

`bd was delivered using bee's FTP credentials`

- Where on the victim host was each payload placed?

`/bWAPP/documents/ws.php`

`/tmp/bd`


## Exploitation

Execution of the exploit
              

- What application(s) were exploited to run the payloads?

`Web server `

- How did the attacker use the results of the exploited application(s)?

`Gained credentials to victim's FTP server, installed the web shell
(ws.php), and used it to run the backdoor (bd)`



## Installation 

Malware is installed on the computer

- Did the attacker install any malware on the victim host?

`The backdoor and the web shell were installed and could be used
again to regain control of the victim host`

- What were the attackers first actions after successfully exploiting the victim?

`Downloaded files from attacking machine and enumerated the victim
machine`



## Command and Control

Remote control of the compromised system

- Name the two different C2 methods that were used by the attacker. 

`Web shell, bind shell`

- What ports and protocols were used for each?

`80, 38877`

- Was each method synchronous or asynchronous?

`Web shell is asynchronous, bind shell is synchronous`



## Action on Objectives

Privilege escalation, persistence, pivoting, data exfiltration, etc.

- What did the attacker use to escalate privileges?

`Linuxprivchecker.py`

- How did the attacker transfer what was needed to the victim system?

`wget`

- What system(s) did the attacker pivot to?

`<host>`

- What file(s) did the attacker steal?

`<pcap-1.pcapng>`
