# Analyzing Executables

Here is a walkthrough showing how the Windows VM, the SIFT-REMnux VM,
and Docker containers can be used to investigate malware detected on one
of our systems.  Executing malware in an isolated environment and
observing how it interacts with the file system, registry, processes,
and network helps us:

- Identify malicious behavior to confirm an incident
- Understand the malware's capabilities to determine incident scope
    and impact
- Establish IOCs that can be used to detect other infected systems in
    the enterprise


In this example, an executable named "putty.exe" was downloaded by a
user and flagged as possible malware.  The file properties show it as
the SSH/Telnet client application from the Putty Suite, but the file was
not downloaded from the official Putty website and the file's hash does
not match the file's hash displayed on the Putty website.  To analyze on
the OOB, copy the putty.exe file which is located in the /CSIRT folder
to your Windows OOB VM and investigate with the following tools:

### PEStudio 

This tool looks for suspicious characteristics in executables:

- Open PeStudio and drag putty.exe into the window      

- Indicators tab shows several high-severity indicators such as the
    file modifies the registry, contains 451 blacklisted strings,
    references the Clipboard, and references MIME64 encoding strings

- VirusTotal tab shows the lookup returns zero results

- Imports tab shows 123 blacklisted libraries and functions referenced

- Version tab shows version, company name, product name, copyright
    info, etc.

- Certificate tab does not show a digital signature

Some of these results indicate a possibly malicious file (no digital
signature, blacklisted strings) but we still have no idea what it is or
what it does.

### Regshot

This tool detects changes to system by comparing 1st and 2nd shots:

- Open regshot from the `C:\tools\Regshot-1.9.0` folder

- Use regshot scan dir1 option... click 1st shot

- Run the executable

- Click 2nd shot

- When that finishes, click Compare to see what changes happened

- Several registry key values were modified and a file may have been
    added/changed

The UserAssist registry key contains information about programs and
shortcuts accessed by the Windows GUI, including execution count and the
date of last execution.  Additional tools are needed to parse the data,
but seeing that these values were changed is normal when running an
executable.  There is also several changes to Internet Connection
Settings keys which could indicate network activity.

### Process Monitor 

Procmon monitors registry, filesystem, network, and process activity (part of SysInternals Suite)

- Open procmon (Run as an Administrator) from the
    `C:\Tools\SysinternalsSuite` directory

- Click on the magnifying glass to stop the capture

- Select Filter -> Filter to open the filter settings

- Uncheck the box for the filter rule "Process Name is System Exclude"

- Select Apply and then OK to close this window

- At the top right there are four icons for registry, filesystem,
    network, and process activity.  Click on the registry, filesystem,
    and process buttons so that ONLY network activity is turned on (has
    a box around it)

- Click on the magnifying glass to start the capture

- Start the putty.exe application

You should see DNS queries, Netbios queries, LLMNR queries, or all three
when you start the putty.exe application.  In order to see what name is
being queried, investigate with Wireshark.

### Wireshark

- First, clear the victim machine's DNS cache by opening PowerShell
    and typing `ipconfig /flushdns`

- Open Wireshark and begin capturing traffic

- Start the putty.exe application and watch Wireshark for
    DNS/NBNS/LLMNR packets

- Notice all the name queries for the host "puttysystemsinc" using
    first DNS, then LLMNR and NBNS

Also notice these queries are not being answered so the malware doesn't
have an IP address for establishing a connection.  The next step is to
set up a fake DNS server to resolve these queries to see what kind of
connection the malware is trying to make.

### FakeDNS

This tool automatically redirects traffic and emulates common services:

- On the SIFT-REMnux, start the fake DNS server by opening a terminal
    and typing `fakedns`

- The SIFT-REMnux host is now listening on port 53 and will reply to
    every name query it receives with an answer that points to its own
    IP address

- Your Windows VM is currently set to use the DNS server assigned by
    the OOB network via DHCP so you need to change it in order to do
    this

- On the Windows VM, set your DNS server to the SIFT-REMnux by opening
    an admin command prompt and typing `netsh interface ip set dns
    "Local Area Connection" static <ip-address-of-SIFT_REMnux>`

- Check to make sure the SIFT-REMnux IP address is now listed as your
    Windows VM's DNS server by typing `netsh interface ip show config`

\*\*\* If you are having trouble getting this to work here, you can also
make puttysystemsinc resolve to your SIFT-REMnux IP address by adding it
to the victim systems hosts file:

- Open PowerShell as an Administrator

- Type `cd drivers\etc`

- Type `notepad hosts`

- Make a new line at the bottom that reads
    `<your-SIFT-REmnux-ip-address>  puttysystemsinc`

- Close the file and save

- Type `ipconfig /flushdns`

The next step is to make sure the queries are being resolved to your
SIFT-REMnux system.

### Wireshark

- First, clear the victim machine's DNS cache by opening PowerShell
    and typing `ipconfig /flushdns`

- Open up Wireshark and begin capturing packets

- Filter packets so that you only see DNS traffic by typing `dns` in
    the filter

- Make sure your FakeDNS server is running on the SIFT-REMnux and run
    the putty.exe application

- Examine the queries for "puttysystemsinc" coming  from the victim
    machine

The name query should now get resolved to the IP address of your
SIFT-REMnux machine.  Now the malware will attempt to communicate to
this IP address.

### TCPView

This is a tool in the Sysinternals Suite that lists all TCP and
UDP endpoints on a system

- Open TCPView from the `C:\Tools\SysinternalsSuite` directory

- Start the putty.exe application

- You should see TCP traffic to the remote system (puttysystemsinc)
    and the remote port (https/443)

- The "State" column shows 'SYN_SENT' for each of these

This is the infected Windows VM now attempting to connect to what it
thinks is "puttysystemsinc" on port 443 but is really your SIFT-REMnux
system.  Port 443 on your SIFT-REMnux should be closed so the 3-way
handshake (SYN, SYN/ACK, ACK) does not complete and no connection is
made.  The next step is to open up port 443 on your SIFT-REMnux to allow
the malware to make its connection to "puttysystemsinc"

### Netcat

This is a raw TCP/UDP networking tool that can be used to send and
receive data over the network

- On your SIFT-REMnux system, open a terminal and type `sudo nc
    -nlvp 443`

- Netcat is now listening on that port for any incoming connections

- Run the putty.exe application again and watch the terminal on the
    SIFT-REMnux

- This time a connection is made and the application sends some data

- To give you an idea what protocol this is, stop the netcat listener
    with **Ctrl+C** and start it up again

- This time open your SIFT-REMnux browser and go to
    <https://localhost>

You should see the same data appear in the terminal when both running
the putty.exe application and using your browser to make an HTTPS
connection.  This means the malware is most likely attempting to make an
https connection to what it thinks is its C2 server.  The next step is
to find out what C2 server it is looking for...

There are many tools that can be used for this so the malware's
characteristics will determine which ones you want to experiment with
first.  The most popular, and a great starting point, is Metasploit
which is included in every version of Kali Linux, but can also be
downloaded and run inside a Docker container.  Running it in a Docker
container is a great way to quickly deploy it in its own runtime
environment and tear it down when you're finished while not having to
worry about extra software components, patching, conflicting
dependencies, etc.

### Metasploit

This is an open source penetration testing tool and exploit
framework

- Build a Metasploit Docker container on your SIFT-REMnux system by
    typing `sudo docker run -rm -it -p 443:443 -v ~/.msf4:/root/.msf4 -v /tmp/msf:/tmp/data remnux/metasploit`

- Set up a meterpreter listener on port 443 by typing `msfconsole -x
    "use exploit/multi/handler;set payload
    windows/x64/meterpreter/reverse_https;LHOST
    <sift-remnux-ip-address>;LPORT 443; run"`

- Metasploit will report that a HTTPS reverse handler has been started
    on your SIFT-REMnux machine

- Execute the putty.exe application on the Windows VM

- Look on the SIFT-REMnux machine and verify a meterpreter shell is
    waiting for commands

- At the meterpreter shell, type `getuid` to see victim server name
    and username

- At the meterpreter shell, type `ps` to see all processes on victim
    machine

- At the meterpreter shell, type `ls c:\` to list files in the C:\ directory

- At the meterpreter shell, type `netstat -ano` to see all network
    connections on victim machine

- At the meterpreter shell, type `shell` to drop into a command
    shell

As you can see, the malware was configured to communicate over HTTPS to
the attacker's Metasploit system located at puttysystemsinc and gives
the attacker interactive shell access to the victim system.  From here,
it could be used to escalate privileges, conduct system and network
reconnaissance, and move laterally through the environment.  Now we can
accurately report on what the malicious file is, what it does, and look
for ways it could have been used against our systems.

Further experimentation will give you an even better idea of what the
malware is capable of:

- See if you can spot the malware's network connection from the victim
    using `netstat -ano`

- Observe the PID associated with this connection and trace it to a
    process by typing `wmic process where processid=<pidofconnection>
    get name`

- You should see putty.exe is associated with the connection

- Now go to the meterpreter shell (type in `exit` if you are still
    in command shell)

- Type `ps` and find out what PID the "explorer.exe" process is
    running under

- Type `migrate <pidofexplorer>`

- Now go back to the victim machine and type `netstat -ano`

- Notice it is now a different process (explorer.exe) that is
    communicating with the C2 server

Meterpreter uses reflective DLL injection which allows it to live only
in memory and migrate to other processes as required.  Additional
research would reveal that this migration technique can be automated to
execute as soon as the session begins.  This means even if the user
started putty.exe and deleted it after it didn't open as expected, the
Meterpreter could still be alive and well in another process.

Here are several more tools capable of providing stealthy, persistent
access and/or interactive shell access:

### Empire

Empire is a pure PowerShell and Python implant which offers many
OPSEC-focused features, a secure and flexible C2 architecture, and a
large collection of memory-only post-exploitation modules for evading
endpoint detection.  The agent is frequently delivered via the browser,
flash exploit, MS Office document, or Adobe Reader PDF.  Like
Meterpreter, it can migrate to other processes by injecting itself into
the process's memory space.  It can be configured to check in at odd
times and intervals using HTTPS making it hard to detect over the
network.

### Cobalt Strike Beacon

Beacon is Cobalt Strike's covert command and control payload that is
used to simulate specific threat actors or campaigns.  It can be
delivered with social engineering packages, client-side exploits, and
session passing and can migrate to another process immediately after
staging.  Its customizable C2 makes detection extremely difficult:

- configurable URIs to have multiple C2 servers to get around any
    IP/domain blocking

- random intervals using changing protocols (DNS, SMB, HTTP, HTTPS)

- configurable user agent, metadata/ID format, headers of both the
    client and the server interactions, both GET and POST requests

All these characteristics can be changed in order to disguise the C2
traffic as google web bugs, Pandora streaming, amazon browsing, etc. 

### Throwback & Slingshot

Throwback is a stealthy HTTP/S beaconing backdoor and C2 server created
by Silent Break Security.  Slingshot is their full-featured payload
which uses reflective DLL injection for interactive post-exploitation. 
Multiple apache servers host php files that collect callback data from
the implants which can be configured to check in for tasks every 1, 4,
8, 12 hours in case the interactive shell drops.

### Pupy

A multiplatform, multifunction remote access tool written in Python with
a very small footprint.  The tool operates in memory, can migrate into
processes, load remote python code.  Modules can be delivered via
portable executables, python files, powershell commands, etc.  Data
exfiltration can be conducted using stackable transports such as HTTP
over HTTP over AES over XOR.
