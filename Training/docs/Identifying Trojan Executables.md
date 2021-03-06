# Identifying Trojan Executables

In this scenario, a user was discovered to be using a fully functional
portable executable of an authorized program (WinSCP.exe) but did not
get the file from the vendor's website or the Software Center.  The
following steps walk through several stages of analysis showing the
different tools that can be used to determine if the file is legitimate
or malicious.   

- [Automated Analysis](#automated-analysis)
- [Static Analysis](#static-analysis)
- [Dynamic Analysis](#dynamic-analysis)


Start the REMnux machine with VirtualBox and copy over the file from:

    /CSIRT/Sample-Files/WinSCP.exe

## Automated Analysis

Submitting the file to [Malwr](https://malwr.com/) shows an Internet
connection to 34.210.28.254 on port 80. 

But everything else appears to be normal... more information can be
obtained through static analysis.

![](images/Identifying%20Trojan%20Executables/image001.png)


## STATIC ANALYSIS

We'll use the following tools to perform static analysis:

- [Floss](#floss)
- [PEScanner](#pescanner)
- [ReadPE](#readpe)
- [PEDump](#pedump)
- [VT](#vt)


### Floss

`floss <filename>`

Floss is great at extracting obfuscated strings, but turns out it can only do this on files smaller than 16777216 bytes.  This file is larger than this so all we get is an enormous number of strings found in the file which we can already get using the strings program.

### PEScanner]

`pescanner.py <filename> `

This gives us a lot of information about the file:

- Metadata (hash, type, date, language, entry point

- Version info (company, website, product name and version,
    description)

- Sections (.text, .data, .tls, .rdata )

- Imports (ws2_32, winhttp )

- Suspicious IAT alerts

- Exports

We can download the legitimate version of WinSCP.exe, run PEScanner
    on both, and compare the two outputs:

- `pescanner.py good-WinSCP.exe > pescan-good.txt`

- `pescanner.py bad-WinSCP.exe > pescan-bad.txt`

- `diff pescan-good.txt pescan-bad.txt`

This shows the two files are very similar but have different sizes, hashes, CRCs, and memory addresses for .text and .reloc.



### ReadPE

`readpe -f <filename> > read.txt`

This tool prints out all PE headers, section headers, data directories, imported functions, exported functions

This tool's output can also be compared for both files:

- `readpe -f good-WinSCP.exe > read-good.txt`

- `readpe -f bad-WinSCP.exe > read-bad.txt`

- `diff read-good.txt read-bad.txt`


This shows differences in size, checksum, and physical addresses.

### PEDump

`pedump <filename>`

This tool extracts similar information to the Malwr automated scan---headers, version info, sections, strings, etc.

Notice that the tool output of the good file has something the bad file doesn't have---a security section with certificates:

![](images/Identifying%20Trojan%20Executables/image002.jpg)


### VT

`vt -s <hash>`

Submit or check hash with VirusTotal... you can get a public API key for free by signing up and place the key in the `.vtapi` config file.

This is what a hit looks like (I used a known malicious file to produce this output):

![](images/Identifying%20Trojan%20Executables/image003.jpg)


- Submitting just the hash of bad-WinSCP.exe  with  `vt -s <md5hash>`  returns no results

- Scanning the file `bad-WinSCP.exe` with `vt -f bad-WinSCP.exe` returns no results


## Dynamic Analysis

We'll use the following to perform dynamic analysis:

- [REMnux and Vagrant](#remnux-and-vagrant)
- [FakeNet-NG](#fakenet-ng)
- [Metasploit](#metasploit)


### REMnux and Vagrant

Spin up a Windows 10 32 bit machine with Vagrant

`cd /win10x32 && vagrant up`

Start a DHCP server with the following two commands:

```bash
vboxmanage natnetwork add --netname intnet --network "10.10.10.0/24" --enable
vboxmanage dhcpserver add --netname intnet --ip 10.10.10.1 --netmask 255.255.255.0 --lowerip 10.10.10.10 --upperip 10.10.10.20 --enable
```

Put both of the VMs on the same internal network by going to Machine --> Settings --> Network --> Attached to: NAT Network

Name of the network should be "`intent`"

On the Windows system, open PowerShell and type:

`ipconfig /release; ipconfig /renew`

On the REMnux system, open Terminal and type:

`sudo ifdown eth0 && sudo ifup eth0`

Now both VMs should have been assigned IP addresses and you should be
able to ping REMnux from the Windows host.

To ping the Windows host from the REMnux host, you must enable ping
replies on the Windows host with:

`netsh firewall set icmpsetting 8 enable`

Make the Windows host's default gateway the REMnux machine by typing:


```powershell
$nic = get-wmiobject win32_networkadapterconfiguration -filter "ipenabled = 'true'"
$nic.setagateways("10.10.10.10", 1)
$nic.SetDNSServerSearchOrder("10.10.10.10")
```

Now all traffic and DNS requests will go to the REMnux host.


### FakeNet-NG

`sudo fakenet`

FakeNet-NG simulates commonly used services such as DNS, HTTP, HTTPS, and SMTP.

We directed all DNS to our REMnux system so any name that is queried on
the Windows system will be found and given a fake IP address by
FakeNet-NG.

You can test this by doing an nslookup for any host from the windows
system which FakeNet-NG will resolve:

![](images/Identifying%20Trojan%20Executables/image004.jpg)


Or requesting any web page in the browser which is provided by
FakeNet-NG:

![](images/Identifying%20Trojan%20Executables/image005.jpg)


Execute the `WinSCP.exe` and notice the Windows host is now sending GET
requests to host 34.210.28.254 for a suspicious webpage:

![](images/Identifying%20Trojan%20Executables/image006.jpg)


By default, FakeNet-NG captures all traffic and stores it in the current
directory in PCAP files for additional analysis:

![](images/Identifying%20Trojan%20Executables/image007.png)


FakeNet-NG is responding with the file `FakeNet.html` but the host keeps
requesting the same page so it is looking for something specific.

### Metasploit

Now that we have confirmed the port and protocol being used, set up a C2
server for this using the Metasploit Docker image included in REMnux.

We're using an alternate port for this (8080):

`sudo docker run -rm -it -p 8080:8080 remnux/metasploit`

If the image cannot be found locally, you'll need to change to Bridge
mode in order to reach the Internet and download the image:

On the Virtual Box menu:

Go to Machine --> Settings --> Network --> Attached to: Bridged Adapter

On the REMnux system, open Terminal and type:

`sudo ifdown eth0 && sudo ifup eth0`

Now REMnux will pull down the image.  This will take about ten minutes
or so.  Once it's complete, destroy the Docker image (type `exit`) and
switch back to the isolated "`intent`" network:

On the VirtualBox menu:

Go to Machine --> Settings --> Network --> Attached to: NAT Network, Name: `intnet`

On the REMnux system, open Terminal and type:

`sudo ifdown eth0 && sudo ifup eth0`

Once you're back on the isolated network, fire up the Metasploit Docker
image:

`sudo docker run -rm -it -p 8080:8080 remnux/metasploit`

After the Docker image is ready, you should have a root prompt.

We now need to redirect traffic to our Docker image.  In a second
terminal:

First flush the iptables rules by typing `sudo iptables -F`

Then verify there are no rules with `sudo iptables -L`

Now add a rule to send all port 80-bound traffic to the port Docker is
listening on:

`sudo iptables -t nat -A PREROUTING -p tcp -dport 80 -j REDIRECT -to-ports 8080`

Type the following to set up the C2 server:

```bash
msfconsole
use multi/handler
set LHOST 0.0.0.0
set LPORT 8080
```

There are only a few payloads that use reverse HTTP so eventually
you'll guess the right one:

```powershell
set payload windows/meterpreter/reverse_http
run
```

![](images/Identifying%20Trojan%20Executables/image008.jpg)


We now have control of the Windows system in the same way that the
attacker may have had control of the user's machine.

Now that the malicious program is connected to the C2 server we can do
some live analysis on the host with Rekall, Process Hacker, etc.

See if you can find a way to detect the Meterpreter implant running on
the system without using its network activity.