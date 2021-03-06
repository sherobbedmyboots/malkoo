# Windows Processes and Memory Analysis

For this exercise, I created a memory image of the Persistence VM. 
Redline and Volatility are two tools that can be used to analyze the
image, I go through this one with Volatility because of its flexibility
and the fact that it is already installed on our REMnux VM.  The image
is located here:

    /CSIRT/Sample-Files/VM-USER-PC-20170410-132913.dmp


Analysis of physical memory is typically used for rapid triage and
analysis leads, but it also enables full analysis and event
reconstruction when a system is under investigation.  Collecting data
from memory is the only way to get the true state of a system at the
time of capture and is a key component to scoping and understanding an
incident.  Used in conjunction with disk and network forensics, it can
correlate forensic artifacts to identify associations that would
otherwise go unnoticed.  Comprehensive memory analysis not only allows
recovery of memory-only artifacts not available on disk or the network,
but also provides a more accurate and complete reconstruction of events.

Examples of memory-only artifacts:

|Type|Description|
|-|-|
|Residual data|Data from disconnected external media devices, previous boots, terminated shells, wiped event logs and browser history no longer available on disk|
|Volatile data|Registry keys manipulated directly in memory are not written to disk and can be used to track user activity or locate malware persistence|
|Network data|Evidence of proxy or port redirection, network share data, traffic traversing SSH/VPN tunnels, encrypted communications, connected wireless devices|
|Hidden services|Services can be running with no traces in event log, registry, or memory of services.exe, but running process, DLL, or kernel driver is still in memory|
|File data|Recently used files, deleted files, executable paths and timestamps allow evidence of file execution/knowledge, directory traversal|
|Application data|Data an application received over the network, decompressed and/or decrypted instructions in memory, encryption keys|
|Command History|Extract full console input and output, data from user/attacker sessions such as usernames, passwords, programs/files accessed|
|SIDs/Privileges obtained|User, group, and privilege information associated with user and attacker-controlled accounts and malicious processes|
|Malware-created artifacts|Parameters of the infection, C2 and exfiltration data, hidden files and processes, hooked drivers, injected code|
|Anti-forensic artifacts|Evidence of file wiper use, programs run from removable devices, event log modifying/deleting, resetting timestamps|
|Passwords|Plaintext passwords stored by OS/applications that may be reused on other systems/services, passwords for encrypted files and containers|


The most common artifacts available in memory are kernel objects such as
processes, files, and network sockets.  Here are some object types:

|Name|Object|Description|
|-|-|-|
|File|`_FILE_OBJECT`|An instance of an open file that represents a process or kernel module's access into a file|
|Process|`_EPROCESS`|A container that allows threads to execute within a private virtual address space, maintains open handles to resources such as files, registry keys, etc.|
|SymbolicLink|`_OBJECT_SYMBOLIC_LINK`|Created to support aliases that can help map network share paths and removable media devices to drive letters|
|Token|`_TOKEN`|Stores security context information (such as security identifiers \[SIDs\] and privileges) for processes and threads|
|Thread|`_ETHREAD`|An object that represents a scheduled execution entity within a process and its associated CPU context|
|Mutant|`_KMUTANT`|An object that represents mutual exclusion and is typically used for synchronization purposes or to control access to particular resources|
|WindowStation tag|`WINDOWSTATION`|A security boundary for processes and desktops, which also contains a clipboard and atom tables|
|Desktop tag|`DESKTOP`|An object that represents the displayable screen surface and contains user objects such as windows, menus, and buttons|
|Driver|`_DRIVER_OBJECT`|Represents the image of a loaded kernel-mode driver and contains addresses of the driver's input/output control handler functions|
|Key|`_CM_KEY_BODY`|An instance of an open registry key that contains information about the key's values and data|
|Type|`_OBJECT_TYPE`|An object with metadata that describes an object


## Processes

Each process has its own private virtual memory space, one or more
threads that execute code, and handles to various objects that it needs
to function.  By enumerating and examining these we can determine:

- What applications are running

- What objects (files, registry keys, etc.) they are using

- What security context (or privilege level) they have obtained


Below is a list of normal processes on a Windows system.  Learning their
characteristics and the conditions that they run under will help you
identify when malware attempts to impersonate or blend in with them in
order to avoid detection.

- [Idle and System](#idle-and-system)
- [Session Manager](#session-manager)
- [Windows Initialization Process](#session-manager)
- [Client Server Runtime Subsystem](#client-server-runtime-subsystem)
- [Service Control Manager](#service-control-manager)
- [Local Security Authority](#local-security-authority)
- [Service Hosting Process](#service-hosting-process)
- [Load Session Manager Service](#load-session-manager-service)
- [Windows Logon Process](#windows-logon-process)
- [Windows Explorer](#windows-explorer)


### Idle and System

- These are not real processes, there is no corresponding executable on disk
- Idle is a container that the kernel uses to charge CPU time for idle threads
- System serves as the default home for threads that run in kernel mode and has a PID of 4 (owned by SYSTEM)
- Created by `ntoskrnl.exe` via the process manager function, which creates and terminates processes and threads
- No visible parent processes
- System has a static PID of 4
- System creates `smss.exe`
- There should only be one system process running


### Session Manager

`C:\Windows\System32\smss.exe`

- The first real user-mode process that starts during the boot sequence
- Creates the sessions that isolate OS services from the various users who may log on via the console or RDP
- Username: `NT AUTHORITY\SYSTEM`
- Creates session 0 (OS services) and runs within session 0
- Creates session 1 (User session) which creates csrss and winlogon then exits, which is why they have no parent process and they both have session ids of 1
- Only one `smss.exe` process should be running at one time. There can be more sessions if more users are logged on to the system. 0 and 1 are for a single user logged onto the system.


### Windows Initialization Process

`C:\Windows\System32\wininit.exe`

- Performs user-mode initialization tasks
- Created by `smss.exe`, but since `smss.exe` exits it shows a non-existent process
- Creates `services.exe`, `lsass.exe` and `lsm.exe`
- Username: `NT AUTHORITY\SYSTEM`
- Creates `%windir%\temp`
- Runs within session 0


### Client Server Runtime Subsystem

`C:\Windows\System32\csrss.exe`

- Creates and deletes processes and threads, temp files, etc.
- It maintains a private list of the objects that you can use to cross-reference with other data sources
- Created by Session Manager (`smss.exe`)
- Username: `NT AUTHORITY\SYSTEM`
- One per session
- Runs within session 0


### Service Control Manager

`C:\Windows\System32\services.exe`

- Loads a database of services into memory
- Manages Windows services and maintains list of them
- Created by `wininit.exe`
- Creates `svchost.exe`, `dllhost.exe`, `taskhost.exe`, `spoolsv.exe`, etc.
- Username: `NT AUTHORITY\SYSTEM`
- One services process per session
- Runs within session 0


### Local Security Authority

`C:\Windows\System32\lsass.exe`

- Enforces the security policy, verifies passwords, creates access tokens, etc.
- Often targeted by malware as a means to dump passwords since plaintext passwords are contained within its memory space
- Created by `wininit.exe`
- Username: `NT AUTHORITY\SYSTEM`
- Runs within session 0
- It should not have child processes
- Only one process


### Service Hosting Process

`C:\Windows\System32\svchost.exe`

- Multiple processes exist, they provide a container for DLLs that implement services
- Created by `services.exe`
- Username: Should only be one of three options: `NT AUTHORITY\SYSTEM`, `LOCAL SERVICE`, or `NETWORK SERVICE`
- Command Line: `svchost.exe -k <name>`
- They should all be running within session 0


### Load Session Manager Service

`C:\Windows\System32\lsm.exe`

- Manages the state of terminal server sessions on the local machine, Sends the requests to smss.exe to start new sessions
- Created by `wininit.exe`
- No child processes
- Receives logon/off, shell start and termination, connect/disconnects from a session, and lock/unlock desktop
- Username: `NT AUTHORITY\SYSTEM`
- Runs within session 0


### Windows Logon Process

`C:\Windows\System32\winlogon.exe`

- Presents the interactive logon prompt, screen saver, loads user profiles
- Handles interactive user logons/logoffs when SAS keystroke combination is entered (`Ctrl+Alt+Delete`)
- No parent process
- Could have a child process of LogonUI if smartcard, etc. are used to authenticate
- LogonUI will terminate once the user enters their password
- Loads Userinit within `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` and runs shell value located at `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` which is `explorer.exe`
- Since Userinit exists `explorer.exe` doesn't have a parent process
- Runs within session 1


### Windows Explorer

`C:\Windows\explorer.exe`

- Handles user interactions such as GUI-based folder navigation, start menu, etc.
- No parent process since `Userinit.exe` exits
- The value "explorer.exe" is stored in shell value at `Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
- Username: The logged on user account
- This will contain multiple child processes
- One process for each logged-on user


## Analysis with Volatility

Volatility is an advanced memory forensic framework written in Python. 
When Volatility searches a memory image, it traverses through the
underlying data structures and formats that an operating system and
applications use gaining maximum visibility into the runtime state of
the system.  The physical offsets of artifacts are mapped to virtual
addresses in the memory dump to allow linking evidence to the specific
processes or kernel modules that had references to the data.  A
collection of over 400 plugins and thousands of different OS
version-specific profiles are used to provide even further context for
artifacts allowing deep and complete analysis. 

In REMnux, the `vol.py` command runs the tool, but each time we run it,
we need to specify the OS profile (`--profile`),  the image file (`-f`),
and the plugin we're using (`pslist`). 


`vol.py --profile=<profile> -f <image-file> <plugin>`

Each plugin is designed to parse and enumerate specific information.  To
see a summary of each plugin available, bring up the help menu by
typing:  `vol.py --info`


### Processes 

Here are some things to look for when examining processes in memory:

- Parent/child relationships of processes
- Process privileges, users names the processes are running under
- Command line parameters for processes
- Location they are being run from
- Spelling of the process names
- Processes that should not be connecting out to the Internet but are
- Suspicious URLs/IPs, strings, etc.

First we'll use the `pslist` plugin to look at all running processes,
their start times, their session \#, parent processes, and spelling:

![](images/Windows%20Processes%20and%20Memory%20Analysis/image001.png)


![](images/Windows%20Processes%20and%20Memory%20Analysis/image002.png)


Notice all the `svchost.exe` processes start at around the same time, run
at session 0, and are children of `services.exe`.

However, `scvhost.exe` (misspelled) starts much later, is spawned from
`explorer.exe`, and runs at session 1:

![](images/Windows%20Processes%20and%20Memory%20Analysis/image003.png)


Many of the malicious processes are spawned by `explorer.exe`, running at
session 1, and attempt to appear as system services.

The `pstree` plugin takes the output from `pslist` and formats it in a tree
view, so you can easily see parent and child relationships:

![](images/Windows%20Processes%20and%20Memory%20Analysis/image004.png)


This shows several suspicious processes that are children of
`explorer.exe` (nc, malware_destroyer, mDNS responder, bind, scvhost). 
Normally system services like Anti-Virus products, DNS applications, and
svchost (correctly spelled) are not spawned by a user's explorer process
but by the Service Control Manager (`services.exe`):

![](images/Windows%20Processes%20and%20Memory%20Analysis/image005.png)


### Connections/Sockets

Using the `netscan` plugin shows four of the attacker's persistence files
right off the bat.  These listening ports would immediately stand out as
well as their names (netcat, misspelled `svchost.exe`, malware_destroyer,
bind).

![](images/Windows%20Processes%20and%20Memory%20Analysis/image006.png)


![](images/Windows%20Processes%20and%20Memory%20Analysis/image007.png)


### Registry Keys

`printkey` will show registry key and subkey values.  Using it to check a
key commonly used for persistence shows the "GooglesUpdaters" service
starts each time the user logs on to the system:

![](images/Windows%20Processes%20and%20Memory%20Analysis/image008.png)


### Handles

A handle is a reference to an open instance of a kernel object, such as
a file, registry key, mutex, process, or thread.   The `handles` plugin
lists open handles for a process so we can determine what process was
reading or writing a particular file, accessing a specific registry key,
etc.  

In this case we see the `7z.exe` process (pid 2100) accessing the
user's `index.dat` file:

![](images/Windows%20Processes%20and%20Memory%20Analysis/image009.png)


This may or may not be normal, it depends on the program.  But looking
at the registry keys that were accessed by `7z.exe` shows even more
network-type objects which is unusual for a program that zips and unzips
files:

![](images/Windows%20Processes%20and%20Memory%20Analysis/image010.png)


![](images/Windows%20Processes%20and%20Memory%20Analysis/image011.png)


We now have several indications that this is not the legitimate 7zip
executable and that it is trying to access another system over the
network.

### Yara Rules

The `yarascan` plugin scans for custom binary or textual patterns and
compound rules within memory space.  Using it on the image to search the
`7z.exe` process for the string "https://" shows several instances of the
attacker's address and port number "192.168.2.110:22222" in its memory
space, resulting from its outbound callbacks.

![](images/Windows%20Processes%20and%20Memory%20Analysis/image012.png)


![](images/Windows%20Processes%20and%20Memory%20Analysis/image013.png)


As you can see, the more plugins you're familiar with, the more
artifacts you can find.  Try some of the other plugins and see if you
can find any artifacts that wouldn't be available on disk or in network
traffic captures. 

In part two we'll look at hidden processes, tokens and privileges, and
code injection.
