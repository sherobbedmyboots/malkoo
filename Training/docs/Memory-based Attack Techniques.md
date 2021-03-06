# Memory-based Attack Techniques

The growth of memory-resident malware and network encryption are quickly
making physical memory an invaluable search space for artifacts.  Modern
malware can load itself over the network, decrypt itself in memory, and
hide processes and network connections from a live system---all without
writing to disk.  In this example, malicious software on the victim
machine is communicating to its C2 server over HTTPS and there are very
few artifacts available on disk.  In these cases we can use a memory
image to find and analyze the malicious code, determine its
capabilities, and report as much as possible about what actions were
taken on the compromised host.

The image is located here on the CSIRT OOB:

    /CSIRT/Sample-Files/VM-USER-PC-2017-05-02-202227.raw



## Memory-Based Attacks

Common Memory-based Attack Techniques:

- [Process Hiding with DKOM](#process-hiding-with-dkom) 
- [PEB Unlinking](#peb-unlinking)
- [Code injection](#code-injection)
- [DLL injection](#dll-injection)    
- [Reflective DLL injection](#reflective-dll-injection)
- [Process Hollowing](#process-hollowing)


### Process Hiding with DKOM 

Using Direct Kernel Object Manipulation (DKOM), an attacker can hide a process by unlinking its entry from
the doubly linked list, a set of sequentially linked processes running
on the system.  This will prevent tools like `tasklist`, `pslist`, Process
Hacker, and Process Explorer from seeing the process.  This is
accomplished by either loading a kernel driver, mapping a writeable view
of the `\Device\PhysicalMemory` object, or using an API function such as
ZwSystemDebugControl.

Volatility's `psscan` scans a memory image for pools with same attributes
as EPROCESS objects, finding them even if they are unlinked from the
list.  Compare `psscan` results with the results of `pslist` (and other lists) by
using the `psxview` plugin to find hidden processes.

### PEB Unlinking

This memory-evasion technique is similar to Process Hiding, but instead
of hiding a process it hides a DLL.  Loaded DLLs are tracked in three
different linked lists for each process.  Malware can unlink loaded DLLs
from these lists to hide them from security tools and system admins.  To
detect this we need to compare what Windows API reports as loaded versus
what is actually loaded. 

Volatility's `ldrmodules` plugin queries each list and gets details about
every allocated memory segment in a process which can be used to find
unlinked DLLs.

### Code Injection

This happens when a target process is made to run malicious code on
behalf of the malware. 

The malware enables debug privilege (SE_DEBUG_PRIVILEGE) and uses the
following functions:

|Function|Description|
|-|-|
|OpenProcess|Grabs handle to target process|
|VirtualAllocEx|Allocates a new chunk of memory with PAGE_EXECUTE_READWRITE protection|
|WriteProcessMemory|Writes code/payload into target process|
|CreateRemoteThread|Starts a new thread to execute the payload|

The `malfind` plugin looks for hidden or injected code that standard
methods and tools don't see.  It looks for memory segments that are
executable, marked as private, or are memory-resident only (indicated by
the VadS tag).  Once a suspicious module is detected, the analyst can
dump the modules or disassemble code for further analysis.

### DLL Injection

This happens when a target process is made to run a malicious DLL on
behalf of the malware.

The malware enables debug privilege (SE_DEBUG_PRIVILEGE) and uses the
following functions:

|Function|Description|
|-|-|
|OpenProcess|Grabs handle to target process|
|VirtualAllocEx|Allocates a new chunk of memory|
|WriteProcessMemory|Writes complete path of DLL to into target process|
|CreateRemoteThread|Starts a new thread to execute the DLL|

Volatility's `dlllist` can be used to examine suspicious dlls in active,
linked processes.

Look for:

- Suspicious names

- Common names loaded from non-standard directories

- Out of context dlls such as `wininet.dll`, `urlmon.dll`, `winsock32.dll`, `ws2_32.dll` for non-network processes

- DLLs that allow access to protected resources such as `sfc_os.dll` and `pstorec.dll`

### Reflective DLL Injection

Reflective DLL injection is when a DLL maps itself into memory. 
Normally a DLL is loaded by LoadLibrary and is registered as a loaded
DLL for that process.  Reflective DLL injection loads the DLL without
registering so that it doesn't show up in the list of loaded DLLs for
the process.

The malware uses the following steps to accomplish:

|Function|Description|
|-|-|
|OpenProcess|Grabs handle to target process|
|VirtualAllocEx|Allocates a new chunk of memory|
|WriteProcessMemory|Copies the DLL into the allocated memory space|
|CreateRemoteThread|Starts execution of the DLL using a reflective loader function as entry point|

The `malfind` plugin can detect Reflective DLL injection by examining
memory segments that are executable, marked as private, or are
memory-resident only.  DLLs that have no mapped path indicate an
injected DLL not on disk.

### Process Hollowing

When malware performs process hollowing, it creates a new legitimate
process such as `lsass.exe`, suspends it, "hollows" out the memory
containing `lsass.exe`'s code, and inserts its own code.  The new
malicious process now looks similar to the original, legitimate process
and its image name, image path, and command line remain the same.

The malware enables debug privilege (SE_DEBUG_PRIVILEGE) and uses the
following functions:

|Function|Description|
|-|-|
|CreateProcess|Target process is suspended with CREATE_SUSPEND option|
|ReadRemotePEB|Process Environment Block (PEB) is located|
|NtUnmapViewOfSection|Target process is hollowed| 
|VirtualAllocEx|Allocates a new chunk of memory to host malicious code|
|WriteProcessMemory|Writes the malicious code into the allocated memory space|
|SetThreadContext|Sets context of process|
|ResumeThread|Target process is resumed|

Volatility's `pstree` plugin can be used to identify processes with more
than normal number of instances or those with incorrect parent PIDs. 
Malfind can be used to identify PAGE_EXECUTE_READWRITE memory sections
that are not mapped to disk.  Viewing the process's open handles,
registry keys, and open network sockets and extracting their executable
images to examine with `strings`, `ssdeep`, IDA pro, or a hex editor can
also be used to identify this technique.

## Memory Analysis

To start, open REMnux, copy the memory image file over, and navigate to
the directory containing the memory image file.

We'll examine the image looking at the following:

- [Processes](#processes)
- [Sockets](#sockets)
- [DLLs](#dlls)
- [Handles](#handles)
- [Yara Rules](#yara-rules)
- [Privileges](#privileges)
- [Putting it all together](#putting-it-all-together)


For each plugin, use the format `vol.py --profile=Win7SP1x64 -f VM-USER-PC-2017-05-02-202227.raw <plugin>`


### Processes

A process is a container which holds:

|||
|-|-|
|Executable code|such as notepad.exe or malware.exe|
|Process Environment Block (PEB)|contains information about the process and OS as a whole, points to parameters|
|Parameters|such as ImageFileName, CommandLine, ImageFilePath|
|Variables|Environment variables|
|Heap|Blocks of allocated memory|
|Stack|Related to the state of threads|
|Set of DLLs|ntdll.dll, nernel32.dll, advapi32.dll, user32.dll|

First, look at what was running on the host at the time of the image
capture and if it was legitimate or not (Names, PIDs, PPIDs, relationships)

|Plugin|Look for|
|-|-|
|`pslist`|image file names with blank extensions, incorrect spelling, random names, one or two char names|
||image file paths with incorrect locations|
|`psscan`|hidden processes that are not on the linked list and reported by `pslist`|
|`pstree -v`|user processes should not spawn system processes and vice versa    
||suspicious command line arguments|
||parent/child relationships of processes|
|`psinfo`|wscript.exe, rundll32.exe, what is on the command line|
|`psxview`|differences in visibility of processes in `pslist`, `psscan`, and others|

Notice that `psscan` shows one more process than `pslist` shows.  The
process not shown in the pslist output is named `oNJYzGRBzrJPNv`.

Looking at the `psxview` output, you can see that the False flag under the
`pslist` column indicates it is not seen by `pslist`.  Also, notice another
process with a blank name is also hidden from both `pslist` and `psscan`.

So we have two suspicious processes at this point:

|Physical Offset|Name|PID|
|-|-|-|
|0x0000000002dc69d0|oNJYzGRBzrJPNv|660|
|0x0000000002e6a340|(Blank)|504|

### Sockets

Looking for network artifacts in a memory image, we can see not only
full content of network communications but also previous connections and
bindings to ports.  The netscan plugin scans for all network structures
including socket objects and connection objects to identify even those
that aren't on list of active connections and listening sockets.

|Plugin|Look for|
|-|-|
|`netscan`|processes that should not be connecting out to the Internet|
||suspicious IP addresses, and ports|

Looking at this plugin's output, several processes can be seen making
external connections:

```bash
powershell.exe
oNJYzGRBzrJPNv
svchost.exe
explorer.exe
```

Let's add these to our list of suspicious processes (use `psscan` to get
the physical offset of each process):

|Physical Offset|Name|PID|Network Connections|
|-|-|-|-|
|0x0000000002dc69d0|oNJYzGRBzrJPNv|660|172.31.1.217:4444|
|0x0000000002e6a340|(Blank)|504|172.31.1.217:4444|
|0x000000011e99e960|powershell.exe|2952|172.31.1.217:443|
|0x000000011ec53b30|svchost.exe|892|34.208.205.97:443|
|0x000000011e82f060|explorer.exe|2036|96.17.153.18:443|

### DLLs

DLLs are shared libraries of code that can be used by multiple
programs.  They have the same format as traditional PE files but cannot
be executed directly---they must be called from another program.

DLLs are designed to run inside a host process with access to all of the
process' threads, handles, etc.  Some malicious programs hide their list
of imported DLLs, then manually call functions necessary to load and
execute the code in other DLLs.

Common DLLs:

|Name|Description|
|-|-|
|ntdll.dll|basic windows services (low-level, OS)|
|kernel32.dll|memory management (input/output)|
|advapi32.dll|advanced windows services (accessing registry)|
|agi32.dll|graphics driver|
|user32.dll|user interface (bars, buttons, mouse, keyboard)|
|comdlg32.dll|common dialog boxes (opening, saving files)|
|msvcr*.dll|MS Visual C runtime libraries (C, C++ Dev tools)|
|ws2_32.dll|low-level networking (raw sockets)|

The `dlllist` plugin shows all modules loaded into a process' address
space, their size and virtual address where they were loaded.

Look at loaded DLLs for suspicious processes and check for unusual
functionality and for incorrect paths.  For example, notepad.exe
containing network-related DLLs such as `wininet.dll`, `dhcpcsvc.dll`, `npmproxyj.dll`,
`mswsock.dll`, `schannel.dll`, and `dnsapi.dll` could indicate process hollowing or code
injection.  A DLL with an unusual path could indicate DLL hijacking or
DLL injection.

You can call a process with `dllist` using either its PID (`-p`) or its
physical offset (`--offset=`). 

|Plugin|Look for|
|-|-|
|`dlllist`|unusual functionality and incorrect paths|

Let's add our results to the table:

|Physical Offset|Name|PID|DLLs
|-|-|-|-|
|0x0000000002dc69d0|oNJYzGRBzrJPNv|660|n/a|
|0x0000000002e6a340|(Blank)|504|n/a|
|0x000000011e99e960|powershell.exe|2952|nothing unusual|
|0x000000011ec53b30|svchost.exe|892|nothing unusual|
|0x000000011e82f060|explorer.exe|2036|nothing unusual|


### Handles

A handle is a reference to an open instance of a kernel object, such as
a file, registry key, mutex, process, or thread.   The `handles` plugin
lists open handles for a process so we can determine what process was
reading or writing a particular file, accessing a specific registry key,
etc. 

Use the `handles` plugin to search for the following kernel objects using
this format:

`vol.py --profile=Win7SP1x64 -f VM-USER-PC-2017-05-02-202227.raw handles -t <kernel-object>`

List of kernel objects to search:

- key
- mutant
- file
- process

Some of the processes had handles on other processes (powershell,
cscript) and files (xnyxzm, iuggwy).  Added the new processes to the
table:

|Physical Offset|Name|PID|DLLs|Handles|CommandLine|Network Connections|
|-|-|-|-|-|-|-|
|0x0000000002dc69d0|oNJYzGRBzrJPNv|660|n/a|n/a||172.31.1.217:4444|
|0x0000000002e6a340|(Blank)|504|n/a|n/a||172.31.1.217:4444|
|0x000000011e872b30|mnemonic1.exe|2892|n/a||||                                                                                                     
|0x000000011e99e960|powershell.exe|2952|normal|powershell.exe (2672)||172.31.1.217:443 34.208.205.97:443|
|0x000000011e7442b0|powershell.exe|2672|normal||`-s -NoLogo -NoProfile`||
|0x000000011e82f060|explorer.exe|2036|normal|`\Device\NamedPipe\xnyxzm`, `\Device\NamedPipe\iuggwy`||96.17.153.18:443|
|0x000000011f438440|cscript.exe|1632|normal||`C:\Users\vm-user\AppData\Local\Temp\VhjQPqUesT.vbs`||       
|0x000000011e79e060|cscript.exe|2364|normal||`C:\Users\vm-user\AppData\Local\Temp\DybeBcBfkbHPV.vbs`||   

So several of these processes look suspicious.  Let's start with
powershell (2952) and see what we find.

### Yara Rules

The `yarascan` plugin scans for custom binary or textual patterns and
compound rules within memory space.  Using it on the image to search the
powershell.exe (2952) process for the string "https://" shows several
instances of suspicious URL https://unioncentralorchids.com/index.asp followed by some powershell
syntax which looks like outbound callbacks.

`vol.py --profile=Win7SP1x64 -f VM-USER-PC-2017-05-02-202227.raw yarascan -p 2952 --yara-rules="https://"`

![](images/Memory-based%20Attack%20Techniques/image001.png)


We can take the memory location of the string and see it in context
using the `volshell` plugin.

Copy and paste the memory location which is `0x07cd8650`, then start
volshell with:

`vol.py --profile=Win7SP1x64 -f VM-USER-PC-2017-05-02-202227.raw volshell`

At the prompt type `ps()` to see a list of processes

Change to the process we're interested in by typing `cc(pid=2952)`

Display the contents in our copied memory address by typing `db(0x07cd8650)`

Now we can adjust the length of what we want to see...

Type `db(x07cd8650, length=598)` to capture the entire command:

![](images/Memory-based%20Attack%20Techniques/image002.png)


This is the same PowerShell Empire stager we extracted from the packed
file `mnemonic1.exe` which downloads the agent from its C2 server and runs
it in memory.

![](images/Memory-based%20Attack%20Techniques/image003.png)


So we have determined that the mnemonic1.exe packed executable launched
an Empire stager which communicated over HTTPS to its C2 server at unioncentralorchids.com. 

One way to find other processes related to an intrusion is to examine
all for the privileges they have enabled.

### Privileges

A privilege is the permission to perform a specific task and must be
present in the process' token to perform that task.  Here are a few that
malware frequently use:

|Privilege|Description|
|-|-|
|SeBackupPrivilege|This grants read access to any file on the file system, regardless of its specified access control list (ACL). Attackers can leverage this privilege to copy locked files|
|SeDebugPrivilege|This grants the ability to read from or write to another process' private memory space. It allows malware to bypass the security boundaries that typically isolate processes. Practically all malware that performs code injection from user mode relies on enabling this privilege|
|SeLoadDriverPrivilege|This grants the ability to load or unload kernel drivers|
|SeChangeNotifyPrivilege|This allows the caller to register a callback function that gets executed when specific files and directories change. Attackers can use this to determine immediately when one of their configuration or executable files are removed by antivirus or administrators|
|SeShutdownPrivilege|This allows the caller to reboot or shut down the system. Some infections, such as those that modify the Master Boot Record (MBR) don't activate until the next time the system boots. Because of this, you'll often see malware trying to manually speed up the procedure by invoking a reboot|


Running the following shows 4 processes that enabled the
SeDebugPrivilege, a strong indicator of malicious activity:

`vol.py --profile=Win7SP1x64 -f VM-USER-PC-2017-05-02-202227.raw privs | grep 'Enabled '`

![](images/Memory-based%20Attack%20Techniques/image004.png)


Let's add some more information to our table:

|Physical Offset|Name|PID|DLLs|Privs|Handles|CommandLine|Network Connections|Domain|
|-|-|-|-|-|-|-|-|-|
|0x0000000002dc69d0|oNJYzGRBzrJPNv|660|n/a||n/a||172.31.1.217:4444|Private IP|
|0x0000000002e6a340|(Blank)|504|n/a||n/a||172.31.1.217:4444|Private IP|
|0x000000011e82f060|explorer.exe|2036|normal||`\Device\NamedPipe\xnyxzm\` `\Device\NamedPipe\iuggwy`||96.17.153.18:443|CDN (Akamai|
|0x000000011ec2c3c0|powershell.exe|2140|normal|SeDebugPrivilege|||||                                                                                              |0x000000011e872b30|mnemonic1.exe|2892|n/a||||||
|0x000000011e99e960|powershell.exe|2952|normal|SeDebugPrivilege|powershell.exe(2672)||172.31.1.217:443 34.208.205.97:443|Private IP unioncentralorchids.com|
|0x000000011e7442b0|powershell.exe|2672|normal|SeDebugPrivilege||`-s -NoLogo -NoProfile`|||
|0x000000011f438440|cscript.exe|1632|normal|||`C:\Users\vm-user\AppData\Local\Temp\VhjQPqUesT.vbs`|||                            
|0x000000011e79e060|cscript.exe|2364|normal|||`C:\Users\vm-user\AppData\Local\Temp\DybeBcBfkbHPV.vbs`|||                              
|0x000000011ec14060|conhost.exe|1552|normal|SeDebugPrivilege|powershell.exe(2672)||||                                                                           


### Putting it All Together

The following is a good example of starting with network traffic and
using different plugins to trace all the way back to the malicious code
responsible.  Right now, it doesn't appear that this callback was even
successful, but we can tie it to one or more processes, and examine the
processes to identify the cause of the traffic.

If we look closer at the network traffic to the Private IP, we can see
that two processes sent SYNs to port 4444, and one either closed an
existing connection or sent a SYN and timed out to port 443:

![](images/Memory-based%20Attack%20Techniques/image005.png)


Since the victim system did not have a route to the 172.16.0.0/12
network, all three of these attempts most likely failed... but what was
causing these attempts?

We can search for processes that may have had handles to the two
processes calling out to 4444 with the `handles` plugin:

![](images/Memory-based%20Attack%20Techniques/image006.png)


So we can see that at least one of the `cscript.exe` processes had handles
on one of the two hidden processes that were calling out.  This was most
likely a persistence mechanism trying to re-establish a connection with
its C2 server.

Now run the following to find what process had handles on the two
`cscript.exe`'s:

`vol.py --profile=Win7SP1x64 -f VM-USER-PC-2017-05-02-202227.raw handles -t Process | grep '(1632)|(2364)'`

This returns several different processes.  The first one we want to look
at is `explorer.exe` since it spawned both `cscript.exe`'s and is already on
our list of suspicious processes.

Check the loaded dll's within the `explorer.exe` process by typing:

`vol.py --profile=Win7SP1x64 -f VM-USER-PC-2017-05-02-202227.raw dlllist -p 2036`

All dlls appear to be normal so let's check for unlisted dlls or
injected code within this process with `malfind`.

First create an output directory by typing `mkdir output` 

Then run `malfind` on the `explorer.exe` process with:

`vol.py --profile=Win7SP1x64 -f VM-USER-PC-2017-05-02-202227.raw malfind -p 2036 -D output/`

This will dump all suspicious modules detected in to the `output` directory.

Now run an AV scan on all the dumped modules with `clamscan`:

`clamscan output/proc*`

This shows that two modules are identified as meterpreter:

![](images/Memory-based%20Attack%20Techniques/image007.png)


We've identified two different implants present on the victim machine
(meterpreter and Empire) along with one of their persistence mechanisms
(`cscript.exe`) processes initiating requests to port 4444).

Perform further analysis to see if you can answer the following
questions:

## Questions

1. What domain was the C2 server of the meterpreter implant?

2. What persistence mechanism did the PowerShell Empire implant use?

3. What file was used to download and install the meterpreter implant?

4. What type of memory-based attack technique was used by each implant?
