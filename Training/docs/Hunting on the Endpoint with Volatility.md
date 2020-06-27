# Hunting on the Endpoint with Volatility

Hunting is searching for adversaries without a particular indicator. When hunting on the endpoint, that means searching for rogue processes, suspicious network connections, evidence of persistence---any artifacts that could indicate an attack or compromise.

Collecting data from memory is the only way to get the true state of a system at the time of capture and is an excellent hunting technique.  Physical memory can contain all data a system processed including files, network traffic, user input, etc.  It is basically a collection of code and data used on a system over time.

Hunting with Volatility offers several advantages to the analyst including the ability to find:

- Malware in unpacked/unencrypted form
- Injected code that doesn't exist on disk
- Hidden and exited processes
- Closed network connections and sockets
- Cached and deleted files

<br>

This document will review:

- [Memory Analysis Overview](#memory-analysis-overview)
	- [Physical Memory](#physical-memory)
	- [Kernel Objects](#kernel-objects)
	- [Unstructured Analysis](#unstructured-analysis)
	- [Structured Analysis](#structured-analysis)
- [Volatility Setup](#volatility-setup)
	- [Dump Physical Memory](#dump-physical-memory)
	- [Set Environment Variables](#set-environment-variables)
	- [Clone Community Repo](#clone-community-repo)
- [Memory Analysis Steps](#memory-analysis-steps)
	- [Examine Processes](#examine-processes)
	- [Examine DLLs, Handles, and Threads](#examine-dlls-handles-and-threads)
	- [Examine Network Activity](#examine-network-activity)
	- [Search for Code Injection](#search-for-code-injection)
	- [Search for Rootkit Behavior](#search-for-rootkit-behavior)
	- [Dump Processes and Modules](#dump-processes-and-modules)
	
<br>
The memory image used can be found on the OOB at:

`/CSIRT/Sample-Files/win_7.mem`

## Memory Analysis Overview

- [Physical Memory](#physical-memory)
- [Kernel Objects](#kernel-objects)
- [Unstructured Analysis](#unstructured-analysis)
- [Structured Analysis](#structured-analysis)


### Physical Memory

A computer’s memory is constantly changing.  The CPU reads program instructions from dozens of different processes and reads and writes data to and from memory.

This physical memory, also known as main memory or Random Access Memory (RAM), is anywhere from 8 to 32 GB on most of our systems and must support 50-100 different processes, each requiring their own private memory space to store their executable code, imported DLLs, and application data. 

To manage this, each process is assigned "virtual" memory space which the OS maps to an actual location in physical memory (RAM).

So when a program needs to read or write data in memory, it does so using virtual addresses (`0x00000000` to `0x7fffffff` for 32-bit).  But in reality, the data that is read or written exists at physical addresses (`0x000000000` to `0x200000000` for 8GB RAM). These memory spaces are split into fixed-length sections and a page table is used to map virtual addresses to physical offsets in RAM.

In virtual memory, the smallest unit of memory is called a page. In physical memory, or in a paging file on disk, the smallest unit of memory is called a frame. The default page size for most architectures is 4,096 bytes or 4KB or 0x1000 in hex.

The kernel allocates memory using pages.  For small structures, the kernel uses pool memory to store small pieces of data efficiently. Instead of allocating a full 4KB page for an 8 byte piece of data, the kernel stores it with other small structures in a shared pool memory region. This is more efficient in terms of space used as well as the overhead required for allocating and deallocating memory.

Each process's memory is continuously being allocated, used, and deallocated until the moment we pull an image which takes a snapshot of physical memory at that time.  This snapshot contains the memory spaces of all processes that were currently (or recently) running on the system, which contain all the kernel objects each process had created, deleted, or was currently using.

Examining the properties of these kernel objects allow us to determine how they were being used and what actions were performed on a system.


### Kernel Objects

Kernel objects, or executive objects, are the structures that are created and deleted in memory (processes, files, registry keys, etc.). Creating and interacting with objects is how the OS allocates, uses, tracks, and disposes of system resources.

Here are just a few of the many different types of kernel objects:

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
|Type|`_OBJECT_TYPE`|An object with metadata that describes an object|

<br>

Here is an example showing the lifetime of an object in memory:


Let’s say a process (`explorer.exe`) wants to create a new file.  The following happens:

-	Explorer.exe calls a Windows API such as `CreateFileA` or `CreateFileW` from `kernel32.dll`
-	The APIs call the kernel and the `NtCreateFile` function is used to allocate memory for a `_FILE_OBJECT`  object
-	A pointer to the new `_FILE_OBJECT` is added to explorer.exe’s handle table
-	The `explorer.exe` process uses this handle to find the file in memory and interact with it
-	Other processes can now also request a handle to this object and read and write to it
-	When `explorer.exe` is finished reading or writing to the file, it calls a Windows API such as `CloseHandle`
-	If the `_FILE_OBJECT` handle count becomes zero (no processes are using it), the block of memory is released to be reallocated for a different purpose
-	The object is not immediately overwritten—it can persist for days, weeks, even months depending on the system’s requirements and activity

<br>

When performing memory analysis, we need a way of locating interesting objects.  There are two general methods to do this:

- [Unstructured Analysis](#unstructured-analysis)
- [Structured Analysis](#structured-analysis)


### Unstructured Analysis 

Unstructured Analysis is performed by tools that look for specific patterns such as known file headers and footers and carve out the files that are discovered.  Since filesystem structures are not used to find data, this method can be used on any OS, disk images or memory images, even damaged or corrupted filesystems.  The tools simpy look for small pieces of data that fit a specific structure such as credit card numbers, domains, email addresses, and phone numbers.

Some of these tools, such as [Bulkextractor](http://www.forensicswiki.org/wiki/Bulk_extractor), can detect compressed data, decompress it, and search through the decompressed data (Bulkextractor goes down five levels by default).

[Bulkextractor](http://www.forensicswiki.org/wiki/Bulk_extractor) also computes histogram files which show counts of occurrences for types of data found.

- Encryption keys 
- Network packets 
- Email addresses, usernames, URLs, 

This type of analysis works well when data is smaller than 4KB.  If a file is larger than 4KB, it will span multiple pages and will most likely be fragmented which will require structured analysis to obtain the full file.


### Structured Analysis

Structured Analysis uses OS structures to locate and provide context for objects in memory. There are two main ways Volatility uses plugins to do this:

|Method|Plugins|
|-|-|
|[List Traversal](#list-traversal)|`pslist`, `pstree`, `dlllist`, `hivelist`, `handles`, `modules`, `vadwalk`|
|[Pool Scanning](#pool-scanning)|`psscan`, `filescan`, `mutantscan`, `thrdscan`, `driverscan`, `hivescan`, `modscan`, `netscan`|


#### List Traversal		

Plugins that traverse lists use specific offsets to parse OS structures, walking through all the values that the OS knew about. When object information is retrieved, the plugins provide the relevant details along with the **VIRTUAL** addresses of the objects.


#### Pool Scanning

Pool scanning plugins search entire memory image from beginning to end looking for objects that aren't on lists... sockets, threads, file objects, mutants, etc. These may be from a previous boot, or not used anymore, or they could be intentionally unlinked from lists designed to track them. When objects are discovered, the plugins provide the relevant details along with the **PHYSICAL** addresses of the objects.


## Volatility Setup

Volatility runs on Python or can be ran as a standalone Windows executable.  Set up with the following steps:

- [Dump Physical Memory](#dump-physical-memory)
- [Set Environment Variables](#set-environment-variables)
- [Clone Community Repo](#clone-community-repo)


### Dump Physical Memory

In this case the image has already been pulled.  But when examining a sample in a VirtualBox VM, use the following steps to create a memory image for analysis:

1.	Start the VM from the command line using:  `virtualbox --dbg --startvm <vm name>`

2.	When ready to dump memory, select `Debug` --> `Command Line`

3.	Dump memory to a file with the command:  `.pgmphystofile <image name>.mem`

The RAM image will be saved to the current directory and can be read by Volatility.



### Set Environment Variables

When you set the location and profile environment variables for Volatility, you don't need to specify them each time you run a plugin:

```
export VOLATILITY_LOCATION=file:///sample.mem
export VOLATILITY_PROFILE=Win7SP1x64
```

### Clone Community Repo

The community repo contains a large collection of plugins that can be used in addition to the ones that come default with Volatility.

Copy it to your home directory using:

```
git clone https://github/volatilityfoundation/community
```

When using one of these plugins, you must place the `plugins` switch immediately after the Volatility binary:

```
vol.py --plugins=/home/remnux/community -f win_7.mem --profile=Win7SP1x64 dnscache
```
<br>


## Memory Analysis Steps

Best practices for hunting in memory include using the following steps:

- [Examine Processes](#examine-processes)
- [Examine DLLs, Handles, and Threads](#examine-dlls-handles-and-threads)
- [Examine Network Activity](#examine-network-activity)
- [Search for Code Injection](#search-for-code-injection)
- [Search for Rootkit Behavior](#search-for-rootkit-behavior)
- [Dump Processes and Modules](#dump-processes-and-modules)


### Examine Processes

Use the following process listing and scanning plugins to find processes with unusual characteristics:

|Plugin|Description|
|-|-|
|`pslist`|Walks doubly-linked list and shows process info|
|`pstree -v`|Shows tree with command line, image file name, and audit path|
|`psscan`|Scans for hidden processes|
|`psxview`|Shows if any processes are missing from any lists|

<br>

Learn to recognize and verify these critical processes along with their respective accounts, session, and descriptions:

|Name|Process Name|PID|Session|Owner|Description|
|-|-|-|-|-|-|
|Idle|System Idle|0|0|NTAUTHORITY\SYSTEM|Container that the kernel uses to charge CPU time for idle threads|
|System|System|4|0|NTAUTHORITY\SYSTEM|Default home for threads that run in kernel mode|
|Session Manager|smss.exe|-|0|NTAUTHORITY\SYSTEM|Creates session 0 (OS), sessions 1 and up (user), csrss, and winlogon|
|Client/Server Runtime|csrss.exe|-|0|NTAUTHORITY\SYSTEM|Creates/deletes processes, threads, temp files, etc.|
|Windows Initialization|wininit.exe|-|0|NTAUTHORITY\SYSTEM|Creates lsm, lsass, and services, creates `%windir%\temp`|
|Load Session Manager|lsm.exe|-|0|NTAUTHORITY\SYSTEM|Manages the state of terminal server sessions|
|Local Security Authority|lsass.exe|-|0|NTAUTHORITY\SYSTEM|Enforces the security policy, verifies passwords, creates access tokens, etc|
|Service Control Manager|services.exe|-|0|NTAUTHORITY\SYSTEM|Loads and manages services|
|Service Hosting|svchost.exe|-|0|NTAUTHORITY\SYSTEM<br>NTAUTHORITY\LOCAL SYSTEM<br>NTAUTHORITY\NETWORK SERVICE|Provides a container for DLLs that implement services|
|Windows Logon|winlogon.exe|-|1|NTAUTHORITY\SYSTEM|Presents the interactive logon prompt, screen saver, loads user profiles|
|Windows Explorer|explorer.exe|-|1|DOMAIN\USER|Handles GUI-based folder navigation, start menu, etc|
|Windows Logon|winlogon.exe|-|1|DOMAIN\USER|Presents the interactive logon prompt, screen saver, loads user profiles|

<br>

Some things we should look for here:

- What processes are running and what are they doing?  Are there any processes present that do not have a legitimate reason to be running?

- User processes are user programs, have session 1 and can be tracked back to Explorer.exe.  Are there any user level processes that are running at session 0?

- System processes are part of the OS, have session 0 and can be tracked back to System.  Are there any system processes that are running at session 1?

- System processes should not spawn user processes and vice versa.  Looking at the parent processes for each process, are there any anomalies like this?

- Malicious processes often have one or more of the following: unusual parent, odd executable path, incorrect spelling, incorrect SID, unusual start time, unusual command line argument---Do any of the processes have any of these?

<br>

After running `pslist`, `pstree`, `pscan`, and `psxview`, there doesn't appear to be any unusual or hidden processes.



### Examine DLLs Handles and Threads

- [DLLs](#dlls) - the libraries a process is using
- [Handles](#handles) - references used to interact with objects
- [Threads](#threads) - the way processes execute their code on the system

#### DLLs

DLLs can be loaded by a process (the normal way), injected into processes, executed with `rundll32.exe`, or implemented as services with `svchost.exe`.

Each running process has a ProcessEnvironmentBlock (PEB) which contains process information including a list of loaded modules---the original executable and DLLs used.

The listing plugin `dlllist` shows the DLLs loaded by a process and listed in their PEB.  The scanning plugin `ldrmodules` shows DLLs loaded by a process that have been unlinked from the PEB.  This allows us to see all loaded DLLs even if PEB Unlinking has been performed.

Use the following DLL listing and scanning plugins to find DLLs with unusual characteristics:

|Plugin|Description|Example|
|-|-|-|
|`dlllist`|Display loaded DLLs listed in PEB|`dlllist -p <pid>`|
|`ldrmodules`|Detects unlinked DLLs by comparing VAD data to lists in PEB|`ldrmodules -p <pid>`| 
|`dlldump`|Dump DLLs to a directory|`dlldump -p PID -D <dir>`|
||Dump unlinked DLL by offset|`dlldump -o <offset>`|
||Dump unlinked DLL by address|`dlldump -b <baseaddr>`|


<br>

Here are some techniques to look for when examining a process's DLLs:

|Technique|Description|
|-|-|
|Remote DLL Injection|Malicious process loads a DLL from disk into a target process|
|DLL Hijacking|Process is forced to load a malicious DLL file from disk|
|Module Hollowing|Legitimate module is loaded from disk, then overwritten with malicious code|

<br>

Some things we should look for here:

- Are there any unlinked DLLs?

- Are there any DLLs not in standard paths such as System32 or the same directory as the executable loading it?

- Are there any DLLs with odd context such as names or load timestamps?

<br>

### Handles

The `handles` plugin walks the handle tables for each process and shows the handles they had to objects.

|Plugin|Description|Example|
|-|-|-|
|`handles`|display handles to all objects|`handles -p=<pid>`|
||display handles by offset|`handles -o <offset>`|
||display handles by object type|`handles -t <object type>`|

<br>

Some things we should look for here:

- Are there any handles to objects unusual for the process?

- Are there any handles to processes, files, or registry keys of interest?

- Are there any handles to mutex objects that are either unknown or known to belong to malicious programs?

<br>

### Threads

Threads execute independently inside of the process using their own own ThreadID, register set, and stack.  However, they share the same code, data, address space, and OS resources.  The CPU executes multiple threads, switching back and forth, suspending the execution of one and resuming another, and saving each thread’s context in main memory.

Use the following thread listing and scanning plugins to find interesting threads:

|Plugin|Description|Example|
|-|-|-|
|`threads`|Searches lists for all threads|`threads`|
||List available filters that can be used|`threads -L`|
||Specify a filter to use|`threads -F <filter>`|
|`thrdscan`|Does a brute force search for ETHREAD structures|`thrdscan`|

<br>

Some things we should look for here:

- Are there any threads that start from a memory region that is executable and not associated with a memory-mapped file?

- Are there any threads that have unusual start/exit times?

<br>


At this point, we usually have a process we're interested in that we can investigate further by examining its loaded DLLs, object handles, and threads.  

We could dump every DLL for every process and perform YARA or AV scans, but for now let's move on to the next step and circle back once we narrow it down to a process.


### Examine Network Activity

The `netscan` plugin shows network connections and sockets for Win7/2008 and later.

Here are the possible states a connection can have:

|State|Description|
|-|-|
|CLOSED|No connection|
|LISTENING|Waiting for connection|
|SYN-SENT|SYN sent but not acknowledged|
|SYN-RECEIVED|SYN received and acknowledged|
|ESTABLISHED|Open connection|
|FIN-WAIT-1|Termination request sent but not acknowledged|
|FIN-WAIT-2|Termination request sent but not acknowledged|
|TIME-WAIT|Termination request received, waiting for remote host to acknowledge|
|CLOSE-WAIT|Waiting for termination request from local process|
|LAST-ACK|Waiting for acknowledgement of termination request|

<br>

After running this plugin, we find a process initiating network connections that shouldn't be---rundll32.exe:

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image001.png)<br><br>


At this point, we should circle back and look at the process and its DLLs, handles, and threads:

The `pslist` plugin shows the start time and parent process which can't be found (1312):

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image002.png)<br><br>


The `dlllist` plugin shows an unusually low number of loaded DLLs:

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image006.png)<br><br>


This happens to be a special case for WOW64 processes as they do not list all DLLs in the process's PEB.

And as Volatility states, we should use the `ldrmodules` plugins to list all loaded DLLs for the Wow64 process:

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image003.png)<br><br>


Nothing unusual is observed, let's look at the process's handles with:

```
vol.py handles -p 576
```

Besides handles to objects normally accessed when using the network, nothing unusual observed.

Specifying the type as 'mutant', we can get Mutex objects:

```
vol.py handles -t mutant
```

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image007.png)<br><br>

Examine the process's threads with:

```
vol.py threads -p 576
```

In this case the `thrdscan` plugin shows the same threads:

```
vol.py thrdscan | grep ' 576\|Off'
```

Grepping for the 'Off' lets us keep the column headers:

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image008.png)<br><br>

Two threads in this process have a starting address that is labelled UNKNOWN:

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image015.png)<br><br>

This could indicate an injected thread.


### Search For Code Injection

When hunting for code injection, we should be looking for the following techniques:

|Technique|Description|
|-|-|
|Remote Code Injection|Malicious process injects code into memory space of target process and executes it|
|Reflective DLL Injection|Malicious process writes DLL into memory space of target process which loads itself|
|Process Hollowing|Malicious process starts new instance of legitimate process, suspends it, empties code and replaces with malicious code|

<br>

And use the following plugins for detection:

|Plugin|Description|
|-|-|
|`malfind`|Detects and extracts injected code, API hooks|
|`hollowfind`|Detects process hollowing|



<br>

The `malfind` program looks for hidden or injected code and DLLs.  It searches for memory segments with executable permissions that are not backed by an image (marked as Private instead of Image) as well as executables that aren't listed in the process's module lists in its PEB. 

Here are descriptions of the different memory permissions:

|Permission|Description|
|-|-|
|PAGE_EXECUTE|The memory can be executed, but not written. This protection cannot be used for mapped files|
|PAGE_EXECUTE_READ|The memory can be executed or read, but not written|
|PAGE_EXECUTE_READWRITE|The memory can be executed, read, or written. Injected code regions almost always have this protection|
|PAGE_EXECUTE_WRITECOPY|Enables execute, read-only, or copy-on-write access to a mapped view of a file. It cannot be set by calling VirtualAlloc or VirtualAllocEx. DLLs almost always have this protection|
|PAGE_NOACCESS|Disables all access to the memory. This protection cannot be used for mapped files. Applications can prevent accidental reads/writes to data by setting this protection|
|PAGE_READONLY|The memory can be read, but not executed or written|
|PAGE_READWRITE|The memory can be read or written, but not executed|
|PAGE_WRITECOPY|Enables read-only or copy-on-write access to a mapped view of a file. It cannot be set by calling VirtualAlloc or VirtualAllocEx|

<br>

The `malfind` plugin detects two injected modules in the `rundll32.exe` process:

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image004.png)<br><br>

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image005.png)<br><br>

We can dump these modules specifying the dump directory `dump` with the `-D` switch:

```
vol.py malfind -p 576 -D dump/
```


Using the `file` command, one is identified as an executable, and the other as data:

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image009.png)<br><br>


Looking at the contents of both files, they both appear to be executables, only the 'MZ' file header has been stripped from the second:

```
hexdump -C process.0xfffffa800398f060.0x100000.dmp -n 120
```

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image010.png)<br>

```
hexdump -C process.0xfffffa800398f060.0x2b0000.dmp -n 120
```

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image011.png)<br><br>

We can learn more about these using static, dynamic, and code analysis.


### Search For Rootkit Behavior

The following plugins search for indications of a rootkit including malicious redirections, IDT/GDT modifications, and malicious callbacks:

|Plugin|Description|
|-|-|
|`apihooks`|Detects IAT and inline hooks|
|`idt`|used to search for IDT hooks|
|`gdt`|used to search for GDT hooks|
|`callbacks`|used to search for malicious callbacks|
|`driverirp`|used to search for hooked IRP functions|
|`devicetree`|used to search for malicious drivers|
|`timers`|used to search for malicious use of kernel timers|

Nothing interesting is found with the above plugins---we'll explore these more with future samples.


### Dump Processes and Modules

Volatility can dump the entire memory space of a process or dump a process's executable from memory and rebuild for static and code analysis.

|Plugin|Description|
|-|-|
|`procdump`|parses PE header and reads pages from memory creating new file on disk that is as close as possible to the original PE before it was loaded into memory|
|`memdump`|dumps out the process memory space of entire executable, without putting sections back into PE format|


#### procdump

All PE files loaded into memory are considered modules: executables, DLLs, and kernel drivers.  Each has a header that points to a number of sections and specifies the location and size of each section on the disk and in RAM.  

When a module is loaded:

- Each section is copied from the disk into memory
- Functions imported from other modules are found and mapped, the IAT is updated
- A virtual address is chosen, if address is taken then the PE is relocated
- If relocation of the module is required the new base address is updated throughout the module

Changes made to the IAT and the relocations will prevent us from recovering an exact copy of the original file, but it is possible to get very close using `procdump`.  

In this case we have found indications that the process `rundll32.exe` was injected into so we are more interested in dumping the process's memory space.


#### memdump

The `memdump` plugin creates a file that holds the contents of virtual memory for the process.  

Here the `rundll32.exe` memory space is dumped into a file named `576.dmp`:

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image012.png)<br><br>


Once you have dumped the executable and/or the virtual memory for the process, you can search for strings:

For ASCII strings:

```
strings -a 576.dmp > Ascii.Strings.txt
```

For Unicode strings:

```
strings -a -e l 576.dmp > Unicode.Strings.txt
```

![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image013.png)<br><br>


![](images/Hunting%20on%20the%20Endpoint%20with%20Volatility/image014.png)<br><br>

In addition to the memory space of the injected process, we have also extracted the two injected modules with `malfind` which we can load in a debugger/disassembler for code analysis.

<br>

## Summary

Hunting in memory with Volatility not only allows recovery of memory-only artifacts not available on disk or the network, but also provides a more accurate and complete picture of the state of the endpoint during the time the memory image was captured.  Finding and analyzing hidden processes, injected code, and malware in its unpacked or unencrypted form are just a few of the advantages Volatility has over traditional tools.  
