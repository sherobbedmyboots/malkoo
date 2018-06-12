# Memory Analysis with Volatility

[Effective detection and response](https://sector.ca/wp-content/uploads/presentations16/Case-Sector-2016-Scalable-IR.pdf) requires visibility, historical data, and analysis processes that can defeat anti-forensics:

- **Visibility** - Monitor the current state of systems and the network
- **Historical data** - Endpoint logs and network data to support investigations
- **Analysis processes that defeat anti-forensics** - Centralized logging, memory analysis

As we have learned, sometimes one or more of these requirements are missing or are incomplete which makes analysis and response extremely difficult.  This document will walkthrough analysis of two infected systems from last week's exercise using only a memory image to demonstrate what memory forensics can provide in an incident involving missing/incomplete historical data or loss of visibility to the victim system. Then we'll compare what we found to the logs and alerts caused by each system's compromise.

- [Analysis of 1](#analysis-of-1)
- [Analysis of 2](#analysis-of-2)



### Analysis of 1

This system had multiple alerts in FireEye on 4/10 and 4/11 and the request for the acquisition of full memory happened the next day on 4/12.  Let's see what we can find using [Volatility](http://www.volatilityfoundation.org/).

First run the `pstree` module to look at the running processes:

![](images/Memory%20Analysis%20with%20Volatility/image001.png)<br><br>

The two `powershell.exe` processes followed by multiple `rundll32.exe` processes are an indication of malicious activity so we want to work towards identifying the entire process chain starting with the `svchost.exe` process:

```
- svchost.exe (364) 
 - WmiPrvSE.exe (3972) 
  - cmd.exe (10800) 
   - powershell.exe (9876) 
    - powershell.exe (11088) 
     - rundll32.exe (10252, 9812,...) 
```

<br>

Next, use the `cmdline` plugin to see the command-line arguments for each process:

![](images/Memory%20Analysis%20with%20Volatility/image002.png)<br><br>


Decoding the Base64 command that was executed by PowerShell reveals a web request that downloads a file:

![](images/Memory%20Analysis%20with%20Volatility/image006.png)<br><br>

This technique is frequently used by malware to download and a script and execute it in memory.  If the script created objects in the PowerShell session, we can search for them by dumping process memory with the `memdump` plugin and searching for object-tagged strings with PowerShell's [Select-String](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-6):

```powershell
mkdir 9876
vol -f 1.mem --profile=Win7SP1x64 memdump -p 9876 -D 9876
$objs = sls '<Obj RefId=.*</Obj>' .\9876\9876.dmp | %{$_.Matches} | %{$_.Value}
```

<br>

This returned 22 results.  The 20th one `objs[19]` contains some interesting code which we can extract using `[regex]::match`:

```powershell
[regex]::match($objs[19], 'N="V">([^\<]+)\<').Groups[1].Value
```


![](images/Memory%20Analysis%20with%20Volatility/image055.png)<br><br>

We have seen this file before---it is used to launch the stager for the Cobalt Strike Beacon.  Remember the first PowerShell process generates the code needed to set up the .NET environment and stores it in the `DoIt` variable:

![](images/Memory%20Analysis%20with%20Volatility/image020.png)<br><br>


It then checks to see if it's running in a 64-bit process with `[IntPtr]::size`.  If it is, then it will start a new 32-bit PowerShell process with [Start-Job](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/start-job?view=powershell-6) to run the code in the `DoIt` variable. If not, it will run this code in the current process.

![](images/Memory%20Analysis%20with%20Volatility/image019.png)<br><br>


We can use the `ldrmodules` plugin to confirm that the first PowerShell process was a 64-bit process.  It shows that the `9876` PowerShell process was loaded from the `System32` directory so the 32-bit `11088` PowerShell process was created which runs out of the `SysWOW64` directory:

```powershell
vol -f 1.mem --profile=Win7SP1x64 ldrmodules -p 9876,11088 | sls exe$
```

![](images/Memory%20Analysis%20with%20Volatility/image050.png)<br><br>

The code in the `DoIt` variable runs using .NET reflection to interact with the Windows API and download the Beacon one request at a time. After it's completely downloaded, the Beacon runs in the PowerShell process and can spawn additional processes like `rundll32.exe` to execute post-exploitation jobs:

![](images/Memory%20Analysis%20with%20Volatility/image021.png)<br><br>

Notice that two `rundll32.exe` processes exit seconds after they are created while one appears to have still been running at the time of memory acquisition:

```powershell
vol -f 1.mem --profile=Win7SP1x64 pslist | sls 11088
```

![](images/Memory%20Analysis%20with%20Volatility/image007.png)<br><br>


The two short-lived `rundll32.exe` processes were most likely used to execute post-exploitation modules for the Beacon.  In the past, Beacon jobs have been observed using the syntax `powershell -nop -exec bypass -EncodedCommand "SQBFAFgAIA..."` so we can search for similar strings in each `rundll32.exe` process with:

```powershell
vol -f 1.mem --profile=Win7SP1x64 yarascan -p 10252,10176,9812,10024 --yara-rule="powershell -nop -exec bypass -EncodedCommand"
```

<br>

We get one hit for the `10252` process:

![](images/Memory%20Analysis%20with%20Volatility/image052.png)<br><br>

The `volshell` plugin can be used to inspect any address in memory.  By navigating to the address where the string was found, we can obtain the entire command:

```powershell
db(0x02493800, 500)
```

![](images/Memory%20Analysis%20with%20Volatility/image051.png)<br><br>

One way to search all the `rundll32.exe` processes for these strings is to dump each process with the `memdump` plugin:

```powershell
vol -f 1.mem --profile=Win7SP1x64 memdump -p 10252,10176,9812,10024 -D dump
```

<br>

And then use PowerShell's [Select-String](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-6) with a regular expression:

```powershell
Select-String -Path *.dmp -Pattern 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQB[a-zA-Z0-9=+/]{200,}' | %{$_.Matches} | %{$_.Value} 
```

<br>

Piping the results to the [ConvertFrom-Base64]() cmdlet shows the syntax of a post-exploitation module being run:

```powershell
Select-String -Path *.dmp -Pattern 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQB[a-zA-Z0-9=+/]{200,}' | %{$_.Matches} | %{$_.Value} | %{ConvertFrom-Base64 $_}
```

![](images/Memory%20Analysis%20with%20Volatility/image053.png)<br><br>


Let's review the process chain we have so far:

```
- svchost.exe (364) 
 - WmiPrvSE.exe (3972)
  - cmd.exe (10800) calls powershell with encoded command
   - powershell.exe (9876) downloads 'a' file, runs it with IEX, checks if 32 or 64-bit process
    - powershell.exe (11088) runs "Doit" code, loads .NET, stager downloads and runs the beacon DLL
     - rundll32.exe (10252, 9812,...) multiple instances are created to run post-exploitation jobs
```

<br>

Knowing this, we should expect to find a copy of the stager and the Beacon in the memory space of `powershell.exe` process `11088`.

The `malfind` plugin can detect [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection) by examining memory segments that are executable, marked as private, or are memory-resident only.  DLLs that have no mapped path indicate an injected DLL not on disk.

Run the `malfind` plugin to dump any injected code found in the `11088` process:

```powershell
vol -f 1.mem --profile=Win7SP1x64 malfind -p 11088 --dump-dir=11088
```

![](images/Memory%20Analysis%20with%20Volatility/image003.png)<br><br>

There are three files here that we are interested in:

- [Stager](#stager)
- [Decoded Payload](#decoded-payload)
- [Beacon DLL](#beacon-dll)

#### Stager

The first file that is 4096 bytes in size is the memory space allocated for the stager that was run by the dynamically generated .NET assembly. You can see the User Agent `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727)` and URL `x.x.x.x` that was used for the network connections:

![](images/Memory%20Analysis%20with%20Volatility/image004.png)<br><br>

By using a hex editor or Cyber Chef, we can search the web for the escaped (`\x`) hex representation of this shellcode.

![](images/Memory%20Analysis%20with%20Volatility/image011.png)<br><br>

Cobalt Strike uses code derived from Metasploit, so you'll find that much of the code is almost identical to the shellcode generated by [Metasploit's reverse HTTPS stager](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/windows/reverse_https_proxy.rb) with proxy support.  

![](images/Memory%20Analysis%20with%20Volatility/image012.png)<br><br>

The stager's job is to allocate 4 MB of memory space for Beacon's reflective DLL, download it into memory, and pass execution to it.


#### Decoded Payload

In order to evade network detection tools, Beacon's reflective DLL is XOR-encoded and prepended with a small stub that queries its size, finds its XOR key, and uses it to decode the rest of the blob in place.  Once it is decoded, it passes execution to its `ReflectiveLoader` function which loads itself into memory.

If you inspect the 4 MB memory dump you will see the decoded DLL and the stub at the beginning of the file that decoded it.  If you disassemble the stub code you will find the opcodes that performed the XOR decoding:

![](images/Memory%20Analysis%20with%20Volatility/image013.png)<br><br>


Once the stub finishes decoding the reflective DLL, it passes execution to the DLL's `ReflectiveLoader` function.  This function does many of the same things that the [LoadLibrary](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175.aspx) function would do:

- calculates images base address
- gets the PEB, gets locations of libraries it needs
- loads image into a new permanent location in memory
- loads all sections into memory
- process image's import table, relocations
- call images entry point

If successful, the Beacon DLL is copied to another place in memory and begins running inside the injected process.

#### Beacon DLL

The third memory space we're interested in (270k) is where the Beacon DLL was written into memory to run permanently in the injected process.  Now that we have a copy of this DLL on disk, we can use various tools to perform static analysis:

```powershell
cat .\process.0xfffffa80150de060.0x4920000.dmp -head 1 | Format-Hex
```

![](images/Memory%20Analysis%20with%20Volatility/image005.png)<br><br>


The Beacon can also be found in the `rundll32.exe (10252)` process along with the decoded DLL with stub---just as we saw in the `powershell.exe (11088)` process.  But there is no file containing the stager here:

![](images/Memory%20Analysis%20with%20Volatility/image054.png)<br><br>

This indicates the `rundll32.exe` process was created for the purpose of migrating out of the PowerShell process.  Since the DLL didn't need to be downloaded this time, the stager was not written to this process's memory space.

Now that we've located the Beacon and a process that it migrated to, let's go back the other way with our process chain and try to determine how it was introduced to the system:

```
- svchost.exe (364)  
 - WmiPrvSE.exe (3972) 
  - cmd.exe (10800) calls powershell with encoded command
   - powershell.exe (9876) downloads 'a' file and runs it with IEX, checks if 32 or 64-bit process
    - powershell.exe (11088) runs "Doit" code, loads .NET, stager downloads and runs the beacon DLL
     - rundll32.exe (10252) created to migrate into from powershell.exe process
     - rundll32.exe (9812,...) multiple instances are created to run post-exploitation jobs
```

<br>

Every process has a token which includes the security identifiers (SIDs) of users or groups that the process is running as and the privileges that it is allowed to perform.  Here is a list of standard accounts and their integrity level:

|Account|Integrity Level|
|-|-|
|Anonymous|Untrusted Mandatory Level|
|Everyone|Low Mandatory Level|
|Authenticated Users|Medium Mandatory Level|
|Cryptographic Operators|High Mandatory Level|
|Backup Operators|High Mandatory Level|
|Administrators|High Mandatory Level|
|NETWORK SERVICE|System Mandatory Level|
|LOCAL SERVICE|System Mandatory Level|
|SYSTEM|System Mandatory Level|

<br>

The `privs` and `getsids` plugins show us the `11088` PowerShell process was running with a High Mandatory Level security context with nearly all privileges enabled:

![](images/Memory%20Analysis%20with%20Volatility/image037.png)<br><br>

This is a good indication that the processes were started by an administrator account.  Since the WMI Provider Service `WmiPrvSE.exe` was used to execute `cmd.exe`, the most likely explanation is that an administrator account interacted with the system remotely using WMI.  

WMI uses the Distributed Component Object Model (DCOM) to make Remote Procedure Calls (RPC) when making a remote WMI connection.  Scanning for services with `svcscan` reveals the DcomLaunch service was running under svchost.exe (364):


```powershell
vol -f 1.mem --profile=Win7SP1x64 svcscan | sls 'Process Id: 364' -Context (3,6)
```

![](images/Memory%20Analysis%20with%20Volatility/image014.png)<br><br>

After determining the role each process played in the chain, we get a better idea of the events and the order in which they occurred on the system:

```
- svchost.exe (364) hosts the DcomLaunch service 
 - WmiPrvSE.exe (3972) uses DCOM to handle remote WMI calls
  - cmd.exe (10800) calls powershell with encoded command
   - powershell.exe (9876) downloads 'a' file and runs it with IEX, checks if 32 or 64-bit process
    - powershell.exe (11088) runs "Doit" code, loads .NET, stager downloads and runs the beacon DLL
     - rundll32.exe (10252) created to migrate into from powershell.exe process
     - rundll32.exe (9812,...) multiple instances are created to run post-exploitation jobs
```

<br>

Finally, to see what account made the WMI call we can use the `envars` plugin which shows the environment variables for each process.

The username environment variable for the original `cmd.exe` was applied to all processes spawned from it:

```powershell
vol -f 1.mem --profile=Win7SP1x64 envars -p 10800,9876,11088,10252 | sls USERNAME
```


![](images/Memory%20Analysis%20with%20Volatility/image015.png)<br><br>


#### Check Logs and Alerts

Since the EDR agent was installed on this host, we can check the alerts to ensure it aligns with our analysis:

This alert shows the WMI call spawning `cmd.exe`:

![](images/Memory%20Analysis%20with%20Volatility/image031b.png)<br><br>

And this alert shows the `rundll32.exe` process calling PowerShell to execute the Invoke-Bloodhound post-exploitation module:

![](images/Memory%20Analysis%20with%20Volatility/image031.png)<br><br>



## Analysis of 2

This system first alerted on 4/11 at 15:37Z and full memory was requested the next day on 4/12.

First, run Volatility's `pstree` plugin to see a list of processes:

![](images/Memory%20Analysis%20with%20Volatility/image035.png)<br><br>

We see a PowerShell process spawning a `rundll32.exe` process, let's start there.

Run `malfind` to detect any injected processes with:

```powershell
vol -f 2.mem --profile=Win7SP1x64 malfind
```

<br>

Processes `explorer.exe`, `lync.exe`, and `powershell.exe` all contain what looks to be DLLs injected in memory:

![](images/Memory%20Analysis%20with%20Volatility/image036.png)<br><br>

Make a directory for each process and dump the injected content from each one at a time with the `-D` option:

```powershell
vol -f 2.mem --profile=Win7SP1x64 malfind -p 6472 -D 6472/
```

<br>

The `explorer.exe` process has what looks to be a keylogger based on the project file name discovered:

![](images/Memory%20Analysis%20with%20Volatility/image016.png)<br><br>

The DLLs exported function named `ReflectiveLoader` also indicates it was reflectively loaded:

![](images/Memory%20Analysis%20with%20Volatility/image018.png)<br><br>


The file at `0x46b0000` in the `lync.exe` process was quickly detected by EDR when I tried to open it with a hex editor:

![](images/Memory%20Analysis%20with%20Volatility/image017.png)<br><br>

But examining it with the `volshell` plugin shows it could be the same keylogger DLL that was injected into the `explorer.exe` process:

![](images/Memory%20Analysis%20with%20Volatility/image056.png)<br><br>

![](images/Memory%20Analysis%20with%20Volatility/image057.png)<br><br>


The areas of memory that were dumped from the `powershell.exe` process include what looks to be the same three files we found on the last system:

![](images/Memory%20Analysis%20with%20Volatility/image022.png)<br><br>

Examining in a hex editor confirms it is the stager (4K), the decoded Beacon DLL with stub (4MB), and the Beacon DLL itself (270K).


Here we see some of the functions it imports:

![](images/Memory%20Analysis%20with%20Volatility/image023.png)<br><br>

As well as the module name (`beacon.dll`) and the function it exports (`_ReflectiveLoader@4`):

![](images/Memory%20Analysis%20with%20Volatility/image024.png)<br><br>

Dump the memory of the `rundll32.exe` process and search for suspicious strings with:

```powershell
vol -f 2.mem --profile=Win7SP1x64 memdump -p 11064 -D 11064
strings -n 10 11064\11064.dmp | sls encoded
```

<br>

In the results we find an encoded PowerShell command:

![](images/Memory%20Analysis%20with%20Volatility/image058.png)<br><br>

This is a unique way to launch powershell and searching the web reveals it is used by the Metasploit Framework's [msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/) when generating PowerShell payloads.  Again, since [Cobalt Strike](https://www.cobaltstrike.com/) uses code derived from Metasploit, this is likely the result of one of Cobalt Strike's modules for lateral movement.

Looking at the PowerShell process, running `envars` doesn't give us the name of the compromised account this time:

```powershell
vol -f 2.mem --profile=Win7SP1x64 envars -p 6472 | sls USERNAME
```

![](images/Memory%20Analysis%20with%20Volatility/image025.png)<br><br>


When we run `getsids`, the High Mandatory Level security context indicates the process was running under either the NETWORK SERVICE, LOCALS SERVICE, or SYSTEM account:

![](images/Memory%20Analysis%20with%20Volatility/image032.png)<br><br>

Here's our process chain at this point:


```
- ??? (10984) 
  - powershell.exe (6472) 
    - rundll32.exe (11064) 
```

<br>

Process `10984` cannot be found in the image, but we think it is likely `cmd.exe` from the syntax we found above.  We don't know its parent process either, but we know whatever called it was running with a High Mandatory Level security context.

The most common way a remote user can start a process running as SYSTEM is to use a privileged account to create a service via the Service Control Manager.  The new service will run with SYSTEM privileges and any processes this service spawns will also run as SYSTEM.

[Cobalt Strike](https://www.cobaltstrike.com/) includes a module named `psexec_psh` which does this:

![](images/Memory%20Analysis%20with%20Volatility/image033.png)<br><br>


We can test this in a lab and see what logs and artifacts are generated when it executes successfully:

![](images/Memory%20Analysis%20with%20Volatility/image034.png)<br><br>


This generated 7045 and 7009 events in the System logs:

![](images/Memory%20Analysis%20with%20Volatility/image038.png)<br><br>

![](images/Memory%20Analysis%20with%20Volatility/image039.png)<br><br>



### Check Logs and Alerts

When we check the System logs, we see Event 7045 shows a similarly named service was installed using the syntax we observed in the memory image and an encoded PowerShell command was passed as the Service File Name:

![](images/Memory%20Analysis%20with%20Volatility/image029.png)<br><br>

This service timed out just like in the test with Cobalt Strike:

![](images/Memory%20Analysis%20with%20Volatility/image030.png)<br><br>

