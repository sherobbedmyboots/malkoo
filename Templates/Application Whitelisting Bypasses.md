# Application Whitelisting Bypasses
 
Malware is constantly evolving.  As whitelisting, code-signing, and
reputation services have improved, there has been a significant shift
towards malware using trusted components to run its malicious code, also
known as "living off the land". 
 
Where traditional malware might run in its own processes and implement
its own C2, modern malware attempts to blend in with normal activity by
using legitimate programs and functions for execution, lateral movement,
C2, and persistence.
 
Last week we used AppLocker, one of Microsoft's application whitelisting
solutions, to prevent malware from dropping and executing untrusted
binaries and scripts on our host.
 
This week we'll look at different techniques that can be used to bypass
application whitelisting and how we can detect them:
 
- [Bypassing Path Rules](#bypassing-path-rules)
 
- [Bypassing Publisher Rules](#bypassing-publisher-rules)
 
- [Leveraging Trusted Programs](#leveraging-trusted-programs)
 
The following files will be used in the examples and are available on
the OOB at /CSIRT/Sample-Files/bypass:
 
|File|Description|
|-|-|
|assembly .xml|Calls out to a C2 address|
|bypass.bat|Prints "BAT script executed"|
|bypass.cmd|Prints "Cmd script executed"|
|bypass.dll|Calls out to a C2 address|
|bypass.exe|Mimikatz with a fake Microsoft digital signature|
|bypass.hta|Allows execution of JavaScript or VBScript|
|bypass.js|Prints "JavaScript executed"|
|bypass.ps1|Prints "PowerShell script executed"|
|bypass.sct|Prints "VBScript executed"|
|bypass.vbs|Prints "VBScript executed"|
|bypass.xml|Prints "JavaScript executed"|
|dotnet-bypass.exe|Calls out to a C2 address|
|mimikatz.exe|Credential stealer, post-exploitation tool|
 
 
 
 
## Set Up
 
First let's configure AppLocker and create some basic rules for
executables and scripts:
 
### 1. Start AppIDSvc (required for AppLocker)
 
For Windows 7:
 
```powershell
Set-Service AppIDSvc --StartupType Automatic
Start-Service AppIDSvc
```
 
For Windows 10:
 
```powershell
Set-ItemProperty --Path HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc --Name Start --Value 2
Start-Service AppIDSvc
```
 
### 2. Configure AppLocker
 
```powershell
gpedit
```
 
Then:
 
- Computer --> Windows Settings --> Security Settings --> Application Control Policies --> AppLocker
 
- Create default rules for executables and scripts
 
- Delete BUILTIN\Administrator rule for executables and scripts
 
- Configure rule enforcement for all scripts and executables
 
 
### 3. Configure PowerShell Execution Policy back to default
 
```powershell
Set-ExecutionPolicy --Scope CurrentUser Undefined
Set-ExecutionPolicy --Scope LocalMachine Unrestricted
```
 
 
## Bypassing Path Rules
 
With the two path rules being enforced, attempting to run mimikatz.exe
on the Desktop is denied by the default Path rules:
 
![](images/Application%20Whitelisting%20Bypasses/image001.png)
 
 
But if this executable is moved to a path that is whitelisted, it will
be allowed to run.
 
Since our user account is in the Administrators group, we could move
this file to `C:\Windows` or `C:\Program Files`, but a normal user would
need to search for a place they can write to under these directories.
 
There are already tools that have the capability to do this, but an
attacker may choose to use a simple script to find a directory that
meets these conditions.
 
For example, this is a short script that checks a directory for folders
with ACLs that allow normal users to write/create and execute files.
 
![](images/Application%20Whitelisting%20Bypasses/image002.png)
 
 
Since one of the default path rules whitelists everything under
`C:\Windows`, a non-privileged user would probably run the script there
first.
 
![](images/Application%20Whitelisting%20Bypasses/image003.png)
 
 
The Tasks folder is writable and executable for non-privileged users by
default.  Running the executable from that directory works:
 
![](images/Application%20Whitelisting%20Bypasses/image004.png)
 
 
## Bypassing Publisher Rules
 
The
[Allow-Signed.ps1]() script creates an AppLocker rule that only allows signed executables to
run.
 
Running the script adds this rule to the two path rules:
 
![](images/Application%20Whitelisting%20Bypasses/image005.png)
 
 
Now, if an executable has a valid digital signature, it meets one of the
AppLocker rules and will be allowed to run. 
 
Original mimikatz.exe on the Desktop isn't in a whitelisted path and
does not have a digital signature so it is not allowed to execute.
 
![](images/Application%20Whitelisting%20Bypasses/image006.png)
 
 
However, there is a technique described
[here](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
where an attacker can steal a code signing certificate from another
executable to make an untrusted binary appear to have a valid digital
signature.
 
In this example, a digital certificate is extracted from a Microsoft
binary with [SigThief](https://github.com/secretsquirrel/SigThief) and
inserted into the untrusted binary creating a new "signed" file named
bypass.exe.
 
Two registry keys on the system are then changed (process described
[here](https://blog.conscioushacker.io/index.php/2017/09/27/borrowing-microsoft-code-signing-certificates/))
to cause the OS's signature check of the bypass.exe file to pass.
 
The new file with a stolen digital certificate will now pass a signature
check and execute, bypassing the AppLocker Publisher rule:
 
![](images/Application%20Whitelisting%20Bypasses/image007.png)
 
 
You can even see the details of the stolen certificate in the Properties
tab (the certificate actually belongs to the file
`C:Windows\System32\consent.exe`):
 
![](images/Application%20Whitelisting%20Bypasses/image008.png)
 
 
This technique can also be used to make untrusted scripts appear to have
valid signatures.
 
## Leveraging Trusted Programs
 
There are [many different
ways](https://github.com/api0cradle/UltimateAppLockerByPassList) to
evade whitelisting rules and run malicious code (EXEs, DLLs, scripts,
shellcode) by using a trusted binary.  Here are several examples:
 
- [powershell](#powershell)
 
- [cmd](#cmd)
 
- [mshta](#mshta)
 
- [regsvr32](#regsvr32)
 
- [rundll32](#rundll32)
 
- [MSbuild](#msbuild)
 
- [InstallUtil](#installutil)
 
 
 
### powershell.exe
 
When EXEs and DLLs are loaded into memory to run, they have an
associated file path which corresponds to their actual location on
the disk.
 
[Invoke-ReflectivePEInjection]() is a tool included in PowerSploit that
can load and run EXEs or DLLs from memory rather than from disk
(reflective loading).
 
A common use of this technique is to load a file into memory from
over the network so that the file executing is never written to
disk.
 
In this example, we'll first load the EXE's bytes into a place in
memory (variable $Bytes), then load it from memory and execute it
inside the PowerShell process.
 
![](images/Application%20Whitelisting%20Bypasses/image009.png)
 
 
The executable runs even though it is unsigned, not in a whitelisted
path, and not listed as an approved file hash.
 
Also, it is very difficult to detect that mimikatz is even running
since it is running inside of the PowerShell process:
 
![](images/Application%20Whitelisting%20Bypasses/image010.png)
 
 
Script rules can be bypassed with PowerShell in the same
way---executing from memory rather than calling the actual file on
disk.
 
Running the script in the traditional way with the script rules
turned on correctly fails.
 
To bypass, the `cat` command grabs the contents of the script and
pipes it to IEX which executes it:
 
![](images/Application%20Whitelisting%20Bypasses/image011.png)
 
 
### cmd
 
BAT and CMD scripts called by filename will also not execute from
the Desktop under these rules:
 
![](images/Application%20Whitelisting%20Bypasses/image012.png)
 
 
But can be made to run if their contents are piped to cmd.exe:
 
![](images/Application%20Whitelisting%20Bypasses/image013.png)
 
 
### mshta.exe
 
This executable is designed to run HTML Application (HTA) files
which can use JavaScript or VBScript to execute arbitrary code.
 
Default AppLocker script rules prevent executing our .vbs script:
 
![](images/Application%20Whitelisting%20Bypasses/image014.png)
 
 
But embedded VBScript code in an HTA file will be executed:
 
               
![](images/Application%20Whitelisting%20Bypasses/image015.png)
 
 
HTAs can also be used to execute JavaScript code:
 
               
![](images/Application%20Whitelisting%20Bypasses/image016.png)
 
 
### regsvr32
 
This program is used to register OLE controls in the registry, but
can also be used to run JavaScript or VBScript bypassing AppLocker's
script rules.
 
The scriptlet below (bypass.sct) contains the JavaScript code we
want to run.
 
Regsvr.exe runs the scriptlet and the JavaScript executes:
 
![](images/Application%20Whitelisting%20Bypasses/image017.png)
 
Regsvr32.exe can also download and execute code from over the
network.
 
It is very attractive to attackers because it is proxy aware, can
use TLS, and will follow redirects.
 
Here regsvr32.exe downloads a .sct from a remote server and executes
the VBScript code it contains:
 
![](images/Application%20Whitelisting%20Bypasses/image018.png)
 
 
### rundll32
 
This executable is designed to load and run DLLs so this is another
way malicious code can run using a trusted binary.
 
DLLs are designed to run inside a process, so to run it in rundll32 we
must pass the DLL's entry point as an argument.
 
You can find this by opening the file in PEStudio and looking at the
exports section.  If a DLL has an export named Start, try:
 
```powershell                               
rundll32 malware.dll,Start
```
 
This loads the DLL and calls the function named Start.
 
In this case there weren't any exports so I used the
entry point "main".
 
This starts the rundll32.exe process which loads and
runs the DLL which begins sending SYNs to a C2 address.
 
![](images/Application%20Whitelisting%20Bypasses/image019.png)
 
 
Rundll32.exe can also be used to run JavaScript which bypasses AppLocker
script rules.
 
The following command was run in cmd.exe:
 
![](images/Application%20Whitelisting%20Bypasses/image020.png)
 
 
Many applications use rundll32.exe---if an attacker can create
conditions for a malicious DLL to execute, it will run inside a rundll32
process.
 
For example, when opening the Control Panel, there is a registry key
that is checked for .cpl files and if any are present they are loaded
and run.
 
It is possible for a non-privileged user to rename a malicious dll to a
.cpl and place it in the registry key so it will be loaded and run when
the Control Panel is started.
 
When Control Panel starts, rundll32.exe which is trusted and
whitelisted, runs the DLL and again we see SYNs being sent to a C2
address:
 
![](images/Application%20Whitelisting%20Bypasses/image021.png)
 
 
### MSBuild
 
A non-privileged user can run JavaScript, VBScript, .NET assemblies
and more with this trusted executable.
 
This .xml project file contains JavaScript that can be executed
using MSBuild.exe:
 
![](images/Application%20Whitelisting%20Bypasses/image022.png)
 
 
This .xml file project file contains C Sharp code that beacons out
to a C2 server:
 
![](images/Application%20Whitelisting%20Bypasses/image023.png)
 
 
When the file is passed to MSBuild.exe, the code runs inside the
MSBuild.exe process:
 
![](images/Application%20Whitelisting%20Bypasses/image024.png)
 
 
### InstallUtil
 
This is a command line utility that can be used to run .NET
executables.
 
Trying to run the unsigned .NET executable from the Desktop is not
successful:
 
![](images/Application%20Whitelisting%20Bypasses/image025.png)
 
 
But when running the .NET executable inside the InstallUtil.exe
process, all AppLocker executable rules are bypassed:
 
![](images/Application%20Whitelisting%20Bypasses/image026.png)
 
 
These are just a few examples, there are many more
trusted binaries that can be used to run arbitrary code with the same
technique.
 
## Summary
 
Even though our enterprise is not configured to enforce AppLocker rules,
it is still important to understand how these bypass techniques are
used.
 
As more enterprises implement application whitelisting, malware and
post-exploitation tools will increasingly rely on whitelisting bypasses
to circumvent security controls, stay hidden, and accomplish their
mission.  
 
To detect these techniques:
 
### [Bypassing Path Rules](#bypassing-path-rules)
 
Look for suspicious executables and scripts running out of traditionally whitelisted directories:
 
- `C:\Windows`
- `C:\Windows\System32`
- `C:\Program Files`
- `C:\Program Files (x86)`
 
 
### [Bypassing Publisher Rules](#bypassing-publisher-rules)
 
Look for modifications of the following registry keys:
 
|Key|Value|
|-|-|
|HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType0\CryptSIPDllVerifyIndirectData{C689AAB8-8E78-11D0-8C47-00C04FC295EE}|C:\Windows\System32\ntdll.dll|
|HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType0\CryptSIPDllVerifyIndirectData{C689AAB8-8E78-11D0-8C47-00C04FC295EE}|DbgUiContinue|
 
Use script block and transcription logging to reveal malicious script actions.
 
Inspect signed files with multiple other tools/sources to reveal stolen/invalid signatures.
 
 
### [Leveraging Trusted Programs](#leveraging-trusted-programs)
 
Be familiar with the list of trusted binaries that can be used to run arbitrary code on Windows systems:
 
- powershell.exe
- cmd.exe
- mshta.exe
- regsvr32.exe
- rundll32.exe
- MSbuild.exe
- InstallUtil.exe
- IEExec.exe
- regsvcs.exe
- regasm.exe
- BGinfo.exe
- MSDT.exe
- PresentationHost.exe
- dfscv.exe
- cdb.exe
- dnx.exe
- rcsi.exe
- csi.exe
- msxsl.exe
- msiexec.exe
- cmstp.exe
- xwizard.exe
- fsi.exe
- odbcconf.exe
 
When there is evidence of one of these programs running, look for unusual behavior which may be:
 
- network connections
- parent/child processes
- loaded DLLs
- open file handles
- command line arguments
 