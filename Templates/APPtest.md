**Application Whitelisting Bypasses**

Malware is constantly evolving. As whitelisting, code-signing, and
reputation services have improved, there has been a significant shift
towards malware using trusted components to run its malicious code, also
known as “living off the land”.

Where traditional malware might run in its own processes and implement
its own C2, modern malware attempts to blend in with normal activity by
using legitimate programs and functions for execution, lateral movement,
C2, and persistence.

Last week we used AppLocker, one of Microsoft’s application whitelisting
solutions, to prevent malware from dropping and executing untrusted
binaries and scripts on our host.

This week we’ll look at different techniques that can be used to bypass
application whitelisting and how we can detect them:

- Bypassing Path Rules

- Bypassing Publisher Rules

- Leveraging Trusted Executables

The following files will be used in the examples and are available on
the OOB at /CSIRT/Sample-Files/bypass:

- assembly .xml Calls out to a C2 address

- bypass.bat Prints “BAT script executed”

- bypass.cmd Prints “Cmd script executed”

- bypass.dll Calls out to a C2 address

- bypass.exe Mimikatz with a fake Microsoft digital signature

- bypass.hta Allows execution of JavaScript or VBScript

- bypass.js Prints “JavaScript executed”

- bypass.ps1 Prints “PowerShell script executed”

- bypass.sct Prints “VBScript executed”

- bypass.vbs Prints “VBScript executed”

- bypass.xml Prints “JavaScript executed”

- dotnet-bypass.exe Calls out to a C2 address

- mimikatz.exe Credential stealer, post-exploitation tool

*Set Up*

First let’s configure AppLocker and create some basic rules for
executables and scripts:

- Start AppIDSvc which is required for AppLocker operation

o For Windows 7, type Set-Service AppIDSvc –StartupType Automatic

o For Windows 10, type Set-ItemProperty –Path
HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AppIDSvc –Name Start –Value
2

o Type Start-Service AppIDSvc

- Configure AppLocker by typing gpedit then Computer -&gt; Windows
Settings -&gt; Security Settings -&gt; Application Control Policies
-&gt; AppLocker

o Create default rules for executables and scripts

o Delete BUILTIN\\Administrator rule for executables and scripts

o Configure rule enforcement for all scripts and executables

- Configure PowerShell Execution Policy back to default

o Type Set-ExecutionPolicy –Scope CurrentUser Undefined

o Type Set-ExecutionPolicy –Scope LocalMachine Unrestricted

*Bypassing Path Rules*

With the two path rules being enforced, attempting to run mimikatz.exe
on the Desktop is denied by the default Path rules:

![cid:image003.png@01D35480.F97E7E00](media/image6.png){width="6.5in"
height="2.4305555555555554in"}

But if this executable is moved to a path that is whitelisted, it will
be allowed to run.

Since our user account is in the Administrators group, we could move
this file to C:\\Windows or C:\\Program Files, but a normal user would
need to search for a place they can write to under these directories.

There are already tools that have the capability to do this, but an
attacker may choose to use a simple script to find a directory that
meets these conditions.

For example, this is a short script that checks a directory for folders
with ACLs that allow normal users to write/create and execute files.

![cid:image009.png@01D353B7.129BFE50](media/image38.png){width="6.5in"
height="2.1666666666666665in"}

Since one of the default path rules whitelists everything under
C:\\Windows, a non-privileged user would probably run the script there
first.

![cid:image010.png@01D353B7.129BFE50](media/image12.png){width="6.5in"
height="0.9166666666666666in"}

The Tasks folder is writable and executable for non-privileged users by
default. Running the executable from that directory works:

![cid:image008.png@01D354F4.10CE8640](media/image26.png){width="6.5in"
height="3.3333333333333335in"}

*Bypassing Publisher Rules*

The
[*Allow-Signed.ps1*](https://git.uscis.dhs.gov/USCIS-SOC/FO/blob/master/scripts/Allow-Signed.ps1)
script creates an AppLocker rule that only allows signed executables to
run.

Running the script adds this rule to the two path rules:

![cid:image016.png@01D35491.8DD64FA0](media/image18.png){width="6.5in"
height="1.5972222222222223in"}

Now, if an executable has a valid digital signature, it meets one of the
AppLocker rules and will be allowed to run.

Original mimikatz.exe on the Desktop isn’t in a whitelisted path and
does not have a digital signature so it is not allowed to execute.

![cid:image005.png@01D35428.2C8205A0](media/image20.png){width="5.916666666666667in"
height="3.6527777777777777in"}

However, there is a technique described
[*here*](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
where an attacker can steal a code signing certificate from another
executable to make an untrusted binary appear to have a valid digital
signature.

In this example, a digital certificate is extracted from a Microsoft
binary with [*SigThief*](https://github.com/secretsquirrel/SigThief) and
inserted into the untrusted binary creating a new “signed” file named
bypass.exe.

Two registry keys on the system are then changed (process described
[*here*](https://blog.conscioushacker.io/index.php/2017/09/27/borrowing-microsoft-code-signing-certificates/))
to cause the OS’s signature check of the bypass.exe file to pass.

The new file with a stolen digital certificate will now pass a signature
check and execute, bypassing the AppLocker Publisher rule:

![cid:image022.png@01D354F4.10CE8640](media/image24.png){width="6.5in"
height="3.3194444444444446in"}

You can even see the details of the stolen certificate in the Properties
tab (the certificate actually belongs to the file
C:Windows\\System32\\consent.exe):

![cid:image006.png@01D35428.2C8205A0](media/image34.png){width="6.5in"
height="6.722222222222222in"}

This technique can also be used to make untrusted scripts appear to have
valid signatures.

*Leveraging Trusted Executables*

There are [*many different
ways*](https://github.com/api0cradle/UltimateAppLockerByPassList) to
evade whitelisting rules and run malicious code (EXEs, DLLs, scripts,
shellcode) by using a trusted binary. Here are several examples:

- powershell.exe

- cmd.exe

- mshta.exe

- regsvr32.exe

- rundll32.exe

- MSbuild.exe

- InstallUtil.exe

1\. powershell.exe

When EXEs and DLLs are loaded into memory to run, they have an
associated file path which corresponds to their actual location on the
disk.

Invoke-ReflectivePEInjection is a tool included in PowerSploit that can
load and run EXEs or DLLs from memory rather than from disk (reflective
loading).

A common use of this technique is to load a file into memory from over
the network so that the file executing is never written to disk.

In this example, we’ll first load the EXE’s bytes into a place in memory
(variable \$Bytes), then load it from memory and execute it inside the
PowerShell process.

![cid:image004.png@01D35490.494922F0](media/image14.png){width="6.5in"
height="1.7361111111111112in"}

The executable runs even though it is unsigned, not in a whitelisted
path, and not listed as an approved file hash.

Also, it is very difficult to detect that mimikatz is even running since
it is running inside of the PowerShell process:

![cid:image012.png@01D35490.494922F0](media/image48.png){width="6.5in"
height="1.4583333333333333in"}

Script rules can be bypassed with PowerShell in the same way—executing
from memory rather than calling the actual file on disk.

Running the script in the traditional way with the script rules turned
on correctly fails.

To bypass, the ‘cat’ command grabs the contents of the script and pipes
it to IEX which executes it:

![cid:image017.png@01D35491.8DD64FA0](media/image10.png){width="6.5in"
height="1.1388888888888888in"}

2\. cmd.exe

BAT and CMD scripts called by filename will also not execute from the
Desktop under these rules:

![cid:image014.png@01D35490.494922F0](media/image52.png){width="6.5in"
height="0.6111111111111112in"}

But can be made to run if their contents are piped to cmd.exe:

![cid:image015.png@01D35490.494922F0](media/image42.png){width="6.5in"
height="1.6388888888888888in"}

3\. mshta.exe

This executable is designed to run HTML Application (HTA) files which
can use JavaScript or VBScript to execute arbitrary code.

Default AppLocker script rules prevent executing our .vbs script:

![cid:image001.png@01D3549E.BE1B9140](media/image40.png){width="6.5in"
height="2.6527777777777777in"}

But embedded VBScript code in an HTA file will be executed:

![cid:image002.png@01D3549E.BE1B9140](media/image16.png){width="6.5in"
height="2.1527777777777777in"}

HTAs can also be used to execute JavaScript code:

![cid:image007.png@01D3549E.BE1B9140](media/image46.png){width="6.5in"
height="2.2083333333333335in"}

4\. regsvr32.exe

This program is used to register OLE controls in the registry, but can
also be used to run JavaScript or VBScript bypassing AppLocker’s script
rules.

The scriptlet below (bypass.sct) contains the JavaScript code we want to
run.

Regsvr.exe runs the scriptlet and the JavaScript executes:

![cid:image013.png@01D354DB.BEDAD5E0](media/image30.png){width="6.5in"
height="3.0277777777777777in"}

Regsvr32.exe can also download and execute code from over the network.

It is very attractive to attackers because it is proxy aware, can use
TLS, and will follow redirects.

Here regsvr32.exe downloads a .sct from a remote server and executes the
VBScript code it contains:

![cid:image018.png@01D354DB.BEDAD5E0](media/image2.png){width="6.5in"
height="1.6944444444444444in"}

5\. rundll32.exe

This executable is designed to load and run DLLs so this is another way
malicious code can run using a trusted binary.

DLLs are designed to run inside a process, so to run it in rundll32 we
must pass the DLL’s entry point as an argument.

You can find this by opening the file in PEStudio and looking at the
exports section. If a DLL has an export named Start, try:

rundll32 malware.dll,Start

This loads the DLL and calls the function named Start.

In this case there weren’t any exports so I used the entry point “main”.

This starts the rundll32.exe process which loads and runs the DLL which
begins sending SYNs to a C2 address.

![cid:image019.png@01D354E8.B0E1CBD0](media/image50.png){width="6.5in"
height="1.4305555555555556in"}

Rundll32.exe can also be used to run JavaScript which bypasses AppLocker
script rules.

The following command was run in cmd.exe:

![cid:image020.png@01D354E8.B0E1CBD0](media/image8.png){width="6.5in"
height="1.3333333333333333in"}

Many applications use rundll32.exe—if an attacker can create conditions
for a malicious DLL to execute, it will run inside a rundll32 process.

For example, when opening the Control Panel, there is a registry key
that is checked for .cpl files and if any are present they are loaded
and run.

It is possible for a non-privileged user to rename a malicious dll to a
.cpl and place it in the registry key so it will be loaded and run when
the Control Panel is started.

When Control Panel starts, rundll32.exe which is trusted and
whitelisted, runs the DLL and again we see SYNs being sent to a C2
address:

![cid:image021.png@01D354E8.B0E1CBD0](media/image36.png){width="6.5in"
height="1.4027777777777777in"}

6\. MSBuild.exe

A non-privileged user can run JavaScript, VBScript, .NET assemblies and
more with this trusted executable.

This .xml project file contains JavaScript that can be executed using
MSBuild.exe:

![cid:image023.png@01D354F4.10CE8640](media/image22.png){width="6.5in"
height="2.5in"}

This .xml file project file contains C Sharp code that beacons out to a
C2 server:

![cid:image011.png@01D355C6.D7BD4F70](media/image28.png){width="6.5in"
height="3.0555555555555554in"}

When the file is passed to MSBuild.exe, the code runs inside the
MSBuild.exe process:

![cid:image024.png@01D355C6.D7BD4F70](media/image44.png){width="6.5in"
height="1.4722222222222223in"}

7\. InstallUtil.exe

This is a command line utility that can be used to run .NET executables.

Trying to run the unsigned .NET executable from the Desktop is not
successful:

![cid:image025.png@01D355C6.D7BD4F70](media/image4.png){width="6.5in"
height="1.1805555555555556in"}

But when running the .NET executable inside the InstallUtil.exe process,
all AppLocker executable rules are bypassed:

![cid:image026.png@01D355C6.D7BD4F70](media/image32.png){width="6.5in"
height="1.3611111111111112in"}

These are just a few examples, there are many more trusted binaries that
can be used to run arbitrary code with the same technique.

*Summary*

Even though our enterprise is not configured to enforce AppLocker rules,
it is still important to understand how these bypass techniques are
used.

As more enterprises implement application whitelisting, malware and
post-exploitation tools will increasingly rely on whitelisting bypasses
to circumvent security controls, stay hidden, and accomplish their
mission.

To detect these techniques:

- **Path Rule Bypasses**

Look for suspicious executables and scripts running out of traditionally
whitelisted directories such as C:\\Windows, C:\\Program Files, etc.

- **Publisher Rule Bypasses**

Look for modifications of the following registry keys:

o HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType
0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}
C:\\Windows\\System32\\ntdll.dll

o HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType
0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}
DbgUiContinue

Use script block and transcription logging to reveal malicious script
actions

Inspect signed files with multiple other tools/sources to reveal
stolen/invalid signatures

- **Leveraging Trusted Executables**

Be familiar with the list of trusted binaries that can be used to run
arbitrary code on Windows systems:

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

When there is evidence of one of these programs running, look for
unusual behavior which may be:

- network connections

- parent/child processes

- loaded DLLs

- open file handles

- command line arguments
