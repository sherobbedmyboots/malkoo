# Developing TTP-based Responses

Last week focused on using knowledge of adversary techniques to improve
detection---this week we'll look at using it to improve response.

Using the same example, we'll use specific TTPs we've
observed to develop responses that will be successful against this and
other similar attacks across our environment.

Here are the steps we'll use:

- [Gathering Information](#gathering-information)
- [Identifying TTPs Being Used](#identifying-ttps-being-used)
- [Finding Common Techniques](#finding-common-techniques)
- [Determining Best Responses](#determining-best-responses)

The file used in this example:

    9b57.exe

## Gathering Information

We stopped short of pivoting to another sample last week and focused on
detecting what we had discovered up to that point.

But normally we would want to inspect additional samples found as well
as they could utilize different techniques that could assist in
detection and response.

Remember we discovered a link to what looks like a second stage payload
being hosted on the C2 page:

![](images/Developing%20TTP-based%20Responses/image001.png)


Checking again a few days later, there is a new link to another exe:

![](images/Developing%20TTP-based%20Responses/image002.png)


We now have two additional domains and samples to analyze---and more
opportunities to learn about how this particular adversary intends to
gain access to our network.

## Identifying TTPs Being Used

Let's look at both files using automated analysis and see what we can
find:

### Automated

|||
|-|-|
|`9b57.exe`|[9b57071cb66366b192d3abb3710c0ea3841baae1.exe](https://www.hybrid-analysis.com/sample/c7ef5921984770ef607bb8b3893858bad3252834296718e4d42295a9003b8666?environmentId=100)|
|`1fug.exe`|[1fugauqzeihgaxidua.exe](https://www.hybrid-analysis.com/sample/59b2cb2f919c668ac402a42bfbd684c3282740ca7a4416274d75f4f9ca99475c?environmentId=100)|

Right away we see that they are very similar in how they execute.

Both use cmd.exe to execute a Batch file located in the `%TEMP%`
directory.

![](images/Developing%20TTP-based%20Responses/image003.png)



Notice how the old one `9b57.exe` is already identified by AV engines,
but the most recent one `1fug.exe` is not identified by any yet.

This is why these files are regularly modified, to stay ahead of AV
engine detection by hash, filename, etc.

The .bat files are exactly the same size:

![](images/Developing%20TTP-based%20Responses/image004.png)



And appear to have the same functionality, to delete the original
executable and itself.

(The original executable was named after its SHA256 value and executed
in the `C:\` directory by the sandbox)

![](images/Developing%20TTP-based%20Responses/image005.jpg)


They also create the same mutant:

![](images/Developing%20TTP-based%20Responses/image006.jpg)



There are a few differences between the two... `9b57.exe` generates some
network activity while `1fug.exe` doesn't:

![](images/Developing%20TTP-based%20Responses/image007.png)


These IPs both belong to Google so there is not much value in pivoting
on these.

We have some good context now that will help us doing static and dynamic
analysis.
            

### Static analysis

Pescanner shows both files contain multiple suspicious libraries:

```
GetTickCount
Sleep
IsDebuggerPresent
OutputDebugStringA
GetProcAddress
ShellExecuteExA
LoadLibraryA
```

Here we see a few significant differences between the files...

`9b57.exe` uses the NSIS installer commonly used by Ransomware to avoid
detection described
[here](https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-families-use-nsis-installers-to-avoid-detection-analysis/):

![](images/Developing%20TTP-based%20Responses/image008.png)


Besides what we've found, not much additional functionality can be
identified based on the strings contained in the two files.

Now let's run the first sample in a lab environment.

### Dynamic Analysis

After setting up some interactive analysis tools, the first sample
`9b57.exe` is executed on the Desktop.

RegShot sees the same two files we saw in the sandbox report get added
and the original sample get deleted:

![](images/Developing%20TTP-based%20Responses/image009.png)


![](images/Developing%20TTP-based%20Responses/image010.png)


About 5 minutes later, Fiddler shows a svchost process sending HTTPS
traffic to two suspicious domains not provided by our automated
analysis:

![](images/Developing%20TTP-based%20Responses/image011.png)


Process Hacker shows strings in memory that appear to be our C2 traffic:

![](images/Developing%20TTP-based%20Responses/image012.png)


Allowing the infected system to connect to its C2 confirms the svchost
process is being used to download what looks like encrypted commands and
files:

![](images/Developing%20TTP-based%20Responses/image013.png)


Notice the HTTP traffic to Google... this explains what we saw in the
sandbox report. 

The infection persists even after restarting the machine.

Looking at the event logs, we can identify the process timeline of both
infection and persistence:

- For infection, Notepad.exe is created, creates a copy of itself
    which then creates two svchost processes

- Later, the cmd.exe process is called to execute the .bat file

- `9b57.exe`
    - C:\\Users\\kbota\\Appdata\\Roaming\\Notepad++\\plugins\\Notepad.exe
        - C:\\Users\\kbota\\Appdata\\Roaming\\Notepad++\\plugins\\Notepad.exe
            - C:\\Windows\\SysWOW64\\svchost.exe
            - C:\\Windows\\SysWOW64\\svchost.exe
    - C:\\Windows\\SysWOW64\\cmd.exe

The Notepad.exe is the original file renamed:
                              

![](images/Developing%20TTP-based%20Responses/image014.png)


- For persistence, explorer executes the Notepad.exe which creates a
    copy of itself and starts two svchost processes

- One of the svchost processes creates the `updd2c0ce2b.exe` process

- Explorer.exe
    - C:\\Users\\kbota\\Appdata\\Roaming\\Notepad++\\plugins\\Notepad.exe
        - C:\\Users\\kbota\\Appdata\\Roaming\\Notepad++\\plugins\\Notepad.exe
            - C:\\Windows\\SysWOW64\\svchost.exe
                - C:\\Users\\kbota\\AppData\\Local\\Temp\\updd2c0ce2b.exe
            - C:\\Windows\\SysWOW64\\svchost.exe

This new executable is located in the `%TEMP%` directory:

![](images/Developing%20TTP-based%20Responses/image015.png)


Again, this is just the `9b57.exe` file renamed.

Using `autoruns` from SysInternals, we see an unsigned executable is
configured to run on logon:

![](images/Developing%20TTP-based%20Responses/image016.png)


### Memory Analysis

You can dump physical memory with `DumpIt.exe` from the Tools folder, but
when using VirtualBox there's an easier way that doesn't involve
starting a new process:

1. Start the VM from the command line using:  `virtualbox --dbg --startvm win7`

2. When ready to dump memory, select Debug --> Command Line

3. Dump memory to a file with the command: `.pgmphystofile win7.mem`

The RAM image will be saved to the current directory and can be read by
Volatility.

We are interested in the Service Hosting Processes (svchost.exe) that
are communicating to manrovm\[d\]gdn. 

Normal svchost.exe processes are created by services.exe and run at
session 0.

A `pslist` quickly identifies two svchost.exe processes that were not
created by services.exe and are running at session 1:

![](images/Developing%20TTP-based%20Responses/image017.png)


A `pstree` confirms one of the svchost.exe processes created the
`updd2c0ce2b.exe` process:

![](images/Developing%20TTP-based%20Responses/image018.png)

The parent process with PID 1960 (0x7a8) cannot be found but we can look
at our logs to see which process this was:

![](images/Developing%20TTP-based%20Responses/image019.png)


Volatility's Autoruns plugin also finds the persistence:

![](images/Developing%20TTP-based%20Responses/image020.png)


The `netscan` plugin shows the connections from the svchost.exe (628)
process to the C2 IP address:

![](images/Developing%20TTP-based%20Responses/image021.png)


Running `psxview` does not show any indications of hidden processes, so
the malicious code should be in these three processes we've identified.

Dumping executables from process memory with `dlldump` and `malfind` and
scanning with ClamAV or VT is a quick way to check for previously
identified malware.

First create a directory and dump each process's listed DLLs into it
with `dlldump`:

![](images/Developing%20TTP-based%20Responses/image022.png)


Then dump any hidden DLLs and shellcode to the same directory with
`malfind`:

![](images/Developing%20TTP-based%20Responses/image023.png)


Scan the directory with `clamav` (make sure you update first using
`freshclam`)... in this case nothing is detected:

![](images/Developing%20TTP-based%20Responses/image024.png)


You can also search all the file hashes on the VirusTotal site one at a
time or you can use the API and script it like below:

![](images/Developing%20TTP-based%20Responses/image025.png)


No hits on VT either... we could start inspecting each of these files
one by one but first let's find out how the malware persists.

### Testing for Persistence

We also need to identify the techniques being used for persistence and
how they can be countered.

The first thing I tried was to delete the registry key using
`regedit.exe`.  I opened it straight from the Autoruns entry, deleted it,
and it disappeared.

For some reason this didn't work...

After removing the registry key and rebooting, the host still created
the same processes and connected out to its C2.

But the registry key is just a pointer to the file that starts the two
svchost processes, Notepad.exe, so let's try moving it out of its
directory.

This resulted in a different file being created in its place... this one
named `Bespin.exe`.

The filename changed, but this is still the same original file just
running under a different name again:

![](images/Developing%20TTP-based%20Responses/image026.png)


Now let's try deleting it:

![](images/Developing%20TTP-based%20Responses/image027.png)


Several different combinations of Remove-Item with the force and recurse
flags were tried and were all unsuccessful.

The account has the required permissions---full control as a member of
the Administrators group, why doesn't this work?

One thing that could cause this is that another process is currently
using the file.

We can easily find our malicious svchost processes by searching only for
the ones that are running as session 1:

![](images/Developing%20TTP-based%20Responses/image028.png)


Once we kill these processes, the file can be deleted:

![](images/Developing%20TTP-based%20Responses/image029.png)


And when the infected system restarts, we see autoruns reports the
`Notepad.exe` was not found:

![](images/Developing%20TTP-based%20Responses/image030.png)


Another option that works is changing the registry value to "0"

![](images/Developing%20TTP-based%20Responses/image031.png)


A reboot confirms that setting the registry key to "0" destroys the
persistence.

At this point, management is most likely wanting some actionable
information.  We can't spend days tearing apart the malware, we need to
quickly identify specific techniques being used and figure out how what
can be done to improve our response.

Also, the second sample `1fug.exe` runs but immediately exits and
deletes itself most likely due to some anti-analysis/VM checks.  Let's
go with what we've found so far...

## Finding Common TTPs

Passive Total shows both of our newly discovered domains were recently
registered with what looks to be fake information.

The Sample tabs for both domains give us a list of associated sample MD5
hashes with the date they were observed.

![](images/Developing%20TTP-based%20Responses/image032.png)


At the time of this writing, lemanva\[d\]gdn was associated with 17
samples and manrovm\[d\]gdn was associated with 3 samples.

Just browsing the file reports on VirusTotal and Hybrid Analysis, we can
already spot some TTPs used by this adversary.

Out of the 20 samples seen from these domains:

- **11** of them use `cmd.exe` to execute an **11-character BAT file in
    %TEMP% directory** beginning with 'upd' delete their executables

- **14** of them are reported as **not having a digital signature**
    (most likely all of them are missing a signature)

From our analysis, we saw that:

- a copy of the original **exe executes in the Temp directory** for
    persistence.

These are three examples of common TTPs we can use to counter the
majority of malware deployed by this adversary. 

This supports some of the observations we made during automated
analysis, but now we understand how the attack works and can recommend
responses that are more likely to be successful.

For example, a response that prevents the .bat file from being created
in a system's `TEMP` folder won't necessarily stop the attack itself as
its job is only to delete the executable after it runs along with
itself.

And a response that blocks HTTP/HTTPS traffic from svchost processes
would block the attacker's C2 but may also interfere with legitimate
traffic from other svchost processes.

Here are several responses that could be used during both analysis and
remediation given what we know so far...

## Determining Best Responses

If a host shows signs of this malware, a great first option would be to
contain with FireEye HX so that all C2 is stopped and you have full
control of the system.

Some things to consider:

- FireEye HX agent may not be installed on the system

- Containment may not be an option depending on the specific system or
    number of systems involved

- If contained, you still need to have a good idea of how to prevent,
    isolate, or eradicate the malware

With this in mind, we'll make an example response based on each of the
common TTPs we observed using AppLocker.

### AppLocker

AppLocker is one of Microsoft's application control tools used to limit
the execution of executables, DLLs, scripts, and installer files.

By defining rules with an AppLocker policy, we can prevent and/or allow
running applications and files based on their path, hash value, or
digital signature.

Prerequisites (still working on a way to automate these):

- Import the module with `Import-Module AppLocker`

- Start AppIDSvc with `Start-Service AppIDSvc`

- Configure AppIDSvc to start automatically:

    -   Win7    `Set-Service AppIDSvc -StartupType Automatic`

    -   Win10   `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name Start -Value 2`

- Create default AppLocker executable rules (delete the BUILTIN\\Admin ones) and enable rule enforcement using `secpol`


#### 11-character BAT file in %TEMP% directory

We know that a BAT file is used to delete the original executable and
itself. 

If we wanted to prevent the malware from deleting these artifacts, we
could create a script rule with AppLocker based on the BAT's file path.

This
[Deny-Path.ps1]()
script can be used to create an AppLocker rule that does this by
specifying the file type and path:

![](images/Developing%20TTP-based%20Responses/image033.png)


Running this script on a system configures it to preserve artifacts that
would normally be destroyed.

(By choosing `-script`, we are denying the execution of .bat, .js, .ps1,
.cmd, and .vbs files)

![](images/Developing%20TTP-based%20Responses/image034.png)


Now when the sample is executed, the BAT file doesn't run---so it can't
delete itself or the original executable:

![](images/Developing%20TTP-based%20Responses/image035.png)


Looking at the .bat file, you can see I executed the sample in the `Temp`
folder, the same place the malicious doc's PowerShell command downloaded
`23.exe` to:

![](images/Developing%20TTP-based%20Responses/image036.png)


However, vbs scripts in other directories were not affected by the rule
and were allowed to execute:

![](images/Developing%20TTP-based%20Responses/image037.png)


#### EXE Executes in Temp Directory

We know the original exe `23.exe` is downloaded by a PowerShell command
into the `$env:temp` directory and executed.

If we wanted to prevent the first stage (`23.exe`), second stage
(`9b57.exe`) and any other executables from running here, we could use
this same script to create an executable rule.

The variable `$env:temp` may refer to different locations on different
machines---it was `Temp` on the analysis VM but `Temp\1` on my
workstation.

AppLocker path rules are recursive so if we make the rule for the Temp
directory, it will also work for all of Temp's subdirectories.

Again, we can use the
[Deny-Path.ps1]()
script to do this:

![](images/Developing%20TTP-based%20Responses/image038.png)


Now no executable will be allowed to run in the `Temp` folder or any of
its subdirectories.

![](images/Developing%20TTP-based%20Responses/image039.png)


If we wanted to let the `9b57.exe` run but prevent the `Notepad.exe`, we
could make the rule for the Roaming directory instead.

Also, we can prevent executables from running in both directories by
specifying the `c:\users\cpillar\AppData` directory in the script since
AppLocker Path rules are recursive.

We can even create exception rules for programs that are allowed to run
under the AppData directory such as Slack, Github Desktop, etc.

Since AppLocker path rules are recursive, files running from root
directories such as `C:\` can be problematic.

In this case, a better option might be to build a rule based on
executable's publishers.

#### Files Without a Digital Signature

Since the majority of the samples found do not contain a digital
signature, we can configure the system to only allow signed executables
to run.

This
[Allow-Signed.ps1]()
script can be used to do this:

![](images/Developing%20TTP-based%20Responses/image040.png)


Running this script on a system creates a rule that will prevent any
unsigned executable from running.

![](images/Developing%20TTP-based%20Responses/image041.png)


Attempting to run the file anywhere on the system fails and produces
this message:

![](images/Developing%20TTP-based%20Responses/image042.png)


Allow-listing publishers or creating exception rules for legitimate
unsigned executables are other ways we implement this.

## Summary

In all three examples, we're using what we know about how the adversary
operates to develop the best responses that meet IRM's requirements.

These responses can be implemented using built-in tools like AppLocker
or third party endpoint security suites.

Knowledge of the attack reveals TTPs and these TTPs can be used to
recommend different responses based on what IRM needs to be
accomplished.

The more you know about the different stages of the attack, the easier
it makes these tasks.
