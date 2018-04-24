# Moving From Detection To Containment

The impact of a security incident to an organization largely depends on how fast an IR team can transition from detecting potential incidents to containing any compromised systems.  IR triage is the process of responding to suspicious events, determining if a security incident took place, and deciding the required response actions and priority for each system involved based on the severity of compromise.  It starts with a detection from monitoring/hunting and ends with a clear picture of the incident, the systems involved, and a plan to stop the progress of the attack.  

IR Triage can be separated into the following steps:

|Step|Description|
|-|-|
|[Initial Assessment](#initial-assessment)|Form theories that would explain the indications that caused the detection|
|[Gather Information](#gather-information)|Gather historical and contextual evidence and artifacts that support or disprove theories|
|[Perform Analysis](#perform-analysis)|Use artifacts to establish facts, answer key questions, and provide analysis|
|[Report Findings](#report-findings)|Provide accurate, actionable information to management so they can make time-sensitive decisions to defend systems|

<br>

This document will walk through these steps using XXX as an example to demonstrate performing triage on an incident involving multiple compromised machines.


## Initial Assessment

> Form theories that would explain the indications that caused the detection

<br>

The initial assessment is based on alerts and/or detections and should attempt to explain what most likely happened and the appropriate course of the investigation.  During the first hour of the incident, we started with the following:

- Splunk Dashboard Alerts
- Reports of a Phishing Email
- FireEye HX Alerts


The first detection was a Splunk dashboard reporting multiple systems making repeated HTTPS requests to the same IP address.  Between 7 and 8 AM CST, 31 different systems were observed making these requests with the highest number of requests made by a single system being 516.   

Around that time we received several reports of a phishing email containing a link to an HTA file which was hosted at a domain that resolved to the IP address.

Also during that first hour, many systems alerted in FireEye HX for the following rules:

- SUSPICIOUS POWERSHELL USAGE (METHODOLOGY)
- POWERSHELL MEMORY INJECTION (METHODOLOGY)
- COBALT STRIKE (BACKDOOR)


Based on these three detections, our initial theory was that the HTA file contained a PowerShell command that injected a stager into memory and that the hundreds of additional requests to the IP by each system was the post-exploitation agent being downloaded into memory.

To support or disprove this theory, we began gathering more information...


## Gather Information

> Gather historical and contextual evidence and artifacts that support or disprove theories

<br>

Artifacts establish the facts related to the incident and help further the investigation. For this step, we used the following methods:

- [File Analysis](#file-analysis)
- [Endpoint Agent Data](#endpoint-agent-data)
- [Remote Survey Scripts](#remote-survey-scripts)


### File Analysis

The file is an important artifact and can be obtained either using the link from the phishing email or recovering a copy of the file downloaded by one of the victims.  In this case, the HTA was discovered in a compromised system Downloads directory and copied over for analysis.

The file contained obfuscated VBScript, which when deobfuscated revealed it starts a hidden PowerShell process on execution and then closes. The PowerShell command loads and runs a .NET assembly in memory by using the `System.Reflection` namespace to generate code dynamically.  This allows the current PowerShell session to interact with the Windows API (.NET Reflection described [here](http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html).  

After inspecting the code, we could see that:

- [InternetOpenUrl](https://msdn.microsoft.com/en-us/library/windows/desktop/aa385098.aspx) is used to download the Beacon code one HTTPS request at a time
- [VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx) is used to allocate space for the Beacon in process memory
- [CreateThread](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682453.aspx) is used to start the Beacon running in memory  

Here is the stager which calls the [InternetOpenUrl](https://msdn.microsoft.com/en-us/library/windows/desktop/aa385098.aspx) function with the user agent and URL as arguments:

```
cat decoded
![](images/Moving%20From%20Detection%20To%20Containment/image008.png)<br><br>
```

### Endpoint Agent Data

Our endpoint agent is FireEye HX which tracks the state of each system, monitors for IOCs, and alerts if any are seen.  After the alerts on these systems, a triage collection was automatically acquired containing system state data at the time of the alert including lists of processes, file write events, network connection events, URL history, download history, etc.

First we see `powershell.exe` running under X account making HTTPS requests to IP with User Agent `Microsoft-CryptoAPI/6.1`:

![](images/Moving%20From%20Detection%20To%20Containment/image001.png)<br><br>

The time of the first request is shown along with the full URL and browser used:

![](images/Moving%20From%20Detection%20To%20Containment/image002.png)<br><br>

The hidden PowerShell process start time is shown along with command line, PID, and parent process:

![](images/Moving%20From%20Detection%20To%20Containment/image003.png)<br><br>

The file write event of the HTA file shows process and file metadata:

![](images/Moving%20From%20Detection%20To%20Containment/image004.png)<br><br>


### Remote Survey Scripts

Running survey scripts on a remote host can be used to check systems for specific events or conditions that would support one or more of our theories.

While checking for PowerShell processes, we discovered many of the systems had multiple PowerShell processes running.  The most likely explanation for this is that since the HTA file did not contain any errors or open any decoy files, most users probably ran the file several times trying to get it to do something which created a new `powershell.exe` process and stager instance each time.

![](images/Moving%20From%20Detection%20To%20Containment/image005.png)<br><br>

The [Get-InjectedThread.ps1](scripts/Get-InjectedThread.ps1) script from Jared Atkinson looks for threads that were created as a result of memory injection by checking if the memory page of each thread's base address is allocated but not backed by a file on disk.  This was used to check systems that had alerted for any injected processes:

![](images/Moving%20From%20Detection%20To%20Containment/image014.png)<br><br>

File analysis, endpoint agent data, and remote survey scripts each provided evidence that supported our theory which can now be used to perform analysis.


## Perform Analysis

> Use artifacts to establish context, answer key questions, and provide analysis

<br>

Here we used the information we'd gathered up to this point to identify what had happened, what would most likely happen next, and how we could stop it.  We knew how the systems were being compromised---the HTA file spawns a hidden PowerShell process that downloads the Beacon from IP and runs it completely in memory.  When this happens, the adversary has control of the system via C2 and the injected process (`powershell.exe`) and can begin their action on objectives.  

Knowledge about the tool being used helped provide specific actions to look for after a system was successfully compromised.  After Cobalt Strike Beacon began running on a host, there were three things we thought were likely to occur:

- [Migration to a Different Process](#migration-to-a-different-process)
- [Execution of Post-Exploitation Modules](#execution-of-post-exploitation-modules)
- [Attempts at Lateral Movement](#attempts-at-lateral-movement)


### Migration to a Different Process

Mature post-exploitation tools will have the ability to migrate to a different process that will receive less attention than the initial process used to get a foothold.  Instead of staying in the `powershell.exe` process, migrating to processes that normally use the network such as `iexplore.exe` and `lync.exe` would allow the adversary to avoid detection for a longer period of time.  

Cobalt Strike Beacon uses reflective DLL injection to migrate to another process: 

1. The Beacon running in `powershell.exe` allocates memory space with RWX permissions in a remote process (`explorer.exe`)

2. Beacon writes its reflective DLL into the memory of the remote process 

3. Beacon calls [CreateRemoteThread](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682437.aspx) to start execution of the reflective DLL in the remote process 

4. The reflective DLL's loader function finds the addresses for libraries it needs and loads itself into memory

5. This new Beacon DLL drops a .NET assembly in memory which gives it access to .NET and Windows API functions

6. The new Beacon DLL uses the .NET assembly to execute PowerShell commands inside the remote process (`explorer.exe`)

<br>

Knowing this process, the [Get-InjectedThread.ps1](scripts/Get-InjectedThread.ps1) script was used to create the [getInjectionIp](scripts/Get-InjectionFunctions.ps1) function which checks a list of IP addresses for injected processes.  Running the script on IPs that had run the HTA file revealed systems that had the stager or Beacon running and the processes in which they were running: 

![](images/Moving%20From%20Detection%20To%20Containment/image006.png)<br><br>

This was evidence that the Beacon was migrating to other processes but could be removed (in the short-term) from the system if that process was discovered and terminated.  However, if any persistence modules had run on the system during the time it was controlled by the adversary, then a new PowerShell process would eventually start again to download and run the Beacon. 


### Execution of Post-Exploitation Modules

Post-exploitation modules are a way of automating activities commonly performed on a compromised host.  Cobalt Strike Beacon used multiple PowerShell post-exploitation modules that were logged on our systems.

Event 4104 from Windows PowerShell Operational Logs provides the entire contents of a script when it is loaded into memory:

![](images/Moving%20From%20Detection%20To%20Containment/image009.png)<br><br>

Event 600 from Windows PowerShell logs records when the post-exploitation module is run:

![](images/Moving%20From%20Detection%20To%20Containment/image010.png)<br><br>

The encoded command decodes to:

![](images/Moving%20From%20Detection%20To%20Containment/image011.png)<br><br>

At this point, the [getPostExpModules](scripts/Get-InjectionFunctions.ps1) function was created to search PowerShell logs for post-exploitation modules being run on target hosts:

![](images/Moving%20From%20Detection%20To%20Containment/image007.png)<br><br>

Sorting the results by time produces a timeline of hosts that were being controlled, the type of post-exploitation activity that was being performed, and the accounts that were being used.

Here are some other post-exploitation modules that were discovered to have run on compromised systems:

- Install-RegPersistence
- Invoke-UserHunter
- Invoke-BloodHound
- Invoke-AllChecks
- Write-HijackDll
- Invoke-AutoKerberoast

<br>

This gave us an idea of what was being performed on compromised systems and was used to monitor adversary actions in Splunk, FireEye HX, or by interrogating hosts with remote survey scripts.


### Attempts at Lateral Movement

Once an account is compromised, it can be used to pivot to other hosts on the network.  Searches in Splunk and Exabeam were used to find accounts that were accessing multiple systems, failing logons, or otherwise exhibiting unusual behavior.

A Splunk dashboard showed several accounts logging into hundreds of other systems within the same hour:

![](images/Moving%20From%20Detection%20To%20Containment/image012.png)<br><br>


Exabeam saw this as well and assigned high scores for these accounts based on their abnormal behavior:

![](images/Moving%20From%20Detection%20To%20Containment/image013.png)<br><br>


This confirmed what was happening after an account became compromised and how we could detect it.  It also gave these systems a higher priority since they were actively being used to discover and interact with other hosts on the network.

## Report Findings

> Provide accurate, actionable information to management so they can make time-sensitive decisions to defend systems

<br>

This step is where we report our findings, which are based on technical facts, to build an overall picture of the incident.  Provide a summary of supporting evidence and artifacts explaining how they were discovered and why they individually or together indicate malicious activity.  Also provide a timeline of events of what is known up to this point and what can be expected to occur next.  Finally, recommend next steps in the investigation as well as options for containment and/or eradication.  


- [Summary](#summary)
- [Artifacts](#artifacts)
- [Timeline of Events](#timeline-of-events)
- [Recommendations](#recommendations)

### Summary

At least 31 users have fallen victim to a phishing email containing a link to a malicious HTA file.  The file which is hosted at <url> contains obfuscated VBScript that launches a hidden PowerShell process on the system.  After it launches, the process makes hundreds of HTTPS requests to <IP> to download a RAT (Remote Access Tool) named Cobalt Strike Beacon and run it in memory.

Beacon is an asynchronous payload implemented as a reflective DLL that can migrate to other processes, load custom modules, and perform a wide range of post-exploitation activities.  We have observed it being used to do the following:

- Migrate to safer processes to avoid detection
- Check for privilege escalation opportunities 
- Perform Active Directory reconnaissance 
- Obtain password hashes via Kerberoasting
- Install persistence via registry keys
- Attempt lateral movement to hundreds of systems via SMB network logons with compromised accounts
- Perform DLL Hijacking to add a new local user account

### Artifacts

Splunk search [X]() shows 31 different systems and counting that are currently communicating with adversary C2 infrastructure.

The HTA file was obtained from host X.  Analysis of the file shows it creates a hidden PowerShell process that runs a .NET assembly in memory, downloads the Beacon from <IP>, and runs it in memory.

Endpoint agent data was examined and process list, file write events, and URL history confirm the HTA file is downloaded over HTTPS using <URL> into temporary internet files directory (IE) or Downloads (Other) and runs the Base64-encoded PowerShell command.

The [Get-InjectedThread.ps1](scripts/Get-InjectedThread.ps1) script detected multiple injected PowerShell processes on victim systems caused by users running the HTA file multiple times.  Once the Beacon was completely downloaded and running in memory, the script revealed the Beacon would migrate to a safer process such as `dwm.exe`, `lync.exe`, `explorer.exe`, and `iexplore.exe` to avoid detection. 

PowerShell logs were queried and Events 4104 and 600 showed the following post-exploitation modules being loaded and run on victim systems:

|Module|Description|
|-|-|
|[Install-RegPersistence]()|Stores stager code in chosen registry key, and sets an autorun key to launch the script on user login|
|[Invoke-UserHunter](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)|Searches for systems that a specific user is logged into and if that user has admin access|
|[Invoke-BloodHound](https://github.com/BloodHoundAD/BloodHound)|Searches for hidden or unintended relationships within an Active Directory environment|
|[Invoke-AllChecks](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)|A collection of privilege escalation checks|
|[Write-HijackDll](https://attack.mitre.org/wiki/Technique/T1038)|Writes a chosen DLL to a search path for an executable|
|[Invoke-AutoKerberoast](https://github.com/nidem/kerberoast)|Extracts accounts and requests Kerberos ticket for cracking or passing attack|

<br>

Splunk search [Y]() shows 5 accounts that were compromised and used to attempt logons to hundreds of other hosts on the network.  

[Exabeam]() has also alerted on these accounts based on their abnormal behavior.  


### Timeline of Events

|Time|System|Event|
|-|-|-|
|7:09:00|Multiple|Systems began contacting <IP> / <URL>| 
|7:19:00|Multiple|Lateral movement attempts with compromised accounts: X, X, X, X, X|
|7:32:32|<host>|Find-LocalAdminAccess -Threads 30|
|8:07:21|<host>|Install-RegPersistence|
|8:13:29|<host>|Install-RegPersistence|
|8:15:53|<host>|Install-RegPersistence|
|8:16:46|<host>|Install-RegPersistence|
|8:57:03|<host>|Install-RegPersistence|
|9:51:00|<host>|Invoke-AllChecks|
|9:53:47|<host>|Get-Help Write-HijackDll -Full|
|10:07:31|<host>|Write-HijackDll -DllPath 'C:\Program Files (x86)\Kodak\Document Imaging\kds_i11xx\Smart Touch\\wlbsctrl.dll' -Architecture "x64"|
|10:15:28|<host>|Invoke-BloodHound -CollectionMethod ACL,ObjectProps,Group,ComputerOnly -CompressData|
|10:24:49|<host>|Invoke-AllChecks|
|10:38:24|<host>|Invoke-AutoKerberoast -GroupName "*admin*"|
|10:52:40|<host>|Find-LocalAdminAccess -Threads 40|
|12:54:01|<host>|Invoke-BloodHound -CollectionMethod Session -CompressData|


### Recommendations

We are confident that the adversary has successfully obtained network, system, and user data that will help them escalate privileges and pivot to additional systems on the network.

- Block all traffic to <IP> <DOMAIN>
- Lock or reset passwords for all compromised accounts
- Search for and terminate injected processes, contain systems
- Examine all affected systems for changes, exfil, persistence

<br>

## Summary

Triage includes eliminating false positives, investigating malicious activity, recognizing if an incident has occurred, and determining the most effective response.  The primary goal is to reduce the time it takes to move affected systems from initial detection to containment.

During initial assessment:
- Understand the requirements and purpose of the alert/detection
- Identify different scenarios that could be the cause
- Use most likely scenarios to develop theory

When gathering information:
- Determine what information will be needed to prove/disprove theory
- Use all tools available to examine host and network
- Try to obtain a copy of the file for analysis

During analysis:
- Use evidence to establish what happened
- Gain a solid understanding of how defenses are being bypassed
- Use TTPs and tools observed to determine what will most likely happen next

When reporting:
- Make reports understandable and useful
- Be clear about what is known and what is likely to have happened
- Be specific and support statements with factual evidence
- Based on evidence, make recommendations for containment/eradication 
