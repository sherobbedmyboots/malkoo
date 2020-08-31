# Tracking Lateral Movement By Authenticated RCE

Once an adversary obtains valid credentials, lateral movement can be accomplished by executing just one command on a remote system.  This one command is frequently a PowerShell one-liner that downloads and runs a stager on the victim via web delivery.  Since an authenticated account is used to execute code, this one remote command blends in with daily system administration tasks and can be very difficult to detect.

There are [many different ways](https://attack.mitre.org/wiki/Lateral_Movement) to perform lateral movement, but this will focus on methods that use authenticated sessions.  To track this activity, we need to understand what techniques can be used, ensure we have an accurate way to detect them when they occur, and collect the results in a way that will allow us to answer key questions during the response---such as "What accounts and systems have been compromised at this point in time?"

This document will use last week's exercise to demonstrate this process.
	
- [Identify Techniques](#identify-techniques)
    - [Windows Management Instrumentation](#windows-management-instrumentation)
    - [Service Control Manager](#service-control-manager)
    - [Windows Remoting](#windows-remoting)
    - [Remote Registry](#remote-registry)
    - [Remote File Access](#remote-file-access)
    - [Task Scheduler](#task-scheduler)
    - [Remote Desktop](#remote-desktop)
    - [MMC20.Application DCOM](#mmc20.application-dcom)
- [Create Detections](#create-detections)
    - [WMI](#wmi)
    - [SCM](#scm)
    - [WinRM](#winrm)
    - [Registry](#registry)
    - [File Access](#file-access)
    - [Scheduler](#scheduler)
    - [RDP](#rdp)
    - [MMC20](#mmc20)
- [Collect Results](#collect-results)
    - [Timeline of Lateral Movement Events](#timeline-of-lateral-movement-events)
    - [Adding External Detections](#adding-external-detections)
    - [Reporting Options](#reporting-options)

<br>

## Identify Techniques

Authenticated Remote Code Execution (RCE) can be performed several different ways:

|Technique|Description|
|-|-|
|[Windows Management Instrumentation](#windows-management-instrumentation)|Use WMI to execute a command on a remote system|
|[Service Control Manager](#service-control-manager)|Create a service that will execute a command when started|
|[Windows Remoting](#windows-remoting)|Use Windows Remoting (WinRM) to execute command|
|[Remote Registry](#remote-registry)|Write command to execute to a registry key|
|[Remote File Access](#remote-file-access)|Write file containing command to execute to an administrative share|
|[Task Scheduler](#task-scheduler)|Schedule a command to run at the provided time|
|[Remote Desktop](#remote-desktop)|Log in with credentials and execute code in an interactive session|
|[MMC20.Application DCOM](#mmc20.application-dcom)|Instantiate a COM object remotely and call ExecuteShellCommand method|

<br>

We'll simulate each of the techniques using `powershell -c calc.exe` instead of the encoded powershell commmand used to run the stager.

## Windows Management Instrumentation

Windows Management Instrumentation (WMI) provides several ways to interface with the DcomLaunch service to remotely start a process:

|||
|-|-|
|VBScript|`Set objWMIService = GetObject("winmgmts:\\" & "<remotehost>" & "\root\cimv2:Win32_Process")` `objWMIService.Create("cmd /c powershell -c calc.exe", Null, Null, intProcessID)`|
|WMIC|`wmic /node:<hostname> process call create "cmd /c powershell -c calc.exe"`|
|PowerShell|`Invoke-WmiMethod <remotehost> -Class win32_process -Name Create -ArgumentList "cmd /c powershell -c calc.exe"`|

<br>

In each of these, `svchost.exe` has spawned the WMI Provider Service (`WmiPrvSE.exe`) process which executes the `cmd /c powershell -c calc.exe` command for the remote user.


## Service Control Manager

Windows services are created using the Services Control Manger (SCM) and run as SYSTEM by default.  There are several techniques that can be used to start a service on a remote Windows system:

|Technique|Description|
|-|-|
|[Sysinternals PsExec](#sysinternals-psexec)|PsExec and its clones copy a service executable (`Psexesvc.exe`) to the `Admin$` share of the remote system and start it using the SCM API.  The input and output streams of the executable's process are controlled so that you can interact with the executable from the local system. When it exits, it stops the service and deletes the binary.|
|[Smbexec and Others](#smbexec-and-others)|SMBExec and similar tools can be used to start a service remotely without dropping a binary on the system.  It does this by passing the new service a binpath that is actually a command that creates a bat file containing the command to be executed, executes it, and then deletes it.  No files are left on the system but System logs will show the creation of the service and the command it was passed.|
|[Metasploit psexec Module](#metasploit-psexec-module)|Metasploit's psexec module uses the SCM to start a service and passes the command to be executed as the binary path.  The command executes but the service immediately errors and exits.| 

<br>

This can be simulated using the `sc` command line tool that interacts with the SCM:

```
sc \\<remotehost> create test01 binPath= "%COMSPEC% /Q /c powershell.exe -c calc.exe"
sc \\<remotehost> start test01
```

When this is run, the service is created successfully but an error is received when it is started:

```powershell
sc <hostname> create test01 binPath= "%COMPSPEC% /Q /c powershell.exe -c calc.exe"
# [SC] CreateService SUCCESS

sc <hostname> start test01
# [SC] StartService FAILED 1053:
```

 
The logs reveal that the service was installed successfully:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image032.png)<br><br>

And that even though the service temporarily started and exited, the command still ran on the remote system::

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image033.png)<br><br>


## Windows Remoting

Windows Remote Management (WinRM) can be called with the `winrm` command or various PowerShell cmdlets: 

|||
|-|-|
|winrs|`winrs -r:<remotehost> powershell -c calc.exe`|
|PowerShell|`Invoke-Command <remotehost> -Command {powershell -c calc.exe}`|

<br>

## Remote Registry

Windows registry editor `reg.exe` can be used to modify run keys on remote systems to execute code at user logon:

```powershell
reg add \\<remotehost>\\HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v keyname /t REG_SZ /d "powershell -c calc.exe"
```

<br>

## Remote File Access

Access to a remote host's filesystem can be used to execute code via service modification, DLL hijack, logon script, etc.:

```powershell
xcopy malware.bat "\\<remotehost>\C$\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\malware.bat"
```

<br>


## Task Scheduler

|||
|-|-|
|`schtasks.exe`|`schtasks /create /tn test /tr "cmd /c powershell -c calc.exe" /sc once /st 07:00 /S <remotehost> /RU System` `schtasks /run /tn test /S <remotehost>`|
|`at.exe`|`at \\<remotehost> 07:00 "cmd /c powershell -c calc.exe"`|

<br>

## Remote Desktop

Interactive sessions can be initiated with a compromised account and used to execute arbitrary commands on a system.  In this case, soon after logon the adversary would most likely run the encoded PowerShell command which runs the stager and downloads the Beacon into memory.

<br>

## MMC20.Application DCOM

This technique [described here](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) uses a COM object that can execute shell commands.  By instantiating the COM object on a remote host, an adversary can run arbitrary commands using the following:


```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "<remotehost>")).Document.ActiveView.ExecuteShellCommand("C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe", $null, "-c calc.exe", "7")
```

<br>

## Create Detections

To create detections, we need to know the Event Codes and processes involved in each technique.  Different tools can be used to detect these techniques but I've found Splunk is a great choice here.  Build a search for each technique, simulate it using the command `powershell -c calc.exe`, and then confirm each technique will be detected with a test run.

|Technique|Event Codes|Processes|
|-|-|-|
|[WMI](#wmi)|4688|`svchost.exe` > `WmiPrvSE.exe` > `cmd` > `powershell.exe`|
|[SCM](#scm)|7045, 4697|`services.exe` > `cmd.exe` > `powershell.exe`|
|[WinRM](#winrm)|4688|`svchost.exe` > `WsmProvHost.exe` > `powershell.exe`|
|[Registry](#registry)|4624, 4657|`svchost.exe`|
|[File Access](#file-access)|4624, 4663|`cmd.exe` > `powershell.exe`|
|[Scheduler](#scheduler)|4698, 4688|`schtasks.exe`, then `taskeng.exe` > `powershell.exe`|
|[RDP](#rdp)|4624, 4688|`powershell.exe`|
|[MMC20](#mmc20)|4688|`svchost.exe` > `mmc.exe` > `powershell.exe`|


### WMI

Splunk search:

```
sourcetype=WinEventLog:Security EventCode=4688 powershell "calc.exe" 
| transaction host maxspan=1s startswith=New_Process_Name="*cmd.exe" 
    endswith=New_Process_Name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| eval samaccountname = mvindex(Account_Name, 1)
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname
```

Test run:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image038.png)<br><br>


### SCM

Splunk search:

```
sourcetype=WinEventLog:System EventCode=7045 OR EventCode=4697 powershell "calc.exe"
| lookup Users.csv SID as Sid
| fillnull value="Not Found" samaccountname
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname
```

Test run:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image039.png)<br><br>


### WinRM

Splunk search:

```
sourcetype=WinEventLog:Security EventCode=4688 (powershell "calc.exe") OR 
(New_Process_Name="C:\\Windows\\System32\\Wsmprovhost.exe")
| transaction host maxspan=2s startswith=New_Process_Name="C:\\Windows\\System32\\Wsmprovhost.exe" 
    endswith=New_Process_Name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| eval samaccountname = mvindex(Security_ID, 0)
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname
```

Test run:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image040.png)<br><br>

### Registry

Splunk search:

```
sourcetype="WinEventLog:Security" (EventCode=4624 Logon_Type=3) OR 
(EventCode=4657 Process_Name="C:\\Windows\\System32\\svchost.exe"  Object_Name="*\\CurrentVersion\\*")
| transaction maxspan=1s startswith=EventCode=4624  endswith=EventCode=4657
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| eval samaccountname = mvindex(Security_ID, 0)
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname
```

Test run:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image043.png)<br><br>


### File Access

Splunk search:

```
sourcetype="WinEventLog:Security" (EventCode=4624 Logon_Type=3) OR 
(EventCode=4663 Process_ID="0x4"  Object_Name="*\\Startup\\*")
| transaction maxspan=1s startswith=EventCode=4624  endswith=EventCode=4663
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| eval samaccountname = mvindex(Security_ID, 0)
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname
```

Test run:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image045.png)<br><br>


### Scheduler

Splunk search:

```
sourcetype=WinEventLog:Security EventCode=4698 powershell calc.exe
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| eval samaccountname = mvindex(user, 0)
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname
```

Test run:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image041.png)<br><br>

### RDP

Splunk search:

```
sourcetype=WinEventLog:Security (EventCode=4624 Logon_Type=10) OR
(EventCode=4688 powershell "calc.exe")
| transaction maxspan=1m startswith=EventCode=4624 endswith=EventCode=4688
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| eval samaccountname = mvindex(Security_ID, 0)
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname
```

Test run:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image044.png)<br><br>


### MMC20

Splunk search:

```
sourcetype=WinEventLog:Security EventCode=4688  
Process_Command_Line="C:\\WINDOWS\\system32\\mmc.exe -Embedding" OR (powershell "calc.exe")
| transaction host maxspan=2s startswith=Process_Command_Line="C:\\WINDOWS\\system32\\mmc.exe -Embedding" 
    endswith=New_Process_Name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| eval samaccountname = mvindex(user, 1)
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname
```

Test run:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image042.png)<br><br>

## Collect Results

Now we need to gather the results of all searches and use them to answer key questions.  Substitute the `powershell "calc.exe"` in each search with an actual indicator of the stager being launched such as `powershell "JABzAD0A*"`.

- [Timeline of Lateral Movement Events](#timeline-of-lateral-movement-events)
- [Adding External Detections](#adding-external-detections)
- [Reporting Options](#reporting-options)


### Timeline of Lateral Movement Events


For searches ran 4/2 - 4/6 and 4/9 - 4/13:

|Technique|Events|Comments|
|-|-|-|
|[WMI](#wmi)|1|Detected by EDR on 1 host not reporting to Splunk|
|[SCM](#scm)|**38**|**Their preferred method which runs Beacon as SYSTEM**|
|[WinRM](#winrm)|0|n/a|
|[Registry](#registry)|0|Very few hosts have file auditing enabled|
|[File Access](#file-access)|0|Very few hosts have file auditing enabled|
|[Scheduler](#scheduler)|0|n/a|
|[RDP](#rdp)|0|PIV requirement makes this difficult|
|[MMC20](#mmc20)|0|n/a|

<br>

Now we need to add the event detected by EDR into our timeline...

<br>

### Adding External Detections

First let's add a `technique` field and sort by `TimeOfPivot`:

```
sourcetype=WinEventLog:System EventCode=7045 OR EventCode=4697 powershell "JABzAD0A*"
| eval technique="Service Control Manager"
| lookup Users.csv SID as Sid
| fillnull value="Not Found" samaccountname
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname technique
| sort TimeOfPivot
```

<br>

This search shows when the activity began, the systems they first moved to, and the accounts they used:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image046.png)<br><br>


EDR detected the use of a second technique (WMI) which we need to add to our timeline:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image047.png)<br><br>


Create a CSV containing events you wish to add to the Splunk search (must convert to epoch time):

```powershell
[Math]::Floor([decimal](Get-Date(Get-Date('04/10/18 08:22:24')).ToUniversalTime() -uformat "%s"))

$content = @'
TimeOfPivot,host,samaccountname,technique
1523366544,<remotehost>,<account>,WMI
'@

Set-Content -Path edr_events.csv -Value $content
Get-Content edr_events.csv
```


Now upload the CSV and add it to the search with `append` and `inputlookup`:

```
sourcetype=WinEventLog:System EventCode=7045 OR EventCode=4697 powershell "JABzAD0A*"
| eval technique="Service Control Manager"
| lookup Users.csv SID as Sid
| fillnull value="Not Found" samaccountname
| eventstats earliest(_time) as TimeOfPivot count by host
| dedup host TimeOfPivot
| append [|inputlookup edr_events.csv]
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| table TimeOfPivot host samaccountname technique
| sort TimeOfPivot
```

<br>

And the externally-observed technique is now in our timeline:

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image049.png)<br><br>


### Reporting Options

#### Basic CSV

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image050.png)<br><br>


#### Account Activity Over Time

```
sourcetype=WinEventLog:System EventCode=7045 OR EventCode=4697 powershell "JABzAD0A*"
| eval technique="Service Control Manager"
| lookup Users.csv SID as Sid
| fillnull value="Not Found" samaccountname
| eventstats earliest(_time) as TimeOfPivot count by host
| append [|inputlookup edr_events.csv]
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| timechart count by samaccountname
```

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image051.png)<br><br>


#### Number of Events for Each Host

```
sourcetype=WinEventLog:System EventCode=7045 OR EventCode=4697 powershell "JABzAD0A*"
| eval technique="Service Control Manager"
| lookup Users.csv SID as Sid
| fillnull value="Not Found" samaccountname
| eventstats earliest(_time) as TimeOfPivot count by host
| append [|inputlookup edr_events.csv]
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| stats count by host
```

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image052.png)<br><br>

#### Number of Hosts Compromised By Each Account

```
sourcetype=WinEventLog:System EventCode=7045 OR EventCode=4697 powershell "JABzAD0A*"
| eval technique="Service Control Manager"
| lookup Users.csv SID as Sid
| fillnull value="Not Found" samaccountname
| eventstats earliest(_time) as TimeOfPivot count by host
| append [|inputlookup edr_events.csv]
| fieldformat TimeOfPivot=strftime(TimeOfPivot,"%x %X")
| stats dc(host) by samaccountname
```

![](images/Tracking%20Lateral%20Movement%20By%20Authenticated%20RCE/image053.png)<br><br>
