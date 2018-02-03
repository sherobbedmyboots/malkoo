# Endpoint Interrogation with PowerShell

When investigating a system during a possible incident, we gather
evidence that will support an initial assessment of the system including
interesting network connections, processes, registry and file changes,
etc.

This initial assessment requires answering some basic questions about
the system, the most common ones being:

- What network connections is the host making?

- What processes are currently running on the host?

- What users are active on the system?

- What files have been recently created, modified, or accessed?

- Have any persistence methods have been configured on the host?

There are two primary methods we use to get this type of information:

|||
|-|-|
|Data-centric Analysis|Using Splunk logs to retrieve historical network-level, host-level, and alert events|
|Endpoint Interrogation|Using FireEye HX to retrieve information about the current state of the system and recent events|

There are times when the host under investigation is not reporting to
Splunk, does not have a FireEye HX agent, or for one reason or another
cannot provide the specific information we need.  In this case, one
option is to interrogate the host directly using PowerShell.  Using
`Invoke-Command` with PowerShell scripts are a quick and easy way to
gather comprehensive information that can help answer key questions
during an initial assessment.

Here are several scripts created for this purpose:

|||
|-|-|
|[Network Connections](#network-connections)|Get-Netstat.ps1|                                           
|[Active Processes](#active-processes)|Get-ActiveProcesses.ps1|                           
|[Logon Event Details](#logon-event-details)|Get-LogonDetails.ps1|                                  
|[Recent Filesystem Changes](#recent-filesystem-changes)|Get-FilesystemChanges.ps1|                                      
|[Persistence Methods](#persistence-methods)|Get-PSAutoRun.ps1|                     


To run these scripts on a remote host, the remote host must have PS
Remoting enabled and be on your WSMan Trusted Hosts list.

To see your list of trusted hosts, type:

```powershell
(Get-Item WSMAN:\localhost\client\TrustedHosts).Value
```

An asterisk (\*) indicates all hosts are trusted

To set a host to your trusted list:

```powershell
Set-Item WSMan:\localhost\client\TrustedHosts -Value <hostname> -Force
```

To append a host to the trusted list:

```powershell
Set-Item WSMan:\localhost\client\TrustedHosts -Value <hostname> -Force -Concatenate
```

To clear the trusted host list:

```powershell
Clear-Item WSMan:\localhost\Client\TrustedHosts -Force
```

For each of these scripts, capture the results in a variable for
manipulating and filtering by property:

## Network Connections

A list of a system's network connections is key information during an
investigation.

The
[Get-Netstat.ps1]()
script is a modified version of PSHunt's `Get-Netstat.ps1`.  To use it,
run it on a remote machine like below, collecting the results in a
variable (`$n`):           

```powershell
$n = Invoke-Command -ComputerName <target> -FilePath .\Get-Netstat.ps1
```


This variable now contains all the results returned by the remote host in object form. 

Use the `Get-Member` cmdlet to see all the object properties and
methods:

```powershell
$n | Get-Member
```


You can specify the properties you're interested in by
using the `Select-Object` (select) and `Where-Object` (?) cmdlets:

```powershell
$n | ? ProcessName -eq spoolsv | select ProcessNme,Dst_Address,Dst_Port,State
```


This displays all the processes using network sockets:

```powershell
$n | select ProcessID,ProcessName,Src_Address,Src_Port,Dst_Address,Dst_Port,protocol,state | ft
```

This filters out established connections and the
processes responsible:

```powershell
$n | ? state -eq Established | select ProcessID,ProcessName,Src_Address,Src_Port,Dst_Address,Dst_Port,protocol,state | ft
```


This filters listening ports and the processes that are holding them
open:

```powershell
$n | ? state -eq Listening | select ProcessID,ProcessName,Src_Address,Src_Port,protocol,state | ft
```

## Active Processes

The
[Get-ActiveProcesses.ps1]()
script is a modified version of PSHunt's `Get-Processes` function.  To use it,
run it on a remote machine like below, collecting the results in a
variable (`$p`):        

```powershell
$p = Invoke-Command -ComputerName <target> -FilePath .\Get-ActiveProcesses.ps1
```

See recently started processes:

```powershell
$p | select CreationDate,Name,ProcessID,Owner,PathName | sort -desc CreationDate | ft
```

See binaries running out of non-standard paths:

```powershell
$p | %{if($_.PathName){$_ | ? PathName -notmatch 'System32|Program Files|SysWOW64'}} | select Name,ParentProcessName,Owner,PathName | ft
```

Find processes created by a specific user:

```powershell
$p | ? Owner -eq <account> select CreationDate,Name,Owner,PathName | sort -desc CreationDate | ft
```

Find processes spawned by a specific process:

```powershell
$p | ? ParentProcessName -eq explorer.exe | select CreationDate,ParentProcessName,Owner,PathName | sort -desc CreationDate | ft
```


## Logon Event Details

The
[Get-LogonDetails.ps1]()
script is a modified version of Joe Bialek's `Get-ComputerDetails.ps1`
which searches logs and registry keys on a remote system and reports
the details of interactive and network logons to and from the system.

Each function gathers different information:

|Function|Description|
|-|-|
|LogonEvent4624|Contains accounts logging onto the system, whether they are local, network, or interactive, source network addresses|
|LogonEvent4648|Contains accounts that have started RDP, where they logged on to from that system and what account names they used|
|RdpClientData|Contains details of past RDP client connections including account, destination server and destination account used|


To use it, run it on a remote system with
`Invoke-Command` and capture the results in a variable (`$l`):

```powershell
$l = Invoke-Command -ComputerName <target> -FilePath .\Get-LogonDetails.ps1
```

This shows logons to the target host:

```powershell
$l.logonevent4624 | select NewLogonAccount,LogonType,WorkstationName,SourceNetworkAddress,Count | sort -desc Count | ft
```

This shows logons from the target host to other hosts:

```powershell
$l.logonevent4648 | select SourceAccount,TargetAccount,TargetServer,Count,Times | sort -desc Count | ft
```

This shows RDP logons from the target hosts to other
hosts:

```powershell
$l.RdpClientData | select SourceAccount,TargetServer,TargetAccount
```


## Recent Filesystem Changes

The
[Get-FilesystemChanges.ps1]()
script returns files changed, accessed, or modified in a user profile
directory within the last X number of days.

To use it, run it on a remote system with `Invoke-Command` and
capture the results in a variable (`$f`).

For this one you must include the two required arguments---an account
name and the number of days back you want to search:

```powershell
$f = Invoke-Command -ComputerName <target> -FilePath .\Get-FileSystemChanges.ps1 -ArgumentList @('<account>', '<numDays>')
```


This lists all files created, accessed, or written to (except for
hidden files) in the last seven days:

```powershell
$f | select FullName,CreationTime,LastWriteTime,LastAccessTime | sort -desc CreationTime | ft
```


This looks at file details sorted by LastAccessTime:

```powershell
$f | select FullName,Attributes,Length,LastAccessTime | sort -desc LastAccessTime | ft
```



This looks at file details sorted by LastWriteTime:

```powershell
$f | select FullName,Attributes,Length,LastWriteTime | sort -desc LastWriteTime | ft
```

This looks at file details sorted by CreationTime:

```powershell
$f | select FullName,Attributes,Length,CreationTime | sort -desc CreationTime | ft
```


## Persistence Methods

The
[Get-PSAutoRun.ps1]()
script is a modified version of PSHunt's `Get-PSAutorun.ps1` which is a
PowerShell version of the Sysinternals Autoruns program.

This can be run on a remote machine to search for
persistence methods such as:

|Type|Description|
|-|-|
|Logon|Startup Folders, Run and RunOnce Keys that launch executables on boot or logon|
|Scheduled tasks|Files configured to run in the future or on a recurring basis|
|Services and Drivers|Most services are DLLs that run inside hosting process svchost.exe, Drivers load .sys|
|WMI|A Filter, Consumer, and Binding being used for WMI Event Subscription persistence|
|Office Add-Ins|DLLs that get loaded from Startup/Addins folders (.wll, .xll)|
|LSA Packages|Authentication package DLLs loaded by the Local Security Authority process at system start|
|Active Setup Installed Components|Executable in StubPath at `HKLM\Software\Microsoft\Active Setup\Installed Components\<GUID>` is run by Explorer.exe at user logon|
|Known DLLs|DLLs placed in the "wrong" path to exploit search-order hijacking|
|Userinit|Used by Winlogon processes to launch logon scripts|
|Browser Helper Objects|COM DLLs that get loaded into IE process when iexplore.exe executes, `CurrentVersion\Explorer\Browser Helper Objects\{CLSID}`|
|Shell Extensions|DLLs that get loaded into IE process when explorer.exe executes, `HKCR\CLSID\{CLSID}\InprocServer32\(Default)`|
|Image Hijacks|Mapping an executable's name to a different debugger source in order to load a malicious file|
|Appinit DLLs|DLLs automatically injected into every user-mode application linked to user32.dll|


To use the `Get-PSAutoRun` script, run it on the remote host and collect
the results in an object (`$ar`):

```powershell
$ar = Invoke-Command -ComputerName <target> -FilePath .\Get-PSAutoRun.ps1
```

You may get an error, but it should not affect the script
returning its results.

When complete, get the contents of the variable and group them by any
of the properties---here I'm grouping by Category:

```powershell
$ar | group Category | sort -desc Count
```

Use `Where-Object` (?) to look at entries for an individual
category:


```powershell
$ar | ? Category -eq WMI | select Item,Value
```

This reveals a suspicious PowerShell script that has been configured
to persist using WMI Event Subscriptions.

To see the entire entry, use `-exp` to expand the property:


```powershell
$ar | ? Category -eq WMI | select -exp Value
```

Specify the category and values you're interested in:

```powershell
$ar | ? Category -eq 'Office Addins'| select Item,Value,SHA1
```

Some categories may have many results, such as Services which had 308:

```powershell
$ar | ? Category -eq Services | measure
```

Filtering out certain paths will help you identify unusual
binaries/locations:

```powershell
$ar | ? Category -eq Services | ? ImagePath -notmatch 'System32|Program Files|Windows' | select Item,Value
```

This reveals an unusual service configured for persistence and running
out of a user's directory.

Further investigation shows it is currently stopped, but its startup
type is set for Automatic which means it will start on the next boot:

```powershell
Get-WmiObject win32_service -filter "Name = 'DemoService'"
```

Filtering on LastWriteTime will return recently written entries:

```powershell
$ar | ? LastWriteTime -gt (Get-Date).AddDays(-30)
```


In this case, the `AdmPwd.dll` was configured for Logon
persistence, but this is a legitimate program called Local Admin
Password Solution (LAPS).

Also, using the `SigStatus` field is a great way to narrow the focus to files that are not digitally signed.

Here, the `Get-PSAutoRun` script returns 1,541 possible persistence mechanisms.

Filtering on this property reveals that 1,517 of them (98%) have been verified as signed:

```powershell
$ar | measure
```

Returns 1541

```powershell
$ar | ? SigStatus -eq Signed | measure
```

Returns 1517
