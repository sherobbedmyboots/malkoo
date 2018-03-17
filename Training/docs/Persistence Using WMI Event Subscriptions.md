# Persistence Using WMI Event Subscriptions

Windows Management Instrumentation (WMI) is a set of tools designed by
Microsoft for local and remote administration of Windows systems.

WMI can be used by attackers for many purposes including reconnaissance,
code execution, covert data storage, C2, and persistence. 

This document will give an overview of WMI, how to access it, and how
WMI Event Subscriptions can be used for persistence.

- [WMI Overview](#wmi-overview)
- [Using PowerShell to Access WMI](#using-powershell-to-access-wmi)
- [WMI Event Subscriptions](#wmi-event-subscriptions)
- [Testing WMI Persistence](#testing-wmi-persistence)


## WMI Overview

WMI is an administration tool that is used to query, change, and manage
the components that make up the operating system. 

To do this, it uses classes and objects to represent different OS
components such as processes, file systems, and registry keys.

Here are some examples of classes:

|||
|-|-|
|Win32_Process|running processes|
|Win32_Service|running services|
|Win32_LogicalDisk|disk size, space, type|
|Win32_NetworkAdapter|network adapters|
|Win32_NetworkConnection|mapped network drives|
|Win32_Product|list of installed software|
|Win32_OperatingSystem|OS name, architecture, version information|
|Win32_StartupCommand|software in Startup folders|

Here are some objects in the Win32_Process class, most are
self-explanatory:

||
|-|
|PSComputerName|
|ProcessName|
|Handles|
|CommandLine|
|CreationDate|
|Description|
|ExecutablePath|
|HandleCount|
|Name|
|ParentProcessId|
|ProcessId|
|SessionId|
|Status|
|ThreadCount|


All WMI Objects have methods and properties that are easily accessed
using several different tools.

One of these is the `wmic` command line utility was designed to interact
with WMI objects:

```powershell
wmic process where 'Name="calc.exe"' list full
```


But these objects can be more easily accessed and manipulated using
PowerShell.
 

## Using PowerShell to Access WMI

There are many PowerShell cmdlets that can be used to interact with WMI
including:

```powershell
Get-WmiInstance
Set-WmiInstance
Get-CimInstance
Set-CimInstance
Register-WmiEvent
Register-CimIndicationEvent
Invoke-WmiMethod
Invoke-CimMethod
```

One of the most common cmdlets used to access WMI with PowerShell is the
 `Get-WmiObject`  cmdlet.

When using it, specify the class, and select the objects you need.

This command shows mounted shares:

```powershell
Get-WmiObject -Class Win32_Share
```



This command gets mapped network drives:

```powershell
Get-WmiObject -Class Win32_NetworkConnection
```


This command gets size and provider name for all logical volumes on the
system:

```powershell
Get-WmiObject -Class Win32_LogicalDisk | select DeviceId,Size,ProviderName
```


And this command gets OS information:

```powershell
Get-WmiObject -Class Win32_OperatingSystem | select Caption,Version,CSDVersion,OSArchitecture | fl
```


When querying and changing OS data, storing objects in variables makes
it easier to access their methods and properties.

Here I have stored a WMI object (the calculator process) in a variable
named `$calc` where I can call a property (`processid`) or call a method
(`terminate`):

```powershell
$calc | Get-WmiObject -Class Win32_Process | ? name -eq calc.exe
$calc.ProcessId
34152
$calc.Terminate()
```


To see all of an object's methods and properties, pipe the object to the
`Get-Member` cmdlet:

```powershell
$calc | Get-Member
```


To cut down on the length of commands, use the Get-WmiObject alias
`gwmi` and leave out the `-class` parameter name :

```powershell
gmwi Win32_Process | ? Name -eq calc.exe
```

## WMI Event Subscriptions

Event Subscriptions are a group of WMI classes contained within the
`root\subscription` namespace that can be used to respond asynchronously
to almost any OS event. 

There are three components involved:

- [Event Filters](#event-filters)
- [Event Consumers](#event-consumers)
- [Filter-Consumer Bindings](#filter-consumer-bindings)


### Event Filters

WMI Event Filters are objects that represent event of interest and can
be configured to alert administrators when certain conditions exist.

This capability has been used by attackers for a variety of purposes
because it allows them to execute an arbitrary command when a chosen
event occurs. 

It can be a recurring event like a system process starting or a single
event like a failed logon by a unique username.  

Here are some examples of event filters being used for persistence:

- Specific time of day (8:30 AM)
- Specific username that fails to logon (4625)
- A specific interval (weekly)
- A specific duration of time after startup
- A specific process is started
- A waitfor.exe trigger


### Event Consumers

WMI Event Consumers are objects that contain the actions to be performed
when an event of interest is observed.

Here are the five event consumer classes:

|Class|Description|
|-|-|
|CommandLineEventConsumer|Executes a command line program|
|ActiveScriptEventConsumer|Executes VBScript/Jscript|
|SMTPEventConsumer|Sends an email with event data|
|LogFileEventConsumer|Writes to a text log file|
|NTEventLogEventConsumer|Writes to the event log|

The two primary event consumers used by attackers are
`CommandLineEventConsumer` and `ActiveScriptEventConsumer`.

Using these creates "fileless" persistence as dropping a file to disk is
not required.  The malicious script or command is stored in the WMI
repository.

### Filter-Consumer Bindings

WMI Filter-Consumer Bindings are objects that bind a Filter to a
Consumer, linking the trigger event with the action to be performed.

A binding could ensure the following triggers and responses for example:

|Trigger|Response|
|-|-|
|Failed logon by user "AAdministrator"|Executes PowerShell script that downloads malware into memory|
|An hour after system powers on|Malicious service is started running under SYSTEM privileges|
|At 9:00 AM every Monday|Executes VBScript that configures backdoor for attacker|


You can see all the filters, consumers, and bindings on a host using
these commands:

Filters:

```powershell
gwmi __EventFilter -namespace root\subscription | select name,query
```

Consumers:

```powershell
gwmi __EventConsumer -namespace root\subscription | select name
```


Bindings:

```powershell
gwmi __FilterToConsumerBinding -namespace root\subscription | select Filter,Consumer
```

## Testing WMI Persistence

I created a
[Test-WMIPersistence.ps1]()
script to quickly set or remove persistence so we can become more
familiar with how the technique works, what to look for, how to respond,
etc.

The script simulates a malicious process being started with time-based
persistence using the calculator program `calc.exe`.

It can be used in three different modes:

|Mode|Description|
|-|-|
|Set|creates a filter, consumer, and binding to launch calc.exe at a specific time|
|Detect|searches for and displays the filter, consumer, and binding created|
|Remove|removes the filter, consumer, and binding|

To set persistence on your machine, use the `-set` switch and specify a
name, hour, and minute for it to launch:

```powershell
.\Test-WMIPersistence.ps1 -set -name TEST -hour 12 -minute 15
```


Make sure no `calc.exe` processes are currently running on your system:

```powershell
ps -name calc
```

You can "discover" the WMI persistence you set by running the script
with the `-detect` switch:

This will show the filter:

```powershell
.\Test-WMIPersistence.ps1 -detect -name TEST
```

The consumer:

```powershell
Name: TEST
ExecutablePath: C:\Windows\System32\calc.exe
```


And the binding that was created:

```powershell
Consumer: CommandLineEventConsumer.Name="TEST"
Filter: __EventFilter.Name="TEST"
```


A minute or so after our chosen time, we see that a new `calc.exe` process
has started in the background:

```powershell
ps -name calc
```

Security logs show the process ID of the process that spawned `calc.exe`:

It is the WMI Provider Host (`WmiPrvSE.exe`) process:

Go to the WMI logs in Applications and Services Logs --> Microsoft -->
Windows --> WMI-Activity --> Operational.

Here is an event showing the SOC_TEST Filter and the Consumer was
created:

And this log event shows the query, host process ID, and creator's SID:

To remove the WMI persistence, use the `-remove` switch and specify the
name:

```powershell
.\Test-WMIPersistence.ps1 -remove -name TEST 
```

Then verify it's been removed by using `-detect` switch:

```powershell
.\Test-WMIPersistence.ps1 -detect -name TEST
```

Finally, kill the process created by the WMI persistence:

```powershell
kill -name calc -force
```
