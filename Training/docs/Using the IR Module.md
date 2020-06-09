# Using the IR Module

When gathering information in support of an incident or investigation, having quick access to useful scripts and functions can save a great deal of time and effort. I've compiled several IR-related functions into a PowerShell module that can be imported and used by an analyst to quickly collect information relevant to an investigation.

- [Setup](#setup)
	- [Create an IRmodule Directory](#create-an-irmodule-directory)
	- [Put Module File in Directory](#put-module-file-in-directory)
	- [Add Import-Module Command to Profile](#add-import-module-command-to-profile)
- [Processes](#processes)
	- [Get-ActiveProcesses](#get-activeprocesses)
	- [Get-ProcessStrings](#get-processstrings)
	- [Get-ClrReflection](#get-clrreflection)
	- [Get-InjectedThread](#get-injectedthread)
	- [Get-VirtualMemoryInfo](#get-virtualmemoryinfo)
	- [Get-RawBytes](#get-rawbytes)
	- [Get-ProcessDump](#get-processdump)
- [Network Connections](#network-connections)
	- [Get-Netstat](#get-netstat)
	- [Get-NetConnectionProfile](#get-netconnectionprofile)
	- [Get-DnsCache](#get-dnscache)
	- [Get-FirewallLog](#get-firewalllog)
- [Filesystem and User Data](#filesystem-and-user-data)
	- [Get-FileSignature](#get-filesignature)
	- [Get-FilesystemChanges](#get-filesystemchanges)
	- [Get-ForensicAlternateDataStream](#get-forensicalternatedatastream)
	- [Get-ForensicUserAssist](#get-forensicuserassist)
	- [Get-LogonDetails](#get-logondetails)
	- [Get-PSAutoRun](#get-psautorun)
	- [Get-ShadowCopies](#get-shadowcopies)


## Setup

First configure your PowerShell profile to import the module when starting a new session.  Open a PowerShell session and check the contents of your profile:

![](images/Using%20the%20IR%20Module/image001.png)<br><br>

These are commands that run automatically when you start a new session.  To import the [IRmodule](scripts/modules/IRmodule.psm1) module with every new session:

- [Create an IRmodule Directory](#create-an-irmodule-directory)
- [Put Module File in Directory](#put-module-file-in-directory)
- [Add Import-Module Command to Profile](#add-import-module-command-to-profile)

### Create an IRmodule Directory

This is what a module directory should look like:

![](images/Using%20the%20IR%20Module/image002.png)<br><br>

If you don't have one, create one:

![](images/Using%20the%20IR%20Module/image003.png)<br><br>


### Put Module File in Directory

Save the [IRmodule](scripts/modules/IRmodule.psm1) module file to this directory:

![](images/Using%20the%20IR%20Module/image004.png)<br><br>


### Add Import-Module Command to Profile

Update your PowerShell profile (`$profile`) to contain the command that imports the module (`Import-Module IRmodule`):

![](images/Using%20the%20IR%20Module/image005.png)<br><br>

Now when you open a terminal, the module is imported and its commands are available:

![](images/Using%20the%20IR%20Module/image006.png)<br><br>

And you can run these from any directory:

![](images/Using%20the%20IR%20Module/image007.png)<br><br>

Let's take a closer look at each function...


## Processes

- [Get-ActiveProcesses](#get-activeprocesses)
- [Get-ProcessStrings](#get-processstrings)
- [Get-ClrReflection](#get-clrreflection)
- [Get-InjectedThread](#get-injectedthread)
- [Get-VirtualMemoryInfo](#get-virtualmemoryinfo)
- [Get-RawBytes](#get-rawbytes)
- [Get-ProcessDump](#get-processdump)

### Get-ActiveProcesses

Gather important information about each process running on the host:

```powershell
$c = Get-Credential
$p = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-ActiveProcesses} -Credential $c
$p | Select CreationDate,Name,ProcessID,Owner,PathName | Sort -Desc CreationDate | ft
```

![](images/Using%20the%20IR%20Module/image008.png)<br><br>

### Get-ProcessStrings

Extract ASCII and Unicode strings from a process:

```powershell
$c = Get-Credential
$strings = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-ProcessStrings} -ArgumentList @('<process-id>', '<min-length>', '<encoding>') -Credential $c
$strings | ? String -Match Essential
```

![](images/Using%20the%20IR%20Module/image009.png)<br><br>

Search for strings using regular expressions:

```powershell
$Regex = [Regex] "https?://[\w\d\-\/\.]{5,}\s"
$Regex.Matches($strings.String) | Select Value
```

![](images/Using%20the%20IR%20Module/image010.png)<br><br>

### Get-ClrReflection

Run the `Get-ClrReflection` cmdlet to search for .NET programs running in memory.  When discovered, the process containing the program is identified and the file is downloaded into the current directory and named after the process name and the file's hash:

![](images/Using%20the%20IR%20Module/image011.png)<br><br>


### Get-InjectedThread

Run the `Get-InjectedThread` cmdlet to search for injected EXEs, DLL, and shellcode in memory.  When discovered, the process containing the program is identified along with the base memory address of the thread and other details:

![](images/Using%20the%20IR%20Module/image012.png)<br><br>


### Get-VirtualMemoryInfo

Use `Get-VirtualMemoryInfo` to get information about a memory address:


```powershell
$c = Get-Credential
$vmi = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-VirtualMemoryInfo} -ArgumentList @('<process-id>', '<modulebaseaddress>', '<pagesize>') -Credential $c
```

![](images/Using%20the%20IR%20Module/image013.png)<br><br>


### Get-RawBytes

Use `Get-RawBytes` to dump all the bytes stored in that memory segment and save it to a file:

```powershell
$c = Get-Credential
$bytes = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-VirtualMemoryInfo} -ArgumentList @('<process-id>', '<baseaddress>' -Credential $c
$bytes | Set-Content Injected.exe -Encoding Byte
Get-ItemProperty Injected.exe | Select *
```

![](images/Using%20the%20IR%20Module/image014.png)<br><br>

### Get-ProcessDump

Dump all memory space for a process using `Get-ProcessDump`:

```powershell
$c = Get-Credential
Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-ProcessDump} -ArgumentList '$(Get-Process -Id <process-id>)' -Credential $c
```

![](images/Using%20the%20IR%20Module/image015.png)<br><br>

## Network Connections

- [Get-Netstat](#get-netstat)
- [Get-NetConnectionProfile](#get-netconnectionprofile)
- [Get-DnsCache](#get-dnscache)
- [Get-FirewallLog](#get-firewalllog)

### Get-Netstat

```powershell
$c = Get-Credential
$n = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-Netstat} -Credential $c
$n | Select ProcessId,ProcessName,Src_Address,Src_Port,Dst_Address,Dst_Port,Protocol,State
```

![](images/Using%20the%20IR%20Module/image016.png)<br><br>

### Get-NetConnectionProfile

Use `Get-NetworkConnectionProfile` to list the networks being used on a host along with their firewall profile category, IP address, and status.


![](images/Using%20the%20IR%20Module/image017.png)<br><br>

### Get-DnsCache

```powershell
$c = Get-Credential
$dc = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-DnsCache} -Credential $c
$dc | Select Data,Name,TimeToLive,Type
```

![](images/Using%20the%20IR%20Module/image018.png)<br><br>


### Get-FirewallLog

Capture Domain, Private, and Public firewall logs into objects using `Get-FirewallLog`:

```powershell
$c = Get-Credential
$logs = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-FirewallLog} -Credential $c
$logs | Select Date,Time,Profile,Action,Protocol,SrcIp,SrcPort,DstIp,DstPort,Path |  ft -auto
```

![](images/Using%20the%20IR%20Module/image034.png)<br><br>

Filter and sort by any property:

```powershell
$logs | ? Date -eq '2019-02-02' | Group DstIp -NoElement | Sort -Desc Count
```

![](images/Using%20the%20IR%20Module/image035.png)<br><br>

## Filesystem and User Data

- [Get-FileSignature](#get-filesignature)
- [Get-FilesystemChanges](#get-filesystemchanges)
- [Get-ForensicAlternateDataStream](#get-forensicalternatedatastream)
- [Get-ForensicUserAssist](#get-forensicuserassist)
- [Get-LogonDetails](#get-logondetails)
- [Get-PSAutoRun](#get-psautorun)
- [Get-ShadowCopies](#get-shadowcopies)

### Get-FileSignature

Get the signature of both catalog-signed and embedded-signature PE files:

```powershell
$c = Get-Credential
$o = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-FileSignature} -ArgumentList '<file>' -Credential $c
$o | Select Path,Status,SignatureType,SignerCertificate
$o.SignerCertificate | Select *
```

![](images/Using%20the%20IR%20Module/image019.png)<br><br>

![](images/Using%20the%20IR%20Module/image020.png)<br><br>

### Get-FilesystemChanges

```powershell
$c = Get-Credential
$fc = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-FileSystemChanges} -ArgumentList @('<username>',<days>) -Credential $c
$fc | Select CreationTime,LastWriteTime,LastAccessTime,FullName | Sort -Desc CreationTime | ft
```

![](images/Using%20the%20IR%20Module/image021.png)<br><br>


### Get-ForensicAlternateDataStream

Getting alternate data streams on a host is an easy way to identify all files that were obtained from the Internet:

```powershell
$c = Get-Credential
$ads = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-ForensicAlternateDataStream} -Credential $c
$ads | ? StreamName -Match Identifier | Select StreamName,Name | Sort -Desc Name
```

![](images/Using%20the%20IR%20Module/image022.png)<br><br>


You can filter out the "Zone.Identifier" stream name to identify all other streams:

```powershell
$ads | ? StreamName -NotMatch Identifier | Select StreamName,Name,FullName
```

![](images/Using%20the%20IR%20Module/image023.png)<br><br>

You may find files with normal names that contain streams that behave suspiciously:

![](images/Using%20the%20IR%20Module/image024.png)<br><br>

### Get-ForensicUserAssist

```powershell
$c = Get-Credential
$ua = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-ForensicUserAssist} -Credential $c
$ua | Select RunCount,User,LastExecutionTimeUtc,ImagePath | Sort -Desc LastExecutionTimeUtc | ft -auto
```

![](images/Using%20the%20IR%20Module/image025.png)<br><br>


### Get-LogonDetails

The `LogonEvent4624` object contains info :

```powershell
$c = Get-Credential
$ld = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-LogonDetails} -ArgumentList @('<username>',<days>) -Credential $c
$ld.LogonEvent4624 | Select NewLogonAccount,LogonType,WorkstationName,SourceNetworkAddress,Count | ft
```

![](images/Using%20the%20IR%20Module/image026.png)<br><br>

The `LogonEvent4648` object:

```powershell
$ld.LogonEvent4648 | Select SourceAccount,TargetAccount,TargetServer,Count,Times | ft
```

![](images/Using%20the%20IR%20Module/image027.png)<br><br>

The `RdpClientData` object:

```powershell
$ld.RdpClientData | Select SourceAccount,TargetServer,TargetAccount | ft
```

![](images/Using%20the%20IR%20Module/image028.png)<br><br>

### Get-PSAutoRun

```powershell
$c = Get-Credential
$ar = Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-PSAutoRun} -Credential $c
$ar | Sort -Desc LastWriteTime | Select Item,Category,LastWriteTime | ft -auto
```

Find latest written:

![](images/Using%20the%20IR%20Module/image032.png)<br><br>

Sort by category:

![](images/Using%20the%20IR%20Module/image033.png)<br><br>

### Get-ShadowCopies

Use the `Get-ShadowCopies` function to list volume shadow copies on a host and the dates they were created:

```powershell
$c = Get-Credential
Invoke-Command -ComputerName $target -ScriptBlock ${Function:Get-ShadowCopies} -Credential $c
```

![](images/Using%20the%20IR%20Module/image029.png)<br><br>

Choose a copy, create a device object with it, and mount it using a symbolic link:

```powershell
$sc = gwmi Win32_ShadowCopy | ? {$_.ID -eq '{22B65D3A-F6D8-4464-A906-A74FB52F7B1A}'}
$dv = $sc.DeviceObject + "\"
cmd /c mklink /d C:\ShadowCopy "$dv"
```
![](images/Using%20the%20IR%20Module/image030.png)<br><br>

You can now access the filesystem as it was on that day:

![](images/Using%20the%20IR%20Module/image031.png)<br><br>

To remove the mounted shadow copy:

```
cmd /c rmdir C:\ShadowCopy
```
