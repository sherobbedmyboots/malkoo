# Creating Analysis and Sandbox VMs

Analysis VMs and Sandbox VMs are important tools for analyzing malware and researching post-exploitation tools.  A common setup includes multiple, clean VMs configured for easy deployment and customized for their intended purpose.  Creating multiple VMs with different requirements can be time consuming, but much of the work can be reduced using various scripts and tools.

This document will review our process of creating a brand new Windows VM, tuning out unnecessary processes and network traffic, customizing it for its intended use, and packaging it into a Vagrant box for reuse.

The [Prepare-PackageVM](/scripts/Prepare-PackageVM.ps1) script contains all the functions reviewed in this document. 

- [Create Base Boxes](#create-base-boxes)
    - [Windows 7](#windows-7)
    - [Windows 10](#windows-10)
- [Tuning Windows 7](#tuning-windows-7)
    - [SSDP Discovery](#ssdp-discovery)
    - [Computer Browser Service](#computer-browser-service)
    - [IPv6](#ipv6)
    - [Windows Time Service](windows-time-service)
    - [LLMNR](#llmnr)
    - [Windows Update Service](#windows-update-service)
    - [Miscellaneous Queries](#miscellaneous-queries)
- [Tuning Windows 10](#tuning-windows-10)
    - [Unnecessary Services](#unnecessary-services)
    - [Unnecessary Apps](#unnecessary-apps)
    - [Telemetry](#telemetry)
    - [Tasks](#tasks)
    - [Cortana](#cortana)
    - [Reporting Apps](#reporting-apps)
- [Customize VM](#customize-vm)
    - [Evidence of Normal Use](#evidence-of-normal-use)
    - [Enable Advanced Logging](#enable-advanced-logging)
    - [External Tools](#external-tools)
    - [Shortcuts and Path](#shortcuts-and-path)
    - [Disable Windows Defender](#disable-windows-defender)
- [Package VM](#package-vm)
    - [Prepare VM](#prepare-vm)
    - [Package with Vagrant](#package-with-vagrant)


## Create Base Boxes

[Malboxes](https://github.com/GoSecure/malboxes) was created to make custom VM-building faster and easier for malware analysts.  It uses [Packer](https://www.packer.io/docs/index.html) to build a brand new VM configured with all desired OS changes, client software, and analysis tools.  It then converts this customized base VM to a Vagrant box that can be quickly spun up for malware analysis of an individual sample, destroyed when analysis is completed, and spun up again for use with additional samples.

Creating the base box requires three steps:

- [Configure Programs to Install](#configure-programs-to-install)
- [Build the VM](#build-the-vm)
- [Install Updates](#install-updates)


### Configure Programs to Install

The `~/.config/malboxes/config.js` file is used to list the programs you want Malboxes to install automatically using [Chocolatey](https://chocolatey.org) package manager.  List them in the file and separate with commas:

```
"choco_packages": "7zip, googlechrome, python2, adobereader, firefox, networkmonitor"
```

Network Monitor is needed for tuning, the rest are commonly found on client machines and come in handy when setting up other tools we need on each box.

### Build the VM

The `build` command needs one argument---the template--which can be Windows 7 or 10, 32-bit or 64-bit:

This builds a Windows 10 64-bit box:

```python
malboxes build win10_64_analyst
```

This builds a Windows 7 32-bit box:

```python
malboxes build win7_32_analyst
```

When complete, spin up the new VM with the `spin` command.  This will create a Vagrantfile for your new box in the current directory.  To start the VM use `vagrant up`:

```python
malboxes spin win7_32_analyst <new_box_name>
vagrant up
```

### Install Updates

The Windows 7 boxes that Malboxes builds need the following:

- Install Service Pack 1 (`choco install KB976932 -y --force`) 
- Install .NET 4.5 (`choco install dotnet4.5 -y --force`)
- Install PowerShell (`choco install powershell -y --force`)
- Turn on Automatic Updates and install all important updates (~190) 

Since these require reboots to install, they aren't likely to work if included in the `config.js` file.  Some of this can be scripted but it's sometimes easier to do this part manually to ensure everything installs correctly and you're able to handle any problems that may occur.

## Tuning Windows 7

Tuning out as much network noise as possible will make spotting malicious traffic on our Sandbox and Analysis VMs much easier.

First, disable the firewall:

```powershell
# Disable Firewall
netsh advfirewall set allprofiles state off
```


Then turn on [Network Monitor]() and start documenting the traffic:

|Service|Description|Destination IP|Destination Port|Protocol|Description|
|-|-|-|-|-|-|
|[SSDP Discovery](#ssdp-discovery)|Network device discovery|239.255.255.250|1900/udp|SSDP|SSDP:Request, M-SEARCH |
|[Computer Browser Service](#computer-browser-service)|Maintains list of computers on network|10.0.2.255|138/udp|SMB|Browser: Host Announcement, ServerName = HHI-FRONTDESK02|
|[IPv6](#ipv6)|IP Version 6|FF02::1:2|547/udp|DHCPV6|DHCPV6:MessageType = SOLICIT|
|[Windows Time Service](windows-time-service)|Synchronizes system time|13.65.245.138|123/udp|NTP|NTPv3 Request|
|[LLMNR](#llmnr)|Name resolution using local network|224.0.0.252/FF02::1:3|5355/udp|LLMNR|Queries for unresolved names such as `wpad`|
|[Windows Update Service](#windows-update-service)|Checks for/installs updates|134.170.58.221|443/tcp|HTTPS|Client Hello to `www.update.microsoft.com`|
|[Miscellaneous Queries](#miscellaneous-queries)|Microsoft or third-party software resolving hostnames|10.0.2.3|53/udp|DNS|Queries for `crl.microsoft.com`, `armmf.adobe.com`, `update.googleapis.com`, etc. |

### SSDP Discovery Service

Intended for non-enterprise systems, the SSDP Discovery Service uses HTTP, SOAP, and XML requests and responses to automatically announce services running on the local computer and discover and interact with other devices on the network.  This service is used by the Universal Plug and Play (UPnP) Device Host Service.

To disable both services:

```powershell
$services = @(
    'SSDPSRV'               # SSDP Discovery Service
    'UPNPHOST'              # Universal Plug & Play Host
    'fdPHost'               # Function Discovery Provider Host
    'FDResPub'              # Function Discovery Resource Publication
)
foreach ($s in $service){
    Get-Service $s | Stop-Service -Force
    Get-Service $s | Set-Service -StartupType Disabled
}
```

### Computer Browser Service

This is a Windows service that uses NetBIOS to locate and browse shared resources from other devices on the subnet.  

To disable:

```powershell
Get-Service Browser | Stop-Service -Force
Get-Service Browser | Set-Service -StartupType Disabled

wmic nicconfig where index=1 call SetTcpipNetbios 2

$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
gci $regkey | %{ Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose} 
```


### IPv6

IPv6 is installed and enabled by default in Windows 7/2008 and later.  To disable: 

```powershell
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name 'DisabledComponents' `
-Value '0xff' -PropertyType 'DWord'
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name 'IGMPLevel' -Value '2'
```


### Windows Time Service

The Windows Time Service maintains date and time synchronization. To disable:

```powershell
Get-Service 'W32Time' | Stop-Service -Force
Get-Service 'W32Time' | Set-Service -StartupType Disabled
```


### LLMNR

Link Local Multicast Name Resolution (LLMNR) allows a system to resolve a hostname by querying other hosts on the local subnet.  To disable:

```powershell
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' `
-Value '0' -PropertyType 'DWord'
```


### Windows Update Service

Once the sandbox VM is fully updated, the Windows Update Service is not needed so we can disable it:

```powershell
Get-Service 'wuauserv' | Stop-Service -Force
Get-Service 'wuauserv' | Set-Service -StartupType Disabled
```


### Miscellaneous Queries

Queries for known Microsoft-owned domains and other hostnames we're not interested in can be kept off the network by resolving them to `0.0.0.0` in the hosts file: 

```powershell
$list = @( 
    'crl.microsoft.com'
    'dns.msftncsi.com'
    'armmf.adobe.com'
    'update.googleapis.com'
)
foreach ($l in $list) {
    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "0.0.0.0  $l" -Encoding ASCII
}
```


### Miscellaneous Services

Some client applications such as Adobe Reader install services that attempt to update over the network.  Others such as WLAN AutoConfig and Bluetooth Support Service are not needed and can be disabled.  Identify all these services, stop them, and change their startup type to `Disabled`:

```powershell
$services = @(
    'AdobeARMService'           # Adobe Acrobat Update Service
    'AeLookupSvc'               # Application Experience Service
    'WERSVC'                # Windows Error Reporting Service
    'WinHttpAutoProxySvc'           # WinHTTP Web Proxy Auto-Discovery
    'WlanSvc'               # WLAN AutoConfig
    'wscsvc'                # Security Center Service
    'bthserv'               # Bluetooth Support Service
    'HomeGroupListener'         # HomeGroup Listener
    'HomeGroupProvider'         # HomeGroup Provider
    'WSearch'               # Windows Search
    'TrkWks'                # Distributed Link Tracking Client
    'WbioSrvc'              # Windows Biometric Service
    'WMPNetworkSvc'             # Windows Media Player Network Sharing Service
    'RemoteAccess'              # Routing and Remote Access
    'RemoteRegistry'            # Remote Registry
    'SharedAccess'              # Internet Connection Sharing (ICS)
    'NetTcpPortSharing'         # Net.Tcp Port Sharing Service
    'DiagTrack'             # Diagnostics Tracking Service
    'gupdatem'              # Google Update Service
    'gupdate'               # Google Update Service
)
foreach ($s in $services){
    Get-Service $s | Stop-Service -Force
    Get-Service $s | Set-Service -StartupType Disabled
}
```


## Tuning Windows 10

Windows 10 comes with a large collection of unnecessary services and applications such as gaming apps, telemetry, reporting and feedback, etc. So in addition to the changes we made with Windows 7, we'll also implement the following based on a great list of Windows 10 tweaks found [here](https://github.com/equk/windows/tree/master/windows_10):

- [Unnecessary Services](#unnecessary-services)
- [Unnecessary Apps](#unnecessary-apps)
- [Telemetry](#telemetry)
- [Tasks](#tasks)
- [Cortana](#cortana)
- [Reporting Apps](#reporting-apps)

### Unnecessary Services

These services are not needed and can be disabled:

```powershell
$services = @(
    'DcpSvc'                                   # Data Collection and Publishing Service
    'diagnosticshub.standardcollector.service' # Microsoft (R) Diagnostics Hub Standard Collector Service
    'dmwappushservice'                         # WAP Push Message Routing Service
    'lfsvc'                                    # Geolocation Service
    'MapsBroker'                               # Downloaded Maps Manager
    'XblAuthManager'                           # Xbox Live Auth Manager
    'XblGameSave'                              # Xbox Live Game Save Service
    'XboxNetApiSvc'                            # Xbox Live Networking Service    
    'OneSyncSvc'                               # Sync Host Service
    'ERSVC'                                    # Error Reporting Service
    'CDPSvc'                                   # Connected Devices Platform Service
    'DsSvc'                                    # Data Sharing Service
    'DcpSvc'                                   # Data Collection and Publishing Service
    'lfsvc'                                    # Geolocation service
    'SensrSvc'                                 # Monitors Various Sensors           
)
foreach ($s in $services){
    Get-Service $s | Stop-Service -Force
    Get-Service $s | Set-Service -StartupType Disabled
}
```


### Unnecessary Apps

```powershell
Get-AppXProvisionedPackage -online | Remove-AppxProvisionedPackage -online
Get-AppxPackage -AllUsers | Remove-AppxPackage
```


### Telemetry

We don't need our boxes to report telemetry data to Microsoft. To disable:

```powershell

$regkeys = @{
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows'     = 'DataCollection';
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows'         = 'AppCompat';
    'HKLM:\SOFTWARE\Policies\Microsoft'             = 'SQMClient';
    'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient'       = 'Windows'
}
$regkeys.keys | %{
    if (-not (Test-Path "$_\$regkeys.Item($_)" )){
        New-Item -Path $_ -Name $regkeys.Item($_) -Force
    }
}

# Disable Telemetry
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

# Disable PSR
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableUAR" 1

# Disable Application Impact Telemetry
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "AITEnable" 0

# Disable Customer Experience Improvement Program
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0
```


### Tasks

There are several tasks we can prevent from occurring:

```powershell
$tasks = @(
    "SmartScreenSpecific"
    "Microsoft Compatibility Appraiser"
    "ProgramDataUpdater"
    "Proxy"
    "Consolidator"
    "KernelCeipTask"
    "UsbCeip"
    "Microsoft-Windows-DiskDiagnosticDataCollector"
    "Microsoft-Windows-DiskDiagnosticResolver"
    "Sqm-Tasks"
)
foreach ($task in $tasks) {
    Get-ScheduledTask -TaskName $task | % { Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath }
}
```


### Cortana

Cortana also sends data to Microsoft which creates unnecessary network traffic.  To disable:

```powershell
$regkeys = @{
    'HKCU:\Software\Microsoft\Personalization'      = 'Settings';
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows'         = 'Windows Search';
    'HKCU:\Software\Microsoft'              = 'InputPersonalization';
    'HKCU:\Software\Microsoft\InputPersonalization'     = 'TrainedDataStore'
}
$regkeys.keys | %{
    if (-not (Test-Path "$_\$regkeys.Item($_)" )){
        New-Item -Path $_ -Name $regkeys.Item($_) -Force
    }
}

# Disable Cortana
Set-ItemProperty "HKCU:\Software\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CortanaEnabled" 0
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0

# Disable Web Search
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1

# Disable Connected Search
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchPrivacy" 3
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchSafeSearch" 3
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWebOverMeteredConnections" 0

# 
Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

# Disable Cortana on Taskbar
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 0
```


### Reporting Apps

Removing these reporting apps will significant reduce the amount of traffic to/from the VM:

```powershell
$sysapppath = "$env:systemroot\SystemApps"
$sysapps = @(
    "Microsoft.Windows.Cortana_cw5n1h2txyewy"
    "ContactSupport_cw5n1h2txyewy"
    "ParentalControls_cw5n1h2txyewy"
    "WindowsFeedback_cw5n1h2txyewy"
)

Get-Process *SearchUI* | Stop-Process -Force
foreach ($sysapp in $sysapps) {
    [int]$i = "1"
    $dis = "_disabled"
    $moveto = "$sysapppath\$sysapp$dis"
    $movefrom = "$sysapppath\$sysapp"
    if (Test-Path $sysapppath\$sysapp) {
        if (Test-Path $moveto) {
            do {
                mv $sysapppath\$sysapp $moveto$i -EA SilentlyContinue
                $i++
                }
            until (!(Test-Path $sysapppath\$sysapp))
        }
        else {
            mv $sysapppath\$sysapp $moveto
        }
    }
}
```


## Customize VM

Now we need to customize the VM for its intended purpose:

- [Evidence of Normal Use](#evidence-of-normal-use)
- [Enable Advanced Logging](#enable-advanced-logging)
- [External Tools](#external-tools)
- [Shortcuts and Path](#shortcuts-and-path)
- [Disable Windows Defender](#disable-windows-defender)

### Evidence of Normal Use

Depending on the type of VM, you may want to create a browsing history containing dozens of different websites that were previously visited.  You could also include fake documents, cookies, images, and other files that will help make the system fit the profile of an attractive target for malware.

Change things like the system's time zone to match those of production systems.  Also think about the settings you will need to enable to accurately simulate how malware and post-exploitation tools interact with production systems.  If most production systems allow users to log on via RDP and PSRemoting, ensure the analysis VMs do as well:

```powershell
# Change Time Zone
Set-TimeZone -Id "Central Standard Time"

# Enable RDP    
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name `
  "fDenyTSConnections" -Value 0 -erroraction silentlycontinue   
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -name "UserAuthentication" -Value 1 -erroraction silentlycontinue   

# Set Trusted Hosts list    
Set-Item WSMan:\localhost\Client\TrustedHosts -value * -Force   
```

### Enable Advanced Logging

Analysis VMs will provide better results if configured to log process creations and PowerShell module, script block, and transcript logs: 

```powershell
# Enable PowerShell Module, Script Block, and Full Transcription Logging
Invoke-WebRequest -usebasicparsing `
  "https://raw.githubusercontent.com/matthewdunwoody/PS_logging_reg/master/PS_logging.reg" `
  -O "C:\tools\ps.reg"
reg import "c:\tools\ps.reg"

# Audit Process Creation
cmd.exe /c 'auditpol /set /subcategory:"Process Creation" /success:enable'

# Include command line in Process Creation events
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 -Force
```

### External Tools

Python modules can be installed with [pip]():

```powershell
# Upgrade pip
C:\Python27\python.exe -m pip install --upgrade pip

# Install pillow
C:\Python27\Scripts\pip.exe install pillow
```

Traditional programs can be downloaded with [Start-BitsTransfer]():

```powershell
# Additional tools  
Start-BitsTransfer -Source "https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe" `
  -Destination "C:\tools\WinDump.exe"  
Start-BitsTransfer -Source "http://graphviz.org/pub/graphviz/stable/windows/graphviz-2.38.zip" `
  -Destination "C:\tools\graphviz-2.38.zip"
Start-BitsTransfer -Source `
  "https://github.com/fireeye/flare-floss/releases/download/v1.5.0/floss-1.5.0-Microsoft.Windows64.zip" `
  -Destination "C:\tools\floss.zip"
```

Extract any tools that are compressed with [7zip]():

```powershell
# Extract tools 
cd C:\Tools 
try {& 7z} catch {$env:PATH += ";C:\ProgramData\chocolatey\bin"}    
& 7z e bintext303.zip -o"bintext" -y    
& 7z e exeinfope.zip -o"exeinfope" -y   
& 7z e lordpe.zip -o"lordpe" -y 
& 7z e malzilla_1.2.0.zip -o"malzilla" -y   
& 7z e pestudio.zip -o"pestudio" -y 
& 7z e procdot_1_2_55_windows.zip -o"procdot" -y    
& 7z e graphviz-2.38.zip -o"graphviz" -y    
& 7z e floss.zip -o"floss" -y   
```


### Shortcuts and Path

For an Analysis VM, it's nice to have shortcuts for all your tools on the Desktop:

```powershell
function MakeShortcut ($name, $filepath) {  
    $shell = New-Object -ComObject WScript.Shell    
    $lnk = $shell.CreateShortcut("$Home\Desktop\$name.lnk") 
    $lnk.TargetPath = $filepath 
    $lnk.Save() 
}
$tools = @{
    'FLOSS'                 = "C:\Tools\floss\floss64.exe"
    'x96dbg'                = "C:\ProgramData\chocolatey\bin\x96dbg.exe"
    'Fiddler'               = "C:\Users\pcuser\AppData\Local\Programs\Fiddler\Fiddler.exe"
    'DNSQuerySniffer'       = "C:\ProgramData\chocolatey\bin\DNSQuerySniffer.exe"
}
$tools.keys | % {
    MakeShortcut $_ $tools.Item($_)
}
```


Adding directories that contain tools to your path allows you to launch all tools from the command line:

```powershell
$paths = @(
    'C:\tools'
    'C:\Windows\Microsoft.NET\Framework\v3.5\'
)

$scope = "Machine" 
$pathElements = @([Environment]::GetEnvironmentVariable("Path", $scope) –split ";")
$paths | % {
    $pathElements += $_
}
$newpath = $pathElements –join ";"
[Environment]::SetEnvironmentVariable("Path", $newpath, $scope)
```

Aliases help distinguish between tool versions:

```powershell
# Set Python3 alias
set-alias -name python3 -value c:\Python36\python.exe
set-alias -name pip3 -value c:\Python36\Scripts\pip.exe

# Set Python2 alias
set-alias -name python2 -value c:\Python27\python.exe
set-alias -name pip2 -value c:\Python27\Scripts\pip.exe
```


### Disable Windows Defender

To disable Windows Defender: 

```powershell
# Disable Windows Defender  
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name `
  "DisableAntiSpyware" -Type DWord -Value 1 
```


## Package VM

- [Prepare VM](#prepare-vm)
- [Package with Vagrant](#package-with-vagrant)

### Prepare VM

First you need to make a Vagrantfile.  You can use the one Malboxes created or you can create a custom one.

This is the one I used to make the current Sandbox VM used by Cuckoo:

![](images/Creating%20Analysis%20and%20Sandbox%20VMs/image001.png)

Notice I've commented out the Shared Folder so it will not be created on the Desktop.

Next, configure the Windows guest:

- Use the Sysinternals tool [sdelete]() to zero out the free space on
    the C drive to improve compression:

```
sdelete -z c:
```

- Ensure that Network Location is set to Private

```powershell
$networkListManager =
[Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
$connections = \$networkListManager.GetNetworkConnections() 
$connections | % {$_.GetNetwork().SetCategory(1)}
```

- Ensure that PS-Remoting is enabled

```powershell
Enable-PSRemoting
```

Shut down the VM and make sure the VM's first network adapter (nic1) is
in NAT mode.  This is a requirement for Vagrant to communicate with the
guest.

### Package with Vagrant

Export the VM to a Vagrant box using the Vagrantfile with the
following command:

```
vagrant package --base <vm_name> --vagrantfile /path/to/Vagrantfile --output <new_name.box>
```

Then add the box:

```
vagrant box add /path/to/new_name.box --name <new_name>
```

Now in a directory with the Vagrantfile you created, start the VM to
ensure everything works:

```
vagrant up
```
