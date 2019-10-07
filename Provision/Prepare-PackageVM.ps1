
#####################################
#                                   #
#       Windows 7 Tuning            #
#                                   #
#####################################

# Disable Firewall
netsh advfirewall set allprofiles state off

# Disable Services
$services = @(
    'SSDPSRV'               # SSDP Discovery Service
    'UPNPHOST'              # Universal Plug & Play Host
    'fdPHost'               # Function Discovery Provider Host
    'FDResPub'              # Function Discovery Resource Publication
    'Browser'               # Computer Browser Service
    'W32Time'               # Windows Time Service
    'wuauserv'              # Windows Update Service
    'AdobeARMService'       # Adobe Acrobat Update Service
    'AeLookupSvc'           # Application Experience Service
    'WERSVC'                # Windows Error Reporting Service
    'WinHttpAutoProxySvc'   # WinHTTP Web Proxy Auto-Discovery
    'WlanSvc'               # WLAN AutoConfig
    'wscsvc'                # Security Center Service
    'bthserv'               # Bluetooth Support Service
    'HomeGroupListener'     # HomeGroup Listener
    'HomeGroupProvider'     # HomeGroup Provider
    'WSearch'               # Windows Search
    'TrkWks'                # Distributed Link Tracking Client
    'WbioSrvc'              # Windows Biometric Service
    'WMPNetworkSvc'         # Windows Media Player Network Sharing Service
    'RemoteAccess'          # Routing and Remote Access
    'RemoteRegistry'        # Remote Registry
    'SharedAccess'          # Internet Connection Sharing (ICS)
    'NetTcpPortSharing'     # Net.Tcp Port Sharing Service
    'DiagTrack'             # Diagnostics Tracking Service
    'gupdatem'              # Google Update Service
    'gupdate'               # Google Update Service
)
foreach ($s in $services){
    Get-Service $s | Stop-Service -Force
    Get-Service $s | Set-Service -StartupType Disabled
}

# Disable Computer Browser service
netsh advfirewall firewall set rule group="network discovery" new enable=no
wmic nicconfig where index=1 call SetTcpipNetbios 2

# Disable NetBIOS
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | %{ Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

# Disable IPv6
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name 'DisabledComponents' -Value '0xff' -PropertyType 'DWord'
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name 'IGMPLevel' -Value '2'

# Disable LLMNR
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value '0' -PropertyType 'DWord'

# Shunt Miscellaneous Queries
$list = @( 
    'crl.microsoft.com'
    'dns.msftncsi.com'
    'armmf.adobe.com'
    'update.googleapis.com'
)
foreach ($l in $list) {
    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "0.0.0.0    $l" -Encoding ASCII
}



#####################################
#                                   #
#       Windows 10 Tuning           #
#                                   #
#####################################

# Unnecessary Services
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

# Unnecessary Apps
Get-AppXProvisionedPackage -online | Remove-AppxProvisionedPackage -online
Get-AppxPackage -AllUsers | Remove-AppxPackage

# Telemetry
$regkeys = @{
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows'     = 'DataCollection';
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows'     = 'AppCompat';
    'HKLM:\SOFTWARE\Policies\Microsoft'             = 'SQMClient';
    'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient'   = 'Windows'
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


# Tasks
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

# Cortana

$regkeys = @{
    'HKCU:\Software\Microsoft\Personalization'      = 'Settings';
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows'     = 'Windows Search';
    'HKCU:\Software\Microsoft'                      = 'InputPersonalization';
    'HKCU:\Software\Microsoft\InputPersonalization' = 'TrainedDataStore'
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


# Reporting Apps
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


#####################################
#                                   #
#           Customize VM            #
#                                   #
#####################################

# Evidence of Normal Use
# Change Time Zone
Set-TimeZone -Id "Central Standard Time"

# Enable RDP    
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0 -erroraction silentlycontinue   
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 -erroraction silentlycontinue   

# Set Trusted Hosts list    
Set-Item WSMan:\localhost\Client\TrustedHosts -value * -Force


# Enable Advanced Logging
# Enable PowerShell Module, Script Block, and Full Transcription Logging
Invoke-WebRequest -usebasicparsing "https://raw.githubusercontent.com/matthewdunwoody/PS_logging_reg/master/PS_logging.reg" -O "C:\tools\ps.reg"
reg import "c:\tools\ps.reg"

# Audit Process Creation
cmd.exe /c 'auditpol /set /subcategory:"Process Creation" /success:enable'

# Include command line in Process Creation events
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 -Force


# External Tools
# Upgrade pip
C:\Python27\python.exe -m pip install --upgrade pip

# Install pillow
C:\Python27\Scripts\pip.exe install pillow

# Additional tools  
Start-BitsTransfer -Source "https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe" -Destination "C:\tools\WinDump.exe"  
Start-BitsTransfer -Source "http://graphviz.org/pub/graphviz/stable/windows/graphviz-2.38.zip" -Destination "C:\tools\graphviz-2.38.zip"
Start-BitsTransfer -Source "https://github.com/fireeye/flare-floss/releases/download/v1.5.0/floss-1.5.0-Microsoft.Windows64.zip" -Destination "C:\tools\floss.zip"

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


# Shortcuts and Path
# Create Shortcuts
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
    'Tools'                 = "C:\Tools"
    'EXEInfo'               = "C:\Tools\exeinfope\exeinfope.exe"
    'Ollydbg'               = "C:\Program Files (x86)\OllyDbg\OLLYDBG.EXE"
    'Process Hacker'        = "C:\Program Files\Process Hacker 2\ProcessHacker.exe"
    'PE Detective'          = "C:\Program Files\NTCore\Explorer Suite\PE Detective.exe"
    'Sublime'               = "C:\Program Files\Sublime Text 3\sublime_text.exe"
    'API Monitor'           = "C:\ProgramData\chocolatey\bin\apimonitor-x64.exe"
    'Malzilla'              = "C:\Tools\malzilla\malzilla.exe"
    'BinText'               = "C:\Tools\bintext\bintext.exe"
    'Regshot'               = "C:\ProgramData\chocolatey\lib\RegShot\bin\Regshot-x64-Unicode.exe"
    'Notepad++'             = "C:\Program Files\Notepad++\notepad++.exe"
    'Firefox'               = "C:\Program Files\Mozilla Firefox\firefox.exe"
    'ProcMon'               = "C:\ProgramData\chocolatey\bin\procmon.exe"
    'PEStudio'              = "C:\Tools\pestudio\pestudio.exe"
    'Autoruns64'            = "C:\ProgramData\chocolatey\bin\autoruns64.exe"
    'Dependency Walker'     = "C:\ProgramData\chocolatey\bin\depends.exe"
    'IDA Pro'               = "C:\Program Files (x86)\IDA Free\idag.exe"
    'ProcDot'               = "C:\Tools\procdot\procdot.exe"
    'API Monitor x86'       = "C:\ProgramData\chocolatey\bin\apimonitor-x86.exe"
    'Node.js'               = "C:\Program Files\nodejs\node.exe"
    'CFF Explorer'          = "C:\Program Files\NTCore\Explorer Suite\CFF Explorer.exe"
    'HashMyFiles'           = "C:\ProgramData\chocolatey\bin\HashMyFiles.exe"
    'Wireshark'             = "C:\Program Files\Wireshark\Wireshark.exe"
    'Chrome'                = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    'PowerShell'            = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    'Internet Explorer'     = "C:\Program Files\Internet Explorer\iexplore.exe"
    'HXD'                   = "C:\Program Files (x86)\HxD\HxD.exe"
    'Command Prompt'        = "%windir%\system32\cmd.exe"
    'Folder Changes View'   = "C:\ProgramData\chocolatey\bin\FolderChangesView.exe"
    'Network Monitor'       = "C:\Program Files\Microsoft Network Monitor 3\netmon.exe"
}

$tools.keys | % {
    MakeShortcut $_ $tools.Item($_)
}

# Add Tools to path
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

# Add aliases
# Set Python3 alias
set-alias -name python3 -value c:\Python36\python.exe
set-alias -name pip3 -value c:\Python36\Scripts\pip.exe

# Set Python2 alias
set-alias -name python2 -value c:\Python27\python.exe
set-alias -name pip2 -value c:\Python27\Scripts\pip.exe

# Disable Windows Defender
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1 


#####################################
#                                   #
#           Package VM              #
#                                   #
#####################################

# Zero out free space
sdelete -z c:

# Set network location private
$networkListManager =
[Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
$connections = \$networkListManager.GetNetworkConnections() 
$connections | % {$_.GetNetwork().SetCategory(1)}

# Ensure PSRemoting is enabled
Enable-PSRemoting
