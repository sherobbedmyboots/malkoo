
function tuneWindows7 {
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
}

function tuneWindows10 {
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
}

function setUpPowerShell {

    # Enable PS-Remoting
    Enable-PSRemoting

    # Set Trusted Hosts list
    Set-Item WSMan:\localhost\Client\TrustedHosts -value * -Force
    
    # Enable bypass policy
    Set-ExecutionPolicy -Scope LocalMachine Bypass -Force
    Set-ExecutionPolicy -Scope CurrentUser Bypass -Force
}

function setUpNetwork {
    # Make network connection private
    try 
    {
        $Profile = Get-NetConnectionProfile -InterfaceAlias Ethernet1
        $Profile.NetworkCategory = "Private"
        Set-NetConnectionProfile -InputObject $Profile
    }
    catch 
    {
        $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}")) 
        $connections = $networkListManager.GetNetworkConnections()
        $connections | % {$_.GetNetwork().SetCategory(1)}
    }
}

function Main {

    # Install SP1, dotnet4.5, powershell5
    if ($host.version.major -ne 5){
        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\Tools\1.ps1"
        Exit 
    }

    # Copy over agent
    cp C:\Tools\agent.pyw "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

    # Install mitm cert 
    certutil -importpfx "C:\Tools\mitmproxy-ca-cert.p12"

    # Configure powershell
    setUpPowerShell

    # Remove unnecessary services and apps on Windows 7
    tuneWindows7

    # Remove unnecessary services and apps on Windows 10
    if ([Environment]::osversion.Version.Major -eq 10) {
        tuneWindows10
    }

    # Install pillow
    C:\Python27\Scripts\pip.exe install pillow

    # Upgrade pip
    C:\Python27\python.exe -m pip install --upgrade pip

    # Change time zone
    if ((Get-TimeZone).Id -ne 'Central Standard Time'){
        Set-TimeZone -Id "Central Standard Time"
    }

    # Disable active probing
    Set-Location -Path 'HKLM:\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet'
    Set-ItemProperty -Path . -Name "EnableActiveProbing" -Value '1'

    # Configure network
    setUpNetwork

    # Set next startup script
    cp C:\Tools\SysPrep.ps1 "$env:TEMP\"
    Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    Set-ItemProperty -Path . -Name "SysPrep" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe $env:TEMP\SysPrep.ps1"

    # Complete
    Set-Content -Path $env:USERPROFILE\Desktop\Complete -Value complete
    Restart-Computer
}

Main