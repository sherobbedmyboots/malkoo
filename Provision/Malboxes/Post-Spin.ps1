# TODO
# IE shortcut for win7
# Blank home page for IE, 
# Disable script debugging (Internet Explorer)
# Audit object tracking
# Powershell script at https://pennprovenance.net/index.php?n=Tracker.Config will specify folders to audit
# auditpol /Set /subcategory:"File System" /Success:Enable


# Install SP1, dotnet4.5, powershell
workflow Install-PowerShell5
{
    if ([Environment]::osversion.Version.Major -eq 6){
        choco install kb976932 -y
        Restart-Computer -Wait
        choco install kb976932 -y -force
        Restart-Computer -Wait
        choco install dotnet4.5 -y
        Restart-Computer -Wait
        choco install powershell -y
        Restart-Computer -Wait
}

$AtStartup = New-JobTrigger -AtStartup
Register-ScheduledJob -Name ResumeScript -Trigger $AtStartup -ScriptBlock{Import-Module PSWorkflow; Get-Job InstallPowerShell5 -State Suspended | Resume-Job}
Install-PowerShell5 -Jobname InstallPowerShell5

if ($host.version.major -ne 5){
    Write-Host -Fore Yellow "PowerShell 5 not installed. Exiting..."
    Exit 
}

# Enable bypass policy
Set-ExecutionPolicy -Scope LocalMachine Bypass -Force
Set-ExecutionPolicy -Scope CurrentUser Bypass -Force

# Disable screen lock
New-Item -Path "HKLM:\software\Policies\Microsoft\Windows\personalization" | Out-Null
Set-ItemProperty -Path "HKLM:\software\Policies\Microsoft\Windows\personalization" -Name "NoLockScreen" -Type DWord -Value 1

# Remove search bar
If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"){
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

# Remove taskview button
If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"){
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

# Show hidden files
If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"){
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}

# Stop explorer
Stop-Process -name explorer

# Stop Windows Update Service
Stop-Service -Name wuauserv
Set-Service -Name wuauserv -StartUpType Disabled

# Disable OneDrive
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
 
# Disable Telemetry
If (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"){
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
} 

# Disable Bing Search in Start Menu
If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"){
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
}

# Disable Location Tracking
If (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"){
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
}
If (Test-Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration"){
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}

# Disable Feedback
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
 
# Disable Advertising ID
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
 
# Disable Cortana
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}

If (Test-Path "HKCU:\Software\Microsoft\InputPersonalization"){
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
}

If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
 
# Disable Windows Update automatic restart
If (Test-Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings"){
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
}

# Disable Windows Defender
If (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender"){
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
}

# Stop and disable Home Groups services
if (Get-Service HomeGroupListener){
    Stop-Service "HomeGroupListener"
    Set-Service "HomeGroupListener" -StartupType Disabled
}
if (Get-Service HomeGroupProvider){
    Stop-Service "HomeGroupProvider"
    Set-Service "HomeGroupProvider" -StartupType Disabled
}

# Show known file extensions
If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"){
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}
 
# Remove unwanted MS applications
if ([Environment]::osversion.Version.Major -eq 10){
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled
    Stop-Service "dmwappushservice"
    Set-Service "dmwappushservice" -StartupType Disabled
    Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
    Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
    Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
}

# Enable PowerShell Module, Script Block, and Full Transcription Logging
try {wget –usebasicparsing https://raw.githubusercontent.com/matthewdunwoody/PS_logging_reg/master/PS_logging.reg -O ps.reg}
catch {(new-object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/matthewdunwoody/PS_logging_reg/master/PS_logging.reg") >> ps.reg}
finally {reg import ps.reg}

# Audit Process Creation
auditpol /set /subcategory:”Process Creation” /success:enable

# Include command line in Process Creation events
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Change time zone
try {Set-TimeZone -Id "Central Standard Time"}
catch {tzutil.exe /s "Central Standard Time"}

# Additional tools
Invoke-WebRequest https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe -O C:\tools\WinDump.exe
Invoke-WebRequest http://graphviz.org/pub/graphviz/stable/windows/graphviz-2.38.zip -O C:\tools\graphviz-2.38.zip
Invoke-WebRequest https://github.com/fireeye/flare-floss/releases/download/v1.5.0/floss-1.5.0-Microsoft.Windows64.zip -O floss.zip

choco install python2 python pip -y
$env:PATH += ';C:\Python27\;C:\Python36\;C:\Python27\scripts\;C:\Python36\scripts\'
pip install virtualenv
pip install rekal
pip install -U oletools
pip install https://github.com/fireeye/flare-fakenet-ng/zipball/master

# Extract tools
cd C:\Tools
# & 7z e api-monitor-v2r13-x86-x64.zip -o"apimonitor" -y
& 7z e bintext303.zip -o"bintext" -y
& 7z e exeinfope.zip -o"exeinfope" -y
& 7z e lordpe.zip -o"lordpe" -y
& 7z e malzilla_1.2.0.zip -o"malzilla" -y
& 7z e pestudio.zip -o"pestudio" -y
& 7z e procdot_1_2_55_windows.zip -o"procdot" -y
& 7z e graphviz-2.38.zip -o"graphviz" -y
& 7z e floss.zip -o"floss" -y

# Delete default shortcuts
ls -fo c:\Users\"$env:username"\Desktop *.lnk | Remove-Item
ls -fo c:\Users\Public\Desktop *.lnk | Remove-Item

# Make Shortcuts
Function MakeShortcut ($name, $filepath) {
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut("$Home\Desktop\$name.lnk")
        $lnk.TargetPath = $filepath
        $lnk.Save()
}

MakeShortcut "Tools" "C:\Tools"
MakeShortcut "SnippingTool" "%windir%\system32\SnippingTool.exe"
MakeShortcut "PowerShell" "$PSHome\powershell.exe"
MakeShortcut "Command Prompt" "%windir%\system32\cmd.exe"
MakeShortcut "Firefox" "C:\Program Files\Mozilla Firefox\firefox.exe"
MakeShortcut "Chrome" "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
MakeShortcut "Internet Explorer" "C:\Program Files\Internet Explorer\iexplore.exe"
MakeShortcut "x96dbg" "C:\ProgramData\chocolatey\bin\x96dbg.exe"
MakeShortcut "Ollydbg" "C:\Program Files (x86)\OllyDbg\OLLYDBG.EXE"
MakeShortcut "IDA Pro" "C:\Program Files (x86)\IDA Free\idag.exe"
MakeShortcut "Wireshark" "C:\Program Files\Wireshark\Wireshark.exe"
MakeShortcut "Fiddler" "C:\Users\$env:username\AppData\Local\Programs\Fiddler\Fiddler.exe"
MakeShortcut "Network Monitor" "C:\Program Files\Microsoft Network Monitor 3\netmon.exe"
MakeShortcut "PEStudio" "C:\Tools\pestudio\pestudio.exe"
MakeShortcut "CFF Explorer" "C:\Program Files\NTCore\Explorer Suite\CFF Explorer.exe"
MakeShortcut "PE Detective" "C:\Program Files\NTCore\Explorer Suite\PE Detective.exe"
MakeShortcut "EXEInfo" "C:\Tools\exeinfope\exeinfope.exe"
MakeShortcut "BinText" "C:\Tools\bintext\bintext.exe"
MakeShortcut "HXD" "C:\Program Files (x86)\HxD\HxD.exe"
MakeShortcut "Node.js" "C:\Program Files\nodejs\node.exe"
MakeShortcut "Notepad++" "C:\Program Files\Notepad++\notepad++.exe"
MakeShortcut "Sublime" "C:\Program Files\Sublime Text 3\sublime_text.exe"
MakeShortcut "Process Hacker" "C:\Program Files\Process Hacker 2\ProcessHacker.exe"
MakeShortcut "ProcMon" "C:\ProgramData\chocolatey\bin\procmon.exe"
MakeShortcut "HashMyFiles" "C:\ProgramData\chocolatey\bin\HashMyFiles.exe"
MakeShortcut "DNSQuerySniffer" "C:\ProgramData\chocolatey\bin\DNSQuerySniffer.exe"
MakeShortcut "Regshot" "C:\ProgramData\chocolatey\lib\RegShot\bin\Regshot-x64-Unicode.exe"
MakeShortcut "API Monitor" "C:\Tools\apimonitor\apimonitor-x64.exe"
MakeShortcut "Autoruns64" "C:\ProgramData\chocolatey\bin\autoruns64.exe"
MakeShortcut "Malzilla" "C:\Tools\malzilla\malzilla.exe"
MakeShortcut "ProcDot" "C:\Tools\procdot\procdot.exe"
MakeShortcut "FLOSS" "C:\Tools\floss\floss64.exe"

# Clean up
mkdir extra | Out-Null 
ls *.zip,*.txt,*.ps1,*.xml | %{mv $_ extra\}
Remove-Item refresh.sh


