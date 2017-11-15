# TODO
# IE shortcut for win7
# Blank home page for IE, 
# Disable script debugging (Internet Explorer)
# Audit object tracking
# Powershell script at https://pennprovenance.net/index.php?n=Tracker.Config will specify folders to audit
# auditpol /Set /subcategory:"File System" /Success:Enable


# Install SP1, dotnet4.5, powershell
if ($host.version.major -ne 5){
    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\tools\1.ps1"
    Exit 
}

# Enable bypass policy
Set-ExecutionPolicy -Scope LocalMachine Bypass -Force
Set-ExecutionPolicy -Scope CurrentUser Bypass -Force
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Execution Policy set to Bypass"


# Disable screen lock
New-Item -Path "HKLM:\software\Policies\Microsoft\Windows\personalization" | Out-Null
Set-ItemProperty -Path "HKLM:\software\Policies\Microsoft\Windows\personalization" -Name "NoLockScreen" -Type DWord -Value 1
 
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

# Show known file extensions
If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"){
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Personalization settings changed"



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

# Stop and disable Home Groups services
if (Get-Service HomeGroupListener){
    Stop-Service "HomeGroupListener"
    Set-Service "HomeGroupListener" -StartupType Disabled
}
if (Get-Service HomeGroupProvider){
    Stop-Service "HomeGroupProvider"
    Set-Service "HomeGroupProvider" -StartupType Disabled
}
# Disable Windows Update automatic restart
If (Test-Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings"){
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
}
# Disable Windows Defender
If (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender"){
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
}
# Stop Windows Update Service
Stop-Service -Name wuauserv
Set-Service -Name wuauserv -StartUpType Disabled
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Unwanted services disabled"


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
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Additional configuration settings changed"

 
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
    Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Unwanted Microsoft applications removed"
}

# Enable PowerShell Module, Script Block, and Full Transcription Logging
Invoke-WebRequest -usebasicparsing "https://raw.githubusercontent.com/matthewdunwoody/PS_logging_reg/master/PS_logging.reg" -O "C:\tools\ps.reg"
reg import "c:\tools\ps.reg"
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "PowerShell module, script block, transcription logging enabled"

# Audit Process Creation
auditpol /set /subcategory:”Process Creation” /success:enable

# Include command line in Process Creation events
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Process creation event logging enabled"

# Change time zone
try {Set-TimeZone -Id "Central Standard Time"}
catch {tzutil.exe /s "Central Standard Time"}
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Time zone changed"

# Additional tools
Invoke-WebRequest -usebasicparsing "https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe" -O "C:\tools\WinDump.exe"
Invoke-WebRequest -usebasicparsing "http://graphviz.org/pub/graphviz/stable/windows/graphviz-2.38.zip" -O "C:\tools\graphviz-2.38.zip"
Invoke-WebRequest -usebasicparsing "https://github.com/fireeye/flare-floss/releases/download/v1.5.0/floss-1.5.0-Microsoft.Windows64.zip" -O "C:\tools\floss.zip"
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Downloaded files via web request"

choco install python2 python3 -y
$env:PATH += ";C:\Python27;C:\Python27\scripts;C:\Python36;C;\Python36\scripts"
C:\Python27\Scripts\pip.exe install virtualenv
virtualenv "C:\Users\$env:username\Desktop\Dev"
C:\Users\$env:username\Desktop\Dev\Scripts\activate
C:\Python27\Scripts\pip.exe install --upgrade setuptools pip wheel
pip install rekall
deactivate
C:\Python27\Scripts\pip.exe install -U oletools
C:\Python27\Scripts\pip.exe install "https://github.com/fireeye/flare-fakenet-ng/zipball/master"
Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Installed Python tools"

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
ls -fo "c:\Users\$env:username\Desktop" *.lnk | Remove-Item
ls -fo "c:\Users\Public\Desktop" *.lnk | Remove-Item

# Make Shortcuts
Function MakeShortcut ($name, $filepath) {
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut("$Home\Desktop\$name.lnk")
        $lnk.TargetPath = $filepath
        $lnk.Save()
}

$toolnames = @(
    "Tools",
    "PowerShell",
    "Command Prompt",
    "Firefox",
    "Chrome",
    "Internet Explorer",
    "x96dbg",
    "Ollydbg",
    "IDA Pro",
    "Wireshark",
    "Fiddler",
    "Network Monitor",
    "PEStudio",
    "CFF Explorer",
    "PE Detective",
    "EXEInfo",
    "BinText",
    "HXD",
    "Node.js",
    "Notepad++",
    "Sublime",
    "Process Hacker",
    "ProcMon",
    "HashMyFiles",
    "DNSQuerySniffer",
    "Regshot",
    "API Monitor",
    "API Monitor x86",
    "Autoruns64",
    "Malzilla",
    "ProcDot",
    "FLOSS",
    "Dependency Walker",
    "Folder Changes View"
)

$shortcuts = @(
    "C:\Tools",
    "$PSHome\powershell.exe",
    "%windir%\system32\cmd.exe",
    "C:\Program Files\Mozilla Firefox\firefox.exe",
    "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "C:\Program Files\Internet Explorer\iexplore.exe",
    "C:\ProgramData\chocolatey\bin\x96dbg.exe",
    "C:\Program Files (x86)\OllyDbg\OLLYDBG.EXE",
    "C:\Program Files (x86)\IDA Free\idag.exe",
    "C:\Program Files\Wireshark\Wireshark.exe",
    "C:\Users\$env:username\AppData\Local\Programs\Fiddler\Fiddler.exe",
    "C:\Program Files\Microsoft Network Monitor 3\netmon.exe",
    "C:\Tools\pestudio\pestudio.exe",
    "C:\Program Files\NTCore\Explorer Suite\CFF Explorer.exe",
    "C:\Program Files\NTCore\Explorer Suite\PE Detective.exe",
    "C:\Tools\exeinfope\exeinfope.exe",
    "C:\Tools\bintext\bintext.exe",
    "C:\Program Files (x86)\HxD\HxD.exe",
    "C:\Program Files\nodejs\node.exe",
    "C:\Program Files\Notepad++\notepad++.exe",
    "C:\Program Files\Sublime Text 3\sublime_text.exe",
    "C:\Program Files\Process Hacker 2\ProcessHacker.exe",
    "C:\ProgramData\chocolatey\bin\procmon.exe",
    "C:\ProgramData\chocolatey\bin\HashMyFiles.exe",
    "C:\ProgramData\chocolatey\bin\DNSQuerySniffer.exe",
    "C:\ProgramData\chocolatey\lib\RegShot\bin\Regshot-x64-Unicode.exe",
    "C:\ProgramData\chocolatey\bin\apimonitor-x64.exe",
    "C:\ProgramData\chocolatey\bin\apimonitor-x86.exe",
    "C:\ProgramData\chocolatey\bin\autoruns64.exe",
    "C:\Tools\malzilla\malzilla.exe",
    "C:\Tools\procdot\procdot.exe",
    "C:\Tools\floss\floss64.exe",
    "C:\ProgramData\chocolatey\bin\depends.exe",
    "C:\ProgramData\chocolatey\bin\FolderChangesView.exe"
)

for ($i=0; $i -lt $toolnames.length; $i++) {
    MakeShortcut $toolnames[$i] $shortcuts[$i]
}

# Clean up
choco install winpcap -y --Force
mkdir extra | Out-Null 
ls *.zip,*.txt,*.ps1,*.xml,*.reg | %{mv $_ extra\}
Remove-Item refresh.sh
1..5 | %{ rm -fo ".\$_.ps1"}

