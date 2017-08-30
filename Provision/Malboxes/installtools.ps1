# ExecutionPolicy is previously set to Unrestricted in Autounattend.xml
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# For some reason, AutoHotkey.portable wasn't working with WinPcap, so use the full installation
cinst autohotkey -y
$env:Path = "$($env:Path)C:\Program Files\AutoHotkey;"

# Enable PowerShell Module, Script Block, and Full Transcription Logging
try {wget –usebasicparsing https://raw.githubusercontent.com/matthewdunwoody/PS_logging_reg/master/PS_logging.reg -O ps.reg}
catch {(new-object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/matthewdunwoody/PS_logging_reg/master/PS_logging.reg") >> ps.reg}
finally {reg import ps.reg}

# Audit Process Creation
auditpol /set /subcategory:”Process Creation” /success:enable

# Include command line in Process Creation events
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

# Audit object tracking
# Powershell script at https://pennprovenance.net/index.php?n=Tracker.Config will specify folders to audit
# auditpol /Set /subcategory:"File System" /Success:Enable

# Change time zone
try {Set-TimeZone -Id "Central Standard Time"}
catch {tzutil.exe /s "Central Standard Time"}
