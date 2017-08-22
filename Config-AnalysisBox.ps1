# Configuration script for analysis boxes


# Set time zone
Set-TimeZone -Id "Central Standard Time"

# Chocolatey packages
choco install -y networkmonitor hashmyfiles sublimetext3 runinbash nodejs.install hxd curl `
                 explorersuite dnsquerysniffer sysinternals ollydbg x64dbg.portable ida-free `
                 7zip putty.install fiddler4 processhacker apm winpcap wireshark adobereader `
                 regshot powershell python2 python3 googlechrome notepadplusplus.install `
                 git.install firefox

# List of other tools

# api-monitor-v2r13-x86-x64.zip
# bintext303.zip
# CaptureBAT-Setup-2.0.0-5574.exe
# exeinfope.zip
# lordepe.zip
# malzilla_1.2.0.zip
# pestudio.zip
# procdot_1_2_55_windows.zip


# Enable Module, Script Block, and Full Transcription Logging
wget –usebasicparsing https://raw.githubusercontent.com/matthewdunwoody/PS_logging_reg/master/PS_logging.reg -O ps.reg
reg import ps.reg
 
# Enable Audit Process Creation
# Auditpol /set /subcategory:”Process Creation” /success:enable  
 
# Include command line in Process Creation events
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
 
# Audit object tracking
# auditpol /Set /subcategory:"File System" /Success:Enable 

# Enable AMSI to intercept and monitor PowerShell calls in order to block malicious scripts. 
# This lets an engine look beyond basic obfuscation and dynamic code generation.
 
# Enable AppLocker to limit the execution of executables, DLLs, and scripts. 
# AppLocker identifies the applications through information about the path, file hash, or publisher.
# In an ideal enterprise environment, a whitelist approach would be used. 
# With PowerShell 5, AppLocker can enforce Constrained Language Mode.

# Configure network adapter
# New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.20.0.2 -PrefixLength 24 -DefaultGateway 172.20.0.1
# Set-DNSClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 172.20.0.1

# Extract tools
$ToolDir = "C:\Tools"
7z e $ToolDir\api-monitor-v2r13-x86-x64.zip -o"$ToolDir"\apimonitor -y
7z e $ToolDir\bintext303.zip -o"$ToolDir"\bintext -y
7z e $ToolDir\exeinfope.zip -o"$ToolDir"\exeinfope -y
7z e $ToolDir\lordpe.zip -o"$ToolDir"\lordpe -y
7z e $ToolDir\malzilla_1.2.0.zip -o"$ToolDir"\malzilla -y
7z e $ToolDir\pestudio.zip -o"$ToolDir"\pestudio -y
7z e $ToolDir\procdot_1_2_55_windows.zip -o"$ToolDir"\procdot -y


#Make Shortcuts
Function MakeShortcut ($name, $filepath) {

    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut("$Home\Desktop\$name.lnk")
    $lnk.TargetPath = $filepath
    $lnk.Save()
    }

MakeShortcut "SnippingTool" "%windir%\system32\SnippingTool.exe"
MakeShortcut "PowerShell" "$PSHome\powershell.exe"
MakeShortcut "Command Prompt" "%windir%\system32\cmd.exe"
MakeShortcut "Firefox" "C:\Program Files\Mozilla Firefox\firefox.exe"
MakeShortcut "Chrome" "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
MakeShortcut "x96dbg" "C:\ProgramData\chocolatey\bin\x96dbg.exe"
MakeShortcut "Ollydbg" "C:\Program Files (x86)\OllyDbg\OLLYDBG.EXE"
MakeShortcut "IDA Pro" "C:\Program Files (x86)\IDA Free\idag.exe"
MakeShortcut "Wireshark" "C:\Program Files\Wireshark\Wireshark.exe"
MakeShortcut "Fiddler" "C:\Program Files (x86)\Fiddler2\Fiddler.exe"
MakeShortcut "Network Monitor" "C:\Program Files\Microsoft Network Monitor 3\netmon.exe"
MakeShortcut "PEStudio" "C:\Tools\pestudio\pestudio\pestudio.exe"
MakeShortcut "CFF Explorer" "C:\Program Files\NTCore\Explorer Suite\CFF Explorer.exe"
MakeShortcut "PE Detective" "C:\Program Files\NTCore\Explorer Suite\PE Detective.exe"
MakeShortcut "EXEInfo" "C:\Tools\exeinfope\ExeinfoPe\exeinfope.exe"
MakeShortcut "BinText" "C:\Tools\bintext\bintext.exe"
MakeShortcut "HXD" "C:\Program Files (x86)\HxD\HxD.exe"
MakeShortcut "Node.js" "C:\Program Files\nodejs\node.exe"
MakeShortcut "Notepad++" "C:\Program Files\Notepad++\notepad++.exe"
MakeShortcut "Sublime" "C:\Program Files\Sublime Text 3\sublime_text.exe"
MakeShortcut "Process Hacker" "C:\Program Files\Process Hacker 2\ProcessHacker.exe"
MakeShortcut "ProcMon" "C:\ProgramData\chocolatey\bin\procmon.exe"
MakeShortcut "HashMyFiles" "C:\Tools\hashmyfiles\HashMyFiles.exe"
MakeShortcut "DNSQuerySniffer" "C:\Tools\dnsquerysniffer\DNSQuerySniffer.exe"
MakeShortcut "Regshot" "C:\ProgramData\chocolatey\lib\RegShot\bin\Regshot-x64-Unicode.exe"
MakeShortcut "API Monitor" "C:\Tools\apimonitor\API Monitor (rohitab.com)\apimonitor-x64.exe"
MakeShortcut "Autoruns64" "C:\ProgramData\chocolatey\bin\autoruns64.exe"


