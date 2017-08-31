# Extract tools
cd C:\Tools
& 7z e api-monitor-v2r13-x86-x64.zip -o"apimonitor" -y
& 7z e bintext303.zip -o"bintext" -y
& 7z e exeinfope.zip -o"exeinfope" -y
& 7z e lordpe.zip -o"lordpe" -y
& 7z e malzilla_1.2.0.zip -o"malzilla" -y
& 7z e pestudio.zip -o"pestudio" -y
& 7z e procdot_1_2_55_windows.zip -o"procdot" -y

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
MakeShortcut "LordPE" "C:\Tools\lordpe\LordPE.EXE"


# Clean up
mkdir extra | Out-Null 
ls *.zip,*.txt,*.ps1,*.xml | %{mv $_ extra\}
Remove-Item refresh.sh
