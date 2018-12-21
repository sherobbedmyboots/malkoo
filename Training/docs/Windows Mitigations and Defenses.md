# Windows Mitigations and Defenses

Hardening the technical environment increases our ability to resist intrusions and counter weaknesses being exploited by ongoing intruder activity.  This document reviews some common tactics and techniques and the respective mitigations and defenses we can check for and/or implement on Windows systems in support of incident analysis and response.  Becoming familiar with these and learning how to assess them in our environment improves performance in all stages of the incident lifecycle.

- [Mitigations and Defenses](#mitigations-and-defenses)
- [Countering Malware](#countering-malware)
	- [Application Whitelisting](#application-whitelisting)
		- [AppLocker](#applocker)
		- [Device Guard](#device-guard)
	- [Patch Management](#patch-management)
	- [Disable Untrusted Office Features](#disable-untrusted-office-features)
		- [Disable Macros](#disable-macros)
		- [Disable OLE Object Execution](#disable-ole-execution)
		- [Disable ActiveX](#disable-activex)
		- [Disable DDE](#disable-dde)
	- [Disable AutoRun-AutoPlay](#disable-autorun-autoplay)
- [Limiting Extent of Damage](#limiting-extent-of-damage)               
	- [Least Privilege](#least-privilege)
		- [User Account Control](#user-account-control)
		- [Writable Windows Shares](#writable-windows-shares)
		- [Restrict Inbound Connections](#restrict-inbound-connections)
		- [Disable or Restrict Unused Features](#disable-or-restrict-unused-features)
	- [Multi-factor Authentication](#multi-factor-authentication)
		- [MFA on Local Accounts](#mfa-on-local-accounts)
		- [MFA on Domain Accounts](#mfa-on-domain-accounts)
	- [Daily Backups](#daily-backups)
		- [Logical or Physical Separation](#logical-or-physical-separation)
		- [Required Validity Check](#required-validity-check)
		- [Continuous Operation](#continuous-operation)
	- [Credential Hygiene](#credential-hygiene)
		- [Use Unique and Complex Passwords](#use-unique-and-complex-passwords)
		- [Monitor for Credential Exposure](#monitor-for-credential-exposure)
		- [Enable Credential Guard](#enable-credential-guard)

## Mitigations and Defenses

**Tactics** can be described as the art or skill of employing available means to accomplish an end.  

**Techniques** are the unique ways or methods used to perform functions such as spearphishing, credential theft, and drive-by downloads.

**Mitigations and Defenses** are the controls we have in place to prevent or counter the use of adversary tactics and techniques in our environment.  

Using the [ATT&CK Technique Matrix](https://attack.mitre.org/wiki/Technique_Matrix), we can get a list of tactics and techniques relevant to a Windows client machine and their respective mitigations/defenses:

|Tactics|Techniques|Mitigations and Defenses|
|-|-|-|
|[Initial Access](https://attack.mitre.org/wiki/Initial_Access)				|[Drive-by](https://attack.mitre.org/wiki/Technique/T1189), [Spearphishing](https://attack.mitre.org/wiki/Technique/T1193), [Removable Media](https://attack.mitre.org/wiki/Technique/T1091)				|[App Whitelisting](#application-whitelisting), [Disable Untrusted Office Features](#disable-untrusted-office-features), [Patch Management](#patch-management), [Sandbox-VM Isolation](#sandbox-vm-isolation), [EMET](), [Disable AutoRun-AutoPlay](#disable-autorun-autoplay)|
|[Execution](https://attack.mitre.org/wiki/Execution)						|[CLI](https://attack.mitre.org/wiki/Technique/T1059), [GUI](https://attack.mitre.org/wiki/Technique/T1061), [PowerShell](https://attack.mitre.org/wiki/Technique/T1086), [WMI](https://attack.mitre.org/wiki/Technique/T1047), [WinRM](https://attack.mitre.org/wiki/Technique/T1028), [Tasks](https://attack.mitre.org/wiki/Technique/T1053) 				|[App Whitelisting](#application-whitelisting), [MFA](#multi-factor-authentication), [Disable NTLM/Only Use Kerberos](), [Disable AutoRun-AutoPlay](#disable-autorun-autoplay)|
|[Persistence](https://attack.mitre.org/wiki/Persistence) 					|[Logon Scripts](https://attack.mitre.org/wiki/Technique/T1037), [Run Keys](https://attack.mitre.org/wiki/Technique/T1060), [Services](https://attack.mitre.org/wiki/Technique/T1058), [Tasks](https://attack.mitre.org/wiki/Technique/T1053), [WMI](https://attack.mitre.org/wiki/Technique/T1084)|[App Whitelisting](#application-whitelisting), [Credential Hygiene](), [Least Privilege]()|
|[Privilege Escalation](https://attack.mitre.org/wiki/Privilege_Escalation)	|[Permissions Weakness](), [Exploit](), [Valid Account]() 					|[App Whitelisting](#application-whitelisting), [MFA](#multi-factor-authentication), [Disable NTLM/Only Use Kerberos](), [Patch Management](#patch-management)|
|[Defense Evasion](https://attack.mitre.org/wiki/Defense_Evasion) 			|[Binary Padding](https://attack.mitre.org/wiki/Technique/T1009), [Token Manipulation](https://attack.mitre.org/wiki/Technique/T1134), [DLL Search Order Hijacking](https://attack.mitre.org/wiki/Technique/T1038), [Indirect Command Execution](https://attack.mitre.org/wiki/Technique/T1202)|[App Whitelisting](), [Least Privilege](), [Patch Management](#patch-management)
|[Credential Access](https://attack.mitre.org/wiki/Credential_Access)		|[Brute Force](https://attack.mitre.org/wiki/Technique/T1110), [Dumping](https://attack.mitre.org/wiki/Technique/T1003), [Discovery](https://attack.mitre.org/wiki/Technique/T1081), [Capture](https://attack.mitre.org/wiki/Technique/T1056)			|[App Whitelisting](#application-whitelisting), [MFA](#multi-factor-authentication), [Disable NTLM/Only Use Kerberos](), [Strong Password Policy](),  [Type3 Logons/Restricted Admin mode RDP]()|
|[Discovery](https://attack.mitre.org/wiki/Discovery)  						|[Account](https://attack.mitre.org/wiki/Technique/T1087), [File](https://attack.mitre.org/wiki/Technique/T1083), [Share](https://attack.mitre.org/wiki/Technique/T1135), [System](https://attack.mitre.org/wiki/Technique/T1018), [System Info](https://attack.mitre.org/wiki/Technique/T1082)						|[App Whitelisting](#application-whitelisting), [MFA](#multi-factor-authentication), [Disable NTLM/Only Use Kerberos]()|
|[Lateral Movement](https://attack.mitre.org/wiki/Lateral_Movement) 		|[DCOM](https://attack.mitre.org/wiki/Technique/T1175), [WinRM](https://attack.mitre.org/wiki/Technique/T1028), [File Copy](https://attack.mitre.org/wiki/Technique/T1105), [Pass Ticket/Hash](https://attack.mitre.org/wiki/Technique/T1097), [Removable Media](https://attack.mitre.org/wiki/Technique/T1091)  |[App Whitelisting](#application-whitelisting), [MFA](#multi-factor-authentication), [Disable NTLM/Only Use Kerberos]()|
|[Collection](https://attack.mitre.org/wiki/Collection)|[Automated Collection](https://attack.mitre.org/wiki/Technique/T1119), [Input Capture](https://attack.mitre.org/wiki/Technique/T1056), [Screen Capture](https://attack.mitre.org/wiki/Technique/T1113)|[App Whitelisting](#application-whitelisting), [MFA](#multi-factor-authentication), [Encryption]()|
|[Exfiltration](https://attack.mitre.org/wiki/Exfiltration)  				|[Automated Exfiltration](https://attack.mitre.org/wiki/Technique/T1020), [Physical Medium]()|[App Whitelisting](#application-whitelisting), [Disable AutoRun-AutoPlay](#disable-autorun-autoplay), [IDPS](), [Proxy Firewall]()|
|[Command and Control](https://attack.mitre.org/wiki/Command_and_Control) 	|[Connection Proxy](https://attack.mitre.org/wiki/Technique/T1090), [Multiband](https://attack.mitre.org/wiki/Technique/T1026), [Removable Media](https://attack.mitre.org/wiki/Technique/T1092), [RAT](https://attack.mitre.org/wiki/Technique/T1219)|[App Whitelisting](#application-whitelisting), [Disable AutoRun-AutoPlay](#disable-autorun-autoplay), [IDPS](), [Proxy Firewall]()|


<br>

Using this table, let's look at some of the most useful mitigation techniques organized into two broad categories:

- [Countering Malware](#countering-malware)
- [Limiting Extent of Damage](#limiting-extent-of-damage)

## Countering Malware

|Mitigation|Description|
|-|-|
|[Application Whitelisting](#application-whitelisting)|Allow and deny drivers, programs, and scripts from running based on characteristics|
|[Patch Management](#patch-management)|Keep operating system and applications at latest versions|
|[Disable Untrusted Office Features](#disable-untrusted-office-features)|Disable features that can run untrusted code such as Macros, OLE Object Execution, ActiveX, DDE|
|[Disable AutoRun-AutoPlay](#disable-autorun-autoplay)|Prevent applicatons from automatically executing when a device is plugged into the computer|


### Application Whitelisting

Over the years, Microsoft Windows has provided different functions for countering the execution of arbitrary code---Software Restriction Policies, AppLocker, and Device Guard which is now called [Windows Defender Application Control](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control) (WDAC).  

Let's look at two of these options:

- [AppLocker](#applocker)
- [Device Guard](#device-guard)

#### AppLocker

AppLocker restricts the execution of executables, DLLs, scripts, and installer files.  By defining rules with an AppLocker policy, we can prevent and allow the execution of applications and scripts based on their path, hash value, or digital signature.

- Whitelist batch scripts, vbscript/javascript, java, block VBA macros
- Restrict PowerShell execution policy to administrators and to only execute signed scripts
- Disable/restrict the WinRM Service to help prevent uses of PowerShell for remote execution
- Use third party solutions such as Bit9, McAfee

To set an AppLocker policy:

```powershell
# Import the module 
Import-Module AppLocker

# Start AppIDSvc service
Start-Service AppIDSvc

# Configure AppIDSvc to start automatically
Set-Service AppIDSvc -StartupType Automatic  # Windows 7
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name Start -Value 2    # Windows 10

# Create and set AppLocker policy
Get-ChildItem C:\Windows\System32\*.exe | Get-AppLockerFileInformation | New-AppLockerPolicy -RuleType Publisher, Hash -User Everyone -RuleNamePrefix System32 | Set-AppLockerPolicy -Merge
```

To clear the AppLocker policy:

```
# Create XML content
$xml = @'
<AppLockerPolicy Version="1">
	<RuleCollection Type="Exe" EnforcementMode="NotConfigured" />
	<RuleCollection Type="Msi" EnforcementMode="NotConfigured" />
	<RuleCollection Type="Script" EnforcementMode="NotConfigured" />
	<RuleCollection Type="Dll" EnforcementMode="NotConfigured" />
</AppLockerPolicy>
'@

# Write to file
Set-Content -Path clear.xml -Value $xml

# Clear AppLocker Policy
Set-AppLockerPolicy -XmlPolicy clear.xml
```

#### Device Guard

Device Guard also restricts the execution of executables, DLLs, scripts, and installer files but does it using virtualization-based security (VBS).  It also ensures that PowerShell runs in Constrained Language Mode.  It is an improvement over AppLocker because its isolation from the rest of the operating system prevents manipulation by administrators or malware with elevated privileges.

It has three main functions:

|Function|Description|
|-|-|
|Platform and UEFI Secure Boot|Ensures the boot binaries and UEFI firmware are signed and have not been tampered with|
|Configurable Code Integrity (CCI)|Ensures that only trusted code runs from the boot loader onwards|
|VSM Protected Code Integrity|Kernel Mode Code Integrity (KMCI) and Hypervisor Code Integrity (HVCI) are executed in isolation using Virtual Secure Mode (VSM)|

To use it, you would create a code integrity policy listing the programs and scripts you want to allow or deny execution based on hash, filename, signed version, publisher, and others.  In thie policy, you would first [add allow rules](http://www.exploit-monday.com/2016/09/introduction-to-windows-device-guard.html) for authorized programs and then [add deny rules](http://www.exploit-monday.com/2016/09/using-device-guard-to-mitigate-against.html) for programs that are bypasses that can be used to run untrusted code.

A good example of a base policy in enforcement mode is provided [here](https://gist.github.com/mattifestation/0e17c5ffbe66597f0d78a2861202848c).  

To make your own you would [do the following](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/create-initial-default-policy#use-a-windows-defender-application-control-policy-to-control-specific-plug-ins-add-ins-and-modules):

```powershell
# Scan the system
$CIPolicyPath=$env:userprofile+"\Desktop\"
$InitialCIPolicy=$CIPolicyPath+"InitialScan.xml"
$CIPolicyBin=$CIPolicyPath+"DeviceGuardPolicy.bin"
New-CIPolicy -Level PcaCertificate -FilePath $InitialCIPolicy –UserPEs 3> CIPolicyLog.txt

# Enable the policy
ConvertFrom-CIPolicy $InitialCIPolicy $CIPolicyBin
cp $CIPolicyBin C:\Windows\System32\CodeIntegrity
```

### Patch Management

Updating software regularly is one of the easiest and most effective ways to secure Windows client workstations and servers. 

Check to see the last dates updates were searched and/or installed:

```powershell
(New-Object -c Microsoft.Update.AutoUpdate).Results
```

See a list of the latest updates installed and the dates and times it happened:

```
Get-HotFix | Sort -desc InstalledOn
```

Generate a list of updates installed using Windows Update, Microsoft Update or Automatic Updates feature:

```powershell
$session = New-Object -ComObject Microsoft.Update.Session 
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and Type='Software'") 
```

The following installs all updates:

```powershell
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $result.Updates
$downloader.Download()
$installer = New-Object -ComObject Microsoft.Update.installer
$installer.Updates = $result.Updates
$installer.install()
```

### Disable Untrusted Office Features

Microsoft Office comes with several features that adversaries commonly use to run untrusted code on a system:

- [Disable Macros](#disable-macros)
- [Disable OLE Object Execution](#disable-ole-execution)
- [Disable ActiveX](#disable-activex)
- [Disable DDE](#disable-dde)


#### Disable Macros

Setting the `VBAWarnings` key to a value of 4 disables the "Enable this Content" notification for users to prevent the execution of VBA macros:

```powershell
'Word', 'Excel', 'PowerPoint' | %{
	if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\$_\Security" -ErrorAction SilentlyContinue).VBAWarnings -ne 4){Write-Host [-] Macros not disabled for $_}
}
```

#### Disable OLE Object Execution

Setting the `PackagerPrompt` key to a value of 2 disables execution of embedded OLE objects:

```powershell
'Word', 'Excel', 'PowerPoint' | %{
	if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\$_\Security" -ErrorAction SilentlyContinue).PackagerPrompt -ne 2){Write-Host [-] OLE execution not disabled for $_}
}
```

#### Disable ActiveX

Disable ActiveX Controls for all Office applications by setting the `DisableAllActiveX` key to a value of `1`. This checks to see if ActiveX is disabled:

```powershell
if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\Security" -ErrorAction SilentlyContinue).DisableAllActiveX -ne 1){Write-Host [-] ActiveX not disabled for $_}
```

#### Disable DDE

Disabling DDE for Word and Excel requires several keys to be setting values for several keys.  This checks to see if DDE is disabled:

```powershell
'Word', 'Excel' | %{
	if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\$_\Options" -ErrorAction SilentlyContinue).DontUpdateLinks -ne 1){Write-Host [-] DDE not disabled for $_}
	if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\$_\Options\WordMail" -ErrorAction SilentlyContinue).DontUpdateLinks -ne 1){Write-Host [-] DDE not disabled for $_}
	if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\$_\Options" -ErrorAction SilentlyContinue).DDEAllowed -ne 0){Write-Host [-] DDE not disabled for $_}
	if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\$_\Options" -ErrorAction SilentlyContinue).DDECleaned -ne 1){Write-Host [-] DDE not disabled for $_}
	if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\$_\Options" -ErrorAction SilentlyContinue).Options -ne 0x117){Write-Host [-] DDE not disabled for $_}
	if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\$_\Security" -ErrorAction SilentlyContinue).WorkbookLinkWarnings -ne 2){Write-Host [-] DDE not disabled for $_}
}
```

### Disable Autorun

Autorun looks for an `Autorun.inf` when a media device is inserted into a computer and will automatically start a program based on the contents of this file.  AutoPlay lets you choose which program to use for different types of media.

This checks to see if Autorun is disabled:

```powershell
if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer").NoDriveTypeAutoRun -eq 255){Write-Host [-] Autorun not disabled}
```

This checks to see if AutoPlay is disabled:

```powershell
# Check AutoPlay
if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers").DisableAutoplay -eq 1){Write-Host [-] AutoPlay not disabled}
```

## Limiting Extent of Damage

|Mitigation|Description|
|-|-|
|[Least Privilege](#least-privilege)|Limit access to only information and resources necessary for normal operation|
|[Multi-factor Authentication](#multi-factor-authentication)|Requiring two or more factors to confirm an identity|
|[Daily Backups](#daily-backups)|Maintaining copies of system files and data at least every day|
|[Credential Hygiene](#credential-hygiene)|Proper protection and handling of passwords and password hashes|


### Least Privilege

- [User Account Control](#user-account-control)
- [Writable Windows Shares](#writable-windows-shares)
- [Restrict Inbound Connections](#restrict-inbound-connections)
- [Disable or Restrict Unused Features](#disable-or-restrict-unused-features)


#### User Account Control

The following registry keys enable User Account Control (UAC) to always ask for permission for privileged operations and to use "secure desktop":

- `EnableLUA`
- `ConsentPromptBehaviorAdmin`
- `PromptOnSecureDesktop`

This checks each key to see if UAC is enabled:

```powershell
# Check UAC
$keys = 'EnableLUA','ConsentPromptBehaviorAdmin','PromptOnSecureDesktop'
$keys | %{if ((Get-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System").$_ -eq 0){Write-Host [-] UAC is not enabled}}
```

#### Writable Windows Shares

Writable Windows shares can be used for planting executables, DLL preloading, shortcut hijacking, or script infecting.  A safe option is to only allow admin-writeable or user-private shares.

This checks for any shares that are readable/writable by non-default accounts:

```powershell
# Check for Writable Shares
$allowed = 'BUILTIN\Administrators','BUILTIN\Backup Operators','NT AUTHORITY\INTERACTIVE'
Get-SmbShare | Get-SmbShareAccess | %{if ($allowed -notcontains $_.AccountName) {Write-Host [-] Check share permissions for $_.Name}} 
```

Examine who has permissions to read and write to the share:

```powershell
Get-SmbShare

Get-SmbShareAccess docs
```

![](images/Windows%20Mitigations%20and%20Defenses/image002.png)

### Restrict Inbound Connections

Establish dedicated admin machines and restrict inbound connections to remote admin sources.  This hardening technique could also be used to contain a host that doesn't have FireEye HX installed.

Use the `Get-NetFirewallRule` cmdlet to gather information about the firewall rules on a system:

![](images/Windows%20Mitigations%20and%20Defenses/image003.png)

You can search for rules by name or group.  Here we have two rules for PSRemoting--one for the Domain and Private profiles and one for the Public profile:

![](images/Windows%20Mitigations%20and%20Defenses/image004.png)

Piping to the `Get-NetAddressFilter` cmdlet allows you to see the addresses associated with the rules:

![](images/Windows%20Mitigations%20and%20Defenses/image005.png)

You can change the addresses allowed in the WinRM firewall rule using the `Set-NetFirewallRule` cmdlet.  This allows the system's WinRM service to only allow connections from the `x.x.x.x/24` subnet:

```powershell
Set-NetFirewallRule -DisplayGroup "Windows Remote Management" -RemoteAddress x.x.x.x/24
Get-NetFirewallRule -DisplayGroup "Windows Remote Management" | Get-NetFirewallAddressFilter | select RemoteAddress
```

![](images/Windows%20Mitigations%20and%20Defenses/image006.png)

You can also set them individually by Name. This returns the Public WinRM rule to `LocalSubnet` and the Domain/Private WinRM rule to `Any`:

![](images/Windows%20Mitigations%20and%20Defenses/image007.png)

The following sets each connection to Public and restricts PS Remoting access to one host (10.10.10.100):

```powershell
# Set all connections to Public
(Get-NetConnectionProfile).Name | % {Set-NetConnectionProfile -name $_ -NetworkCategory Public}

# Restrict inbound connections to one host
Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -RemoteAddress 10.10.10.100
```

#### Disable or Restrict Unused Features

Turn off or restrict access to unused features such as Windows Script Host which allows the execution of VBScript and Javascript:

```powershell
# Disable Windows Scripting Host
if ((Get-ItemProperty 'HKLM:\Software\Microsoft\Windows Script Host\Settings\Enabled' | select -exp `(default`)) -ne 0){
	$answer = Read-Host "[-] Windows Script Host not disabled... Disable it? [y/N]"
	if ($answer -eq 'y'){
		if (Test-Path 'HKLM:\Software\Microsoft\Windows Script Host\Settings\Enabled') {
			Set-Item -Path 'HKLM:\Software\Microsoft\Windows Script Host\Settings\Enabled' -Value 0
		}
		else {
			New-Item -Path 'HKLM:\Software\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 0
		}
	}
}
```

### Multi-factor Authentication

Multi-factor authentication requires using two or more of the following---something you know, something you have, and something you are. The first factor is traditionally username and password while the second can be hardware devices, third party tokens, phone calls, SMS/text messages, or secure mobile push notifications.

The most common solution for Windows accounts is the combination of account credentials (username and password) and a tamper-resistant hardware device (smartcard or U2F device). Here are two examples of using this combination on a Windows system:

- [MFA on Local Accounts](#mfa-on-local-accounts)
- [MFA on Domain Accounts](#mfa-on-domain-accounts)

#### MFA on Local Accounts

MFA on local accounts can be enabled using smart cards or U2F devices such as Yubikeys.  They store a private key which cannot be stolen, dumped from memory, or key-logged.  

The [YubiKey Smart Card Minidriver](https://yubico.com/wp-content/uploads/2016/06/Windows-Login-Yubikey-Configuration_en.pdf) can be used to enroll YubiKeys as smart cards if you want to implement MFA on OOB or personal Windows systems.  You can then require all accounts to use smart cards for interactive logons via GPO:

![](images/Windows%20Mitigations%20and%20Defenses/image017.png)

To see if smart cards are required:

```powershell
if ((Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\System -Name ScForceOption).scforceoption -eq 0){Write-Host -Fore Red "[-] SmartCard Force Option is not enabled"}
```

If this policy isn't enabled for all workstations, we can also create a smartcard requirement on user domain accounts that can be temporarily disabled if a user forgets to bring their smart card to work.

#### MFA on Domain Accounts

Logging on a system in our environment with a normal domain account requires a smart card which contains the user's issued certificates and private keys needed to authenticate the user.  

To see if an account is required to logon with a PIV, use the `Get-ADUser` cmdlet:

```powershell
(Get-ADUser <username> -pr *).SmarcardLogonRequired
```
![](images/Windows%20Mitigations%20and%20Defenses/image018.png)

### Daily Backups

Backups are an important defense against malware.  Windows natively keeps shadow copies of the filesystem which we can view with `Get-CimInstance -ClassName Win32_ShadowCopy | select ID,InstallDate`:

![](images/Windows%20Mitigations%20and%20Defenses/image008.png)

But malware is often configured to search for and delete these shadow copies.  Backing up data to another drive or network share can also be problematic as modern versions of ransomware are now designed to enumerate a system's mapped drives and available network shares and encrypt any files discovered.  

For these reasons, a complete backup solution must satisfy the following three requirements:

|Requirement|Description|
|-|-|
|[Logical or Physical Separation](#logical-or-physical-separation)|Access to the backup destination is not possible except for during scheduled backup operations|
|[Required Validity Check](#required-validity-check)|Checks are built in to ensure a backup is never overwritten by corrupted files|
|[Continuous Operation](#continuous-operation)|Automation is used to ensure backups occur daily|

[Backup and Restore](https://en.wikipedia.org/wiki/Backup_and_Restore) was the standard in earlier versions of Windows, now system image backups aren't necessary with the [Reset your PC](https://support.microsoft.com/en-us/help/12415/windows-10-recovery-options) feature which restores the OS back to its initial state.

Modern Windows systems use [File History](https://support.microsoft.com/en-us/help/17128/windows-8-file-history) which only backs up your personal files, is faster, doesn't require as much space, and provides a way to access individual files and folders if needed.  You can add or exclude folders as necessary, browse copies of the backed up files and folders, and restore them from within File Explorer. But File History is continuously backing up files as the system runs and could unintentionally overwrite good files with unwanted files in the event malware is able to run on the system.

A simple solution would be a script that runs every day and checks to see if one or more [Honeytoken](https://en.wikipedia.org/wiki/Honeytoken) files have been accessed or modified.  If no evidence of tampering is observed, it prompts the user to unlock an encrypted container hosted on a network share, copies new files to the container, and then dismounts the container so nothing else can be written to it.

This would meet all three of our requirements.  Let's build an example script that performs logical separation, validity checking, and is configured to run every day.

#### Logical or Physical Separation

Physical separation would be connecting and disconnecting USB interface or network connectivity before and after each backup. This script will achieve logical separation using a password-protected encrypted container hosted by another system on the network.  

Install VeraCrypt and create an encrypted container on the system hosting the share:

```powershell
# Install VeraCrypt
choco install veracrypt -y
$env:PATH += ';C:\Program Files\VeraCrypt'

# Share a folder on the network
New-Item -Name Backup -Type Directory
New-SMBShare -Name Backup -FullAccess kbotawindows\kbota -Path C:\Backup

# Create encrypted container
& 'VeraCrypt Format.exe' /create C:\Backup\container /password '$uP3r$eCr3t' /encryption AES /filesystem FAT /size 10M /force
```

![](images/Windows%20Mitigations%20and%20Defenses/image009.png)

On the system you're backing up, install VeraCrypt and confirm you can access the container:

```powershell
# Install VeraCrypt
choco install veracrypt -y
$env:PATH += ';C:\Program Files\VeraCrypt'

# Mount the encrypted container as x:
veracrypt /q /v \\192.168.2.147\Backup\container /l x /a /b
```

The password is required to mount the container:

![](images/Windows%20Mitigations%20and%20Defenses/image010.png)

After entering the correct password you can copy files over the network:

```powershell
robocopy /MIR C:\Users\kbota\Desktop x:\ /Z /W:5
```

![](images/Windows%20Mitigations%20and%20Defenses/image011.png)

After files have been copied, dismount the container:

```powershell
# Dismount container
veracrypt /q /d x
```

#### Required Validity Check

At this point we can script mounting the container, copying the files over, and dismounting the container:

```powershell
veracrypt /q /v \\192.168.2.147\Backup\container /l x /a /b
robocopy /MIR C:\Users\kbota\Desktop x:\ /Z /W:5
veracrypt /q /d x
```

Before this happens, we need some code that checks the status of the files we're backing up.  An easy way to do this is to use a honeytoken which only exists to alert you when it has been accessed or modified.

The following commands from [Backup-Files.ps1](scripts/Backup-Files.ps1) check to see if the honeytoken file is still there (`$filegone`) and has its original sha256 hash value (`$hashchanged`):

```powershell
$filegone = $False
$hashchanged = $False

if ((Test-Path C:\Users\kbota\Desktop\HoneyToken.txt) -eq $False){
    $filegone = $true
}

$hash = (Get-FileHash C:\Users\kbota\Desktop\HoneyToken.txt -Algorithm sha256).hash
if ($hash -ne 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'){
    $hashchanged = $true
}

if (($filegone -eq $true) -or ($hashchanged -eq $true)){
    $answer = Read-Host "`n**** Honeytoken has changed! *****`n`nWould you still like to backup [y/N]?"
    if ($answer -eq "y"){
        Write-Host "`nPerforming backup...`n"
    }
    else {
        Write-Host "`nExiting...`n"
    }
}
else {
    Write-Host "`nPerforming backup...`n"
}
```

When the script runs, it alerts us if the honeytoken file has been renamed or its content has changed:

![](images/Windows%20Mitigations%20and%20Defenses/image012.png)

If the honeytoken checks pass, we're prompted for the password:

![](images/Windows%20Mitigations%20and%20Defenses/image013.png)

Then the backup job runs and the container is immediately dismounted:

![](images/Windows%20Mitigations%20and%20Defenses/image014.png)

Now we need to schedule it to execute every day.

#### Continuous Operation

Adding the mounting, copying, and dismounting commands to our `Backup-Files.ps1` file gives us a backup solution with logical isolation and validity checking.  To schedule it to execute daily, use the following:

```powershell
schtasks /create /tn Backup-Files /tr "powershell.exe -file 'C:\Backup-Files.ps1'" /sc daily /st 13:20
```

Every day at the specified time, a powershell window will pop up and run the script.  If the honeytoken checks pass it will prompt you for a password and then perform the backup:

![](images/Windows%20Mitigations%20and%20Defenses/image015.png)

If the checks do not pass, you are alerted and can choose not to backup:

![](images/Windows%20Mitigations%20and%20Defenses/image016.png)

### Credential Hygiene

Good credential hygiene will reduce the risk of credential dumping, hash dumping, and other password attacks.

Credential dumpers use several methods to obtain passwords and hashes:

- Open the LSA Subsystem Service (LSASS) process and locate the LSA secrets key
- Open the Security Accounts Manager (SAM) on the local file system (`%SystemRoot%/system32/config/SAM`)
- Create a dump of the Registry SAM key

[Application whitelisting](#application-whitelisting) will help prevent tools running that are designed to do this, but there are several other things we can do that will help secure credentials:

- [Use Unique and Complex Passwords](#use-unique-and-complex-passwords)
- [Monitor for Credential Exposure](#monitor-for-credential-exposure)
- [Enable Credential Guard](#enable-credential-guard)


#### Use Unique and Complex Passwords

Ensure sufficient password complexity and uniqueness so that passwords cannot be cracked or guessed.  Additionally, limit credential overlap across systems to prevent lateral movement if passwords and hashes are able to be obtained.

The password policy settings can be viewed using `rsop.msc`:

![](images/Windows%20Mitigations%20and%20Defenses/image001.png)<br><br>

Or the `net accounts` command:

![](images/Windows%20Mitigations%20and%20Defenses/image019.png)<br><br>

And since these are set by the Default Domain Policy, we can also use the `Get-ADDefaultDomainPasswordPolicy` cmdlet:

![](images/Windows%20Mitigations%20and%20Defenses/image020.png)<br><br>

On a domain, weak passwords can be discovered with techniques used by tools like [CredDefense Toolkit](https://www.blackhillsinfosec.com/the-creddefense-toolkit/) which can also be used to detect Kerberoasting, Password Spraying, and NBNS Spoofing events.

#### Monitor for Credential Exposure

You can reduce the exposure of domain credentials in memory with the `AccountNotDelegated` property:

```powershell
Get-ADUser -Filter * -pr SAMAccountName,AccountNotDelegated | group -NoElement AccountNotDelegated
```
![](images/Windows%20Mitigations%20and%20Defenses/image021.png)<br><br>

Only some of our accounts have this set.  To see a list of them you can use:


```powershell
Get-ADUser -Filter * -pr SAMAccountName,AccountNotDelegated | ? AccountNotDelegated -eq 'True' | select SAMAccountName | ft -auto
```

![](images/Windows%20Mitigations%20and%20Defenses/image022.png)<br><br>

Also search hosts for scripts, logs, and other files that may contain valid credentials.  A typical sequence begins with a Splunk search such as `sourcetype=WinEventLog:* pass*.txt`:

![](images/Windows%20Mitigations%20and%20Defenses/image023.png)<br><br>

Followed by closer examination of the file contents:

![](images/Windows%20Mitigations%20and%20Defenses/image024.png)<br><br>

In total, this file contained over two dozen unique passwords and answers to security questions for various systems and accounts.

#### Enable Credential Guard

With Windows 10, Microsoft implemented [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard) to protect the LSA secrets that can be used to obtain credentials through forms of credential dumping. It is not configured by default and has hardware and firmware system requirements.

To enable Credential Guard:

```powershell
gpedit

# Go to Computer Configuration --> Administrative Tasks --> System --> Device Guard
# Open up Turn On Virtualization Based Security
# Change to Enabled, Change to Enabled with UEFI Lock

gpupdate /force
```

A quick way to check is by pressing `Win + r` and typing `msinfo32` and `Enter`:

![](images/Windows%20Mitigations%20and%20Defenses/image028.png)<br><br>

## Summary

We just looked at some common Windows mitigations and defenses, here are a few others to keep in mind:

- Disabling file extensions that are frequently used for malicious purposes such as `.hta`, `.js`, `.jse`, `.wsh`, `.wsf`, `.scf`, `.scr`, `.vbs`, `.vbe`, and `.pif`

- Disabling `powershell.exe`, `powershell_ise.exe` and `cmd.exe` execution via Windows Explorer to prevent the use of PowerShell by malicious code trying to infect the system

- Using sandboxing and virtualization to isolate systems and applications that can't be patched,are known to be vulnerable, or to protect against unknown vulnerabilities.  Exploit prevention tools such as the Microsoft Enhanced Mitigation Experience Toolkit (EMET) can also be effective against undiscovered or unpatched vulnerabilities

- Automating local admin account password changes (LAPS)

- Denying local admin net/RDP logons

- Blocking admin accounts from internet and email

- Using full disk encryption and secure boot

- Denying secondary logon and cached credentials

- Blocking HTTP NTLM

- Blocking inter-workstation traffic and direct connections out

- Forcing proxy use

<br>


[Check-MitigationsDefenses.ps1](scripts/Check-MitigationsDefenses.ps1) is a script that checks for and enables some of the mitigations and defenses we reviewed above to quickly harden a Windows 10 host.

Running it in `check` mode will only check and report back status of the hardening option:

![](images/Windows%20Mitigations%20and%20Defenses/image025.png)<br><br>

Running it in `prompt` mode will give the user the opportunity to enable hardening for the option:

![](images/Windows%20Mitigations%20and%20Defenses/image026.png)<br><br>

Running the script in `autoconfigure` mode will automatically make the needed changes:

![](images/Windows%20Mitigations%20and%20Defenses/image027.png)<br><br>
