<#
.EXAMPLE
   .\Check-MitigationsDefenses.ps1 check
   .\Check-MitigationsDefenses.ps1 prompt
   .\Check-MitigationsDefenses.ps1 autoconfigure

.SYNOPSIS
    Check a Windows host for common mitigations and defenses

.DESCRIPTION
	The -mode parameter determines which type of check is being run:
	    check   		Only check settings
	    prompt  		Prompt the user to make changes
	    autoconfigure 	Automatically make changes

Runs the following checks:

	Check-DeviceGuard
	Check-PatchManagement
	Check-Macros
	Check-OLE
	Check-ActiveX
	Check-DDE
	Check-AutoRun
	Check-AutoPlay
	Check-InboundConnections
	Check-WindowsScriptingHost
	Check-UAC
	Check-WritableShares
	Check-SmartCardForceOption
	Check-CredentialGuard

#>

param([string]$mode)

function Check-Args {
    if (!($mode))
    {
        Write-Host "`nYou must enter a mode:       .\Check-MitigationsDefenses.ps1 check `n"
        Write-Host "                             .\Check-MitigationsDefenses.ps1 prompt `n"
        Write-Host "                             .\Check-MitigationsDefenses.ps1 autoconfigure `n"
        Exit
    }
}

$check = $false
$prompt = $false
$auto = $false

if ($mode -eq "check"){
	$check = $true
}

if ($mode -eq "prompt"){
	$prompt = $true
}

if ($mode -eq "autoconfigure"){
	$auto = $true
}



# # # # # # # # # # # # # # # #
#  Application Whitelisting   #
# # # # # # # # # # # # # # # #

function Check-DeviceGuard {
	$option = 'Device Guard'
	$hardened = $false
	$value = @()
	$value += (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning

	if ($value -contains 2) {
		$hardened = $true
	}
	
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or ($auto -eq $true)){
		Invoke-WebRequest https://gist.githubusercontent.com/mattifestation/0e17c5ffbe66597f0d78a2861202848c/raw/18a40a8fddb1dab83b338950459042e5337aa824/BaseEnforcementPolicy.xml -OutFile BaseEnforcementPolicy.xml
		ConvertFrom-CIPolicy -XmlFilePath BaseEnforcementPolicy.xml -BinaryFilePath C:\Windows\System32\CodeIntegrity\SIPolicy.p7b | Out-Null
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "SIPolicy.p7b written to C:\Windows\System32\CodeIntegrity and will be effective upon restart"
	}
}


# # # # # # # # # # # #
#  Patch Management   #
# # # # # # # # # # # #

function Check-PatchManagement {
	$option = 'Patch Management'
	$hardened = $false
	
	$session = New-Object -ComObject Microsoft.Update.Session 
	$searcher = $session.CreateUpdateSearcher()
	$result = $searcher.Search("IsInstalled=0 and Type='Software'") 
	if ($result.Updates.Count -eq 0){
		$hardened = $true
	}
	
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or ($auto -eq $true)){
		$downloader = $session.CreateUpdateDownloader()
		$downloader.Updates = $result.Updates
		$downloader.Download()
		$installer = New-Object -ComObject Microsoft.Update.installer
		$installer.Updates = $result.Updates
		$installer.install()
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "All updates have been downloaded and installed"
	}
}


# # # # # # # # # # # # # # # # # # # # 
#  Disable Untrusted Office Features  #
# # # # # # # # # # # # # # # # # # # #

function Check-Macros {

	$option = 'Office Macros'
	$hardened = $false
	$apps = 'Word', 'Excel', 'PowerPoint'
	$value = @()
	$value += $apps | %{(Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\$_\Security" -ErrorAction SilentlyContinue).VBAWarnings}

	if (!($value -ne 4)) {
		$hardened = $true
	}

	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		$apps | %{hardenKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\$_\Security" 'VBAWarnings' 4}
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "Office macros have been disabled"
	}
}


function Check-OLE {

	$option = 'Office OLE'
	$hardened = $false
	$apps = 'Word', 'Excel', 'PowerPoint'
    $name = 'PackagerPrompt'
	$value = @()
	$value += $apps | %{(Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\$_\Security" -ErrorAction SilentlyContinue).$name}

	if (!($value -notcontains 2)) {
		$hardened = $true
	}

	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		hardenKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security" 'PackagerPrompt' 2
        hardenKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security" 'PackagerPrompt' 2
        hardenKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\PowerPoint\Security" 'PackagerPrompt' 2
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "Office OLE has been disabled"
	}
}

function Check-ActiveX {

	$option = 'Office ActiveX'
	$hardened = $false
	$path = 'HKCU:\SOFTWARE\Microsoft\Office\Common\Security'
	$name = 'DisableAllActiveX'
	$value = @()
	$value = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).$name

	if (!($value -ne 1)) {
		$hardened = $true
	}

	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		hardenKey $path $name 1
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "Office ActiveX has been disabled"
	}
}

function Check-DDE {

	$option = 'Office DDE'
	$hardened = $false
	
	if (
		((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -ErrorAction SilentlyContinue).DontUpdateLinks -eq 1) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options\WordMail" -ErrorAction SilentlyContinue).DontUpdateLinks -eq 1) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -ErrorAction SilentlyContinue).DDEAllowed -eq 0) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -ErrorAction SilentlyContinue).DDECleaned -eq 1) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -ErrorAction SilentlyContinue).Options -eq 0x117) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security" -ErrorAction SilentlyContinue).WorkbookLinkWarnings -eq 2) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -ErrorAction SilentlyContinue).DontUpdateLinks -eq 1) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options\WordMail" -ErrorAction SilentlyContinue).DontUpdateLinks -eq 1) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -ErrorAction SilentlyContinue).DDEAllowed -eq 0) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -ErrorAction SilentlyContinue).DDECleaned -eq 1) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -ErrorAction SilentlyContinue).Options -eq 0x117) `
		-and ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security" -ErrorAction SilentlyContinue).WorkbookLinkWarnings -eq 2) `
	) {
		$hardened = $true
	}

	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" 'DontUpdateLinks' 1
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options\WordMail" 'DontUpdateLinks' 1
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" 'DDEAllowed' 0
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" 'DDECleaned' 1
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" 'Options' 0x117
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security" 'WorkbookLinkWarnings' 2
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" 'DontUpdateLinks' 1
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options\WordMail" 'DontUpdateLinks' 1
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" 'DDEAllowed' 0
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" 'DDECleaned' 1
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" 'Options' 0x117
		hardenKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security" 'WorkbookLinkWarnings' 2
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "Office DDE has been disabled"
	}
}

# # # # # # # # # # # # # # #
#  Disable Autorun-AutoPlay #
# # # # # # # # # # # # # # #

function Check-AutoRun {
	$hardened = $false
	$value = ''
	$option = 'AutoRun'
	$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'
	$name = 'NoDriveTypeAutorun'

	$value = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
	if ($value -eq 0xFF){
		$hardened = $true
	}
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		hardenKey $path $name 0xFF
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "Autorun has been disabled"
	}
}

function Check-AutoPlay {
	$hardened = $false
	$value = ''
	$option = 'AutoPlay'
	$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\AutoplayHandlers'
	$name = 'DisableAutoplay'

	$value = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
	if ($value -eq 1){
		$hardened = $true
	}
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		if ((Test-Path $path) -eq $false) {
			New-Item $path
		}
		hardenKey $path $name 1
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "AutoPlay has been disabled"
	}
}

# # # # # # # # # # # #
#   Least Privilege   #
# # # # # # # # # # # # 

function Check-UAC {
	$hardened = $false
	$value = @()
	$option = 'User Account Control'
	$path = 'HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System'
	$keys = 'EnableLUA','ConsentPromptBehaviorAdmin','PromptOnSecureDesktop'

	$value += $keys | %{return (Get-ItemProperty -Path $path -Name $_).$_}
	if (!($value -contains 0)){
		$hardened = $true
	}
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		hardenKey $path 'EnableLUA' 1
		hardenKey $path 'ConsentPromptBehaviorAdmin' 2
		hardenKey $path 'PromptOnSecureDesktop' 1
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host "UAC has been enabled"
	}
}


function Check-WritableShares {
	$hardened = $false
	$option = 'Writable Shares'
	$accounts = 'BUILTIN\Administrators','BUILTIN\Backup Operators','NT AUTHORITY\INTERACTIVE'
	$shares = @()

	$shares += Get-SmbShare | Get-SmbShareAccess
	$lookinto += $shares | ? AccountName -notin $accounts | ?{$_.AccessRight -eq "Full" -or $_.AccessRight -eq "Change"}

	if (!($lookinto)){
		$hardened = $true
	}
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		$lookinto | %{
			Revoke-SmbShareAccess -Name $_.Name -AccountName $_.AccountName -Force
			Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host $_.AccessRight " access revoked on " $_.Name " share for " $_.AccountName 
		}
	}
}


function Check-InboundConnections {

	$hardened = $false
	$option = 'Inbound Connections'
	$value = @()
	$value += (Get-NetConnectionProfile).NetworkCategory

	if (!($value -ne 'Public')) {
		$hardened = $true
	}
	
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		(Get-NetConnectionProfile).Name | % {Set-NetConnectionProfile -name $_ -NetworkCategory Public}
		Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -RemoteAddress 127.0.0.1
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host $option " using WinRM are restricted to 127.0.0.1"
	}
}

function Check-WindowsScriptingHost {

	$hardened = $false
	$option = 'Windows Scripting Host'
	$path1 = 'HKLM:\Software\Microsoft\Windows Script Host\Settings\Enabled'
	$path2 = 'HKCU:\Software\Microsoft\Windows Script Host\Settings\Enabled'
	$value1 = Get-ItemProperty -Path $path1 -ErrorAction SilentlyContinue | select -exp `(default`)
	$value2 = Get-ItemProperty -Path $path2 -ErrorAction SilentlyContinue | select -exp `(default`)

	if (($value1 -eq 0) -and ($value2 -eq 0)) {
		$hardened = $true
	}

	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		if (!(Test-Path $path1)){
            New-Item $path1
        }
        Set-Item -Path $path1 -Value 0 | Out-Null
        if (!(Test-Path $path2)){
            New-Item $path2
        }
        Set-Item -Path $path2 -Value 0 | Out-Null
        Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host $option " has been disabled"
	}
}


# # # # # # # # # # # # # # # # #
#  Multi-factor Authentication  #
# # # # # # # # # # # # # # # # #

function Check-SmartCardForceOption{
	$hardened = $false
	$value = ''
	$option = 'SmartCard Force Option'
	$path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\System'
	$name = 'ScForceOption'

	$value = (Get-ItemProperty -Path $Path -Name $name -ErrorAction SilentlyContinue).$name
	if ($value -eq 1){
		$hardened = $true
	}
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		hardenKey $path $name 1
        Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host $option " has been enabled"
	}
}

# # # # # # # # # # # #
#  Credential Hygiene #
# # # # # # # # # # # #

function Check-CredentialGuard {
	$option = 'Credential Guard'
	$hardened = $false
	$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
	$value = @()
	$value += (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning

	if ($value -contains 1) {
		$hardened = $true
	}
	reportResult $option $hardened
	if (($prompt -eq $true) -and ($hardened -eq $false)){
		$answer = promptToHarden($option)
	}
	if (($answer -eq $true) -or (($auto -eq $true) -and ($hardened -eq $false))){
		if (!(Test-Path -Path $path)) {
           	New-Item -Path $path -ItemType Directory -Force
    	}
    	hardenKey $path 'RequirePlatformSecurityFeatures' 1
	    hardenKey $path 'EnableVirtualizationBasedSecurity' 1
		hardenKey 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 1
		Write-Host -Fore Cyan "   [+] " -NoNewLine; Write-Host $option " settings enabled, restart required"
	}
}

function reportResult($option,$hardened) {
	if ($hardened -eq $true){
		Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "$option is hardened"
	}
	else {
		Write-Host -Fore Red "[-] "-NoNewLine; Write-Host "$option is not hardened"
	}
}

function hardenKey ($path, $name, $value){
	if (!(Test-Path $path)) {
		New-Item $path | Out-Null	
	}
	Set-ItemProperty -Path $path -Name $name -Value $value | Out-Null
}

function promptToHarden($option){
	Write-Host -Fore Yellow "   [-] " -NoNewLine
	Write-Host "Do you want to enable hardening for $option ? [y/N] " -NoNewLine
	$answer = Read-Host
	if ($answer -eq 'y'){
		$harden = $true
		Write-Host -Fore Green "   [+] " -NoNewLine
	}
	else{
		$harden = $false
	}
	return $harden
}

function main {
	Check-Args
	Check-DeviceGuard
	Check-PatchManagement
	Check-Macros
	Check-OLE
	Check-ActiveX
	Check-DDE
	Check-AutoRun
	Check-AutoPlay
	Check-UAC
	Check-WritableShares
	Check-InboundConnections
	Check-WindowsScriptingHost
	Check-SmartCardForceOption
	Check-CredentialGuard
}

main

