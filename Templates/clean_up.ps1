# Disable Firewall
netsh advfirewall set allprofiles state off

# Disable Services
$services = @(
	'SSDPSRV'				# SSDP Discovery Service
	'UPNPHOST'				# Universal Plug & Play Host
	'Browser'				# Computer Browser Service
	'W32Time'				# Windows Time Service
	'wuauserv'				# Windows Update Service
	'AdobeARMService'			# Adobe Acrobat Update Service
	'AeLookupSvc'				# Application Experience Service
	'WERSVC'				# Windows Error Reporting Service
	'WinHttpAutoProxySvc'			# WinHTTP Web Proxy Auto-Discovery
	'WlanSvc'				# WLAN AutoConfig
	'wscsvc'				# Security Center Service
	'bthserv'				# Bluetooth Support Service
	'HomeGroupListener'			# HomeGroup Listener
	'HomeGroupProvider'			# HomeGroup Provider
	'WSearch'				# Windows Search
	'TrkWks'				# Distributed Link Tracking Client
	'WbioSrvc'				# Windows Biometric Service
	'WMPNetworkSvc'				# Windows Media Player Network Sharing Service
	'RemoteAccess'				# Routing and Remote Access
	'RemoteRegistry'			# Remote Registry
	'SharedAccess'				# Internet Connection Sharing (ICS)
	'NetTcpPortSharing'			# Net.Tcp Port Sharing Service
	'DiagTrack'				# Diagnostics Tracking Service
	'gupdatem'				# Google Update Service
	'gupdate'				# Google Update Service
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
	'armmf.adobe.com'
	'update.googleapis.com'
)
foreach ($l in $list) {
	Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "255.255.255.255    $l" -Encoding ASCII
}

# Restart 
Restart-Computer
