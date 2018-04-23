# Disable SSDP/UPNP
Get-Service SSDPSRV | Stop-Service -Force
Get-Service SSDPSRV | Set-Service -StartupType Disabled
Get-Service UPNPHOST | Stop-Service -Force
Get-Service UPNPHOST | Set-Service -StartupType Disabled

# Disable Computer Browser service
netsh advfirewall firewall set rule group="network discovery" new enable=no
wmic nicconfig where index=1 call SetTcpipNetbios 2

# Disable NetBIOS
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | %{ Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

# Disable IPv6
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name 'DisabledComponents' -Value '0xff' -PropertyType 'DWord'
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name 'IGMPLevel' -Value '2'

# Disable Windows Time service
Get-Service 'W32Time' | Stop-Service -Force
Get-Service 'W32Time' | Set-Service -StartupType Disabled

# Disable LLMNR
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value '0' -PropertyType 'DWord'

# Disable Windows Update service
Get-Service 'wuauserv' | Stop-Service -Force
Get-Service 'wuauserv' | Set-Service -StartupType Disabled

# Disable Miscellaneous Queries
$list = @('wpad'
		  'isatap'
		  'time.windows.com'
		  'teredo.ipv6.microsoft.com'
		  'download.windowsupdate.com'
		  'www.update.microsoft.com'
		  'crl.microsoft.com'
		  )

foreach ($l in $list) {
	Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "255.255.255.255    $l" -Encoding ASCII
}
