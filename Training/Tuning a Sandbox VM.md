# Tuning a Sandbox VM

Create a brand new Windows 7 host and filter out unnecessary traffic.


```powershell
# Turn off Windows Firewall
netsh advfirewall set allprofiles state off

```

## Tune traffic

|Process|Destination IP|Destination Port|Protocol|Description|
|-|-|-|-|-|
|svchost.exe|239.255.255.250|1900/udp|SSDP|SSDP:Request, M-SEARCH |
|system|10.0.2.255|138/udp|SMB|Browser: Host Announcement, ServerName = HHI-FRONTDESK02|
|unknown|FF02::1:2|547/udp|DHCPV6|DHCPV6:MessageType = SOLICIT|
|unknown|10.0.2.3|53/udp|DNS|Query for `time.windows.com` `teredo.ipv6.microsoft.com` `wpad.myboots` `download.windowsupdate.com` `www.update.microsoft.com` `crl.microsoft.com` |
|unknown|13.65.245.138|123/udp|NTP|NTPv3 Request|
|unknown|255.255.255.255|67/udp|DHCP|DHCP:Request, MsgType = INFORM|
|unknown|FF02::1:3|5355/udp|LLMNR|Query for `wpad`|
|unknown|224.0.0.252|5355/udp|LLMNR|Query for `wpad`|
|unknown|FF02::C|1900/udp|SSDP|SSDP:Request, M-SEARCH|
|unknown|67.220.142.139|80/tcp|HTTP|GET `/pki/crl/products/CSPCA.crl`|
|svchost.exe|93.184.215.240|80/tcp|HTTP|GET `/v9/windowsupdate/redir/muv4wuredir.cab`|
|svchost.exe|134.170.58.221|443/tcp|HTTPS|Client Hello to `www.update.microsoft.com`|
|mscorsvw.exe|23.43.62.89|80/tcp|HTTP|GET `/pki/crl/products/CSPCA.crl`|



```powershell
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name 'DisabledComponents' -Value '0xff' -PropertyType 'DWord'
```

DisableServices.ps1

```powershell
# Disable NetBios over TCP/IP
wmic nicconfig where index=1 call SetTcpipNetbios 2

# Also disable Computer Browser service
```






## Add User Files

browsing history, cookies, documents, images etc
evidence of use



## Hide Virtualization Files

vmcloak
pafish
