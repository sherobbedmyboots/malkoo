

# Enable bypass policy
Set-ExecutionPolicy -Scope LocalMachine Bypass -Force
Set-ExecutionPolicy -Scope CurrentUser Bypass -Force

# Configure network adapter
# $nic = get-wmiobject win32_networkadapterconfiguration | ?{$_.IPEnabled}
# $nic.IPAddress = "172.0.0.2"
# $nic.IPSubnet = "255.255.255.0"
# $nic.DefaultIPGateway = “172.0.0.1”
# $nic.DNSServerSearchOrder = “172.0.0.1”

# Configure network adapter
# New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.20.0.2 -PrefixLength 24 -DefaultGateway 172.20.0.1
# Set-DNSClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 172.20.0.1

# Personalization Settings

# Disable screen lock
New-Item -Path "HKLM:\software\Policies\Microsoft\Windows\personalization" | Out-Null
Set-ItemProperty -Path "HKLM:\software\Policies\Microsoft\Windows\personalization" -Name "NoLockScreen" -Type DWord -Value 1

# Unpin edge and store

# Remove search bar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

# Remove taskview button
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

# Show hidden files
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Stop explorer
Stop-Process -name explorer

# 7zip in path?
# $oldpath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path
# if (!($oldpath.contains("7"))){
#    $newpath = “$oldpath;C:\Program Files\7-Zip”
# } 

# IE shortcut for win7
# Blank home page for IE, 

# Disable script debugging (Internet Explorer)

# install SP1 https://www.microsoft.com/en-us/download/details.aspx?id=5842
# (new-object System.Net.WebClient).DownloadString("http://10.0.0.100/windows6.1-KB976932-X64.exe") >> SP1.exe
# .\SP1.exe