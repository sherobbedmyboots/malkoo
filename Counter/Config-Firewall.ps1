# Allow traffic from only one system
 
# Linux                     
iptables –A INPUT –s ! <ip-address> -j DROP

# Redirect port
sudo iptables -A PREROUTING -t nat -p tcp --dport 80 -j REDIRECT --to-port 8080
 
# Windows             
Set-NetFirewallProfile –all –Enabled True
Disable-NetFirewallRule -All
New-NetFirewallRule -DisplayName AllowMe -Direction Inbound -Action Allow –Profile Any –Enabled True –RemoteAddress <ip-address>

#To verify
Get-NetfirewallRule | ?{$_.Enabled –eq ‘True’} | select profile, direction, action, displayname

# Configure network adapter
# $nic = get-wmiobject win32_networkadapterconfiguration | ?{$_.IPEnabled}
# $nic.IPAddress = "172.0.0.2"
# $nic.IPSubnet = "255.255.255.0"
# $nic.DefaultIPGateway = “172.0.0.1”
# $nic.DNSServerSearchOrder = “172.0.0.1”

# Configure network adapter
# New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.20.0.2 -PrefixLength 24 -DefaultGateway 172.20.0.1
# Set-DNSClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 172.20.0.1

