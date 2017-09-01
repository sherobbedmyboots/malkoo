# Allow traffic from only one system
 
# Linux                     
iptables –A INPUT –s ! <ip-address> -j DROP
#To verify
iptables –L
 
# Windows             
Set-NetFirewallProfile –all –Enabled True
Disable-NetFirewallRule -All
New-NetFirewallRule -DisplayName AllowMe -Direction Inbound -Action Allow –Profile Any –Enabled True –RemoteAddress <ip-address>

#To verify
Get-NetfirewallRule | ?{$_.Enabled –eq ‘True’} | select profile, direction, action, displayname