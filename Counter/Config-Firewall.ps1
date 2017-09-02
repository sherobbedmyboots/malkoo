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


