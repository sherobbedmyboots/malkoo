# Ensure that Network Location is set to Private
 
$networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
$connections = $networkListManager.GetNetworkConnections()
$connections | % {$_.GetNetwork().SetCategory(1)}
 
 
# Ensure that PS-Remoting is enabled
 
Enable-PSRemoting
 
 
# Ensure that the firewall is allowing traffic to WinRM port 5985
 
netsh advfirewall firewall show rule name=all | sls 5985 –context 9,4
 
If no rule exists to allow the traffic, create one:
 
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow


# All checks complete

write-host System prepared for package... press any key to zero out free space

# Zero out C drive

sdelete -z c: --acceptuela