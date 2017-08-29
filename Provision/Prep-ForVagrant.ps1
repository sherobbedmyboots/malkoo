# Ensure that Network Location is set to Private
$networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
$connections = $networkListManager.GetNetworkConnections()
$connections | % {$_.GetNetwork().SetCategory(1)}
 
Write-Host "`n" 
# Ensure that PS-Remoting is enabled
Enable-PSRemoting
 
Write-Host "`n" 
# Ensure that the firewall is allowing traffic to WinRM port 5985
netsh advfirewall firewall show rule name=all | sls 5985 -context 9,4

Write-Host "`n" 
# If no rule exists to allow the traffic, create one:
Write-Host "Create a firewall rule for WinRM?" -ForegroundColor yellow
$Read = Read-Host " ( y / n ) "
Switch ($Read)
{
    Y {Write-Host "Yes, Create Rule"; netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow}
    N {Write-Host "No, continue"; break}
    Default {Write-Host "Default, continue"; break}
}

Write-Host "`n"
# Zero out C drive
Write-Host "Zeroing out C drive..." -ForegroundColor yellow
sdelete /accepteula -z c:

# All checks complete
Write-Host "Zeroing complete..."