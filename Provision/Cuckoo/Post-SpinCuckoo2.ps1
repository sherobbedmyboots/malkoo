
# Fix IP address
$nic = gwmi win32_networkadapterconfiguration | ?{$_.IPEnabled}
$nic.IPAddress = "192.168.56.101"
$nic.IPSubnet = "255.255.255.0"
$nic.DefaultIPGateway = "192.168.56.1"
$nic.SetDNSServerSearchOrder('8.8.8.8')
ipconfig /renew

# Verify agent running
if (!(ps -name pythonw)) {Read-Host `n#######`n`nCuckoo agent is not running...`n`n#######`n`nPress [Enter] to exit;Exit}

# Clean up
Remove-Item -Force ~\Desktop\Complete
Remove-Item -Recurse -Force C:\Tools
