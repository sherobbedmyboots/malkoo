# Check
if (Test-Path ~\Desktop\Complete) {
    Exit
}
else{

# Fix IP address
netsh interface ipv4 set address name="Local Area Connection" static 192.168.56.101 255.255.255.0 192.168.56.1
netsh interface ipv4 set dns name="Local Area Connection" static 8.8.8.8

Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Performing connectivity tests...`r`n"

Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Testing gateway..."
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Pinging 192.168.56.1..."
if (!(ping 192.168.56.1)){
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Could not ping 192.168.56.1..."
    Exit
}
else { Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "Gateway found!`r`n"}

Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Testing external address..."
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Pinging 8.8.8.8..."
if (!(ping 8.8.8.8)){
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Could not ping 8.8.8.8..."
    Exit
}
else { Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "External address successfully pinged!`r`n"}

Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Testing DNS resolution..."
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Resolving www.google.com..."
if (!(nslookup www.google.com)){
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Could not resolve www.google.com..."
    Exit
}
else { Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "DNS name resolved!`r`n"}


# Verify agent running
if (!(ps -name pythonw)) {Read-Host `n#######`n`nCuckoo agent is not running...`n`n#######`n`nPress [Enter] to exit;Exit}
else {Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "Cuckoo agent running!`r`n"}

# Clean up
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Cleaning up..."
Remove-Item -Force ~\Desktop\Complete
Remove-Item -Recurse -Force C:\Tools
if ((!(Test-Path ~\Desktop\Complete)) -and (!(Test-Path C:\Tools))){
    Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "Cleanup complete!`r`n"}
}
else {
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Could not delete all files...`r`n"
    Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Ensure ~\Desktop\Complete and C:\Tools get deleted."
    Exit	
}

