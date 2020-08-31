# Check
if (Test-Path ~\Desktop\Complete) {
    Exit
}

# Fix IP address
netsh interface ipv4 set address name="Local Area Connection" static 192.168.56.101 255.255.255.0 192.168.56.1
netsh interface ipv4 set dns name="Local Area Connection" static 8.8.8.8

Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Performing connectivity tests...`r`n"


# Gateway test
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Testing gateway..."
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Pinging 192.168.56.1..."
if (!(ping 192.168.56.1)){
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Could not ping 192.168.56.1..."
    Read-Host "Press [Enter] to exit"
    Exit
}
else { Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "Gateway found!`r`n"}


# External connectivity test
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Testing external address..."
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Pinging 8.8.8.8..."
if (!(ping 8.8.8.8)){
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Could not ping 8.8.8.8..."
    Read-Host "Press [Enter] to exit"
    Exit
}
else { Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "External address successfully pinged!`r`n"}


# DNS test
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Testing DNS resolution..."
Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Resolving www.google.com..."
if (!(nslookup www.google.com)){
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Could not resolve www.google.com..."
    Read-Host "Press [Enter] to exit"
    Exit
}
else { Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "DNS name resolved!`r`n"}


# Verify agent running
if (!(ps -name pythonw)) {
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Cuckoo agent is not running..."
    Read-Host "Press [Enter] to exit"
    Exit
}
else {Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "Cuckoo agent running!`r`n"}


# Clean up
Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "Cleaning up..."
Remove-Item -Recurse -Force C:\Tools
if ((!(Test-Path ~\Desktop\Complete)) -and (!(Test-Path C:\Tools))){
    Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "Cleanup complete!`r`n"}
}
else {
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Could not delete all files...`r`n"
    Write-Host -Fore Yellow "[-] " -NoNewLine; Write-Host "Ensure ~\Desktop\Complete and C:\Tools are deleted and run again..."
    Read-Host "Press [Enter] to exit"
    Exit
}

Write-Host `n`n`n
Write-Host -Fore Green "[-] " -NoNewLine; Write-Host "Everything looks good..."
Read-Host "Press [Enter] to delete the SysPrep.ps1 script"


# Delete self
Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path . -Name "SysPrep"
Set-Content -path $env:TEMP\complete.bat -value "@ECHO OFF"
Add-Content -path $env:TEMP\complete.bat -value "del %TEMP%\SysPrep.ps1"
Add-Content -path $env:TEMP\complete.bat -value '(goto) 2>nul & del "%~f0"'
$env:TEMP\complete.bat
