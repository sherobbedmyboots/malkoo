
Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name '3' -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "$env:TEMP\3.ps1"'

choco install kb976932 -y -force
Restart-Computer