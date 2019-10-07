# Starts SP1 install

Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name "2" -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\Tools\2.ps1"'
choco install kb976932 -y --force
Set-Content -Path C:\Tools\1.txt -Value 1
Restart-Computer
