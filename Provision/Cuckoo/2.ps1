# Continues SP1 install

Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name '3' -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\Tools\3.ps1"'
choco install kb976932 -y -force
Set-Content -Path C:\Tools\2.txt -Value 2
Restart-Computer