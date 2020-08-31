# Starts PowerShell5 install

Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name "5" -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\Tools\Post-SpinCuckoo.ps1"'
choco install powershell -y --force 
Set-Content -Path C:\Tools\4.txt -Value 4
Restart-Computer