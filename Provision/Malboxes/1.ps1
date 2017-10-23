
Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name "2" -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\tools\2.ps1"'

choco install kb976932 -y
Restart-Computer




























