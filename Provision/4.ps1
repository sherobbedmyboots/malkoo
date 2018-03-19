
Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name "5" -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "$env:TEMP\5.ps1"'

choco install powershell -y
Restart-Computer