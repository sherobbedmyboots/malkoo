
Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name "4" -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\tools\4.ps1"'

choco install dotnet4.5 -y
Restart-Computer