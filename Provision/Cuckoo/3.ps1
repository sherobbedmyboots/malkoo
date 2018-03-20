
Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name "4" -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\Tools\4.ps1"'

choco install dotnet4.5 -y
Set-Content -Path c:\Users\jcasy\Desktop\3.txt -Value 3
Restart-Computer