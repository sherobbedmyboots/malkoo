
Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name "5" -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\Tools\Post-SpinCuckoo.ps1"'

choco install powershell -y
Set-Content -Path c:\Users\jcasy\Desktop\4.txt -Value 4
Restart-Computer