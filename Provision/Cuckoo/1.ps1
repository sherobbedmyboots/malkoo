
Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Set-ItemProperty -Path . -Name "2" -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "C:\Tools\2.ps1"'

try {
    choco install kb976932 -y -force
}
catch {
    firefox https://www.microsoft.com/en-us/download/confirmation.aspx?id=5842&6B49FDFB-8E5B-4B07-BC31-15695C5A2143=1
}
Restart-Computer




























