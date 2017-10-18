# ExecutionPolicy is previously set to Unrestricted in Autounattend.xml
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# For some reason, AutoHotkey.portable wasn't working with WinPcap, so use the full installation
cinst autohotkey -y
$env:Path = "$($env:Path)C:\Program Files\AutoHotkey;"

# Install windump 

# Install graphviz

# Install API monitor

# Install FLOSS

# Install FakeNet-NG

# Install OLE tools

# Install Rekall
Invoke-WebRequest –usebasicparsing "https://github.com/google/rekall/releases/download/v1.6.0/Rekall_1.6.0_Gotthard_x64.exe" -O "rekall_install.exe"
.\rekall_install.exe
$env:Path += “C:\Program Files\Rekall;”
$env:Path += “C:\Python27\scripts;”
# pip install virtualenv
# virtualenv Dev
# Dev\scripts\activate
# rekal live



# Install dotnet4.5
choco install dotnet4.5 -y

# reboot
Restart-Computer

# Install PowerShell 5
choco install powershell -y 


