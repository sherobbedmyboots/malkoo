#!/bin/bash

pause(){
	read -p "$*"
}

echo "\e[1;31mInstalling Cuckoo files...\e[0m"
cd /home/cuckoo
virtualenv venv
. venv/bin/activate
pip install -U pip setuptools
pip install -U cuckoo
cuckoo -d
cuckoo community
deactivate


# Copying agent
cp /home/cuckoo/.cuckoo/agent/agent.py /home/cuckoo/agent.pyw

echo "\e[1;31mInstalling malboxes...\e[0m"
virtualenv mbenv
. mbenv/bin/activate
pip3 install -U pip setuptools
pip3 install git+https://github.com/GoSecure/malboxes.git#egg=malboxes

pause 'Go configure .config/malboxes/config.js, then press [Enter] key to continue...'


echo "\e[1;31mBuilding a Windows VM Vagrant box with Malboxes\e[0m"
malboxes build win7_64_analyst

pause 'If build succeeded, press [Enter] key to continue...[Ctrl + C] to Exit'

echo "\e[1;31mSpinning up VM named cuckoo1\e[0m"
malboxes spin win7_64_analyst cuckoo1 
vagrant up

echo "\e[1;31mWhen VM loads up, run Post-SpinCuckoo.ps1 file in C:\Tools... \e[0m"
echo "\e[1;31mThis will install SP1, DotNet4.5, PowerShell and configure various settings.\e[0m"

pause 'when "Complete" file appears on Desktop, press [Enter] key to continue'

vmboxmanage controlvm "cuckoo1" poweroff


echo "\e[1;31mCreating host-only interface\e[0m"
# Create HostOnly interface
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
vboxmanage modifyvm cuckoo1 --hostonlyadapter1 vboxnet0
vboxmanage modifyvm cuckoo1 --nic1 hostonly

echo "\e[1;31mRestarting VM\e[0m"
# Start VM
vboxmanage startvm "cuckoo1" --type gui

pause 'If no error messages, Press [Enter] key to take NoOffice snapshot...'

# Creating snapshot
vboxmanage snapshot "cuckoo1" take "NoOffice" --pause

echo "\e[1;31mInstall Office on the guest using: choco install officeproplus2013 -y\e[0m"
pause 'Press [Enter] key when cuckoo1 VM is ready for WithOffice snapshot...'

# Creating snapshot
vboxmanage snapshot "cuckoo1" take "WithOffice" --pause
vboxmanage controlvm "cuckoo1" poweroff

# Specify snapshot to use
sed -i 's/snapshot =/snapshot = WithOffice/g' /home/cuckoo/.cuckoo/conf/virtualbox.conf

# Enable MongoDB
#Not WOrking
sed ':a;N;$!ba;s/enabled = no/enabled = yes/4' /home/cuckoo/.cuckoo/conf/reporting.conf

# Enable mitm
sed ':a;N;$!ba;s/enabled = no/enabled = yes/1' /home/cuckoo/.cuckoo/conf/auxiliary.conf

# Start cuckoo
echo "\e[1;31mStarting Cuckoo...\e[0m"
. venv/bin/activate
cuckoo

# Start Web Server
echo "\e[1;31mOpen second terminal and type 'cuckoo web runserver 0.0.0.0:8000...\e[0m"
exit
