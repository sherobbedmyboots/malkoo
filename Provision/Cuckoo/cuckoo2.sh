#!/bin/bash

pause(){
	read -p "$*"
}





# Create HostOnly interface
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
vboxmanage modifyvm cuckoo1 --hostonlyadapter1 vboxnet0
vboxmanage modifyvm cuckoo1 --nic1 hostonly

# Start VM
vboxmanage startvm "cuckoo1"


# Transfer agent.py to VM
mkdir -p '/home/cuckoo/VirtualBox VMs/cuckoo1share'
vboxmanage sharedfolder add "cuckoo1" --name "cuckoo1share" --hostpath '/home/cuckoo/VirtualBox VMs/cuckoo1share' --automount
cp /home/cuckoo/cuckoo/agent/agent.py '/home/cuckoo/VirtualBox VMs/windowsxpshare/agent.pyw'

pause 'Press [Enter] key when agent is running on VM...'



pause 'Press [Enter] key when cuckoo1 VM is ready for NoOffice snapshot...'

# Creating snapshot
vboxmanage snapshot "cuckoo1" take "NoOffice" --pause

pause 'Press [Enter] key when cuckoo1 VM is ready for WithOffice snapshot...'

# Creating snapshot
vboxmanage snapshot "cuckoo1" take "WithOffice" --pause
vboxmanage controlvm "cuckoo1" poweroff

# Specify snapshot to use
sed -i 's/snapshot =/snapshot = WithOffice/g' /home/cuckoo/.cuckoo/conf/virtualbox.conf

# Enable MongoDB
sed ':a;N;$!ba;s/enabled = no/enabled = yes/4' /home/cuckoo/.cuckoo/conf/virtualbox.conf

# Enable mitm
sed ':a;N;$!ba;s/enabled = no/enabled = yes/1' /home/cuckoo/.cuckoo/conf/auxiliary.conf

# Start cuckoo
echo "Installing and starting Cuckoo..."

cd /home/cuckoo
virtualenv venv
. venv/bin/activate
pip install -U pip setuptools
pip install -U cuckoo
cuckoo community
cuckoo

# Start Web Server
echo "Open second terminal and type 'cuckoo web runserver 0.0.0.0:8000..."
exit

