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



pause 'Press [Enter] key when cuckoo1 VM is ready for snapshot...'

# Creating snapshot
vboxmanage snapshot "cuckoo1" take "original" --pause
vboxmanage controlvm "cuckoo1" poweroff

# Specify snapshot to use
sed -i 's/snapshot =/snapshot = original/g' /home/cuckoo/.cuckoo/conf/virtualbox.conf

# Start MongoDB
sudo /etc/init.d/mongodb start

# Enable MongoDB
sed ':a;N;$!ba;s/enabled = no/enabled = yes/4' /home/cuckoo/.cuckoo/conf/virtualbox.conf

# Enable mitm
sed ':a;N;$!ba;s/enabled = no/enabled = yes/1' /home/cuckoo/.cuckoo/conf/auxiliary.conf

# Start cuckoo
cd /home/cuckoo/cuckoo
python cuckoo.py


# Start Web Server
cd /home/cuckoo/cuckoo/web
python manage.py runserver 0.0.0.0:8000

