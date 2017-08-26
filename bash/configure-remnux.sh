# Setting up REMnux

# Power -> Blank screen to never

# Install VirtualBox Guest Additions:

sudo mount /dev/cdrom /mnt
sudo /mnt/VboxLinuxAdditions.run
reboot

# Switch to internal net:
sudo sed -i 's/dhcp/static\n\taddress 172.27.0.1\n\tnetmask 255.255.255.0/g' /etc/network/interfaces
sudo ifdown eth0
sudo ifup eth0
ifconfig

# Back to bridge
sudo sed -i 's/static/dhcp/g' /etc/network/interfaces
sudo sed -i 's/\tnetmask 255.255.255.0//g' /etc/network/interfaces
sudo sed -i 's/\taddress 172.27.0.1//g' /etc/network/interfaces
sudo ifdown eth0 && sudo ifup eth0 && ifconfig

# Start ssh on boot:
sudo sed -i 's/exit 0/\/etc\/init.d\/ssh start\nexit 0/g' /etc/rc.local
sudo chmod +x /etc/rc.local

# Vagrant

# Zero out free space on hard drive
# Make sure VM nic1 is in NAT mode
# Make sure SSH starts on boot
# No firewalls up

# vagrant package --base <vm_name> --vagrantfile /path/to/Vagrantfile --output <new_name.box>
 
# vagrant box add /path/to/new_name.box --name <new_name>
 
# vagrant up

# Docker container for Thug
mkdir ~/logs ~/files
chmod 777 ~/logs ~/files
sudo docker run --rm -it -v ~/logs:/home/thug/logs -v ~/files:/home/thug/files remnux/thug bash
./thug.py -F http://example.com


