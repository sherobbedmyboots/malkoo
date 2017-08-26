# Setting up Kali


# Password

# Power -> Blank screen to never

# Start database
service postgresql start
msfdb init

# msfconsole
# db_rebuild_cache


# apt-get update && apt-get upgrade -y


# Install VirtualBox Guest Additions:

sudo mount /dev/cdrom /mnt
cd /mnt
sudo VboxLinuxAdditions.run
reboot

# Configure interface:

sudo nano /etc/network/interfaces

	auto eth0
	iface eth0 inet static
	address 172.0.0.1
	netmask 255.255.255.0

sudo ifdown eth0
sudo ifup eth0

# Start ssh on boot:
systemctl enable ssh.service

# Vagrant

# Zero out free space on hard drive
# Make sure VM nic1 is in NAT mode
# Make sure SSH starts on boot
# No firewalls up

# vagrant package --base <vm_name> --vagrantfile /path/to/Vagrantfile --output <new_name.box>
 
# vagrant box add /path/to/new_name.box --name <new_name>
 
# vagrant up
