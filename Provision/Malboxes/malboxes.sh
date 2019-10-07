#!/bin/bash

verify(){
if ! command -v $1 > /dev/null 
then
	echo $1 not installed
	exit
fi
}


# install Vagrant
wget https://releases.hashicorp.com/vagrant/2.0.3/vagrant_2.0.3_x86_64.deb
sudo dpkg -i vagrant_2.0.3_x86_64.deb
verify vagrant 

# install packer
wget https://releases.hashicorp.com/packer/0.12.2/packer_0.12.2_linux_amd64.zip
sudo unzip -d /usr/local/bin packer_0.12.2_linux_amd64.zip
verify packer

# install malboxes
sudo pip3 install git+https://github.com/GoSecure/malboxes.git#egg=malboxes
verify malboxes