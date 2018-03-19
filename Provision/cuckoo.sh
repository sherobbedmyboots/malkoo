#!/bin/bash

verify(){
if ! command -v $1 > /dev/null 
then
	echo $1 not installed
	exit
fi
}

pip_verify(){
if ! pip show $1 > /dev/null
then
	echo $1 not installed
	exit
fi
}

pause(){
	read -p "$*"
}

# Install dependencies
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install git mongodb libffi-dev build-essential apparmor-utils python-django python python-dev python-pip python-pil python-sqlalchemy python-bson python-dpkt python-jinja2 python-magic python-pymongo python-gridfs python-libvirt python-bottle python-pefile python-chardet tcpdump autoconf libtool libjansson-dev libmagic-dev libssl-dev -y
verify python

# Upgrade pip
sudo pip install --upgrade pip

# Set tcpdump
verify tcpdump
verify apparmor-utils
sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Install Yara
wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz -O yara-3.4.0.tar.gz
tar -zxf yara-3.4.0.tar.gz
cd yara-3.4.0
./bootstrap.sh
./configure --with-crypto --enable-cuckoo --enable-magic
make
sudo make install
verify yara
cd ..

# Install Yara Python
sudo pip install yara-python
pip_verify yara-python

# Install ssdeep
wget http://sourceforge.net/projects/ssdeep/files/ssdeep-2.13/ssdeep-2.13.tar.gz/download -O ssdeep-2.13.tar.gz
tar -zxf ssdeep-2.13.tar.gz
cd ssdeep-2.13
./configure
make
sudo make install
verify ssdeep
cd ..

# Install pydeep
sudo pip install pydeep
pip_verify pydeep

# Install Volatility
sudo pip install openpyxl ujson pycrypto distorm3 pytz m2crypto==0.24.0

pip_verify openpyxl
pip_verify ujson
pip_verify pycrypto
pip_verify distorm3
pip_verify pytz
pip_verify m2crypto

wget https://pypi.python.org/packages/28/f9/8ff25a8f3edb581b5bc0efbed6382dcca22e5e7eff39464346c629105739/distorm3-3.3.4.zip#md5=bf7bba5894b478b33fa2dea47ef13c9f
unzip distorm3-3.3.4.zip
unzip distorm3-3.3.4.zip
sudo python setup.py build install
cd ..

git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
sudo python setup.py build
sudo python setup.py install
verify vol.py
cd ..


# Virtualbox
echo deb http://download.virtualbox.org/virtualbox/debian xenial contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
sudo apt-get update
sudo apt-get install virtualbox-5.1 -y

# Iptables
echo "Creating rules in Iptables..."

sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -j LOG
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
sudo apt-get install iptables-persistent -y


# Create user
echo "Creating user 'cuckoo'..."
sudo adduser cuckoo
sudo usermod -a -G vboxusers cuckoo

# Install cuckoo as cuckoo user
echo "### INSTALLING CUCKOO ###"
echo ""
echo "Open a new terminal and switch to user 'cuckoo' by typing 'su cuckoo'"
echo ""
echo "Navigate to homedir by typing 'cd ~'"
echo ""
echo "Activate virtualenv by typing 'virtualenv venv && . venv/bin/activate'"
echo ""
echo "Install Cuckoo by typing 'pip install -U pip setuptools && pip install -U cuckoo'"
echo ""

pause 'Press [Enter] key when cuckoobox.box has been placed in /home/cuckoo/...'

echo "Now run the cuckoo2.sh script as user 'cuckoo'."
exit




