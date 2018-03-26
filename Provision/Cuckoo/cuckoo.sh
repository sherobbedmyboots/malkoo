#!/bin/bash

writeRed(){
	echo -e "\e[2;91m$1\e[0m"
}
writeGreen(){
	echo -e "\e[2;92m$1\e[0m"
}
writeYellow(){
	echo -e "\e[2;93m$1\e[0m"
}

verify(){
if ! command -v $1 > /dev/null;then
    if ! dpkg -s $1 > /dev/null;then
	writeRed "$1 could not be installed"
	exit
    fi
fi
}

pip_verify(){
if ! pip show $1 > /dev/null
then
	writeRed "$1 could not be installed"
	exit
fi
}

pause(){
	read -p "$*"
}

declare -a arr1=("git"
    "libffi-dev"
    "build-essential"
    "mitmproxy"
    "apparmor-utils"
    "python-django"
    "python"
    "python-dev"
    "python-pip"
    "python-pil"
    "python-sqlalchemy"
    "python-bson"
    "python-dpkt"
    "python-jinja2"
    "python-magic"
    "python-pymongo"
    "python-gridfs"
    "python-libvirt"
    "python-bottle"
    "python-pefile"
    "python-chardet"
    "tcpdump"
    "ssdeep"
    "autoconf"
    "libtool"
    "libjansson-dev"
    "python-virtualenv"
    "libmagic-dev"
    "libssl-dev"
    "swig")

declare -a arr2=("yara-python"
	"pydeep"
	"openpyxl"
	"ujson"
	"pycrypto"
	"distorm3"
	"pytz")


function finishCuckooSetup {

cd /home/cuckoo

# disable screen lock
dconf write /org/gnome/desktop/screensaver/idle-activation-enabled false
dconf write /org/gnome/desktop/screensaver/lock-enabled false

# setup Cuckoo environment
virtualenv venv
. venv/bin/activate
pip install -U pip setuptools
pip install -U cuckoo
cuckoo -d
cuckoo community
deactivate

# create malboxes dir
malboxes -h > /dev/null

writeGreen "Copying config files from /tmp"
cp -r /tmp/tools /home/cuckoo/
cp /home/cuckoo/tools/config.js /home/cuckoo/.config/malboxes/

writeGreen "Copying cuckoo agent to tools dir"
cp /home/cuckoo/.cuckoo/agent/agent.py /home/cuckoo/tools/agent.pyw

writeGreen "Building a Windows 7 VM Vagrant box with Malboxes"
malboxes build win7_64_analyst

pause 'If build succeeded, press [Enter] key to continue...[Ctrl + C] to Exit'


writeGreen "Spinning up VM named cuckoo1"
malboxes spin win7_64_analyst cuckoo1 
vagrant up

writeGreen "When VM loads up, run Post-SpinCuckoo.ps1 file in C:\Tools..."
writeGreen "This will install SP1, DotNet4.5, PowerShell and configure various settings..."

pause 'when "Complete" file appears on Desktop, press [Enter] key to continue'

writeGreen "Creating host-only interface..."
# Create HostOnly interface
vboxmanage controlvm "cuckoo1" poweroff
sleep 5
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
vboxmanage modifyvm cuckoo1 --hostonlyadapter1 vboxnet0
vboxmanage modifyvm cuckoo1 --nic1 hostonly
sleep 5


writeGreen "Restarting VM..."
vboxmanage startvm "cuckoo1" --type gui

pause 'If no error messages, Press [Enter] key to take NoOffice snapshot...'

# Create NoOffice snapshot
vboxmanage snapshot "cuckoo1" take "NoOffice" --pause

writeGreen "Install Office on the guest using: choco install officeproplus2013 -y"
pause 'Verify Office 2013 is installed, Press [Enter] key when ready to take WithOffice snapshot...'

# Create WithOffic snapshot
vboxmanage snapshot "cuckoo1" take "WithOffice" --pause
vboxmanage controlvm "cuckoo1" poweroff

writeGreen "Configuring settings for Cuckoo..."
# Specify snapshot to use
sed -i 's/snapshot =/snapshot = WithOffice/g' /home/cuckoo/.cuckoo/conf/virtualbox.conf

# Enable MongoDB
sed ':a;N;$!ba;s/enabled = no/enabled = yes/4' /home/cuckoo/.cuckoo/conf/reporting.conf

# Enable mitm
sed ':a;N;$!ba;s/enabled = no/enabled = yes/1' /home/cuckoo/.cuckoo/conf/auxiliary.conf

# Start cuckoo
writeGreen "Starting Cuckoo..."
. venv/bin/activate
cuckoo

# Start Web Server
pause 'Open second terminal and type: cuckoo web runserver 0.0.0.0:8000...'

writeGreen "Now browse to localhost:8000 and submit a file to test."
exit
}

if [  "$(whoami)" = "cuckoo" ];then
	finishCuckooSetup
fi

writeYellow "Checking packages..."

for i in "${arr1[@]}"
do
	dpkg -s $i &> /dev/null
	if [ $? -eq 0 ]; then
    	writeGreen "$i is installed..."
	else
    	writeYellow "$i is NOT installed, attempting to install..."
    	sudo apt-get install $i -y
    	verify $i
	fi
done

for i in "${arr2[@]}"
do
	pip show $i &> /dev/null
	if [ $? -eq 0 ]; then
    	writeGreen "$i  is installed..."
	else
    	writeYellow "$i  is NOT installed, attempting to install..."
    	sudo pip install $i
    	pip_verify $i
	fi
done


# Set tcpdump
verify tcpdump
verify aa-disable
# sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Install Yara
if ! command -v yara > /dev/null;then
	wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz -O yara-3.4.0.tar.gz
	tar -zxf yara-3.4.0.tar.gz
	cd yara-3.4.0
	./bootstrap.sh
	./configure --with-crypto --enable-cuckoo --enable-magic
	make
	sudo make install
	verify yara
	cd ..
else
	writeGreen "Yara is installed..."
fi


# Install distorm3
if ! pip show distorm3 > /dev/null;then
	wget https://pypi.python.org/packages/28/f9/8ff25a8f3edb581b5bc0efbed6382dcca22e5e7eff39464346c629105739/distorm3-3.3.4.zip#md5=bf7bba5894b478b33fa2dea47ef13c9f
	unzip distorm3-3.3.4.zip
	cd distorm3-3.3.4
	sudo python setup.py build install
	cd ..
else
	writeGreen "Distorm3 is installed..."
fi


# Install Volatility
if ! command -v vol.py > /dev/null;then
	sudo pip install m2crypto==0.24.0
	pip_verify m2crypto

	git clone https://github.com/volatilityfoundation/volatility.git
	cd volatility
	sudo python setup.py build
	sudo python setup.py install
	verify vol.py
	cd ..
else
	writeGreen "Volatility is installed..."
fi


# Virtualbox
if ! command -v virtualbox > /dev/null;then
	echo deb http://download.virtualbox.org/virtualbox/debian xenial contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
	wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
	sudo apt-get update
	sudo apt-get install virtualbox-5.1 -y
	verify virtualbox
else
	writeGreen "Virtualbox is installed..."
fi


# Install Malboxes
if ! command -v malboxes > /dev/null;then
	writeGreen "Installing Vagrant, Packer, and Malboxes..."

	# install Vagrant
	if ! command -v vagrant > /dev/null;then
           wget https://releases.hashicorp.com/vagrant/2.0.3/vagrant_2.0.3_x86_64.deb
	   sudo dpkg -i vagrant_2.0.3_x86_64.deb
	   verify vagrant
        else
           writeGreen "Vagrant is installed..."
        fi

	# install packer
	if ! command -v packer > /dev/null;then
           wget https://releases.hashicorp.com/packer/0.12.2/packer_0.12.2_linux_amd64.zip
	   sudo unzip -d /usr/local/bin packer_0.12.2_linux_amd64.zip
	   verify packer
        else
          writeGreen "Packer is installed..."
        fi

        # install malboxes
	if ! command -v pip3;then
           writeYellow "Installing python3-pip..."
	   sudo apt-get install python3-pip -y
        fi
        sudo pip3 install git+https://github.com/GoSecure/malboxes.git#egg=malboxes
	verify malboxes
else
	writeGreen "Malboxes is installed..."
fi

# Make VMs start with --type gui
sudo sed -i 's/"headless": "true"/"headless": "false"/g' /usr/local/lib/python3.5/dist-packages/malboxes/templates/snippets/builder_virtualbox_windows.json 


# clean up
declare -a arr3=("rm packer_0.12.2_linux_amd64.zip"
	"ssdeep-2.13.tar.gz"
	"rm yara-3.4.0.tar.gz"
	"rm distorm3-3.3.4.zip")

for i in "${arr3[@]}"
do
	if [ -f "$i" ];then
		rm $i
	fi
done


# Iptables
writeGreen "Creating rules in Iptables..."

sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -j LOG
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1

if ! dpkg -s iptables-persistent > /dev/null;then
	sudo apt-get install iptables-persistent -y
else writeGreen "iptables-persistent is installed..."
fi

# Create user
if ! id -u cuckoo > /dev/null;then
	writeGreen "Creating user 'cuckoo'..."
	sudo adduser cuckoo
	sudo usermod -a -G vboxusers cuckoo
else
	writeGreen "Cuckoo user found..."
fi

writeYellow "Configure the following settings in ./tools/config.js:"
writeYellow " "
writeYellow "     - change username				someusername"
writeYellow "     - change password				somepassword"
writeYellow "     - change computername			somename"
writeYellow "     - change disk_size				51200"
writeYellow "     - choose Chocolatey packages to install	googlechrome, adobereader"
writeYellow "     - change tools_path			/home/cuckoo/tools"
writeYellow " "

pause 'Once this file is configured, press [Enter] key to continue...'

# Copy over files
writeGreen "Copying config files to /tmp..."
cp ./cuckoo.sh /tmp
cp -r tools /tmp

writeYellow "Now log in the cuckoo user GUI and run this script again at: /tmp/cuckoo.sh."
exit

