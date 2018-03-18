


sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install python python-pip python-dev libffi-dev libssl-dev -y
sudo apt-get install python-virtualenv python-setuptools libjpeg-dev zlib1g-dev swig -y
sudo apt-get install mongodb postgresql libpq-dev -y


# Virtualbox
echo deb http://download.virtualbox.org/virtualbox/debian xenial contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
sudo apt-get update
sudo apt-get install virtualbox-5.1 -y

# Tcpdump
sudo apt-get install tcpdump apparmor-utils -y
sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Volatility
wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip
unzip volatility_2.6_lin64_standalone.zip -d ~

sudo pip install --upgrade pip
sudo pip install m2crypto==0.24.0

# Create user
sudo adduser cuckoo
# sudo echo cuckoo:cuckoopassword | chpasswd
sudo usermod -a -G vboxusers cuckoo

# Install
virtualenv venv
. venv/bin/activate
pip install -U pip setuptools
pip install -U cuckoo
cuckoo -d

# Config Files
cp ~/.cuckoo/conf/cuckoo.conf ~/.cuckoo/conf/cuckoo.conf.old
sed -i 's/port = 2042/port = 2000/g' ~/.cuckoo/conf/cuckoo.conf
cp ~/.cuckoo/conf/virtualbox.conf ~/.cuckoo/conf/virtualbox.conf.old
sed -i 's/cuckoo1/core/g' ~/.cuckoo/conf/virtualbox.conf


# Iptables
sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -j LOG
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
sudo apt-get install iptables-persistent -y

sudo /etc/init.d/mongodb start

# Guest
# install python
# C:\Python27\Scripts\pip.exe install Pillow
# Disable Automatic updates
# Turn off Windows Firewall
# cp agent.pyw 'C:\Users\core\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'

# $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# $DefaultUsername = "core"
# $DefaultPassword = "corepassword"
# Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String -Force
# Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String -Force
# Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String -Force

vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
vboxmanage modifyvm core --hostonlyadapter1 vboxnet0
vboxmanage modifyvm core --nic1 hostonly

# Guest Networking
New-NetIpAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.56.101" -PrefixLength 24 -DefaultGateway 192.168.56.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8, 4.4.4.4


VBoxManage snapshot "core" take "snapshot" --pause
VBoxManage controlvm "core" poweroff

# VBoxManage snapshot "core" restorecurrent

sed -i 's/snapshot =/snapshot = cuckoo_snapshot/g' ~/.cuckoo/conf/virtualbox.conf
sed ':a;N;$!ba;s/enabled = no/enabled = yes/4' ~/.cuckoo/conf/reporting.conf


virtualenv venv
. venv/bin/activate
cuckoo -d