#!/bin/bash
# Installs the Streisand server for you https://github.com/jlund/streisand

# Install prerequisites
sudo apt-get update && sudo apt-get install -y git python-paramiko python-pip python-pycurl python-dev build-essential
sudo pip install ansible markupsafe dopy==0.3.5

# Download and configure Streisand
git clone https://github.com/jlund/streisand.git && cd streisand/playbooks
sed -i 's/streisand-host/127.0.0.1/g' streisand.yml 
sudo ansible-playbook -i "localhost," -c local streisand.yml 
sed -i "s/localhost/$(curl -s ipecho.net/plain)/g" ../generated-docs/streisand.html


# Copy generated-docs/streisand.html to local machine
