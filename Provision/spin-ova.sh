#!/bin/bash
# Spin up OVA 


echo "Enter OVA file: "
read ova_file

ova_path=/home/mal/vuln/$ova_file

sug_name=$(vboxmanage import $ova_path | grep 'Suggested VM' | cut -d '"' -f2)

echo "VM will be created under name: $sug_name    Keep[Y/n]?"
read answer
answer=${answer:-'Y'}


if [ "$answer" == "n" ]
then
  echo "Enter new VM name: "
  read vm_name
  change="true"
else
  change="false"
fi

echo "Enter VM NIC: [nic1]"
read vm_nic
vm_nic=${vm_nic:-'nic1'}

echo "Enter host NIC: [enp4s0]"
read host_nic
host_nic=${host_nic:-'enp4s0'}

echo "Headless or gui: [gui]"
read start_type
start_type=${start_type:-'gui'}



# Bridge VM NIC

vboxmanage modifyvm "$sug_name" --$vm_nic bridged --bridgeadapter1 $host_nic

if [ "$change" == "true" ]
then
  vboxmanage modifyvm "$sug_name" --name ""$vm_name"" 
  vboxmanage startvm ""$vm_name"" --type $start_type
else
  vboxmanage startvm "$sug_name" --type $start_type
fi


