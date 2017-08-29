#!/bin/bash
# Switch VM to bridged mode 

echo "Enter VM name: [so]"
read vm_name
vm_name=${vm_name:-'so'}

echo "Enter VM NIC: [nic1]"
read vm_nic
vm_nic=${vm_nic:-'nic1'}

echo "Enter host NIC: [enp4s0]"
read host_nic
host_nic=${host_nic:-'enp4s0'}

echo "Headless or gui: [gui]"
read start_type
start_type=${start_type:-'gui'}


# Power off VM
vboxmanage controlvm "$vm_name" poweroff

# Bridge VM NIC
vboxmanage modifyvm "$vm_name" --$vm_nic bridged --bridgeadapter1 $host_nic

# Start VM
vboxmanage startvm "$vm_name" --type $start_type
