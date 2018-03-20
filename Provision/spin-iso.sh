#!/bin/sh

echo "Enter VM name: [so]"
read vm_name
vm_name=${vm_name:-'so'}

echo "Enter OS type: [Ubuntu_64] "
read vm_type
vm_type=${vm_type:-'Ubuntu_64'}


echo "Enter memory size: [8192] "
read mem_size
mem_size=${mem_size:-'8192'}

echo "Enter hard drive size: [20000] "
read hd_size
hd_size=${hd_size:-'20000'}

echo "Enter iso file: [securityonion.iso]"
read iso_file
iso_file=${iso_file:-'~/iso/securityonion-14.04.5.2.iso'}


echo "Headless or GUI: [gui]"
read start_type
start_type=${start_type:-'gui'}



hd_file="~/VirtualBox VMs/"$vm_name"/"$vm_name".vdi"


echo "Creating VM..."
vboxmanage createvm --name ""$vm_name"" --ostype $vm_type --register

echo "Creating HD..."
vboxmanage createhd --filename "$hd_file" --size $hd_size

echo "Adding IDE Controller..."
vboxmanage storagectl ""$vm_name"" --name "IDE Controller" --add ide --controller PIIX4

echo "Attaching HD..."
vboxmanage storageattach ""$vm_name"" --storagectl "IDE Controller" --port 0 --device 0 --type hdd --medium "$hd_file"

echo "Attaching DVD..."
vboxmanage storageattach ""$vm_name"" --storagectl "IDE Controller" --port 0 --device 1 --type dvddrive --medium $iso_file

echo "Setting Memory Size..."
vboxmanage modifyvm ""$vm_name"" --memory $mem_size

echo "Setting Bridged mode..."
vboxmanage modifyvm ""$vm_name"" --nic1 bridged --bridgeadapter1 enp4s0

echo "Powering on VM..."
vboxmanage startvm ""$vm_name"" --type $start_type

# Shut down and eject the dvd
# vboxmanage storageattach "$vm_name" --storagectl "IDE Controller" --port 0 --device 1 --type dvddrive --medium none
