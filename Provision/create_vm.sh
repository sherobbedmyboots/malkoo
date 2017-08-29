# CREATE A VM

VM='Windows-2008-64bit'

# Create 32GB dynamic disk
vboxmanage createhd --filename $VM.vdi --size 32768

# List OS types
vboxmanage list ostypes

# Creat VM
vboxmanage createvm --name $VM --ostype "Windows2008_64" --register

# Add SATA controller with the dynamic disk
vboxmanage storagectl $VM --name "SATA Controller" --add sata --controller IntelAHCI
vboxmanage storageattach $VM --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $VM.vdi

# Add IDE controller with DVD drive and install ISO
vboxmanage storagectl $VM --name "IDE Controller" --add ide
vboxmanage storageattach $VM --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium /path/to/windows_server_2008.iso

# Miscellaneous system settings
vboxmanage modifyvm $VM --ioapic on
vboxmanage modifyvm $VM --boot1 dvd --boot2 disk --boot3 none --boot4 none
vboxmanage modifyvm $VM --memory 1024 --vram 128
vboxmanage modifyvm $VM --nic1 bridged --bridgeadapter1 eth0

# Boot up
vboxheadless -s $VM

# Shutdown and eject DVD
# vboxmanage storageattach $VM --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium none

# Take snapshot
# vboxmanage snapshot $VM take <name of snapshot>

# Revert to snapshot:
# vboxmanage snapshot $VM restore <snapshot>
