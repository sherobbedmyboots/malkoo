# Exploring Analysis VM Options

There are many ways to build VMs for malware analysis or to replicate problems or scenarios in a production environment.  Depending on the situation, you may want to use one that was [built from scratch](Building%20Analysis%20VMs.md) with your desired toolsets added on.  Other times you may want to take advantage of images that others have created, some that come with a custom toolset installed and some that can be outfitted with a few specific applications. 

This document walks through setting up the following analysis VMs and [converting them to Vagrant boxes](#creating-vagrant-boxes) if needed:

- [OALabs VM](#oalabs-vm)
- [Flare VM](#flare-vm)
- [macOS VM](#macos-vm)


Before you begin, make sure you have latest [VirtualBox](https://www.virtualbox.org/wiki/Downloads) and [VirtualBox Extensions Pack](https://www.virtualbox.org/wiki/Downloads) installed on your OOB host.

## OALabs VM

The [OALabs](https://oalabs.openanalysis.net/2018/07/16/oalabs_malware_analysis_virtual_machine/) blog has a walkthrough explaining how to use their VM in greater detail---here is the short version:


- Download the [Microsoft OVA](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)
- Unzip and import it into Virtual Box
- Take a snapshot and name it `Clean`
- Power on the VM and enable the license:

![](images/Exploring%20Analysis%20VM%20Options/image009.png)<br><br>

- Browse to the PowerShell script and save it as a text file:

![](images/Exploring%20Analysis%20VM%20Options/image002.png)<br><br>

- Change it to a `.ps1` and run it as an Administrator:

![](images/Exploring%20Analysis%20VM%20Options/image005.png)<br><br>


- Allow OALabs tools to be installed (user interaction is needed for python setuptools)


You now have the OALabs VM built and you can add extra tools, configure shortcuts, or change any other settings you want as necessary:

![](images/Exploring%20Analysis%20VM%20Options/image006.png)<br><br>

Now VirtualBox will show that the current version is different than the `Clean` snapshot:

![](images/Exploring%20Analysis%20VM%20Options/image004.png)<br><br>

- Take a new snapshot and name it `WithTools`


Here are the tools included on the OALabs VM:

|Tool|Description|
|-|-|
|Chocolatey|Windows package manager|
|LordPE|PE editor|
|Process Explorer|Sysinternals process management utility|
|7-Zip|file archiver|
|Sublime Text 3|text editor|
|Resource Hacker|resource extraction utility|
|PEBear|PE reversing tool|
|x32dbg|debugger|
|Chrome|browser|
|HxD|Hex Editor|
|OpenSSH|Provides SSH access|
|Python 2.7|Python programming|
|strings.py|finds text in binaries|

<br>

This VM is limited as it only has PowerShell 2 installed and is missing SP1 and DotNet.  You can add these on manually or opt for a VM that automates these installs like Flare VM.

## Flare VM

The [Flare VM page](https://github.com/fireeye/flare-vm), [information page](https://flarevm.info) and [corresponding blog post](https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html) and [update post](https://www.fireeye.com/blog/threat-research/2018/11/flare-vm-update.html) provide additional steps and information about this project.

If you've already made the OALabs VM, we can skip several steps by cloning the `Clean` snapshot, enabling the license on this new VM, and installing the Flare VM:

- `Right Click` --> Settings and change the name to **OALabs**
- `Right Click` --> Clone and change name to **FlareVM**
- Choose **Full Clone** and select **Next**
- Choose **Everything** and select **Clone**

Virtual Box will begin the cloning process:

![](images/Exploring%20Analysis%20VM%20Options/image007.png)<br><br>

Once the VM is cloned:

- Select `FlareVM` --> `Snapshots` and `Right Click --> Restore`

![](images/Exploring%20Analysis%20VM%20Options/image008.png)<br><br>


- Uncheck **Create a snapshot of the current machine state** and select **Restore**
- Power on FlareVM machine and enable the license
- Open IE and navigate to https://raw.githubusercontent.com/fireeye/flare-vm/master/install.ps1 and save
- Run it as an Administrator and you will be prompted for the password:

![](images/Exploring%20Analysis%20VM%20Options/image010.png)<br><br>

- Enter the password and it will begin installing tools:

![](images/Exploring%20Analysis%20VM%20Options/image011.png)<br><br>

The FlareVM's script will reboot several times while it installs SP1, DotNet, and PowerShell 5:

![](images/Exploring%20Analysis%20VM%20Options/image012.png)<br><br>

When the script completes, you'll be directed to hit Enter:

![](images/Exploring%20Analysis%20VM%20Options/image013.png)<br><br>

You now have VM with many installed tools... [here is a list](https://github.com/fireeye/flare-vm).


You may be investigating malware that runs on a Mac--in that case you'd want to create a macOS VM for analysis.

## macOS VM

To build a macOS analysis VM, we start by acquiring a macOS image via either the [Apple Store](https://support.apple.com/downloads/macos) or a third party such as Techsviewer as described in [their article](https://techsviewer.com/install-macos-10-14-mojave-virtualbox-windows/).

In this example, I downloaded the file in six parts:

![](images/Exploring%20Analysis%20VM%20Options/image014.png)<br><br>


And pointed 7zip at the first part to extract them all:

![](images/Exploring%20Analysis%20VM%20Options/image015.png)<br><br>


Once complete, open VirtualBox, click on **New** and name it `macOS`.

- Select the OS (High Sierra) and RAM (4096 or more)
- Choose existing disk and navigate to the Techsviewer file
- In the `System/Motherboard` tab, make sure `Enable EFI` is set
- In the `System/Processor` tab, make sure `Enable PAE/NX` is set
- In the `Display/Screen` tab, make sure `Video Memory` is set to 128 MB
- In the `Storage` tab, make sure `Use Host I/O Cache` is checked
- Close VirtualBox and execute the following `vboxmanage` commands:

```powershell
VBoxManage.exe modifyvm macOS --cpuidset 00000001 000106e5 00100800 0098e3fd bfebfbff
VBoxManage setextradata macOS "VBoxInternal/Devices/efi/0/Config/DmiSystemProduct" "iMac11,3"
VBoxManage setextradata macOS "VBoxInternal/Devices/efi/0/Config/DmiSystemVersion" "1.0"
VBoxManage setextradata macOS "VBoxInternal/Devices/efi/0/Config/DmiBoardProduct" "Iloveapple"
VBoxManage setextradata macOS "VBoxInternal/Devices/smc/0/Config/DeviceKey" ` 
  "ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc"
VBoxManage setextradata macOS "VBoxInternal/Devices/smc/0/Config/GetKeyFromRealSMC" 1
```

<br>

- Create a snapshot named `Clean`
- Power up the machine and begin setup:

![](images/Exploring%20Analysis%20VM%20Options/image016.png)<br><br>

Click through setup and create user account:

![](images/Exploring%20Analysis%20VM%20Options/image017.png)<br><br>

Logon to the desktop:

![](images/Exploring%20Analysis%20VM%20Options/image018.png)<br><br>

Install any tools you need, in this case Chrome:

![](images/Exploring%20Analysis%20VM%20Options/image020.png)<br><br>

![](images/Exploring%20Analysis%20VM%20Options/image021.png)<br><br>

And BurpSuite:

![](images/Exploring%20Analysis%20VM%20Options/image024.png)<br><br>

Now take a snapshot and name it `WithTools` so you have a version with all your changes:

![](images/Exploring%20Analysis%20VM%20Options/image023.png)<br><br>

## Converting To Vagrant Boxes

You now have `Clean` and `WithTools` versions of one or all three analysis VMs.  Use the `WithTools` snapshot to detonate malware and revert back to this snapshot after analysis is complete.  When the Windows license expires, use the `Clean` snapshot to obtain another 90-day license and create a new `WithTools` snapshot for analysis. 

If you've you'd like to convert into a Vagrant base box for quickly standing up one of these analysis VMs or to easily share your customized analysis VM, you first need to make a Vagrantfile.

This is one I use for both Windows and Linux, commenting out the settings not needed for the specific box I'm creating:

```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure(2) do |config|

	config.vm.box = "macOSBurp"

	config.vm.box_url = 'C:\Users\pcuser\Vagrant Boxes\macOsBurp\macOsBurp.box'
	# config.vm.box_url = 'file:///home/userone/core/core-win10.box'

	config.vm.provider "virtualbox" do |vb|
		vb.name = "macOsBurp"
		vb.gui = true
		# vb.memory = 1024
		# vb.cpus = 2

	# config.vm.network "private_network", ip: "192.168.2.2",
		# virtualbox__intnet: true

	# config.vm.network :forwarded_port, guest: 5985, host: 55985, host_ip: "127.0.0.1", id: "winrm", auto_correct: true
	config.vm.network :forwarded_port, guest: 22, host: 22222, host_ip: "127.0.0.1", id: "ssh", auto_correct: true

	config.vm.communicator = "ssh"
	# config.vm.communicator = "winrm"

	config.vm.guest = :linux
	# config.vm.guest = :windows

	config.vm.hostname = "macOsBurp"

	# config.vm.post_up_message = "You may begin..."

	config.ssh.username = "lebronj"
	config.ssh.password = "lebronyellow"
	config.ssh.port = 22
	config.ssh.guest_port = 22
	# config.winrm.username = "IEUser"
	# config.winrm.password = "Passw0rd!"
	# config.winrm.port = 5985
	# config.winrm.guest_port = 5985

	# config.vm.synced_folder ".", 'C:\Users\IEUser\Desktop\host'
	config.vm.synced_folder ".", "/Users/lebronj/Desktop/host"
	end
end
```

<br>

Be sure to change the `config.vm.hostname` parameter to a name that describes the tools or changes you've made.

Before you create a Vagrant box, make sure you've met two major requirements:

1. The VM's first network adapter (nic1) must be in NAT mode
2. The VM's shell access port (5985, 22, etc.) is accessible

NAT mode is easy to check in the VirtualBox console by going to `Settings` --> `Network`:

![](images/Exploring%20Analysis%20VM%20Options/image026.png)<br><br>


For the second, most Windows VMs will require you make all networks Private and enable Winrm:

```powershell
# Set all networks to Private
$networkListManager =
[Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
$connections = \$networkListManager.GetNetworkConnections() 
$connections | % {$_.GetNetwork().SetCategory(1)}

# Enable WinRm
winrm quickconfig
```
<br>

The macOS VM will require enabling the SSH server with:

```bash
sudo systemsetup -setremotelogin on
```

<br>

Once these two requirements are met, save the state of the VM and export it to a Vagrant box using the following command:

```
vagrant package --base <vm_name> --vagrantfile /path/to/Vagrantfile --output <new_name.box>
```


![](images/Exploring%20Analysis%20VM%20Options/image025.png)<br><br>

Now in a directory with the Vagrantfile you created, start the VM with `vagrant up` to ensure everything works:

![](images/Exploring%20Analysis%20VM%20Options/image027.png)<br><br>

When you're finished with analysis, use `vagrant destroy` to terminate the machine and destroy all of its resources:

![](images/Exploring%20Analysis%20VM%20Options/image028.png)<br><br>
