# Building Analysis VMs with Packer, Vagrant, and Malboxes

 
## How it works
 
When you need a Windows VM for analysis:
 
-----------------------------------------------------------------------------------------------------------------------------------
 
1.       Choose a Windows OS, open a terminal, and navigate to the appropriate folder (cd /win10_64):
 
Windows 10 Professional 32-bit                                 /win10_32
Windows 10 Professional 64-bit                                 /win10_64
Windows 7 Professional SP1 32-bit                           /win7_32
Windows 7 Professional SP1 64-bit                           /win7_64
 
2.       Type vagrant up
 
3.       When the VM opens, copy over your sample for analysis using the synced Desktop folders
 
-----------------------------------------------------------------------------------------------------------------------------------
 
 
 
The whole process takes about 15 seconds with the exception of the very first time you spin each VM up which takes a few minutes to add the Vagrant box.
 
These VMs have all of our major client applications and analysis tools installed—and are malware-friendly (Defender disabled, updates disabled, NAT’ed, etc).
 
They are also disposable.  When analysis is complete, type vagrant destroy and the VM is shut down and deleted.
 
 
 
 
There are several ways this new set-up will help improve our OOB analysis:
 
1.       Success Rate
 
Malware is improving in its ability to profile victim systems to distinguish between legitimate user workstations and analysis platforms.  For example, by making queries for resources that would normally be present on a real user workstation (mapped drives, browser plugins), malware may determine it is running on an analysis platform and not reveal its full functionality.  When trying to acquire malware from a malicious site that has infected one of our users, we may be  unable to obtain the payload we want to analyze because our system is easily identified as an analysis machine.  Building a more convincing “victim system” will allow us to obtain, run, and analyze more malware samples.
 
2.       Flexibility
 
While much of the commodity malware out there is designed to run on many types of systems with varying configurations, some types of malware require specific conditions to run and special analysis tools in order to be examined.  In these cases, being able to customize a victim/analysis VM for a particular exploit or malware family is required for proper analysis. 
 
3.       Efficiency
 
It is very time-consuming to create a machine from scratch, configure legitimate-looking user accounts, install various client applications and analysis tools, and end up with a credible environment that will be able to fool system-profiling malicious sites and anti-analysis malware.  Automating this process results in less time spent building and setting up VMs and more time spent on actual malware analysis.
 
4.       Accuracy
 
Testing multiple samples on the same VM instance creates conditions that are difficult to associate with a specific sample which leads to inaccurate reporting.  Starting with a base VM for every sample ensures any system changes you observe were a result of the current malware you are analyzing and not from previous samples and testing performed with the same VM.
 
 
Here are the tools that allow us to quickly build and spin up customized analysis VMs that are pre-configured to resemble real user workstations:
 
-          Packer 
-          Vagrant
-          Malboxes
 
 
## Packer
 
Packer uses a single file (JSON template) to create identical machine images for multiple platforms (EC2, GCE, Virtualbox, VMware, etc.) and makes the entire process automated and repeatable. 
 
Keys in the JSON template specify how a VM’s OS and applications should be built:
 
-          Builders                                download the ISO, verify the hash, create a new VM, boot it, and install the OS
-          Provisioners                       install and configure the software
-          Post-processors               process the image to desired format
 
 
So for example, if we wanted to build a VirtualBox image of a Windows 7 32-bit machine named “John-Doe-PC” with Adobe Reader and several of our analysis tools installed, after configuring the JSON template file we would just type:
 
packer build john_doe.json
 
This would download the Windows ISO, create a new VM, install our OS and applications, configure system settings, and export the machine to a VirtualBox image. 
 
This template could then be used again to build an image of an identical system for a different provider such as a VMWare VMDK, an EC2 AMI, or a GCE gzipped tarball. 
 
But Packer only builds these images, it does not manage them or create an environment in which to run them. 
 
This is where Vagrant comes in…
 
 
 
## Vagrant
 
Vagrant creates and manages portable, reproducible, one-or-more-machine virtual environments that will behave exactly the same when given to someone else.
 
A single file (Vagrantfile) describes the type of machine(s) required and how they are to be configured and provisioned. 
 
A single command (vagrant up) sets up the virtual environment and starts the machine(s).
 
This maintains a consistent, virtualized environment for other users.  If you give someone a Vagrantfile describing your analysis machine and environment, when they type vagrant up, Vagrant will use it to build the exact same machine and environment on their host.
 
 
A basic Vagrant project would look like this:
 
Make a directory to work in and enter it by typing mkdir <directory> then cd <directory>
 
Add a box with the following format:
 
vagrant box add <name> <url>
 
So if you wanted to add one of Hashicorp’s boxes from their website, you would type:
 
vagrant box add bento/centos-6.9 hxxp://atlas.hashicorp.com/bento/boxes/centos-6.9/versions/2.3.5/providers/virtualbox.box
 
This downloads the Vagrant box.
 
Once it completes, initialize a new Vagrant environment for your box by typing:
 
vagrant init bento/centos-6.9
 
This creates a Vagrantfile in your directory
 
Now you can start the machine by typing:
 
vagrant up
 
This imports the box, boots it, and configures everything using your new Vagrantfile.
 
Seconds later you have a Centos VM running in VirtualBox and can connect to it by typing:
 
vagrant ssh
 
 
This is great, but we want to use Vagrant for quickly spinning up identical systems that we have customized specifically for malware analysis.
 
This is where Malboxes comes in…
 
 
 
 
## Malboxes
 
Malboxes was created to make custom VM-building faster and easier for malware analysts.  It uses Packer to build a brand new VM configured with all desired OS changes, client software, and analysis tools.  It then converts this customized base VM to a Vagrant box that can be quickly spun up for malware analysis of an individual sample, destroyed when analysis is completed, and spun up again for use with additional samples.
 
Here are the commands you can use by with the format malboxes <command>:
 
list                          lists available profiles
registry                 modifies a registry key
document           adds a file
directory              modifies a directory
package               adds a package to install
build                      builds a Vagrant box based on a profile
spin                        creates a Vagrantfile for your profile/box
 
 
To Build an Analysis VM:
 
If you want to build an analysis VM with your own configuration, first choose from the available profiles by typing malboxes list
 
 
Right now there are four different base VMs:
 
win10_32_analyst            Windows 10 Professional 32-bit
win10_64_analyst            Windows 10 Professional 64-bit
win7_32_analyst              Windows 7 Professional SP1 32-bit
win7_64_analyst              Windows 7 Professional SP1 64-bit
 
 
Then make the needed changes in the .config/malboxes/config.js file:
 
-          Trial or registered version
-          VM settings (user, password, hostname)
-          Windows defender, updates
-          Chocolatey packages to install
-          Other tools to be copied onto VM
 
 
To start the building process, type malboxes build <profile>
 
 
Here’s what this command does:
 
-          Downloads or copies Guest additions
-          Downloads or copies OS ISO
o   If Windows 7, it copies from “iso_path” or uses local cache
o   If Windows 10, it downloads from Microsoft or copies from local cache
-          Creates floppy disk
-          Copies over Autounattend.xml, enablewinrm.ps1, and fixnetworks.ps1
-          Creates VM and hard drive and attaches floppy
-          Creates forwarded port mapping for WinRM
-          Sets memory and CPUs
-          Starts VM and waits for WinRM to become available
-          Connects over WinRM and runs the following scripts:
o   disable_auto-updates.ps1
o   disable_defender.ps1
o   vmtools.ps1
o   malware_analysis.ps1
o   installtools.ps1
-          Uses Chocolatey to install tools listed in config.js
-          Gracefully halts VM
-          Removes floppy and guest additions drive
-          Exports VM to ovf file
-          Unregisters and deletes VM
-          Creates Vagrant box for VirtualBox named <profile>.box
 
 
On average it takes about 90 minutes…
 
During this process, if Packer gets an error for any reason, it aborts the build and deletes the VM.  Sometimes you may want this—but if you don’t, you can override using the debug flag (-d):
 
malboxes –d build <profile>
 
 
 
To Modify an Analysis VM:
 
If you’ve installed additional tools and made other changes to a VM you’d like to convert into a Vagrant base box, you first need to make a Vagrantfile.
 
This is the one I used to make the current Windows 10 x64 base box:
 
cid:image022.png@01D2E064.65F3E5C0
 
 
On the Windows guest:
 
-          Use the Sysinternals tool “sdelete” to zero out the free space on the C drive to improve compression:
 
sdelete –z c:
 
 
-          Ensure that Network Location is set to Private
 
$networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
$connections = $networkListManager.GetNetworkConnections()
$connections | % {$_.GetNetwork().SetCategory(1)}
 
 
-          Ensure that PS-Remoting is enabled
 
Enable-PSRemoting
 
 
-          Ensure that the firewall is allowing traffic to WinRM port 5985
 
netsh advfirewall firewall show rule name=all | sls 5985 –context 9,4
 
If no rule exists to allow the traffic, create one:
 
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow
 
 
 
Shut down the VM and make sure the VM’s first network adapter (nic1) is in NAT mode.  This is a requirement for Vagrant to communicate with the guest.
 
 
Then export the VM to a Vagrant box using the Vagrantfile with the following command:
 
vagrant package --base <vm_name> --vagrantfile /path/to/Vagrantfile --output <new_name.box>
 
 
Now add the box:
 
vagrant box add /path/to/new_name.box --name <new_name>
 
 
Now in a directory with the Vagrantfile you created, start the VM to ensure everything works:
 
vagrant up
 
 
 
 
## Tools List
 
Here is the list of tools currently on the boxes:
 
Copied into C:\Tools:
OST PST Viewer
SYSTools MSG Viewer   
CaptureBAT
OfficeMalScanner
PEStudio
Xorfiles
OffVis
 
Installed by Chocolatey:
Python 2.7
Python 3.6
Sysinternals Suite
Folderchangesview        
Pscp
Putty    
7-zip
Git                         
Notepadplusplus
Wireshark
AdobeReader
GoogleChrome
Microsoft.NET                  
Firefox
Regshot
ProcessHacker
 
 
 
## Odds and ends:
 
1.       Windows 7 boxes must be built with the default product key.  This requires the following config.js file changes to “trial” and “product_key”:
 
cid:image023.png@01D2E064.65F3E5C0
 
 
2.       I’ve configured all VMs to start in GUI mode.  This is changed with the “headless” parameter in the builder_virtualbox_windows.json file:
 
cid:image024.png@01D2E064.65F3E5C0
 
 
3.       Packer takes a long time to copy over tools.  Either keep them small or copy large files over manually after the build process.
 
 
4.       The tool_path is set to /home/tag/tools and the iso_path is set to /home/tag/iso
 