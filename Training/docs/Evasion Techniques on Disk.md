# Evasion Techniques on Disk

Some of the same techniques that are privacy and security best practices can be used to deter response teams when seizing, copying, and inspecting the contents of electronic storage devices.  As responders we need to be very familiar with each technique so we can identify when it's being used and what artifacts will and will not be available in an investigation.

This document will walk through the following techniques:

- [Using an Encrypted VM](#using-an-encrypted-vm)
- [Using a Hidden VM](#using-a-hidden-vm)
- [Booting to a Hidden OS](#booting-to-a-hidden-os)
- [Booting to a Live OS](#booting-to-a-live-os)


## Using an Encrypted VM

Using an encrypted VM prevents investigators from accessing the VM's virtual hard drive and devices to obtain artifacts since the file system containing these is protected by a password only the user knows.

Two methods of doing this are:

- [Configuring VM Software for Encryption](#configuring-vm-software-for-encryption)
- [Storing VM Files in an Encrypted Container](#storing-vm-files-in-an-encrypted-container)

### Configuring VM Software for Encryption

VM Hypervisors like VirtualBox may offer the user the ability to encrypt the VM's hard disk:

![](images/Evasion%20Techniques%20on%20Disk/image011.png)<br><br>

After encryption is complete, booting the VM requires the disk encryption password:

![](images/Evasion%20Techniques%20on%20Disk/image012.png)<br><br>


### Storing VM Files in an Encrypted Container

Another way is to create an encrypted container to hold the machine's disk image file (VDI, VMDK, VHD, HDD) and settings file (.vbox). With an encrypted container, the data inside cannot be read without using the correct password/encryption keys.

A common way to do this is using [VeraCrypt](https://www.veracrypt.fr/en/Downloads.html).  Download the program to an OOB machine and begin creating an encrypted container:

![](images/Evasion%20Techniques%20on%20Disk/image015.png)<br><br>

Choose a standard encrypted container and give it a location and name:

![](images/Evasion%20Techniques%20on%20Disk/image013.png)<br><br>

Select the encryption algorithm, the size of the container, choose a password, and choose `I will store files larger than 4 GB on the volume`.  Continue on until the container is created.

To mount a container, browse to it in the VeraCrypt window, select it, choose `Mount`, and enter its password:

![](images/Evasion%20Techniques%20on%20Disk/image014.png)<br><br>

Once it's mounted, the file system is unencrypted and you can add the VM disk image and settings files to it:

![](images/Evasion%20Techniques%20on%20Disk/image016.png)<br><br>

Dismount the container and it is now encrypted on disk again.  To access the VM you need the disk image file and settings file which are in the encrypted container and can only be accessed with the correct password.

Without the password, the `std_container` file is just 30 GB of encrypted data.  


## Using a Hidden VM

VM files can also be stored in a [hidden volume](https://www.veracrypt.fr/en/Hidden%20Volume.html) which is a volume that's created within the free space of another encrypted volume.

![](images/Evasion%20Techniques%20on%20Disk/image028.png)<br><br>

To someone else, the encrypted container appears to be only one volume requiring one password to access and when opened only decoy data is observed.  But using a second password to decrypt the same container provides access to a second volume which contains the VM files.  In this instance, the user could comply with an investigation giving up the first password, and possibly fool responders into thinking they accessed all data in the container.

To create a hidden volume, go to `Create Volume` --> `Create an encrypted file container` --> `Hidden VeraCrypt Volume`

Create a standard encrypted container and give it a location and name:

![](images/Evasion%20Techniques%20on%20Disk/image019.png)<br><br>

Select an encryption algorithm, size of the container, and choose a password.

The **outer** volume will then be created:

![](images/Evasion%20Techniques%20on%20Disk/image020.png)<br><br>

Add decoy files to this volume:

![](images/Evasion%20Techniques%20on%20Disk/image021.png)<br><br>

Now choose an algorithm, size, and password for the hidden volume. Select `I will store files larger than 4 GB on the volume` in order to hide a VM disk image.

Continue on until the hidden volume has been created:

![](images/Evasion%20Techniques%20on%20Disk/image022.png)<br><br>

Add the VM disk image and settings files to the hidden volume:

![](images/Evasion%20Techniques%20on%20Disk/image025.png)<br><br>


After the files are copied over, dismount the container.


Now first try mounting the volume with the decoy password:

![](images/Evasion%20Techniques%20on%20Disk/image023.png)<br><br>

You should be presented with the decoy data.  Next, dismount it and try opening it again using the hidden password.  You should now see the VM disk image and settings files.

You can see how this would present significant problems for responders attempting to reconstruct a timeline of events on a system.  Without access to the hidden volume, there is no way to access the VM and the data it contains.

It is also possible to create and boot an operating system residing in a hidden volume...

## Booting To A Hidden OS

When using a [Hidden Operating System](https://www.veracrypt.fr/en/VeraCrypt%20Hidden%20Operating%20System.html), examination of the hard drive will reveal two separate partions, each large enough to contain an operating system:

![](images/Evasion%20Techniques%20on%20Disk/image041.png)<br><br>

When asked to explain the purpose of the two encrytped partitions, the user could state that the first is his OS and the second is a filesystem for storing sensitive files.  When the system boots, the following happens:

- VeraCrypt boot loader prompts for a disk encryption password
- User enters PASSWORD-1 which decrypts Partition 1 and boots the Decoy OS inside
- User runs VeraCrypt, enters PASSWORD-2 to decrypt and mount Partition 2 
- User can now access sensitive files stored on Partition 2


However, there is another OS hidden in the second partition that can only be accessed using a third password, PASSWORD-3.  This password allows the VeraCrypt boot loader to decrypt Partition 2 and boot the hidden OS it contains.  When the system boots, the following happens:

- VeraCrypt boot loader prompts for a disk encryption password
- User enters PASSWORD-3 which decrypts Partition 2 and boots the Hidden OS inside
- User runs hidden OS and has access to hidden files


So entering the decoy password will load the decoy OS and entering the hidden password will load the hidden OS.  The presence of the VeraCrypt boot loader can be explained by the disk encryption of the Decoy OS and the second partition is made to look like encrypted storage.

Another method is to use a boot loader that provides the user a few seconds to hit a specific key combination.  If the user presses the correct key combination, the boot loader will prompt the user to decrypt the hidden OS.  If not, the boot loader prompts the user to decrypt the decoy OS by default.

A hidden OS uses encryption to hide evidence and prevent unwanted access if the disk it is installed on falls into the hands of someone else.  This next technique is designed to leave no evidence of the user's activity on the system.

## Booting To A Live OS

Live OS's run using only the filesystem on the device (USB, CD/DVD) and the computer's RAM to operate. These can be used to make changes to the existing system as well as operate without making any changes to the system.

Try each of the following to demonstrate:

- [Demo with Slax](#demo-with-slax)
- [Demo with TAILS](#demo-with-tails)

### Demo with Slax

Download an iso image of Slax from the [Slax Linux page](https://www.slax.org/).

Open the `Settings` page for a Windows VM and go to the `Storage` tab. Click on the disc with a plus to add a CD/DVD device, select `Choose Disk`, and navigate to the Slax iso:

![](images/Evasion%20Techniques%20on%20Disk/image001.png)<br><br>

Make sure you check the box labeled "Live CD/DVD" to keep it from being removed when ejected.

Start the VM and immediately press `F12` to bring up the boot menu.  You should see this:

![](images/Evasion%20Techniques%20on%20Disk/image002.png)<br><br>


Hit `c` for the CD-ROM and Slax will begin to boot:

![](images/Evasion%20Techniques%20on%20Disk/image003.png)<br><br>

When the OS finishes loading, Right Click --> Terminal to open a command prompt.  

![](images/Evasion%20Techniques%20on%20Disk/image004.png)<br><br>

You are root and you have the Windows C: drive mounted at `/media/sda1`:

You now have root privileges on the entire file system if the hard drive isn't encrypted.

![](images/Evasion%20Techniques%20on%20Disk/image005.png)<br><br>

With an unencrypted hard drive, you can steal sensitive data, write malicious files to the system, or perform virtually any type of attack.  A classic example is replacing the Windows program `sethc.exe` with `cmd.exe`:

Run the following commands:

```
cd /media/sda1/Windows/System32
cp cmd.exe sethc.exe
reboot
```

Now let the machine boot back into Windows.  When the desktop finishes loading, log out of the user's account and press the Shift key five times:

![](images/Evasion%20Techniques%20on%20Disk/image006.png)<br><br>

The `cmd.exe` ran with SYSTEM privileges when the Accessibility feature was enabled.

Although a Live OS can be used to interact with the computer's hard disk, the goal when using it for evasion purposes is to ensure nothing on the disk is changed and that only volatile RAM is used which will be erased on shutdown.

### Demo with TAILS

TAILS is a Live OS designed for privacy and anonymity.  In addition to leaving no traces on the existing system, it conceals the true destinations of all traffic [using Tor](#using-tor) and can be configured to store information in [encrypted persistent volumes](#encrypted-persistent-volumes) on the USB or DVD.

TAILS comes with a number of cryptographic tools installed:

|Tool|Description|
|-|-|
|LUKS|Encrypt the USB|
|HTTPS Everywhere|Encrypt all web traffic|
|OpenPGP|Encrypt and sign emails|
|OTR|Encrypt instant messages|
|Nautilus Wipe|Securely delete files|
|PWGen|Password generator|
|KeePassX|Password manager|

For this demo, we'll run the Live OS off of a USB drive.  For best operation, the TAILS USB needs to be created by the TAILS OS.  This requires using VirtualBox to boot into the TAILS OS to copy the TAILS ISO onto the USB.

In order for VirtualBox to access your USB drive, your account needs to belong to the `vboxusers` and `disk` groups.  To do this, use the following:

```
sudo usermod -a -G vboxusers <username>
sudo usermod -a -G disk <username>
```

Logoff and back in again for this to take effect.

Create a new VM in VirtualBox, name it tails, set type to `Linux`, and version to `Other Linux (64-bit)`:

![](images/Evasion%20Techniques%20on%20Disk/image007.png)<br><br>

Set memory to `4096`, select `Do not add a virtual hard drive`, then `Continue`.

Go to `Settings` --> `Storage`  and select the disk image file labeled "Empty".

Browse to the tails iso , check `Live CD/DVD`:

![](images/Evasion%20Techniques%20on%20Disk/image026.png)<br><br>

Go to the `USB` tab and add your USB device:

![](images/Evasion%20Techniques%20on%20Disk/image027.png)<br><br>

Power on the VM and it should boot directly into TAILS.  Once the desktop loads, go to `Applications` --> `Tails` --> `Tails Installer`.  Your USB should be recognized and already selected for installation:

![](images/Evasion%20Techniques%20on%20Disk/image029.png)<br><br>

Click `Install` to begin the process. The USB will then be partitioned, formatted as FAT32, and written with a live TAILS image.

Once this is complete, close VirtualBox and restart your computer.  This time boot into the TAILS OS using the USB device.

#### Using Encrypted Persistent Volumes

Since this OS was created with the TAILS installer, you can use it to create a persistent volume on the USB by going to `Applications` --> `Tails` --> `Configure persistent volume`:

![](images/Evasion%20Techniques%20on%20Disk/image035.png)<br><br>

Choose a password and then choose which data will be persistent:

![](images/Evasion%20Techniques%20on%20Disk/image031.png)<br><br>

After rebooting, you'll be prompted for the password to access the encrypted persistent volume.  Once you decrypt the filesystem, run `df -h` and you will see the encrypted partition is now mounted and ready for storing data:

![](images/Evasion%20Techniques%20on%20Disk/image033.png)<br><br>

Listing the path of the partition shows all the directories that contain persistent data for different applications:

![](images/Evasion%20Techniques%20on%20Disk/image034.png)<br><br>

Download some files, add accounts, configure applications, etc. and then reboot into the live OS to confirm your settings are all saved on the encrypted persistent volume.

If you had possession of the USB device, you would need to know the password to access the saved data.  Reboot into the host OS, identify the partitions on the USB, and attempt to mount them:

![](images/Evasion%20Techniques%20on%20Disk/image039.png)<br><br>

Using the password, you can unlock and mount the volume to view all the files it contains:

![](images/Evasion%20Techniques%20on%20Disk/image040.png)<br><br>

Now let's see what this system looks like over the network. 

#### Using Tor

For this exercise we need admin privileges to use `tcpdump` and monitor traffic leaving the system.  To do this, we need to set up an administator password which must be done when TAILS starts up.  So, reboot into the live OS and this time when you unlock the encrypted persistent volume, also select the option to create an administrator password.

Start `tcpdump` and write all captured traffic to a file.  Browse to several different websites to generate some traffic.  Then press `Ctrl + c` to stop capturing.

![](images/Evasion%20Techniques%20on%20Disk/image036.png)<br><br>

Now look at all the traffic leaving the TAILS system using `sudo tcpdump -r dump.pcap 'src 192.168.2.20'`:

![](images/Evasion%20Techniques%20on%20Disk/image037.png)<br><br>

Let's look at what left the system that was not destined for port 9001:

![](images/Evasion%20Techniques%20on%20Disk/image038.png)<br><br>

We can see that all traffic from the TAILS OS is encrypted and routed through the Tor network to obscure its true destination.

## Summary

We should be on the lookout for each of these techniques being used on our systems and the controls we have in place to detect/counter them. 

|Technique|Controls|
|-|-|
|[Encrypted VM](#using-an-encrypted-vm)|Large amounts of encrypted data, presence of VM/disk encryption software|
|[Hidden VM](#using-a-hidden-vm)|Large amounts of encrypted data, presence of VM/disk encryption software|
|[Hidden OS](#booting-to-a-hidden-os)|Large encrypted partitions on hard drive or additional drives with disk encryption|
|[Live OS](#booting-to-a-live-os)|Unified Extensible Firmware Interface (UEFI) Secure Boot is a successor of Basic Input Output System (BIOS).  When UEFI is enabled, only signed bootloaders are allowed to run and booting from a CD/USB is not possible|