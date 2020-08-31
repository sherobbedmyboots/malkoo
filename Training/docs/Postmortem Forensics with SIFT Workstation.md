# Postmortem Forensics with SIFT Workstation

Digital forensics is the application of science to the collection, examination, and analysis of data.  It is used to reconstruct computer security incidents, determine what events have occurred on systems, and answer key questions in investigations.

Postmortem forensics is the process of gathering evidence and artifacts after the incident is over---examining and extracting data from the file storage media without the system running.  This gives investigators an excellent view of the filesystem in its original state and also allows investigative processes to be more easily repeated to validate results.  

This document will use INC1250653 as an example to demonstrate the following forensics process documented in [NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf) to investigate the incident and provide an explanation of the sequence of events that occurred on the system in question. 

|Phase|Description|
|-|-|
|[Collection](#collection)|Identify and acquire data relevant to the investigation while preserving integrity of the data|
|[Examination](#examination)|Processing the data collected to identify artifacts of interest|
|[Analysis](#analysis)|Use methods and techniques to determine causes, answer key questions|
|[Reporting](#reporting)|Explain sequence of events, tools used, actions that are required|

<br>

## Setting up the SIFT

If the FRED is not operational, open source tools are the next best option.  The [SIFT Workstation](https://digital-forensics.sans.org/community/downloads) is a forensic toolkit for memory, timeline, and file system examination and analysis.  

To set up an analysis environment:

- Download the SIFT Workstation OVA from the [SANS](https://digital-forensics.sans.org/community/downloads) website
- Import the OVA with `vboxmanage import SIFT-Workstation.ova --vsys 0 --vmname sift`
- Adjust memory with `vboxmanage modifyvm sift --memory 4096 --cpu 4` (more if you have it: `--memory 12288 --cpu 8`)  
- Add a DVD drive containing the VBoxGuestAdditions CD to the SIFT with `vboxmanage storageattach sift --storagectl SATA --port 0 --device 0 --type dvddrive --medium /usr/share/virtualbox/VBoxGuestAdditions.iso`
- Power on the SIFT VM and mount the VBoxGuestAdditions CD with `sudo mkdir /mnt/cdrom && sudo mount /dev/cdrom /mnt/cdrom`
- Install VirtualBox Additions with `sudo /mnt/cdrom/VBoxLinuxAdditions.run`
- Add the `sansforensics` user to `vboxsf` group with `sudo adduser sansforensics vboxsf`
- Reboot with `sudo reboot`

NOTE: Your user account on the host machine must be in the `disk` and `vboxusers` groups.  Confirm with `groups <username>`. 

If not, add to these groups using:

```
sudo usermod -a -G vboxusers <username>
sudo usermod -a -G disk <username>
```


We will now take the OOB, the SIFT VM, and the hard drive recovered from the user's laptop, and work through each step of the forensic process:

- [Collection](#collection)
	- [Acquire a Disk Image](#acquire-a-disk-image)
	- [Acquire a Logical Image](#acquire-a-logical-image)
- [Examination](#examination)
	- [Data Extraction with Bulk Extractor](#data-extraction-with-bulk-extractor)
	- [Super Timeline Creation with Plaso](#super-timeline-creation-with-plaso)
- [Analysis](#analysis)
	- [Timeline Analysis](#timeline-analysis)
	- [Artifact Analysis](#artifact-analysis)
- [Reporting](#reporting)
	- [Summary of Incident](#summary-of-incident)
	- [Analysis Steps](#anaylsis-steps)
	- [Key Findings](#key-findings)


## Collection

The collection phase is identifying and acquiring data relevant to the investigation while preserving the integrity of the data.  This is performed using standard procedures that ensure the proper tools and techniques are being used and that a chain of custody for all evidence is clearly documented.

File storage media can range from hard drives to USB devices to memory sticks.  Each type of media is divided logically into formatted file systems called partitions. In this case we have a 289 GB 2.5 inch SATA hard drive formatted with several partitions.  We'll first make a bit-for-bit copy of the disk image, and then make a copy of the partition inside that contains the system's C drive.

- [Acquire a Disk Image](#acquire-a-disk-image)
- [Acquire a Logical Image](#acquire-a-logical-image)


### Acquire a Disk Image

A disk image---also referred to as a *bit-for-bit copy*---contains all data on the hard drive including deleted files and residual data stored in free space and slack space.  We will perform a disk-to-file copy using the `dd` program to copy all the contents of the device to a single image file.  This image file named `diskimage.img` will be our **master copy** and it is only used for making **working copies** of the disk.  Various **working copies** can then be created for examination and analysis with our tools.

The SATA hard drive can be attached to the OOB using a USB-to-SATA adapter.  Instead of creating lots of storage space on our SIFT VM, we'll make use of the 2TB hard drive mounted to the OOB to store the disk image, then share that directory with the SIFT VM.  But first, we must take precautions to ensure nothing will be able to modify the drive in any way when we plug it in.

A hardware write-blocker is preferred to maintain integrity, but here is another method:

- On the OOB, type `gsettings list-recursively org.gnome.desktop.media-handling` to see the current automount settings
- If either the `automount` or `automount-open` keys are set to true, set them to false using:

	`gsettings set org.gnome.desktop.media-handling automount false`<br>
	`gsettings set org.gnome.desktop.media-handling automount-open false`

- Verify the changed settings with `gsettings list-recursively org.gnome.desktop.media-handling`


Now when you plug in the USB adapter, the OOB operating system will be able to see the device, but it will not be mounted. You can confirm with the `lsblk` command that the new device has a name (`sdc`) but no mountpoint:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image001.png)<br><br>

Make the device read-only with:

```
sudo blockdev --setro /dev/sdc
```

Confirm the value of the `readonly` flag is set to `1` with:

```
blockdev --getro /dev/sdc
```

Navigate to a location within the device where you'll be storing the image file.  On this OOB machine, the HDD directory is the mountpoint for the 2 TB storage device and this is where we will create a directory named `case1`.

You can now make an image copy of the drive with `dd`: 

```
dd if=/dev/sdc bs=32M conv=noerror,sync status=progress | dd of=mastercopy.img bs=32M conv=noerror,sync status=progress
```

Compute the MD5 hash of both the device and the `mastercopy.img` image file you just created:

```
$ sudo md5sum /dev/sdc > image.md5
$ cat image.md5
26d43b690851ff2386125ba17a47cf62

$ md5sum mastercopy.img
26d43b690851ff2386125ba17a47cf62
```

Now that we have verified the integrity of the image file, let's make a working copy with `dd` and allow the SIFT VM to see it:

- Create a working copy with `dd if=mastercopy.img of=diskimage.img` 
- Share the `case1` directory with the SIFT VM using `vboxmanage sharedfolder add sift --name case1 --hostpath "/home/tag/HDD" --readonly`

Power on the SIFT and mount the shared folder using the following:

```
sudo mount -t vboxsf -o uid=1000,gid=1000 case1 /mnt/windows_mount
```

Use `df` and `ls` to confirm this was successful:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image005.png)<br><br>

You can now use the SIFT to interact with the disk image file.

### Acquire a Logical Image

The `diskimage.img` file is an exact copy of the physical drive but we also want to mount the NTFS partition containing the system's C drive and browse its files and directories.  To do this, we need to find what offset this partition starts at using the `fdisk` command.

Type `fdisk /mnt/windows_mount/diskimage.img` and drop into the prompt.  

Press `p` to print the device's partition table:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image006.png)<br><br>

Sectors are the smallest units that can be used for storage on the disk.  The output of the `fdisk` command tells us that the disk uses 512 byte sectors and that the NTFS partition starts after 2048 sectors.

Multiplying these together gives us the offset of the partition (2048 X 512 = 1048576).

Mount the NFTS partition with the following options:

|Option|Description|
|-|-|
|`ro`|Mount as read-only|
|`loop`|Mount on a loop device|
|`show_sys_files`|Show NTFS metafiles|
|`streams_interface=windows`|Use Alternate Data Streams|
|`offset=1048576`|Mount the partition starting at this offset|

<br>

Run this command to mount the partition as a windows filesystem:

```
sudo mount -o ro,loop,show_sys_files,streams_interface=windows,offset=1048576 -t auto diskimage.img /mnt/windows_mount1
```

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image007.png)<br><br>

With this, we can now search for and examine all files on the system's C drive.

You may want to browse the partition's files in a Windows environment and use native Windows tools such as Event Viewer to examine files.  To mount the partition on a Windows VM:

- Add the share with `vboxmanage sharedfolder add win7 --name harddrive --hostpath "/home/tag/HDD" --readonly`
- Start the `win7` VM or other Windows VM
- Open File Explorer and go to `Network\VBOXSVR`
- Right click on `diskimage.img` --> `7-Zip` --> `Open archive`

You can now browse the filesystem using File Explorer, Command Prompt, PowerShell, etc:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image029.png)<br><br>

## Examination

After collecting the data, we need to process it and extract evidence and artifacts that will help us identify events of interest.

Two effective examination techniques are:

- [Data Extraction with Bulk Extractor](#data-extraction-with-bulk-extractor)
- [Super Timeline Creation with Plaso](#super-timeline-creation-with-plaso)

### Data Extraction with Bulk Extractor

[Bulk Extractor](https://github.com/simsong/bulk_extractor) scans a disk image looking for specific patterns such as known file headers and footers and carves out the files that are discovered. It also searches for small pieces of data that fit a specific structure such as credit card numbers, domains, email addresses, and phone numbers and is very useful in helping determine what sensitive information was present on a system.

To run it:
- Create a directory with `mkdir be`
- Pass the image file and output directory as arguments with `bulk_extractor /mnt/windows_mount/diskimage.img -o be`

When started, [Bulk Extractor](https://github.com/simsong/bulk_extractor) splits up the image file into different sections and begins scanning each one for recognizable data.  It completely ignores the file structure searching only for specific string and byte patterns.  If it comes across compressed data, it will automatically decompress the data and mark it for reprocessing.

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image008.png)<br><br>

After it completes, there are files in the output directory for all the data discovered:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image009.png)<br><br>

We can search through this data looking for specific characteristics:

Hostnames discovered: 

```
cat domain_histogram.txt | grep term
```

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image012.png)<br><br>

Internal IP Addresses:

```
cat domain_histogram.txt | grep '     10.'
```


![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image013.png)<br><br>


Email Addresses and PIV Principal Names:

```
cat email_histogram.txt | grep term
```

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image014.png)<br><br>

Prefetch Files:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image015.png)<br><br>

This is good information to have when there are questions about what sensitive data was available to someone in possession of the system, but to continue analysis we need more context---was the email address found in an email, on a webpage, in a document?

The next method will give us some additional context regarding the state of the system and the actions that were performed.

### Super Timeline Creation with Plaso

[Plaso](https://github.com/log2timeline/plaso) is a tool used for forensic timeline extraction.  When pointed to a disk image or a set of files, it parses and extracts all timestamped events it finds and aggregates them into a "super timeline" to support forensic analysis.  

The image of an average windows system will contain 4-5 million events so once this super timeline is created, we will need a way to search and explore these events and collaborate during the analysis phase.  A great open source option for this is Google's [Timesketch](https://github.com/google/timesketch), but we will be using Splunk.

To use [Plaso](https://github.com/log2timeline/plaso), start by running the `log2timeline.py` script which extracts all timestamped events from a disk image and creates a storage file which we'll name `timeline.plaso`.  When it first starts, it will detect multiple volume shadow copies and asks which copy to use.  In this case, we'll use timestamps from the shadow copy created on August 22nd:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image010.png)<br><br>

Once it starts collecting and extracting, a status screen is displayed showing the files currently being processed and processing time:


![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image023.png)<br><br>

This one took 34 hours and 28 minutes with the VM using 8 CPU and 14.7 Gb of memory.  After the storage file is created, we can filter, sort, and run automatic analysis on it using Plaso's `psort` tool.

One way is to filter by time... we're most interested in the first day of activity so we will use the following options and arguments to extract events from that time period:

|Option|Description|
|-|-|
|`timeline.plaso`|Storage file to sort|
|`-q`|Quiet option|
|`-o l2tcsv`|Set output format to CSV|
|`-w timeline.csv`|Write to destination file|
|`date < '2018-08-21 20:00:00`|Events with timestamps before date|
|`date > '2018-08-20 20:00:00`|Events with timestamps after date|


Run the command:
```
psort.py -q timeline.plaso "date < '2018-08-21 20:00:00' and date > '2018-08-20 20:00:00'" -o l2tcsv -w timeline.csv 
```

We now have a CSV file of timestamped events that we can import into Splunk.

```
head timeline.csv
```

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image027.png)<br><br>


## Analysis 

In the analysis phase, we bring together multiple data sources to reconstruct events and draw conclusions from the evidence and artifacts to answer key questions in the investigation.

- [Timeline Analysis](#timeline-analysis)
- [Artifact Analysis](#artifact-analysis)

### Timeline Analysis

With so much information from multiple data sources, it can be challenging for investigators to focus on things relevant to the event and their impact---Splunk is an excellent tool to help with this.  After uploading our `timeline.csv` file into Splunk, we can search for interesting events and timeframes.

Each timestamped event has a sourcetype property:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image028.png)<br><br>

To interpret these events, we need to be familiar with MACB Times and Inodes.

**MACB** stands for Modification, Access, Change and Birth:

|Timestamp|Description|
|-|-|
|Modification|Last time the file was written to|
|Access|Last time the file was accessed|
|Change|Last time the file metadata was changed|
|Birth|A Windows timestamp for creation or birth time|

An **inode** represents a file on disk and contains information about the file type, size, permissions, timestamps, and other attributes.  While there may be many different filenames and links that point to a file, there is only one inode for every file.  This is why we need to deduplicate on the inode field in many of these searches.

We can search for the last time an executable was accessed (and in this case created) and obtain the file's inode with:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image031.png)<br><br>

List interesting types with:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image032.png)<br><br>

Then take a closer look at associated events such as password resets:

```
inputlookup timeline.csv | where match(type,"^Last")
| where match(type,"Last Password Reset") | dedup user
| table date time user desc
```



![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image034.png)<br><br>

Find connections to networks and USB devices:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image033.png)<br><br>

Find shutdown times:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image035.png)<br><br>

As well as program execution times and number of times ran:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image036.png)<br><br>

Login times and counts:

```
inputlookup timeline.csv | where match(type,"^Last")
| where match(type,"Last Login Time") | dedup inode
| table date time user short
```



![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image037.png)<br><br>

You can search for events during a specific timeframe:

```
inputlookup timeline.csv 
| where match(date,"08/21/2018") AND time > "04:10:00" AND time < "04:20:00"
| table date time desc
```

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image038.png)<br><br>


### Artifact Analysis

One important artifact in this case is the `sethc.exe` file that was used to bypass the logon screen.  If we get a file hash of both files we can confirm that the `sethc.exe` file on the laptop is actually the `cmd.exe` program that has been renamed:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image026.png)<br><br>

Another important artifact in this case is the SAM file which contains the password hashes for all local accounts.  If we can obtain the passwords for all accounts on the system, we can run the laptop's OS in a virtual environment, log in as any user, and evaluate the system as that specific user.

To do this, we need to use the [samdump2](https://linux.die.net/man/1/samdump2) tool which is installed on the SIFT to extract the password hashes from the SAM file:

```
cd /mnt/windows_mount1/Windows/System32/config
samdump2 SYSTEM SAM > /cases/case1/hashes.txt
cat /cases/case1/hashes.txt
```
![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image022.png)<br><br>

If lucky, an online hash cracker will have a record of the hash and can provide the password.  Here the guest account had a blank password:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image025.png)<br><br>

This didn't work for the admin account.  Cracking an unknown hash could take a long time so the easy solution is to boot our virtual image of the system, log in as the SYSTEM account via `sethc.exe`, and pull the password from memory using a tool like Mimikatz or the Windows Credential Editor.

In this case though, the VM will not boot correctly and runs the startup repair program each time it's powered on:

![](images/Postmortem%20Forensics%20with%20SIFT%20Workstation/image030.png)<br><br>

This could be a result of corrupted registry, missing/damaged system or driver files, bad memory and hard disk hardware errors, etc.  By using a Windows 7 installation disk or system repair disk we could use one of several options to go forward from here:

- Examine changed files and settings to determine what is preventing Windows from starting and fix it
- Restore the OS to an earlier point in time with System Restore
- Use Windows Memory Diagnostic Tool to check for errors
- Use Command Prompt to access the system

In addition to these options, there are several other techniques and artifacts that could produce valuable insight to the state of the system such as:
- Performing memory analysis on the `C:\hiberfil.sys` and `C:\pagefile.sys` files
- Scanning the disk image for deleted files and data in slack space
- Mounting the partition to a Windows VM and evaluating files and directories in a Windows environment

At this point though, we have learned enough to be able to report several key findings. 

## Reporting

In this phase we report the results of analysis:

- Data sources collected and examined
- Forensic tools and techniques used
- What information each source contained
- How conclusions were drawn
- Recommendations, concerns, etc.

Here is a write-up on the incident including a Summary of Incident, Analysis Steps, and Key Findings sections:


### Summary of Incident

The laptop’s hard drive was not encrypted which allowed the user to bypass authentication and log in as the local administrator account.

### Analysis Steps

- An image file of the entire hard disk was created and verified for integrity  (MD5: 26d43b690851ff2386125ba17a47cf62)
- This master copy was used to make working copies for analysis
- Plaso pulled timestamped events from the image to create a super timeline and additional timelines
- Bulk_extractor was used to search the image for sensitive data
- The disk image was converted to VDI format to run the system’s current OS in a virtual environment 
- A logical image was created from the disk image and this copy of the system’s C drive was used to inspect the current state of files


### Key Findings

Since the laptop’s hard drive was not encrypted, the user had the ability to read and modify any file on the system.  This presents two major problems:

1.	OS files can be read/modified to bypass security controls 

2.	All files can be read and searched for sensitive data
