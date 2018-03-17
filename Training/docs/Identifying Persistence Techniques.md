# Identifying Persistence Techniques

For this exercise, I created a Windows VM (Persistence-VM) that has been
recently compromised.  The attacker had temporary control of the one
user account on the box (vm-user) and was able to successfully implement
10 different methods of persistence which you must find and remediate. 
Some of these are automated, some must be initiated by the attacker, and
some rely on the user to take some kind of action.  For each method,
I've given you a brief description of the technique and some common ways
to detect it on the system and the network.

You will need to use the SIFT-REMnux machine in an isolated environment
to interact with the compromised host.  Generally, the best way to
identify the source of malicious activity is to start with the network
activity, find the processes that are initiating this activity, inspect
the files that are creating these processes, and then determine under
what conditions these files are executed.  However, not all of these
persistence methods are active on the network so feel free to start
wherever you're more comfortable.  If you're starting on the network,
capture traffic from the victim host and create listening ports to
interact with the attacker's processes.  If you're starting on the host,
inspect files, processes, and services for unusual conditions and
suspicious artifacts.

Using `Persistence-VM.ova`, set up an isolated environment where your SIFT-REMnux can
act as the attacker's machine (192.168.2.110) to capture any callbacks,
and the victim host keeps its original IP address (192.168.2.114):

#### In the Virtual Box menu for both VMs:

1. Go to Machine --> Settings --> Network --> Adapter 1

2. For "Attached to"  select "Internal Network"

3. For "Name" select "intnet"

4. Click OK

#### On the SIFT-REMnux VM:

1. Open up a terminal and type:

    `sudo nano /etc/network/interfaces`

2. Change it to show the following lines:

    ```bash
    auto eth0
    iface eth0 inet static
    address 192.168.2.110
    netmask 255.255.255.0
    gateway 192.168.2.1
    ```

3. Press (`Ctrl + O` then `ENTER`) to save it and (`Ctrl + X`) to exit

4. Restart the networking service with:

    `sudo service networking restart`

5. Restart the interface with:

    `sudo ifdown eth0 && sudo ifup eth0`

6. Verify the new IP address with:

    `ifconfig`


## Investigating Persistence-VM

Here are the ten types of persistence present on the host:

- [Startup Folder and Registry Keys](#startup-folder-and-registry-keys)
- [Scheduled Tasks](#scheduled-tasks)
- [Accessibility Features](#accessibility-features)
- [File and Folder Permissions](#file-and-folder-permissions)
- [Logon Scripts](#logon-scripts)
- [Shortcuts](#shortcuts)
- [Service Registry Permissions](#service-registry-permissions)
- [Service Permissions](#service-permissions)
- [New Service](#new-service)
- [Default File Associations](#default-file-associations)



### Startup Folder and Registry Keys

Programs in a user's Startup folder and registry Run keys will execute at user logon. 

- See startup programs by typing `wmic startup get`

- Also try using the SysInternals tool Autoruns with `autorunsc -accepteula -m` which shows non-Microsoft entries

### Scheduled Tasks

Tasks can be created to execute a malicious program on system startup or
at certain days and times. 

- Use `schtasks` and `at` commands to view scheduled tasks on the system

### Accessibility Features

There are several accessibility features that can be abused by an
attacker to maintain access to a system. 

- Locate these files and compare their hashes with known good hashes
    to determine if they are being used for persistence

### File and Folder Permissions

If a program uses a file or folder that has weak permissions, an
attacker can overwrite a legitimate program file with a malicious one. 

- Look for programs using folders that are writable by everyone using `icacls`

- Try using SysInternals tool Accesschk with  `accesschk -accepteula -uwds "Everyone" c:\*.*`

### Logon Scripts

A logon script can be configured to run whenever a user logs into a
system. 

- Check the location of logon scripts for evidence of malicious tools
    or commands

- On SIFT-REMnux, use `sudo tcpdump -i eth0 src host 192.168.2.114 -w outputfile.pcap` to capture traffic originating from the victim
    at startup

### Shortcuts

A shortcut for a legitimate program can be modified and used to open a
malicious program when accessed by a user. 

- Check all shortcuts (`.lnk`) to ensure they point to their intended
    application

- Inspect suspicious shortcuts and the processes they create or are
    opened with

### Service Registry Permissions

If an attacker can modify registry keys, the image path value of a
service can be changed to point to a different executable.

- Use `reg query` or `gci` to list the image paths of all services
    and look for any unusual values

- Search for recently changed registry keys related to services

### Service Permissions

If an attacker can modify a service, the binary path can be changed to
any executable on the system. 

- Use `Get-Service` and `sc` to spot binary paths that look
    suspicious

- Use `netstat -ano` to identify services using the network that
    usually do not

### New Service

A new service can be created and configured by an attacker to execute at
startup.

- Use `Get-Service` and `sc` to investigate suspicious and
    recently created services

- Use `netstat -ano` to identify services using the network that
    usually do not

### Default File Associations

Default file associations determine which programs are used to open
certain file types.  These can be changed so that an arbitrary program
is called when a specific file type is opened.

- Use `regedit` to check the registry for file association values
    that have been changed recently or look suspicious

- Use the `assoc` command to review file association values that are
    not normal

