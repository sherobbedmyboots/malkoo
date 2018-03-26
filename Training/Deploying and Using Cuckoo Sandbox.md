# Deploying and Using Cuckoo Sandbox


- [Prepare Host Machine](#prepare-host-machine)
- [Build a Sandbox VM](#build-a-sandbox-vm)
- [Prepare VM for Cuckoo](#prepare-vm-for-cuckoo) 
- [Setup VM as Cuckoo User](#set-up-vm-as-cuckoo-user)
- [Configure Cuckoo Settings](#configure-cuckoo-settings)



## Prepare Host Machine

- Run `cuckoo.sh` to check for and install dependencies

	This installs VirtualBox, MongoDB, Django, Tcpdump, PEFile, Volatility, Yara, SSDeep, Distorm3 and other programs required for Cuckoo Sandbox. Also configures Iptables rules, creates user 'cuckoo' and adds to vboxusers group.

### Add sudo apt-get install swig


## Build a Sandbox VM

- Configure `.config/malboxes/config.js`

	This contains settings for username, password, computername, and programs for Chocolately to install such as Python 2.7, Adobe Reader, Mozilla Firefox, Google Chrome, 7zip

- Build a base machine with `malboxes build win7_64_analyst`

	Malboxes uses packer to build the machine 

When malboxes finishes building the VM, we need to power it up and run some scripts to configure settings.

- Create a directory to work in by typing `mkdir cuckoobox && cd cuckoobox`

- Create a Vagrantfile for the VM by typing `malboxes spin win7_64_analyst cuckoobox`

- Stand up the VM by typing `vagrant up`


## Prepare VM for Cuckoo

- Run `C:\Tools\Post-SpinCuckoo.ps1` script to install Service Pack 1, .NET version 4.5, and PowerShell 5, and also configure various settings and remove bloatware	

- Power down VM

- Use [Vagrantfile]() to package as a vagrant box

	vagrant package --base cuckoobox --vagrantfile /path/to/Vagrantfile --output cuckoobox.box
	vagrant box add /path/to/cuckoobox.box --name cuckoobox
	vagrant up

- Place box in `/home/cuckoo/` directory


## Setup VM as Cuckoo User

Log in to GUI as user "cuckoo"

Start `cuckoo2.sh` script which will:

- vagrant up the box at `/home/cuckoo/cuckoo1.box`

- Install Cuckoo Agent

	`agent.pyw` is placed in 'C:\Users\core\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' for persistence

- Creates a host-only interface for cuckoo1

- Restarts VM 

At this point the script pauses so you can verify:

- The guest can ping the host `ping 192.168.56.1`

- The guest can ping external addresses `ping 8.8.8.8`

- The host can ping the guest `ping 192.168.56.101`

If these three actions are successful, delete the `C:\Tools` dir and `Host` shortcut and continue the script:

- "NoOffice" snapshot is taken

- Script pauses so MS Office can be installed with `choco install officeproplus2013`

- "WithOffice" snapshot is taken

- VM is powered off

## Set Cuckoo Configurations

### Add enable = yes in auxillary file, correct path to /usr/bin/mitmdump



Once all configurations are set, we can start cuckoo


### Start Cuckoo

```bash
virtualenv venv
. venv/bin/activate
cuckoo community
cuckoo -d
```

In a separate terminal:

```bash
. venv/bin/activate
cuckoo web runserver
```

## Using Cuckoo Sandbox



- analyze emails, websites, documents, executables
- traces API calls 
- searches for static and behavioral signatures
- creates logs, network traffic, and disk/memory artifacts


- Cuckoo runs in the background and waits for submissions

- Cuckoo Web server runs on port 8000, access with browser


The DASHBOARD allows submission of multiple files or multiple URLs/hashes:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image001.png)<br><br>


Once submitted, you can choose ANALYSIS OPTIONS:

- Network Routing through VPN, Tor, etc.

- Analysis Packages such as procmemdump, human, free, doc/exe

- Timeout can be short, medium, long

- Options such as behavior analysis, full memory dump


Click ANALYZE to begin analysis.  When complete, status will change to reported. Click to see results.

|Page|Description|
|-|-|
|Summary|Analysis score, signatures detected, screenshots| 
|Static Analysis|Static properties such as strings, metadata, AV signatures|
|Extracted Artifacts|Files extracted during analysis|
|Behavioral Analysis|Process tree, API calls for each process by file, registry, network, etc|
|Network Analysis|Captured traffic by Host, Protocol, Snort/Suricata signatures, download PCAP|
|Dropped Files|All files written to system during and after execution|
|Dropped Buffers|Portions of data written to memory during and after execution|
|Process Memory|Extracted/injected images, discovered URLs|
|Compare Analysis|Choose another analysis to compare with|
|Export Analysis|Export chosen files for download|
|Reboot Analysis|Analyze sample behavior following a reboot|
|Options|Delete the analysis|
