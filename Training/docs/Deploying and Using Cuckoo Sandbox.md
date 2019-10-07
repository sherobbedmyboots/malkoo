# Deploying and Using Cuckoo Sandbox

This is a quick review on the Cuckoo Sandbox automated malware analysis system.  It is an open-sourced Python program that runs on the OOB and waits for file or URL submissions via its web interface.  When it receives one, it stands up a customized sandbox VM and simulates a user running the file or visiting the link.

It can analyze emails, websites, documents, and executables, trace API calls, and search for static and behavioral signatures.  After analysis is completed, a results page is presented with tabs for dropped files, network traffic, and process memory.  The analyst can then browse the results and download logs, network traffic, and disk and memory artifacts associated with the execution of the sample.  

This document will review the following:

- [Deploying Cuckoo Sandbox](#deploying-cuckoo-sandbox)
    - [Prepare Host Machine](#prepare-host-machine)
    - [Build a Sandbox VM](#build-a-sandbox-vm)
    - [Prepare VM for Cuckoo](#prepare-vm-for-cuckoo) 
    - [Configure and Start Cuckoo](#configure-and-start-cuckoo)
- [Using Cuckoo Sandbox](#using-cuckoo-sandbox)
    - [Artifact Submissions](#artifact-submissions)
    - [Analysis Results](#analysis-results)

## Deploying Cuckoo Sandbox

I created a [cuckoo.sh](scripts/cuckoo.sh) script and additional files to make installing Cuckoo Sandbox on Ubuntu faster and easier.

When using these to deploy Cuckoo, start with the following in your home directory:

- [cuckoo.sh](scripts/cuckoo.sh)
- [tools](scripts/Tools)
    - [1.ps1](scripts/Tools/1.ps1)
    - [2.ps](scripts/Tools/2.ps1)
    - [3.ps1](scripts/Tools/3.ps1)
    - [4.ps1](scripts/Tools/4.ps1)
    - [Post-SpinCuckoo.ps1](scripts/Tools/Post-SpinCuckoo.ps1)
    - [SysPrep.ps1](scripts/Tools/SysPrep.ps1)

<br>

Using these files, we'll walk through the following steps:

- [Prepare Host Machine](#prepare-host-machine)
- [Build a Sandbox VM](#build-a-sandbox-vm)
- [Prepare VM for Cuckoo](#prepare-vm-for-cuckoo) 
- [Configure and Start Cuckoo](#configure-and-start-cuckoo)


### Prepare Host Machine

Start the process by running the `cuckoo.sh` script located in the home directory:

```
./cuckoo.sh
```


This script first checks for and installs dependencies and programs on the host that are needed for installation.  If there is a problem installing them, the script exits reporting the specific program that could not be installed.

Here are some of the programs it checks for:

|Program|Description|
|-|-|
|[VirtualBox](https://www.virtualbox.org/)|Open Source Virtualization product|
|[MongoDB](https://www.mongodb.com/)|A document-oriented database program|
|[Django](https://www.djangoproject.com/)|Python Web framework|
|[Tcpdump](https://www.tcpdump.org/)|A command-line packet sniffer and analyzer|
|[PEFile](https://pypi.python.org/pypi/pefile)|A Python module that parses PEs|
|[Volatility](http://www.volatilityfoundation.org/)|An advanced memory forensics framework|
|[Yara](https://github.com/VirusTotal/yara)|Searches data for matching text and binary patterns|
|[SSDeep](https://ssdeep-project.github.io/ssdeep/)|Uses fuzzy hashes to identify almost-identical files|
|[Distorm3](https://pypi.python.org/pypi/distorm3)|x86/AMD64 disassembler library|
|[Packer](https://www.packer.io/)|Automates creating machine images|
|[Vagrant](https://www.vagrantup.com)|Automates creating development environments|
|[Malboxes](https://github.com/GoSecure/malboxes)|Automates building malware analysis Windows VMs|

<br>

Once the script confirms all programs are installed, it begins configuring Iptables rules that will allow traffic from the Sandbox VM to reach the Internet using the Host machine as a gateway.  The [iptables-persistent](https://packages.debian.org/jessie/iptables-persistent) program is then installed to keep these rules across reboots.

Next, a cuckoo user is created to run the sandbox VM and Cuckoo tools.  This user is then added to the **vboxusers** group.

Finally, the user is prompted to configure the `./tools/config.js` file which contains settings for username, password, computername, and programs for Chocolatey to install such as Python 2.7, Adobe Reader, Mozilla Firefox, Google Chrome, and 7zip.

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image017.png)<br><br>

When this is complete, the `cuckoo.sh` script and `tools` directory are copied over to the `/tmp` directory and the user is directed to log in to the cuckoo user account via the GUI.


### Build a Sandbox VM

Once logged in as the cuckoo user, the `cuckoo.sh` script is run again, this time located at `/tmp/cuckoo.sh`.  The script uses [Malboxes](https://github.com/GoSecure/malboxes) to build a base VM which we'll turn into a sandbox VM.

When the script runs, it does the following:

- Disables screen lock for convenience
- Sets up a virtual environment for Cuckoo
- Copies `tools` directory from `/tmp`
- Copies `tools/config.js` file to malboxes directory
- Copies cuckoo agent `.cuckoo/agent/agent.py` to `tools` directory
- Builds a Windows 7 base machine with Malboxes command `malboxes build win7_64_analyst`

<br>

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image018.png)<br><br>

Now that the base VM is built, it's time to add to it to create the sandbox VM.


### Prepare VM for Cuckoo

If the machine is built with no errors, the user is directed to press \[Enter\] which proceeds to spin up an instance of the base machine called cuckoo1.

Next, the user is directed to run the `C:\Tools\Post-SpinCuckoo.ps1` script on the VM which runs a series of miniscripts (`1.ps1`, `2.ps1`, `3.ps1`, `4.ps1`) to install Service Pack 1, .NET version 4.5, and PowerShell 5 while also performing the required reboots.

The script also:

- Copies the Cuckoo agent `tools/agent.pyw` into `C:\Users\jcasy\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` for persistence
- Configures various settings and removes Windows bloatware that may cause unnecessary file, process, and network activity
- Copies the `C:\Tools\SysPrep.ps1` script into the `%TEMP%` directory

When finished, a file named `Complete` will appear on the desktop.  If everything completes with no errors, the user is directed to delete the `Complete` file on the Desktop and press \[Enter\].

The `cuckoo.sh` script then creates a host-only interface for the VM, restarts it, and waits while the `SysPrep.ps1` script in the `%TEMP%` directory makes a few last changes to the cuckoo1 VM:

- Checks to make sure the cuckoo agent is running
- Performs DNS, gateway, and external connectivity checks
- Deletes any remaining installation artifacts

If the `SysPrep.ps1` script reports everything is good, press \[Enter\] and the script will delete itself.  Then continue the `cuckoo.sh` script by pressing \[Enter\] which will take the first snapshot called **NoOffice**.  This will be used to create additional "WithOffice" snapshots in the event the Office free trial expires.

After this is taken, the user is prompted to install Microsoft Office by opening PowerShell and typing `choco install officeproplus2013 -y`.  If this doesn't work, the user will be instructed to download the installation file from [here](http://care.dlservice.microsoft.com/dl/download/2/9/C/29CC45EF-4CDA-4710-9FB3-1489786570A1/OfficeProfessionalPlus_x86_en-us.img) and install manually.

After Office is successfully installed, the user presses \[Enter\] to take the second snapshot called **WithOffice**.

Now the VM is ready for use, but several settings need to be configured in the Cuckoo config files.

### Configure and Start Cuckoo

The `cuckoo.sh` then makes the following changes:

- The `.cuckoo/conf/virtualbox.conf` file is configured to use the `WithOffice` snapshot
- The `.cuckoo/conf/auxiliary.conf` file is configured to enable `mitmproxy`
- The `.cuckoo/conf/reporting.conf` file is configured to use MongoDB
- The `.cuckoo/conf/reporting.conf` file is configured to enable PDF and HTML reports 
- The `.cuckoo/conf/reporting.conf` file is configured to enable VT/signatures

Once all configurations are set, we are ready start Cuckoo.  

`virtualenv` is a program that creates an isolated Python environment for Cuckoo to run in.  This allows Cuckoo to use specific versions of programs without affecting other applications on the host.  

The `cuckoo.sh` script does this for you, but if you did this manually, you would type:

```bash
virtualenv venv
. venv/bin/activate
cuckoo
```

Once Cuckoo loads up and starts running, the user is directed to open a second terminal window (`Ctrl`+`Alt`+`T`) and start the Cuckoo web server on port 8000:

```bash
. venv/bin/activate
cuckoo web runserver 0.0.0.0:8000
```

If at any point the host machine is rebooted, you'll need to restart the virtual interface that Cuckoo uses in order for Cuckoo to load:

```bash
vboxmanage hostonlyif ipconfig vboxnet0 -ip 192.168.56.1 -netmask 255.255.255.0
```

With the Cuckoo engine and web server running, we are ready to submit files.

<br>

## Using Cuckoo Sandbox

To demonstrate using Cuckoo Sandbox, we'll do a walkthrough with the executable payload analyzed in [Analysis of a Phishing Email](Analysis%20of%20a%20Phishing%20Email.md) which was randomly named [272861.exe](https://www.virustotal.com/en/file/a991f8cfffa6ffaaa9ce886987ac3330ad85bf024ea77a0eb156b5e825b8f4fd/analysis/).  Take note of the differences between manually investigating a file and interpreting results from Cuckoo's automated analysis.


### Artifact Submissions

We will be submitting suspicious artifacts to the Cuckoo web server(s) running on port 8000 which can be accessed with any browser.  Depending on the version being used (standard or modified), you can submit a file, hash, URL, or pcap for analysis.

The [DASHBOARD]() allows submissions of multiple files or multiple URLs/hashes:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image001.png)<br><br>

For emails received with the PhishMe button, use the [Strip-ForCuckoo.ps1](scripts/Strip-ForCuckoo.ps1) script to produce the original emails and a text file containing discovered URLs:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image004.png)<br><br>

After selecting one or more files/URLs, an option page is presented where you can configure analysis settings:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image002.png)<br><br>

Options include:

- Network Routing through VPN, Tor, etc. (not enabled)
- Analysis Packages such as procmemdump, human, free, doc/exe
- Timeout can be short, medium, or long
- Behavior analysis, full memory dump

<br>

We'll keep the default options but also ask for a full memory dump:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image003.png)<br><br>


Click [ANALYZE]() to begin the analysis.  Your file will show as pending until the analysis completes and the status shows as "reported":

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image005.png)<br><br>

### Analysis Results

When complete, the results are provided via a collection of pages:

|Page|Description|
|-|-|
|[Summary Analysis](#summary-analysis)|Analysis score, signatures detected, screenshots| 
|[Static Analysis](#static-analysis)|Static properties such as strings, metadata, AV signatures|
|[Extracted Artifacts](#extracted-artifacts)|Files extracted during analysis|
|[Behavioral Analysis](#behavioral-analysis)|Process tree, API calls for each process by file, registry, network, etc|
|[Network Analysis](#network-analysis)|Captured traffic by Host, Protocol, Snort/Suricata signatures, download PCAP|
|[Dropped Files](#dropped-files)|All files written to system during and after execution|
|[Dropped Buffers](#dropped-buffers)|Portions of data written to memory during and after execution|
|[Process Memory](#process-memory)|Extracted/injected images, discovered URLs|
|[Compare Analysis](#compare-analysis)|Choose another analysis to compare with|
|[Export Analysis](#export-analysis)|Export chosen files for download|
|[Reboot Analysis](#reboot-analysis)|Analyze sample behavior following a reboot|
|[Options](#options)|Delete the analysis|

<br>

### Summary Analysis

The first page presented is the Summary page which provides general information with an overall score, any matching signatures, screenshots taken, and any network traffic observed:

|Section|Description|
|-|-|
|File Properties|The sample's hashes, size, filetype, and if any Yara rules matched|
|Score|The sample's score on a scale from 0 to 10|
|Signatures|Static and behavioral characteristics that indicate possible malicious actions|
|Contacted Hosts|Hosts that were contacted while the sample was running|

<br>

Here are some low-severity signatures that the sample triggered:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image006.png)<br><br>

Some medium-severity:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image007.png)<br><br>

And some high-severity:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image008.png)<br><br>

Expanding the signatures gives additional details:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image019.png)<br><br>


### Static Analysis

The Static Analysis page provides file properties such as:

|Section|Description|
|-|-|
|Compile Time|The timestamp of when the file was reportedly compiled|
|Imphash|A hash of the file's imported libraries and functions|
|Sections|The sections that make up the PE file (.text, .rdata, .data, .rsrc, etc.)|
|Resources|Embedded files within the executable|
|Imports|Shows the APIs that are present in the Import Address Table (IAT)|
|Strings|Ascii and unicode strings discovered in the file|
|AntiVirus|Shows all AV signatures that were triggered|

<br>

The Static Analysis tab shows properties such as compile time and imphash:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image010.png)<br><br>

The Strings tab shows strings discovered in the file:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image011.png)<br><br>

Antivirus tab shows products that have detected this file:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image012.png)<br><br>

### Extracted Artifacts

This page displays potentially interesting information that Cuckoo has extracted such as decoded PowerShell scripts or embedded shellcode.  This `evil-ps.hta` sample (#691) was Base64-encoded but can now be examined in its decoded state:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image028.png)<br><br>



### Behavioral Analysis

The Behavioral Analysis page shows artifacts discovered while running the file:

|Section|Description|
|-|-|
|Process Tree|Parent and child processes observed|
|Process Contents|File, registry, and network artifacts discovered in process memory|

<br>

Here we see the `272861.exe` process spawning a copy of itself:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image013.png)<br><br>

And in process memory we find the API call requesting the allocation of a 57,244 byte region of memory:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image014.png)<br><br>

This is the same thing we saw in the debugger in [Analysis of a Phishing Email](Analysis%20of%20a%20Phishing%20Email.md).

### Network Analysis

The Network tab lists hosts that were contacted:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image015.png)<br><br>

A PCAP of all observed traffic can be downloaded and inspected with Wireshark.  The packet capture shows the same IP was contacted but this time the SYNs were not answered:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image016.png)<br><br>

If the C2 server was still up, we could have inspected the HTTP traffic by selecting each session on the Network tab.



### Dropped Files

Files that are dropped during execution are listed on this page.  Here, the sample writes a copy of itself to the user's `Temp` directory:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image032.png)<br><br>


There is also an option to search for the file on [VirusTotal](https://www.virustotal.com/#/home/upload):

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image033.png)<br><br>



### Dropped Buffers

Data that is written to memory during execution is listed on this page.  Here, the `guidance.hta` file writes the `guidance.dll` to process memory:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image029.png)<br><br>


This page also provides an option to search for the file on VirusTotal:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image030.png)<br><br>



### Process Memory

This page lists any URLs found in the memory of suspicious processes and gives the option to download injected or extracted images discovered in process memory.

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image034.png)<br><br>



### Compare Analysis

Compare against previous analysis reports for the same sample by using this page:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image031.png)<br><br>


### Export Analysis

Reports and artifacts available for download are listed on the Export Analysis page:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image023.png)<br><br>

In this case we have:

- 10 Desktop screenshots
- analysis report summary in three formats (`report.html`, `report.json`, `report.pdf`)
- process memory dumps of the three suspicious processes (`1708-1.dmp`, `2024-1.dmp`, `2640-1.dmp`)
- PCAP containing network traffic observed (`dump.cap`) and a sorted version (`dump_sorted.pcap`)
- list of dropped files (`files.json`)
- cuckoo log (`cuckoo.log`) and trace of analysis execution inside the guest environment (`analysis.log`)
- list of TLS Master Secrets for decrypting HTTPS streams (`tlsmaster.txt`)
- details about the task that ran (`task.json`)
- copy of the sample (`binary`)
- details about the reboot analysis (`reboot.json`)


Some of these can be used for additional analysis if needed.  

For example, downloading and examining the `memory.dmp` file, we find a third `272861.exe` process ran with the `psscan` plugin:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image025.png)<br><br>

The `malfind` plugin identifies injected code in this process:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image021.png)<br><br>

This memory region can be dumped for further analysis.  Here we find the same strings used to detect the presence of a sandbox:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image022.png)<br><br>


### Reboot Analysis

This page is used to request that Cuckoo observe the sample after a reboot.  This generates a new analysis under a different task:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image024.png)<br><br>


### Options

Allows you to delete the analysis:

![](images/Deploying%20and%20Using%20Cuckoo%20Sandbox/image027.png)<br><br>
