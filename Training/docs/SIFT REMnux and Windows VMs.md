# CSIRT SIFT WIN VM
 
Two new VMs are now available on the OOB:
 
- [SIFT-REMnux](#sift-remnux), a VM with SIFT and REMnux toolkits
 
- [Windows 7 Ult VM](#windows-7-ult-vm), a VM with Windows 7 Ultimate + analysis tools
 
 
## SIFT-REMnux
 
This VM contains two collections of analysis tools:
 
- [SANS Investigative Forensic Toolkit](http://sift.readthedocs.io/en/latest/) (SIFT) is a free
incident response and forensic tool suite containing over 400 different tools.
 
- [REMnux](https://remnux.org/docs/) is a free toolkit for analyzing
Windows and Linux malware and their behavior on the network as well as
obfuscated JavaScript and suspicious document files.
 
Combining both of these toolkits on the same VM provides one system
capable of disk mounting, registry examination, timeline analysis,
memory analysis, network forensics, and malware analysis. 
 
To use it for the first time, log on to the OOB, then:
 
1. Open File Viewer
 
2. Navigate to the `/CSIRT` folder
 
3. Open `SIFT-REMnux.ova` with VirtualBox
 
4. Click on Import
 
 
After a few minutes, SIFT-REMnux will appear as one of your machines and
you can power it on.
 
Username: sansforensics
 
Password: forensics
 
When it comes up, go ahead and save a snapshot by selecting Machine à
Take Snapshot.  Name this something like "CLEAN STATE" as this will
serve as a clean version of your machine.  If you conduct analysis on
potentially malicious files and/or sites with the VM, this will be used
to revert back to a clean image before anything suspicious was
introduced to the system.
 
## Windows-7-Ult-VM
 
This is a test machine where you can evaluate how a Windows box is
affected by malicious sites and files.  There are tools included that
will allow close inspection of which processes are started, which files
are touched, and what network connections are made when the box is
introduced to malware.
 
Instructions to import are the same:
 
1. Open File Viewer
 
2. Navigate to the `/CSIRT` folder
 
3. Open `Windows-7-Ult-VM.ova` with VirtualBox
 
4. Click on Import
 
After a few minutes, Windows-7-Ult-VM will appear as one of your
machines and you can power it on.
 
Username: vm-user
 
Password: vmuserpassword
 
When it comes up, go ahead and save a snapshot by selecting Machine 
Take Snapshot.  Name this something like "CLEAN STATE" as this will
serve as a clean version of your machine.  If you conduct analysis on
potentially malicious files and/or sites with the VM, this will be used
to revert back to a clean image before anything suspicious was
introduced to the system.
 
Here are some walk-throughs for using some of the included tools on both
VMs to get you started:
 
- [Investigating a Malicious Website](http://909research.com/how-to-use-thug-honeyclient/)
 
- [Analyzing Weaponized Documents](https://dfir.it/blog/2015/06/17/analysts-handbook-analyzing-weaponized-documents/)
 
- [Analyzing Malicious PDFs](https://countuponsecurity.com/2014/09/22/malicious-documents-pdf-analysis-in-5-steps/)
 
               
## Tools
 
Here are some of the tools available on the SIFT-REMnux VM:
 
### Examine Browser Malware
 
| | |
|-|-|
|Website Analysis|[Thug](https://github.com/buffer/thug), [mitmproxy](http://mitmproxy.org/), [Network Miner Free Edition](http://www.netresec.com/?page=NetworkMiner), curl,[Wget](https://www.gnu.org/software/wget/), [Burp Proxy Free Edition](http://portswigger.net/burp/), [Automater](http://www.tekdefense.com/automater/), [pdnstool](https://github.com/chrislee35/passivedns-client), [Tor](https://www.torproject.org/), [tcpextract](http://tcpxtract.sourceforge.net/),[tcpflow](https://github.com/simsong/tcpflow), [passive.py](https://github.com/REMnux/distro/blob/v6/passive.py), [CapTipper](https://github.com/omriher/CapTipper), [yaraPcap.py](https://github.com/kevthehermit/YaraPcap)|
|Flash|xxxswf, [SWF Tools](http://www.swftools.org/), RABCDAsm, extract_swf, [Flare](http://www.nowrap.de/flare.html)|
|Java| [Java Cache IDX Parser](https://github.com/Rurik/Java_IDX_Parser/), [JD-GUI Java Decompiler](http://jd.benow.ca/), [JAD Java Decompiler](http://varaneckas.com/jad), Javassist, [CFR](http://www.benf.org/other/cfr/)|
|JavaScript|[Rhino Debugger](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Rhino/Debugger), ExtractScripts, SpiderMonkey, [V8](https://code.google.com/p/v8/), [JS Beautifier](https://github.com/einars/js-beautify)|
 
### Examine Document Files
 
| | |
|-|-|
|PDF| [AnalyzePDF](https://github.com/hiddenillusion/AnalyzePDF), [Pdfobjflow](http://www.aldeid.com/wiki/Pdfobjflow), [pdfid](http://blog.didierstevens.com/programs/pdf-tools/), [pdf-parser](http://blog.didierstevens.com/programs/pdf-tools/),  [peepdf](http://eternal-todo.com/tools/peepdf-pdf-analysis-tool#releases), [Origami](https://code.google.com/p/origami-pdf/), PDFtk, swf_mastah, qpdf, pdfresurrect, [PDFXRAY Lite](https://github.com/9b/pdfxray_lite)|
|Microsoft Office| [officeparser](https://github.com/unixfreak0037/officeparser), [pyOLEScanner.py](https://github.com/Evilcry/PythonScripts/raw/master/), [oletools](http://www.decalage.info/python/oletools), [libolecf](https://github.com/libyal/libolecf),[oledump](http://blog.didierstevens.com/programs/oledump-py/), [emldump](https://isc.sans.edu/diary/Malicious+Word+Document+This+Time+The+Maldoc+Is+A+MIME+File/19673/), [MSGConvert](http://www.matijs.net/software/msgconv/), [base64dump.py](http://blog.didierstevens.com/2015/07/05/base64dump-py-version-0-0-1/), [unicode](https://github.com/garabik/unicode)|
|Shellcode| sctest, unicode2hex-escaped, unicode2raw, [dism-this](http://hooked-on-mnemonics.blogspot.com/2012/10/dism-thispy.html),[shellcode2exe](https://github.com/MarioVilas/shellcode_tools/blob/master/shellcode2exe.py)|
 
### Extract and Decode Artifacts
 
| | |
|-|-|
|Deobfuscate|[unXOR](https://github.com/tomchop/unxor/), [XORStrings](http://blog.didierstevens.com/2013/04/15/new-tool-xorstrings/), [ex_pe_xor](http://hooked-on-mnemonics.blogspot.com/2014/04/expexorpy.html), [XORSearch](http://blog.didierstevens.com/programs/xorsearch/), [brxor.py](https://github.com/REMnux/distro/blob/v6/brxor.py),[xortool](https://github.com/hellman/xortool), [NoMoreXOR](https://github.com/hiddenillusion/NoMoreXOR), [XORBruteForcer](http://eternal-todo.com/category/bruteforce), [Balbuzard](https://bitbucket.org/decalage/balbuzard/wiki/Home), [FLOSS](https://github.com/fireeye/flare-floss/)|
|Extract strings|strdeobj, pestr, [strings](http://en.wikipedia.org/wiki/Strings_(Unix))|
|Carving|[Foremost](http://foremost.sourceforge.net/), [Scalpel](http://www.forensicswiki.org/wiki/Scalpel), bulk_extractor, Hachoir|
 
### Handle Network Interactions
 
| | |
|-|-|
|Sniffing|[Wireshark](http://www.wireshark.org/), ngrep, TCPDump, tcpick, [NetworkMiner](http://www.netresec.com/?page=NetworkMiner)|
|Services|FakeDNS, [Nginx](http://nginx.org/), fakeMail, Honeyd, INetSim, [Inspire IRCd](http://www.inspircd.org/),[OpenSSH](http://www.openssh.com/), accept-all-ips|
|Miscellaneous network|[prettyping.sh](https://bitbucket.org/denilsonsa/small_scripts/src/3ec16014c839ea0852fae492813ad2293bd61155/prettyping.sh), set-static-ip, renew-dhcp, Netcat,[EPIC IRC Client](http://www.epicsol.org/), stunnel, [Just-Metadata](https://github.com/ChrisTruncer/Just-Metadata)|
 
### Examine File Properties and Contents
 
| | |
|-|-|
|Define signatures|YaraGenerator, IOCextractor, Autorule, [Rule Editor](https://github.com/ifontarensky/RuleEditor),[ioc-parser](https://github.com/armbues/ioc_parser)|
|Scan|[Yara](http://plusvic.github.io/yara/), ClamAV, TrID, ExifTool, virustotal-submit, Disitool|
|Hashes|nsrllookup, Automater, [Hash Identifier](https://code.google.com/p/hash-identifier/), totalhash, ssdeep,[virustotal-search](http://blog.didierstevens.com/programs/virustotal-tools/), VirusTotalApi|
 
### Edit and View Files
 
| | |
|-|-|
|Text|SciTE, Geany, [Vim](http://www.vim.org/)|
|Images|feh, ImageMagick|
|Binary|wxHexEditor, VBinDiff|
|Documents|Xpdf|
 
### Statically Examine PE Files
 
| | |
|-|-|
|Unpacking|[UPX](http://upx.sourceforge.net/), Bytehist, [Density Scout](http://www.cert.at/downloads/software/densityscout_en.html), PackerID|
|Disassemble|objdump, [Udis86](http://udis86.sourceforge.net/), [Vivisect](http://visi.kenshoto.com/viki/Vivisect)|
|Find anomalies|Signsrch, pescanner, ExeScan, pev, Peframe, pedump|
|Investigate|[Bokken](https://inguma.eu/projects/bokken), RATDecoders, Pyew, [readpe.py](https://github.com/crackinglandia/pype32), PyInstaller Extractor, [DC3-MWCP](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP), [Mastiff](https://git.korelogic.com/mastiff.git/)|
 
### Examine Memory
 
| | |
|-|-|
|Memory Analysis|[Volatility Framework](https://github.com/volatilityfoundation/volatility), findaes, AESKeyFinder, RSAKeyFinder, VolDiff,[Rekall](http://www.rekall-forensic.com/), linux_mem_diff_tool|
 
 
 
## Best Practices
 
Here are some best practices for the SIFT-REMnux and Windows 7 VMs:
 
- [Updating the SIFT-REMnux VM](#updating-the-sift-remnux-vm)
- [Setting up a Shared Folder](#setting-up-a-shared-folder)
- [Setting up an Isolated Network](#setting-up-an-isolated-network)
- [Using Docker Containers](#using-docker-containers)
 
### Updating the SIFT-REMnux VM
 
Open a terminal and run the following commands:
 
```
sudo update-sift
sudo update-remnux
```
 
 
Your SIFT-REMnux VM should now be fully updated with the latest
packages.
 
### Setting up a Shared Folder
 
You will need to share a folder from the OOB host to your VM guests to
transfer files from the OOB to the VMs:
 
1. On the VM machine toolbar, go to Devices --> Shared Folders --> Shared
    Folder Settings
 
2. On the left menu, select Shared Folders
 
3. Right click and select Add Shared Folder
 
4. In the dropdown, select Other
 
5. Select Desktop, then click on Choose
 
6. Select all three boxes and click OK
 
7. Select OK again
 
This shares your Desktop on the OOB with the guest VM.  To transfer a
file to a guest VM:
 
1. Move the file to your Desktop on the OOB
 
2. On your VM, navigate to your Shared Folders and then to your Desktop
    on the OOB
 
3. Transfer file by either Copy & Pasting or Dragging & Dropping to
    your Desktop on the VM
 
 
### Setting up an Isolated Network
 
Sometimes analysis will require an isolated network containing only the
SIFT-REMnux and Windows VMs.  Here is a way to do this using static IP
addresses:
 
#### In the Virtual Box menus:
 
1. For each VM, go to Machine --> Settings --> Network --> Adapter 1
 
2. For "Attached to" select "Internal Network"
 
3. For "Name" select "intnet"
 
4. Click OK
 
#### On the Windows VM:
 
1. Open up an Administrative command prompt and type:
 
```
netsh interface ip set address name="Local Area Connection" static 172.16.1.2 255.255.255.0 172.16.1.1
```
 
2. Restart the interface with:
 
```
ipconfig /release && ipconfig /renew
```
 
3. Verify the new ip address with:
 
```
ipconfig
```
 
#### On the SIFT-REMnux VM:
 
1. Open up a terminal and type:
 
```
sudo nano /etc/network/interfaces
```
 
 
2. Change it to show the following lines:
 
```
auto eth0
iface eth0 inet static
address 172.16.1.3
netmask 255.255.255.0
gateway 172.16.1.1
```
 
3. Press `Ctrl + O` to save it and `Ctrl + X` to exit
 
4. Restart the interface with:
 
```
sudo ifdown eth0 && sudo ifup eth0
```
 
5. Verify the new IP address with:
 
```
ifconfig
```
 
The two VMs (172.16.1.2 and 172.16.1.3) should now be able to
communicate with each other on the 172.16.1.0/24 network.  You should
immediately be able to ping the SIFT-REMnux from the Windows VM and
observe ICMP replies.  The Windows VM however is configured by default
to not allow incoming ping requests.  To make an exception in the
firewall so that the Windows VM will respond to pings, type:
 
```
netsh firewall set icmpsetting 8 enable
```
 
 
To return the VMS to their original configurations:
 
1. For each VM, go to Machine --> Settings --> Network --> Adapter 1
 
2. For "Attached to"  select "Bridged Adapter"
 
3. Click OK
 
#### On the Windows VM:
 
1. Open up an Administrative command prompt and type:
 
```
netsh interface ip set address name="Local Area Connection" dhcp
```
 
2. Restart the interface with:
 
```
ipconfig /release && ipconfig /renew
```
 
3. Verify the new ip address with:
 
```
ipconfig
```
 
#### On the SIFT-REMnux VM:
 
1. Open up a terminal and type:
 
```
sudo nano /etc/network/interfaces
```
 
2. Then change to show the following lines:
 
```
auto eth0
iface eth0 inet dhcp
```
 
3. Press `Ctrl + O` to save it and `Ctrl + X` to exit
 
4. Restart the interface with:
 
```
sudo ifdown eth0 && sudo ifup eth0
```
 
5. Verify the new ip address with:
 
```
ifconfig
```
 
 
### Using Docker Containers
 
The SIFT-REMnux VM has hundreds of tools installed directly on the host
alongside the OS.  It's fine to run most tools this way, however
sometimes you may want to run one of the applications as separate
container.
 
A Docker container of an application contains the software and all its
dependencies.  Once you build it, the container gets its own runtime
environment---its own filesystem, process listing, network stack...
it's very similar to a virtual machine except that it shares the host's
OS kernel instead of having its own and therefore is not as isolated as
a VM.
 
#### Benefits
 
- Separates code from data---store data on the underlying host, run
    application code in the isolated container
 
- You can quickly deploy an app, run it, then tear it down without
    losing customizations or data
 
- Security patches don't break the app and rebuilding an image
    automatically updates the application's dependencies
 
- Apps with conflicting dependencies can run on the same host since
    they are isolated
 
- Easier to control what data and software components are installed
 
- No unwanted files lying around after you finish analysis
 
#### Risks
 
- Running multiple application instances with varying security patch
    levels
 
- Segregation is good but not as robust as virtual machines
 
#### Example
 
To demonstrate using a container, I'll use Thug---a honey-client that
mimics the behavior of a web browser in order to detect and emulate
malicious content.  You can build a Docker image of Thug to investigate
a potentially malicious website by opening a terminal on the SIFT-REMnux
VM and typing:
 
```
sudo docker run --rm -it remnux/thug bash
```
 
The first time you pull down an image, it will take a few minutes. 
After this, it is saved locally and the next time you build a container
of this app it doesn't take as long.
 
When the image has been downloaded and the container is built, your
command prompt will look like this:
 
`thug@[container id]:~$`
 
Each docker image you run will have its own container id.  To see a list
of running docker containers, open a second terminal and type:
 
```
sudo docker ps
```
 
This will list all running containers, their IDs, time created and
status.
 
To kill a container, type:
 
```
sudo docker kill [container id]
```
 
To run Thug and conduct analysis completely inside the container, use:
 
```
thug -FZM  "[http://evil[d]com](http://evil[d]com)"
```
 
To run the Thug container and map its log directory to the host's `/tmp` directory, use the `-v` option:
 
```
thug -FZM -v /tmp:/tmp/thug/logs "[http://evil[d]com](http://evil[d]com)"
```
 
After analysis, you can view the logs inside the container, or on your
host in the /tmp folder.  Thug creates a directory name with the MD5
hash of the site analyzed which contains all analysis artifacts.
 
[Thug's documentation](http://buffer.github.io/thug/doc/index.html)
shows many other ways this tool can be used to analyze websites.
 
When your analysis is complete, at the container prompt, type:
 
```
exit
```
 
The app container, all its files, processes, and network connections are
gone.  If you used the `-v` option to map the container's directory to a
host directory, you'll still be able to access these files for further
off-line analysis.
 