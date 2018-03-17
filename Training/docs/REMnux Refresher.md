# REMnux Refresher
 
Understanding the capabilities of malicious software is critical for detecting, reporting, and responding to incidents.  REMnux contains a ton of useful tools that help us perform static, dynamic, and code analysis as we investigate suspicious files and infrastructure.
 
Here is a refresher on how to use some of the many tools included in the REMnux distro.
 
 
## Websites
 
Use the following tools to obtain artifacts and analyze traffic while investigating potentially malicious websites:

|Tool|Usage|Description|
|-|-|-| 
|Thug|thug -FZM -n . \<website\>|visit website as a vulnerable browser, collect artifacts|
|BurpSuite|burpsuite  (set proxy to localhost:8080)|inspect all traffic to suspicious websites|
|pdnstool.py|pdnstool -dv \<domain\>|passive DNS lookups (put APIs in $HOME/.passivedns-client)|
|wget|wget \<url\> -O \<newfile\>|get contents of a website|
|curl|curl \<url\>|transfer data via HTTP, HTTPS, FTP, SFTP, FTPS, TFTP, SCP and others|
               
 
## Office Documents
 
Use these tools to investigate Office documents containing exploits, macros, or embedded OLE objects:

|Tool|Usage|Description|
|-|-|-|  
|officeparser.py|officeparser.py --extract-macros \<filename\>|extract embedded macros|
||officeparser.py --extract-ole-streams \<filename\>|extract embedded ole streams|
|olevba|olevba.py --reveal \<filename\>|detect macros, suspicious keywords and patterns|
|pyxswf|pyxswf.py -xo \<olename\>|extract embedded SWF files|
| |pyxswf.py -xf \<rtfname\>|extract SWF files from a RTF file|
|rtfobj|rtfobj \<rtfname\>|extract embedded objects from RTF file|
|oledump|oledump.py -D \<filename\>|load a decoder|
| |oledump.py -s  \<item\> -d \<filename\>|select item and dump it|
| |oledump.py -y \<yararule\> \<filename\>|scan streams with Yara rules|
 
 
## PDFs
 
Use the following for analysis of PDFs containing exploits, JavaScript, ActionScript, Flash objects and embedded files:

|Tool|Usage|Description|
|-|-|-| 
|pdf2txt|pdf2txt.py \<filename\>|displays text inside file|
|pdfimages|pdfimages -list \<filename\>|lists images inside file|
|pdfinfo|pdfinfo \<filename\>|scans for set of words, counts occurrences|
|pdfid|pdfid \<filename\>|scan for risky keywords that indicate JS, deobfuscation, encryption, URIs|
|pdfwalker|pdfwalker \<filename\>|browse structure of the PDF|
|pdf-parser|pdfparser.py --stats \<filename\>|displays statistics of objects found in PDF|
| |pdfparser.py --object 20 \<filename\>|shows object 20 in file|
|pdfxray_lite|pdfxray_lite.py -f \<filename\> -r REPORT|examines structure and contents|
|peepdf|peepdf –i \<filename\>|browses structure and extracts various data from PDF|
|Pdfextract|pdfextract -s \<filename\>|extracts streams out of PDF|
 
## Executables
 
Use the following to analyze executables and identify packing, encryption, and other indications of malcode:

|Tool|Usage|Description|
|-|-|-|  
|Bokken|bokken \<filename\>|allows interactive static analysis|
|wxHexEditor|wxHexEditor \<filename\>|graphic hex editor|
|pescanner|pescanner.py \<filename\>|scans PE files for anomalies|
|pedump|pedump \<filename\>|dumps strings, headers, various info from a PE|
|packerid|packerid –emtP \<filename\>|attempts to identify packer used|
|UPX|upx –d \<filename\> -o \<newfile\>|unpack a file packed by UPX|
|peframe|peframe \<filename\>|shows file info, packing, suspicious APIs, filenames|
|signsrch|signsrch \<filename\>|Search file for common code patterns|
|readpe|readpe –f \<filename\> \> \<newfile\>|extract file headers|
|packerID|packerid –emtP \<filename\>|list packer used, extract digital signatures, short list of PE properties|
 
 
## Shellcode
 
Use these tools to manipulate and analyze shellcode:
 
|Tool|Usage|Description|
|-|-|-| 
|unicode2hex-escaped|unicode2hex-escaped \< \<infile\> \> \<outfile\>|converts the shellcode into hex format|
|shellcode2exe.py|shellcode2exe.py -s \<filename\>|converts shellcode hex file into an executable|
|xxd|xxd -r -p \<infile\> \<outfile\>|converts hex file into binary file|
||xxd -p \<filename\>|converts binary file into hex|
|sctest|sctest -d \<filename\>|dumps/emulates shellcode|
|dism-this|dism-this.py -v \<filename\>|prints disassembly|
               
## Deobfuscation
 
Use these tools to reveal file details, shellcode, and script content that has been obfuscated:
 
|Tool|Usage|Description|
|-|-|-| 
|Floss|floss \<filename\>|automatically deobfuscates strings from binaries|
|XORSearch|xorsearch –i \<filename\> \<pattern\>|search a given string in XOR, ROL, ROT, or SHIFT encoding|
|Balbuzard|balbuzard.py \<filename\>|extract and decode suspicious patterns|
|unXOR|unxor.py -g \<pattern\> \<infile\> \<outfile\>|guess keys using known patterns|
|NoMoreXor|NoMoreXor.py –a \<filename\> \<outfile\>|analyze file to guess 256-byte XOR key|
|Xortool|xortool -b \<filename\>|guess xor key and key length|                               
  
## Signatures/Reputation                       
 
Use these tools to run AV scans and hash checks:
 
|Tool|Usage|Description|
|-|-|-| 
|hash_id|hash_id (then enter hash)|identify type of hash|
|totalhash|totalhash.py –s \<hash\>|search the totalhash.com database|
|vt|vt –s \<hash\>|search hash against VirusTotal database (put VT API key in $HOME/.vtapi)|
| |vt –f \<filename\>|submit file to VirusTotal|
|ClamAV|freshclam && clamscan \<filename\>|update ClamAV and scan file|
 
 
## Network
 
Use these tools for traffic analysis and network forensics:
 
|Tool|Usage|Description|
|-|-|-| 
|wireshark|sudo wireshark|network protocol analyzer|
|ngrep|ngrep –i -I \<pcap\> \<term\>|searches for regex or hex matches in packet payloads|
|tcpxtract|sudo tcpxtract -d eth0|extracts files from network traffic based on headers and footers|
|tcpflow|sudo tcpflow –i eth0|captures traffic and reconstructs data streams in flows|
|tcpdump|sudo tcpdump –i eth0|packet analyzer to capture and display traffic|
|Networkminer|Networkminer \<pcapfile\>|passive capturing and analysis tool|
 
 
The creator of REMnux, Lenny Zeltser, has put together a great collection of cheat sheets that can be found [here](https://zeltser.com/cheat-sheets/).          
 
