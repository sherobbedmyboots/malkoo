# Dynamic Analysis Walkthrough

Dynamic analysis, or behavioral analysis, is used to determine how
malware interacts with its environment.  In cases where anti-sandbox and
obfuscation techniques are used to complicate automated and static
analysis, dynamic analysis is a quick way to assess the malware's
capabilities, extract artifacts, and answer key questions to help build
an overall picture of the incident.

Here are several tools we can use for dynamic analysis on our OOB
Windows VMs:

- [Process Hacker](#process-hacker)
- [Process Monitor](#process-monitor)
- [RegShot](#regshot)
- [DNSQuerySniffer](#dnsquerysniffer)
- [Microsoft Network Monitor](#microsoft-network-monitor)
- [FakeNet](#fakenet)
- [Fiddler](#fiddler)
- [ProcDOT](#procdot)

Let's look at each one while examining the following Word document:

	/CSIRT/Sample-Files/topmovies2017.xls

## Process Hacker

This is a great tool with many features explored in depth
[here](https://blogs.sans.org/windows-security/files/Process_Hacker_SANS_Jason_Fossen.pdf). 
It shows the system process tree and also has tabs for monitoring
Services, Network, and Disk.

- New processes are shown in GREEN

- Exiting processes are shown in RED

- Suspended processes are shown in DARK GRAY

Open Process Hacker, right click on column headers and add the following
columns:

`command line`

`integrity level`

When ready:

- Open the document (you may need to enable macros)

You should see Excel spawn a random-named suspicious process:

![](images/Dynamic%20Analysis%20Walkthrough/image001.png)


Another way to spot a malicious process is to view only unsigned
processes by clicking View --> Hide Signed Processes:

![](images/Dynamic%20Analysis%20Walkthrough/image002.png)


To go to where this file is on the file system, right click the process
--> Open file location:

![](images/Dynamic%20Analysis%20Walkthrough/image003.png)


The executable was dropped into and is running out of the user's
`AppData\Roaming\Microsoft\Addins` directory.

You can also search for suspicious strings in memory using regular
expressions:

- Right clicking process --> properties

- Click on `Memory` tab, then `Strings` button

- Click `OK`

- Click Filter --> Regex

- Enter your regex, IP addresses for example:  \[\\d\]{1,3}\\.\[\\d\]{1,3}\\.\[\\d\]{1,3}\\.\[\\d\]{1,3}

Here the ip address of the C2 server is found:

![](images/Dynamic%20Analysis%20Walkthrough/image004.png)


If many processes start and exit at once, a better tool to use is
Process Monitor.

## Process Monitor

ProcMon captures all network, registry, filesystem, and process/thread
activity and provides a collection of filters to eliminate noise.

To set it up:

- Open ProcMon and hit `Ctrl+E` to stop capturing and `Ctrl+X` to
    clear all events

- Under Options, uncheck `Show Resolved Network Addresses`

- Under Options --> Select Columns, check `Thread ID` and click `OK`

    (For this example, also have Wireshark running to capture
    traffic---save it as a pcap file for use with ProcDot later)

- When ready, hit `Ctrl+E` to start capturing (and also Start the
    Wireshark capture)

- Open the document

This will capture all events taking place while the malware runs:

Here we see the Excel process creating a randomly named process running
out of the `Addins` directory:

![](images/Dynamic%20Analysis%20Walkthrough/image005.png)


After a few minutes, stop the capture using `Ctrl+E`.  (and also stop
the Wireshark capture)

To filter on one process, I can right click on the process --> Include `A7F6A2B7.exe`

Now we can see all the events associated with our malicious process:

![](images/Dynamic%20Analysis%20Walkthrough/image006.png)


To clear the filter, hit `Ctrl+R` or select Filter --> Reset Filter.

Another good filter is to isolate new processes.  Do this by right
clicking on a Process Start event --> Include `Process Start`

This shows all the processes that started during the capture:

![](images/Dynamic%20Analysis%20Walkthrough/image007.png)


Reset the filter again and save the capture to a CSV file for use with
ProcDot later:

- File --> Save

- Select `All events` and `Comma-Separated Values`

- Click `OK`

Also save the Wireshark capture as a .pcap.

## RegShot

Regshot uses snapshots of the registry and filesystem to detect changes
made by malware.

- Open Regshot

- Select `Scan dir1`

- Change `C:\Windows` to `C:\`

- When ready, click on 1st shot --> shot

- When the 1st scan completes, open the document

- Click on 2nd shot --> shot

- Click on `Compare`

Regshot's report shows the different file and registry add/modify/delete
events that occurred while the malware ran:

![](images/Dynamic%20Analysis%20Walkthrough/image008.png)


## DNSQuerySniffer

Inspect DNS queries originating from the victim system while running the
malware:

- Open DNSQuerySniffer to begin capturing DNS traffic

- Open the document

![](images/Dynamic%20Analysis%20Walkthrough/image009.png)


This shows opening the document results in DNS queries to a suspicious
domain.

## Microsoft Network Monitor

Determine processes that are communicating over the network and examine
each conversation separately with Network Monitor:

This tool breaks out network activity by process so there is no need to
filter out noise and other legitimate traffic as when using Wireshark.

- Open Network Monitor and click on `New Capture`

- Click the `Start` button to begin capturing

- Open the document

You can see the suspicious process is sending SYNs from different source
ports (49175, 49177, 49178) which are not being answered with SYN-ACKs
since the C2 server is down:

![](images/Dynamic%20Analysis%20Walkthrough/image010.png)


To get more information from the malware, we can stand up a fake C2
server with FakeNet.

## FakeNet

Fake service programs like FakeNet and
[FakeNet-NG](https://github.com/fireeye/flare-fakenet-ng/) act as the
non-existent C2 server in order to inspect the traffic a malicious file
sends.

To install FakeNet, open PowerShell and type:

- `choco install fakenet -y`

- Then start the program with `fakenet`

- Click `Allow access` when prompted by Windows Firewall

- Open the document

FakeNet listens on DNS and  HTTPS by default and will answer both the
query for the C2 domain and the requests sent via HTTPS:

![](images/Dynamic%20Analysis%20Walkthrough/image011.png)


This gives us more information about the malware even when its C2 server
is unavailable.

## Fiddler

If we're lucky and the C2 server is still online, we can inspect all C2
traffic by decrypting the HTTPS with Fiddler.

Enable decryption of HTTPS traffic by doing the following:

- Open Fiddler

- Click on Tools --> Options

- Click on `HTTPS` tab

- Check box next to `Decrypt HTTPS traffic`

- Click `Yes` to trust Fiddler's root certificate

- Click `Yes` to install it and `Yes` again to confirm

This will allow Fiddler to proxy all HTTPS connections between the host
and all destinations and show the traffic in its unencrypted form.

Without HTTPS decryption, all we see is the tunnel to the C2 domain:

![](images/Dynamic%20Analysis%20Walkthrough/image012.png)


With decryption enabled, we see every request the malware sends to its
C2 over HTTPS and their responses including keep-alives, downloaded
files, and packets containing binary commands:

![](images/Dynamic%20Analysis%20Walkthrough/image013.png)



We can extract files sent from the C2 server by Right Clicking a session --> Save --> Response --> Response Body

Extracting the first file that was sent down after the HTTPS handshake
resulted in a hit from VirusTotal:

![](images/Dynamic%20Analysis%20Walkthrough/image014.png)


Dozens of engines recognize this as the meterpreter DLL.

## ProcDOT

This tool will use your ProcMon CSV and your Wireshark pcap of the
traffic to visualize the actions of the malicious document.

To set up dependencies:

- Download `WinDump.exe` by typing

	`wget https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe -O windump.exe`

- Download and install Graphiz by typing

	`wget https://www.graphviz.org/pub/graphviz/stable/windows/graphviz-2.38.zip -O graphviz.msi`

- Then, double-click on the .msi file to install

To configure ProcDot:

- Open ProcDot

- Enter in path to windump:

- Enter in path to dot.exe

- Check Smart-Highlight edges for `is based on` and `has thread` in frames

- Click `OK`

![](images/Dynamic%20Analysis%20Walkthrough/image015.png)


- Click `next` to ProcMon and choose path to CSV

- Click `next` to Windump and choose path to Pcap

- Check `no paths` and `compressed`

- Click `Refresh`

![](images/Dynamic%20Analysis%20Walkthrough/image016.png)


- Click `next` to Launcher

- Double click on `Excel.exe`

Using the graph, we can trace the Excel process, its threads and
children processes:

![](images/Dynamic%20Analysis%20Walkthrough/image017.png)


As well as those of the randomly named executable:

![](images/Dynamic%20Analysis%20Walkthrough/image018.png)

