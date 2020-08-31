# Drive-By Downloads

Drive-by downloads occur when a legitimate website is compromised so
that a visitor's browser is redirected to a malicious site where malware
is downloaded in the background to the victim's system.  The attack is
traditionally carried out by exploit kits which automate the discovery
and exploitation of known vulnerabilities in browsers and popular
third-party applications like Adobe Flash, Adobe Reader, Adobe Acrobat
and Silverlight.

Exploit kits continue to be a challenge for security tools and analysts
as they can:

- Evade reputation filtering by switching hostnames and IPs frequently
    and piggy-backing on legitimate domains

- Evade content detection by dynamically generating components using
    encoding and encryption techniques

- Evade analysis and reverse engineering by using obfuscation and
    anti-sandbox techniques

## Basic Stages of a Drive-by Download

- [Visit to a Compromised Site](#visit-to-a-compromised-site) - User visits a legitimate site that has been compromised

- [Victim is Redirected](#victim-is-redirected) - Malicious code on the compromised site redirects user to an attacker's site

- [Victim System is Profiled](#victim-system-is-profiled) - Exploit kit on the attacker's site profiles the user's OS, browser name and version, and Java, Flash, Silverlight versions

- [Exploit is Attempted](#exploit-is-attempted) - Exploit kit selects application and attempts to exploit it

- [Payload is Delivered](#payload-is-delivered) - Payload (either malware or a downloader) is delivered to user's system

- [Installation of Malware](#installation-of-malware) - Malware installs itself on user's system


## Visit to a Compromised Site

In this incident, the website at usndcorps\[d\]org was compromised and
injected with malicious HTML/JavaScript. Logs show the user found the link to the site in a google search and
loaded the compromised webpage at 17:37:24.

![](images/Drive%20By%20Downloads/image001.png)


## Victim is Redirected

The malicious code on the compromised site directs the user's browser
to the attacker's site, also called a landing page.  This can be done
via an IFRAME (in-line HTML frame), HTTP POST redirection (user tricked
into submitting form), or HTTP redirect (302).  At 17:37:25, one second
after the compromised site was loaded, the user's browser made a request
to the malicious site apivjo.o0turtle\[d\]top:

![](images/Drive%20By%20Downloads/image002.png)



## Victim System is Profiled

Once the landing page is requested, a combination of HTML and JavaScript
can be used to probe and identify the user's browser and plugins. 

While doing this, the exploit kit uses a variety of techniques to evade detection
by security products such as:

- Encoding its main script functionality by storing data strings in
    the parent HTML

- Hiding shellcode data and script content in encoded strings so that
    they are decoded when the landing page is loaded by the browser

- Looking for sandboxes and signs of a virtual environment by checking
    for the presence of security tools, files and directories, available
    drives, available internal network addresses, etc.

The exploit kit uses responses from the victim's browser to determine
the application/plugin most likely to result in exploitation.  These
specific exploit modules are then loaded to exploit the user's specific
configuration.


## Exploit is Attempted

When an application is chosen (in this case Flash version 21.0.0.242),
the victim's browser is instructed to download the malicious file which
contains encrypted exploit code.  At 17:37:28, the victim's system
requests "match-creature-28119360\[d\]swf" to be executed by Flash
Player on the victim's system. 

![](images/Drive%20By%20Downloads/image003.png)


## Payload is Delivered

If the exploit is successful, the payload is requested, decrypted, saved
and run, and is usually inserted directly into memory in the process of
the exploited application/plugin without being written to disk.  The
payload can either be the actual malware or a downloader designed to
download malware to the machine.  The victim's system requested the file
`corp-16534678` at 17:37:29 which may have been the payload but we would
need packet captures showing the content of the file or the file itself
to confirm this.  The payload is frequently delivered as a zip file
disguised as a text file containing both the actual malware and its
configuration file.

![](images/Drive%20By%20Downloads/image004.png)


## Installation of Malware

The malware then installs itself in the form of ransomware, trojan
backdoors for remote control, or botnet software which can be used for
stealing sensitive data, click-fraud operations, etc.    DHS SOC
reported seeing DNS queries to "jvybf1\[.\]x0crocodile\[.\]top" from a
host during OOB analysis-----This could be requests for the actual
malware or possibly C2 traffic if the malware was already installed or
running in memory. 

Splunk helps to put together a timeline of the web traffic and identify
what files were requested by the host but what we really need to confirm
that the host was successfully exploited and infected is system logs and
memory from our FireEye agent along with packet captures of the attack
traffic.  This will allow us to investigate the files that were
downloaded, any new processes or network connections, and the nature of
the data traveling to and from the user's system.

Here's another one, but this time we've
got FireEye agent data.  While Splunk gave us a timeline using proxy
logs, the Triage acquisition performed by the agent that was
pushed to the host provides a system-level view of what happened.

We start with Splunk to show a quick overview of the network traffic:

![](images/Drive%20By%20Downloads/image005.png)


And here is the data acquired by the agent, specifically the
Browser URL History and the File Download History:

![](images/Drive%20By%20Downloads/image006.png)


First the browser is directed to the compromised site from a Google
search:

![](images/Drive%20By%20Downloads/image007.png)


The compromised site redirects the browser to the landing page:

![](images/Drive%20By%20Downloads/image008.png)


The exploit kit checks for files that would indicate a virtual
environment:

![](images/Drive%20By%20Downloads/image009.png)


The exploit kit checks for the presence of files that would indicate
security analysis tools are installed (Fiddler Web Debugger, Wireshark,
and JPEXS Free Flash Decompiler)

![](images/Drive%20By%20Downloads/image010.png)


The exploit kit checks for files indicating the presence of AV products
(BitDefender and ESET NOD32):

![](images/Drive%20By%20Downloads/image011.png)


The flash exploit is delivered to the system:

![](images/Drive%20By%20Downloads/image012.png)


And finally, the payload is delivered:

![](images/Drive%20By%20Downloads/image013.png)


When the payload file was examined, it was discovered to be empty but
packet captures are still needed to confirm it was empty when it was
delivered.

One explanation of an empty payload could be that the landing page had
already been visited by a user with the same external IP address and
the system was served a fake payload.  Many exploit kits are designed to
respond with an empty payload when visited more than once from the same
IP address in order to prevent repeated testing, analysis, and reverse
engineering by security researchers.

Here is a good flow diagram showing the steps conducted by typical
exploit kits, and as you can see the data we acquired shows the exploit
followed this pattern:

![](images/Drive%20By%20Downloads/image014.png)


From:
<http://www.contextis.com/documents/171/Demystifying_the_Exploit_Kit_-_Context_White_Paper.pdf>
