# Improved Detections with YARA Rules

Knowledge of adversary actions improves detection, response, and
planning.  Better detection, response, and planning improves our overall
security posture.

This is simply applying the traditional intelligence cycle---using
information collection and analysis to provide guidance for
decisions---to enterprise security.  Monitoring the network and
investigating incidents give us many opportunities to obtain
intelligence, which in turn provides us with information necessary to
accomplish our mission.  The more we learn about how the adversary
operates, the better we will be able to detect and counter them.

This week we'll look at leveraging this knowledge for
detection and how we can create YARA rules that can be
used to search files, pcaps, and memory space for specific adversary
techniques.

## Opportunities

A common scenario...

An adversary has managed to deliver a phishing lure all the way to an
end user inside our network but it is reported as suspicious by either a
security-conscious user or a security tool.  An investigation reaults in a working sample of one of the adversary's finished products---most likely one of many different finished products
used by this particular adversary, but still this is something they've
built (possibly copied/modified), set up infrastructure for, and
deployed with the intent of compromising systems.  

**This is a
high-quality source of intelligence which we can mine for techniques
currently being used in the wild by this adversary and others**

This was the case recently, but the only
indicators resulting from the investigation were IP addresses, domain
names, and file hashes.  To wrap up an investigation with only gaining
a few atomic indicators is a wasted opportunity for both potential
detection improvements and analyst experience.  If the adversary simply
changes one byte in the file and domain name, we\'ve lost everything
we\'ve gained and are essentially back to square one trying to detect
this type of attack on our network.  Also our analysts will not know any
more than they did before regarding the components of the
attack, how to detect it, or how to investigate it should they see it
again in the future.  We need to take advantage of having an actual
sample to analyze and use it to be in a better position to detect
similar attacks throughout our environment. 

Let's walk through it and see what we can find that will help us
improve the way we detect these types of attacks.

## Review

### Summary

- Phishing email containinglink
	- Clicking link downloads `Canada Post Notice Card.doc`
		- Macro in `.doc` executes PowerShell
			- PowerShell command downloads `23.exe`
				- `23.exe` creates processes and imports suspicious APIs

### File Reputation/Analysis

|`23.exe`|
|-|
|[VirusTotal](https://www.virustotal.com/#/file/f25d974f02453a840507463f4011a221abd87b72afb9a147195b8ea3a438847e/details)|
|[Hybrid-Analysis](https://www.hybrid-analysis.com/sample/f25d974f02453a840507463f4011a221abd87b72afb9a147195b8ea3a438847e?environmentId=100)|

|`Canada Post Notice Card.doc`|
|-|
|[VirusTotal](https://www.virustotal.com/#/file/a40cbb5f6916807e435d3d944a3265c02f53d049068fcf2011d10e987bff752f/details)|
|[Hybrid-Analysis](https://www.hybrid-analysis.com/sample/a40cbb5f6916807e435d3d944a3265c02f53d049068fcf2011d10e987bff752f?environmentId=100)|


### Indicators

|Domains|
|-|
|sudebnii-advokat\[d\]ru|
|tehnospas74\[d\]ru|
|tekflagman\[d\]ru|
|telecomserv\[d\]ru|
|telerad\[d\]ru|
|telexon\[d\]ru|

|IP addresses|
|-|
|176.31.22.17|
|89.253.247.44|

|File|Type|Hash Value|
|-|-|-|
|`23.exe`|MD5|b8b032036de65aa404db210752114867|
||SHA-1|702636a0bf329b58ecf933227c793297afe51501|
||Authentihash|702549baae91065690868ca7dfb97e7c2c5864934c79c5106ba61557ea5f10f5|
|`Canada Post Notice Card.doc`|MD5|b5cf5884dc53d7486a3fd7e0308f0dd4|
||SHA-1|3040911d3b3dd7139d40122c67adb6a7c7a5d664|

### Remediation

No callbacks to embedded URL for past 7 days, purge emails, block
request for embedded URL

The phishing email contains a link to a domain hosting a malicious Word
doc.  The Word doc uses PowerShell to download an executable from a
second domain.  When infected, the host beacons to an IP address.  So
now that we have these indicators, what happens if one byte in the file
changes?  Or the domains change?  Or the IPs change?  Then the
indicators that came from this analysis would not do us any good...

The key to creating high-quality detections is to identify and focus on
adversary tradecraft rather than atomic indicators that are easily
changed.  In order to do this, we must go deeper and understand the
techniques being used.  In this example there was no intrusion, but it
is still a great opportunity to perform analysis and identify what the
malware is designed to do and what we need to be prepared to detect. 
How do the delivery, exploit, installation phases of the attack work and
how we can differentiate these events from legitimate events?

Let's see what else we can find...

## Static Analysis

Starting with the Word doc... we know it has a macro so let's analyze it
with `olevba.py`.

`olevba.py` detects several suspicious methods being used for obfuscation:

![](images/Improved%20Detections%20YARA%20rules/image001.png)


Viewing the macro in Word confirms it uses heavy obfuscation to hide its
functionality:

![](images/Improved%20Detections%20YARA%20rules/image002.png)


We could try deobfuscating code, but this could take a while.

Let's go ahead and execute it in a controlled environment to learn about
its functionality.

## Dynamic Analysis

With ProcMon, Wireshark, Network Monitor, and Process Hacker running, we
open the document and enable content.

Process Hacker gives us an initial view of the processes involved:

![](images/Improved%20Detections%20YARA%20rules/image003.png)


We have full transcription logging enabled so we can look at the
PowerShell command the macro ran and see that `23.exe` was renamed to a
random number between 1 and 65,536 (`17244.exe`):

![](images/Improved%20Detections%20YARA%20rules/image004.png)


Network Monitor shows executable `23.exe` is downloaded from one of the
URLs on the list followed by beaconing to IP address 176.31.22\[d\]17:

![](images/Improved%20Detections%20YARA%20rules/image005.png)


The value of the string parameter being passed is Base64-encoded details
of the victim machine, user, AV suite, and other details:

![](images/Improved%20Detections%20YARA%20rules/image006.png)


The commands are not encrypted... this agent is currently being told to
sleep:

![](images/Improved%20Detections%20YARA%20rules/image007.png)


Now we know we most likely have a RAT being controlled over HTTP requests.

Let's take a closer look at the artifacts that were created to gain a
better understanding of the malware.

Filtering ProcMon for "Process Create" events shows `17244.exe` uses
WScript (1368) to run `23.vbs` while a second WScript (3900) runs a second
.vbs file and creates a scheduled task:

![](images/Improved%20Detections%20YARA%20rules/image008.png)


The scheduled task ensures a VBS file is executed at every logon:

![](images/Improved%20Detections%20YARA%20rules/image009.png)


ProcDot shows the WScript.exe process created multiple persistence
methods:

![](images/Improved%20Detections%20YARA%20rules/image010.png)


One of these is a VBScript file created in the Startup folder:

![](images/Improved%20Detections%20YARA%20rules/image011.png)


By logging out and logging back in, we can see multiple WScript
processes calling out to the same C2 IP address: 

![](images/Improved%20Detections%20YARA%20rules/image012.png)


Looking at the command line arguments in Process Hacker shows the
different persistence methods are being used to run the same script:

![](images/Improved%20Detections%20YARA%20rules/image013.png)


Several different VBScript files were created throughout the system, but
hashing them reveals they are all the same file:

![](images/Improved%20Detections%20YARA%20rules/image014.png)


Looking more closely at this file, it is heavily obfuscated:

![](images/Improved%20Detections%20YARA%20rules/image015.png)


### Pivoting to Another Sample

Looking at the C2 site from a non-infected computer, we see a link to
another executable:

![](images/Improved%20Detections%20YARA%20rules/image016.png)


Downloading the EXE as "`9b57.exe`", we can see that it is a different
file than the `23.exe`/`17244.exe`:

![](images/Improved%20Detections%20YARA%20rules/image017.png)


This executable drops a batch file in the temp directory and spawns an
agent which communicates to a domain over HTTPS.

We could continue pivoting and collect even more TTPs, but for this
example let's create detections for what we've gathered so far.

### Summary of Attack

1. The macro in the Word doc uses PowerShell to download `23.exe` into `%TEMP%` and give it a random name

2. Randomly named EXE (`17244.exe`) creates obfuscated VBScript in
    multiple places and executes them with WScript.exe

3. WScript.exe modifies schtasks, registry, and filesystem so the
    obfuscated VBS script runs on logon, startup, etc.

4. VBScript communicates to C2 server over HTTP


## Using Artifacts to Create YARA Rules

YARA reads its rules from top to bottom looking for patterns of ASCII,
Unicode, or Hex in static files, memory space, and network traffic.  We
can use these rules to search large collections of files, packet
captures, or to search systems for files that match its criteria. 

We've got three artifacts we can use to create our YARA rules:

- [Word Doc with Obfuscated Macro](#word-doc-with-obfuscated-macro)
- [Obfuscated VBScript](#obfuscated-vbscript)
- [Randomly-Named EXE](#randomly-named-exe)

As we make these rules, if possible we want to avoid using static
attributes which can be bypassed easily such as:

- Strings
- Compiler artifacts
- Exif data
- Library and API imports


More robust IOCs are created using dynamic attributes such as:

- In-memory strings
- Process handles, mutexes
- Accessed/created files
- Accessed/created registry keys
- Created network traffic


The best detections are based on methodologies such as:

- Obfuscation
- Automatic functions
- String operations
- Variable renaming
- Shell object creation


### Word Doc with Obfuscated Macro

This document uses several techniques to obfuscate its contents.  We can
use signs of these techniques being used to detect related and
suspicious documents.

Here we're searching for strings that indicate suspicious functionality
such as obfuscation, encoding, and shell object creation:

![](images/Improved%20Detections%20YARA%20rules/image018.png)


If a Word document contains several of these strings, it is likely that
it is not legitimate.

Here is a very basic YARA rule that looks for a `.doc` with three of the
four suspicious strings we've identified:

![](images/Improved%20Detections%20YARA%20rules/image019.png)


Yara identifies the magic number (`$mz`) and that at least three
occurrences of the strings are present:

![](images/Improved%20Detections%20YARA%20rules/image020.png)


### Obfuscated VBScript

Although we may not be able to deobfuscate this file entirely, we can
deconstruct it into its basic parts to find unique characteristics.

The script is organized into three main sections:

1. `a = "~033_019~031_008....`

2. `q = strreverse(")601-802(rhc+)302-803(rhc+)89-031(rhc+)331-332(rhc+)86-871(rhc+)612-713...`

3. `Unescape(Escape(UnEscape(Escape(Unescape(Escape(UnEscape(Escape(Unescape(Escape(UnEscape(Escape(execute(UnEscape(Escape(eval(strreverse(")91-131(rhc+)802-913...`


So the first two sections are variables being declared and the third is nested `escape()` and `unescape()` functions
being used to encode and decode another reversed string.

First we must understand the purpose of the functions:

- Escape() - Return only ASCII characters from a Unicode string
- Unescape() - Return Unicode characters from an escaped ASCII string

There seems to be no legitimate reason why these two functions should
be nested within each other multiple times, so this is a great technique
to build a detection on.

This YARA rule does a case insensitive search for nested `Escape()` and
`Unescape()` functions:

![](images/Improved%20Detections%20YARA%20rules/image021.png)


It finds several occurrences:

![](images/Improved%20Detections%20YARA%20rules/image022.png)


### Randomly-Named EXE

We discovered that the executable creates the `23.vbs` script and executes
it with Wscript.exe.

Pedump, PEStudio, and several other tools identify the executable as a
self-extracting archive (SFX).

Looking at the file in a hex editor reveals the emedded RAR and the
contents of the vbs file are visible:

![](images/Improved%20Detections%20YARA%20rules/image023.png)


Further down we can see the string reversing section of the VBScript:

![](images/Improved%20Detections%20YARA%20rules/image024.png)


We can build a YARA rule that looks for an embedded RAR (magic number in
file body) containing more than 100 "`(rhc+)`" strings that indicate
string reversing:

![](images/Improved%20Detections%20YARA%20rules/image025.png)


These were just a few of many possible rules we could make based on
methodology.  The randomly named executable files, the specific registry
keys touched, and the unique network traffic are other ways we can
search to identify adversary techniques across the enterprise.

## Summary

The capabilities and tactics being used by attackers are changing every
day---we must address threats in a way that will be effective in
numerous attack scenarios with completely different objectives.  TTPs or
methodology detections do this by taking into consideration the
identity, tactics, and techniques of the adversary---things that they do
not often change or are very difficult to change.  To create these we
need to perform complete analysis on all samples obtained to understand
the underlying techniques and how they can be detected in our
environment.
