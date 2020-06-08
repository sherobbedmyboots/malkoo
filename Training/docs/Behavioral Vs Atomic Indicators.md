# Behavioral Vs Atomic Indicators

Knowledge of adversary actions is the basis of all threat intelligence.  As
defenders, we gather different pieces of information and attempt to
identify relationships and correlations as we try to build a complete
picture of adversary operations.

The majority of this knowledge comes from incident response and intrusion
analysis in the form of indicators.  Indicators can be leveraged for decision
advantages--to predict attacks and determine how, why, and when they are most
likely to occur.

This training document will review the different types of indicators and what
is needed to use them for their maximum benefit:

- [Definitions](#definitions)
	- [Indicators](#indicators)
	- [Context](#context)
	- [TIPs](#tips)
	- [Models](#models)
	- [Cycles](#cycles)
- [Use Of Indicators By Phase](#use-of-indicators-by-phase)
	- [Monitoring and Hunting](#monitoring-and-hunting)
	- [Triage](#triage)
	- [Incident Response](#incident-response)
	- [Threat Research](#threat-research)
	- [Operationalize Intelligence](#operationalize-intelligence)
	- [Disseminate Intelligence](#disseminate-intelligence)
- [Summary](#summary)

<br>

## Definitions

- [Indicators](#indicators)
- [Context](#context)
- [TIPs](#tips)
- [Models](#models)
- [Cycles](#cycles)

### Indicators

Indicators are unique pieces of information that have some type of
intelligence value.  Their presence could *indicate* the **possibility** of a
compromise or attack.  Depending on how they are used, they have the ability to
either enhance or impede incident detection, analysis, and response.

Indicators can be [Tactics](https://attack.mitre.org/tactics/enterprise/), [Techniques](https://attack.mitre.org/techniques/enterprise/), and Procedures (TTPs), tools, artifacts, or atomic indicators:

|Indicator|Description|Example|
|-|-|-|
|Tactics|The art or skill of employing available means to accomplish an end|Discovery, Execution, Command and Control|
|Techniques|The unique ways or methods used to perform functions|Pass the Hash, Pass the Ticket, Remote File Copy|
|Procedures|A series of actions done in a specific order|Search for user accounts with SPNs, Request a service ticket, Crack the ticket, Log in with password|
|Tools|The tools used to complete an objective|PSExec, Nmap, WCE, DNScat, Sdelete, etc.|
|Host & Network Artifacts|Artifacts created by tools and TTPs used|Network traffic, log events, registry entries|
|Atomic Indicators|Strings of data and metadata|IP addresses, domain names, hashes, email addresses |

<br>

[This diagram](http://ryanstillions.blogspot.com/2014/04/on-ttps.html)
is similar to the first and shows how each type fits into the big
picture:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image002.jpg)<br><br>

This diagram called the [Pyramid of
Pain](http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) shows common indicator types and the relative "pain level" for
adversaries when defenders deny the use of each one:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image001.png)<br><br>

As you can see, atomic indicators are the least painful for adversaries to bypass
because they can easily be changed.  These are also one of the biggest causes of
false positives since they have no context.  

Here are the most common categories of atomic indicators and an example of each:

|Category|Example|
|-|-|
|Address|`10.0.0.1`|
|EmailAddress|`emailaddress@gmail.com`|
|File|`b7c380f0c33143d5042b699c0e2710a5`|
|Host|`www.google.com`|
|URL|`https://www.google.com:443/?gws_rd=ssl`|
|ASN|`15169`|
|CIDR|`10.0.0.0/8`|
|Mutex|`\Sessions\1\BaseNamedObjects\53c044b1f7ebc1cbf2bff088c95b30`|
|RegistryKey|`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`|
|UserAgent|`Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/55555 Firefox/53.0`|

<br>

Indicators, also referred to as Indicators of Compromise (IOCs), by themselves
aren't very reliable.  For example, here's three different web requests made
from my machine which use a different external IP address each time:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image018.png)<br><br>

Even changing to a different infrastructures is easily done using cloud platforms:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image058.png)<br><br>

Generally when we are researching indicators, we are trying to "move up" the
Pyramid of Pain to gather higher-quality information and a better
overview of the threat.

However, atomic indicators can valuable if used correctly... with context.

### Context

To have value, an indicator must indicate something---an attack technique, a
compromised system, a specific actor, a specific family of malware, etc.  

For example, an IP address can be used to indicate either a suspected
compromised website, an exploit kit landing page, a C2 node, or a data
exfil endpoint... we need to know which one it is to maximize its value.

This search shows the different types of indicators we receive from FireEye
Isight:

```python
index=isight sourcetype=isight_iocs
| eval type=case(
    md5!="null" OR sha256!="null" OR sha1!="null" OR fileName!="null","File",
    senderAddress!="null" OR registrantEmail!="null",EmailAddress,
    asn!="null","ASN",
    url!="null","URL",
    domain!="null","Host",
    ip!="null","Address",
    1=1,"none")
| stats count by type | sort -count
```

<br>

Each one has contextual information such as an indicator type, a publish
date, associated malware families, and links to relevant blogs or reports:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image016.png)<br><br>

Context can also be a threat rating, a confidence rating, the source of the indicator
or other various attributes as seen in [ThreatConnect](https://threatconnect.com/):

![](images/Behavioral%20Vs%20Atomic%20Indicators/image017.png)<br><br>

Once we have indicators with context, we can use them for monitoring and hunting
within our network.  But we also need a way to store and share them...

### TIPs

A Threat Intelligence Platform (TIP) uses crowdsourcing to allow you to:
- discover more than you could on your own
- align overall security efforts to real threats
- prioritize defenses around most-targeted assets

TIPs like the following allow you to search, organize, and share indicators
associated with specific malware, actors, and incidents:

- [FireEye Isight](https://intelligence.fireeye.com)
- [ThreatConnect](https://app.threatconnect.com/)
- [ScoutVision](https://lgss.lgscout.com/)
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/new)
- [AlienVault OTX](https://otx.alienvault.com/browse/pulses/)
- [Blueliv Threat Exchange Network](https://community.blueliv.com/#!/discover)

<br>




A great source of indicators is [FireEye Isight](https://intelligence.fireeye.com),
but we can also use open source TIPs to *pivot* and discover large amounts of "related" indicators.
Keep in mind though, these indicators are only pieces of information that require
proper *link analysis*.

**Pivoting** describes the process of using the knowledge obtained during an
investigation to discover related information.  

**Link analysis** is the
process of analyzing relationships between these pieces of information.

We use them together to determine what is actually relevant to our investigation
and what will provide a better understanding of attacks, intrusions, and
adversary tradecraft.

The idea is to keep enhancing the value of indicators and understand why
their presence in an alert, signature, or search results would have
significance regarding your investigation.

How do we do this?

### Models

There are two primary models used to identify relationships and discover
related indicators:

- [Diamond Model](#diamond-model) great for IR and Triage
- [Kill Chain](#kill-chain) great for Intrusion Analysis

#### Diamond Model

The [Diamond Model](http://www.activeresponse.org/the-diamond-model/) helps
identify related indicators during Incident Response. Using its
four elements (Adversary, Capability, Infrastructure, and Victim),
analysts can pivot to discover related evidence which helps correlate
and piece together data across intrusions.

![](images/Behavioral%20Vs%20Atomic%20Indicators/image003.png)<br><br>

|Element|Description|
|-|-|
|[Adversary]()|Actor/organization responsible, malware author/operator, intruder, etc|
|[Capability]()|Tools, techniques used, exploits, malware samples, C2|
|[Infrastructure]()|Structures used to deliver capability, domains, IPs, email addresses, proxies|
|[Victim]()|Target of the attack/capability|

<br>

Here's a quick example:

> Mgmt reports host `192.168.2[.]177` is beaconing to a known malicious IP address `35.163.126[.]190`

The indicator we've been provided is a C2 IP address, so
we know we can search with it across our proxy logs to identify other
systems that may be reporting to this same IP address.

<br>

> You investigate and discover that a second victim, `192.168.2[.]20` is also beaconing to the same IP address.

We just used the C2 IP address ([Infrastructure]()) to identify an additional
victim ([Victim]()).

<br>

> You discover a backdoor trojan on this second victim with MD5 hash `b7c380f0c33143d5042b699c0e2710a5`

This would be an example of pivoting from the victim ([Victim]()) to a
malicious file used ([Capability]()).

<br>

Each pivot gives us a new indicator and we want to try to get indicators
from each category as we go... but we need context for these indicators.

Was this the file that was downloaded by the victim ([Delivery]()), was it a
file designed to exploit a program on the user's system ([Exploit]()), or
was it being used for persistence ([Installation]())?

#### Kill Chain

During intrusion analysis, the [Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) Model allows us to provide
context regarding adversary phase:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image019.png)<br><br>

|Phase|Description|
|-|-|
|Reconnaissance|Researching the target, scanning, passive recon|
|Weaponization|Preparing a tool for use in intrusion, exploit in PDF, phishing site|
|Delivery|Threat delivers capability to target environment, email with malicious PDF|
|Exploit|Vulnerability or functionality exploited to gather data/gain access|
|Installation|Functionality is modified or installed to maintain persistence|
|Command & Control|Enables threat to interact with target environment|
|Actions on Objectives|Threat works toward its desired goal, exfil, monitoring|

<br>

Continuing with our example:

> The original IP address provided is being used to control the victims

You can associate this address with the [Command & Control]() phase.  Any host
communicating with it is likely already compromised.

> You discover the trojan was downloaded from `googlmail[.]net`

Here, the origin of the file was tracked back to a domain and can be associated
with the [Delivery]() phase.  Hosts communicating to it are likely
downloading and running the trojan.

<br>

> You determine the IP address that this domain is being hosted on is `210.9.33[.]28`

This is the address hosting the domain and so it can also be associated with
the [Delivery]() phase.  The adversary may be hosting additional domains at
that same address.

<br>

Now, however you've chosen to organize your indicators ([threat_note](https://github.com/defpoint/threat_note) is used here), they each have important contextual information included:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image020.png)<br><br>

### Cycles

We are continually gathering, using, and sharing indicators to anticipate and
predict adversary operations.  One of the best ways to do this is with the [Intelligence-driven Incident
Response](https://medium.com/@sroberts/intelligence-concepts-f3ead-964a0653be13)
cycle which applies the traditional intelligence cycle---using information
collection and analysis to provide guidance for decisions---to enterprise security.

![](images/Behavioral%20Vs%20Atomic%20Indicators/image069.png)<br><br>

In the F3EAD process, **Operations** directs the **Intelligence** effort which
in turn provides **Operations** with information necessary for improving network
defenses for future attacks.  The goal for defenders is to use this process to
plan and execute operations against the adversary faster than the adversary can
react:

|Phase|Description|
|-|-|
|[Monitoring and Hunting](#monitoring-and-hunting)|Evaluate the environment for the presence of attacker activity or compromise.  Monitor and search for unusual configurations, baseline variations, behavioral TTPs, and indicators with the goal of discovering malicious activity. Detect using alerts, analytics, endpoint interrogation|
|[Triage](#triage)|Responding to suspicious events, determining if a security incident took place, and deciding the required response actions and priority for each system involved based on the severity of compromise. Make decisions on prioritization, remediation, countermeasures|
|[Incident Response](#incident-response)|Investigating, containing, and resolving security incidents while minimizing loss and destruction. Scope incidents, contain and eradicate threats|
|[Threat Research](#threat-research)|Collect and evaluate data from past incidents, known adversary malware and TTPs, offensive tools and exploits, and technical reports that can be used to prevent and detect adversary operations.<br>Perform malware and intrusion analysis, reverse binaries/scripts and malicious infrastructure, assess and predict malware capabilities<br>Profile the static and behavioral characteristics of malware and malicious infrastructure. Obtain data from artifacts and adversary tradecraft for intelligence purposes|
|[Operationalize Intelligence](#operationalize-intelligence)|Organize data and develop into intelligence that can be leveraged for decision advantages.  Build detections, mitigations, and remedial actions to prepare for similar attacks and predict how, why, and when they are most likely to occur. Produce actionable intelligence for decision advantage|
|[Disseminate Intelligence](#disseminate-intelligence)|Disseminating knowledge of adversary capabilities, infrastructure, motives, goals, and resources in useful formats to provide a more focused approach for defense. Feed intelligence to partners, analysts, tools, processes|

<br>

Let's look at each of these cycles in the context of an incident.

## Use Of Indicators By Phase

Each cycle allows us opportunities to obtain intelligence, which in turn
provides us with information necessary to accomplish our mission.  We'll walk through each phase using a phishing incident as an example scenario:

- [Monitoring and Hunting](#monitoring-and-hunting)
- [Triage](#triage)
- [Incident Response](#incident-response)
- [Threat Research](#threat-research)
- [Operationalize Intelligence](#operationalize-intelligence)
- [Disseminate Intelligence](#disseminate-intelligence)

## Monitoring and Hunting

We'll start in the **Find** phase where we are monitoring the systems and networks
under our responsibility using our tools.  In our example, our tools are configured with the following atomic indicators to detect a malicious Word document which
could potentially reach our users.

|Indicator|Type|
|-|-|
|`sudebnii-advokat[.]ru`|Host|
|`89.253.247[.]44`|Address|
|`3.19.114[.]185`|Address|
|`b5cf5884dc53d7486a3fd7e0308f0dd4`|File|

<br>

FireEye HX is equipped with [Isight](https://intelligence.fireeye.com) data and can alert on network traffic to
these endpoints or the presence of these files on a system:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image007.png)<br><br>

Splunk is also ingesting [Isight](https://intelligence.fireeye.com) data and can be configured to alert on any
log events containing the indicators:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image006.png)<br><br>

Let's quickly look at two scenarios that illustrate the caution that is required
when monitoring and hunting with atomic indicators:

- [DNS Prefetching](#dns-prefetching)
- [String Hunting](#string-hunting)

### DNS Prefetching

DNS Prefetching is a browser feature that resolves domain names of hyperlinks
on web pages before they are clicked to prevent delays due to DNS resolution
time.  

These DNS requests are normal queries logged by Infoblox and searchable
in Splunk.  The only difference is that the domains queried are **not visited** by
the user.

Suspicious site `taurancoci.mylftv[.]com` triggers an alert:

![](images/DNS%20Prefetching%20and%20Suspicious%20Sites/image001.png)<br><br>

But did the user actually make a web request to the website?

![](images/DNS%20Prefetching%20and%20Suspicious%20Sites/image002.png)<br><br>

Next check sites that were visited seconds before the query:

![](images/DNS%20Prefetching%20and%20Suspicious%20Sites/image004.png)<br><br>

Find the domain that contained the link in its content:

![](images/DNS%20Prefetching%20and%20Suspicious%20Sites/image006.png)<br><br>

Visiting the site reveals that it was a comment posted to the page that
contained a link to the suspicious site:

![](images/DNS%20Prefetching%20and%20Suspicious%20Sites/image007.png)<br><br>

So we would most likely want to adjust the alert to exclude DNS queries for a
malicious site that are not accompanied by web traffic to the site.

### String Hunting

This [ProofPoint](https://www.proofpoint.com/us/threat-insight/post/operation-rat-cook-chinese-apt-actors-use-fake-game-thrones-leaks-lures) article has some great information that could be used to detect a APT29 RAT
that was being delivered via a malicious phishing document back in 2017:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image046.png)<br><br>

Reading this article without understanding the important components of the attack
might lead you to perform a search like this which is a great example of
"string hunting":

![](images/Behavioral%20Vs%20Atomic%20Indicators/image049.jpg)<br><br>

Filenames and variations of filenames are weak indicators and rarely result in actual
detections.  This is why we avoid hunting with atomic indicators such as IP addresses,
domain names, file hashes, etc.  

They can be easily changed, they produce massive
amounts of false positives, and they require much, much more context to produce a
true positive.  

Also, we already have specialized security tools designed to look for
suspicious strings/hashes/IPs and they are far better at it than we are.  

Instead, we primarily hunt using TTPs which are designed to detect techniques
even if atomic indicators change. These are more challenging to create and require
understanding the lifecycle of the attack, but generate significantly fewer false
positives.

They also detect any use of the technique, not just use by a specific
actor, group, or campaign.  For example, the same article shows the PowerShell
command the `.lnk` file uses to download the 9002 RAT shellcode:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image047.png)<br><br>

Searching for this technique results in an actual successful attack that the NCATS
pentesting team used to download a RAT and compromise one of our servers:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image048.png)<br><br>

This is what makes TTP searching superior—no matter who the actor is, what the
filename is, or where its being downloaded from—the use of this particular
technique is a strong indication of malicious activity.

<br>

Let's continue our scenario in which we get an alert for a system that has
been observed communicating with the address `89.253.247[.]44`.  We'll now
move on to the Fix phase, or Triage.

## Triage

IR triage is the process of responding to suspicious events, determining if a security incident took place, and deciding the required response actions and priority for each system involved based on the severity of compromise. It starts with a detection from monitoring/hunting and ends with a clear picture of the incident, the systems involved, and a plan to stop the progress of the attack.

|Step|Description|
|-|-|
|[Initial Assessment](#initial-assessment)|Form theories that would explain the indications that caused the detection|
|[Gather Information](#gather-information)|Gather historical and contextual evidence and artifacts that support or disprove theories|
|[Perform Analysis](#perform-analysis)|Use artifacts to establish facts, answer key questions, and provide analysis|
|[Report Findings](#report-findings)|Provide accurate, actionable information to management so they can make time-sensitive decisions to defend systems|

<br>

In the event of an alert, we will need to investigate systems involved, determine
if a security incident took place, and gather information to support decision-
making for prioritization, remediation, and countermeasures.

- [Automated Analysis](#automated-analysis)
- [Manual Analysis](#manual-analysis)
- [OSINT Pivoting](#osint-pivoting)

### Automated Analysis

If you have the sample, you can submit to an automated sandbox to scan for
common characteristics and techniques.  One of the best is [AnyRun](https://app.any.run/)
which provides important information right away, such as the process chain this sample initiates:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image009.png)<br><br>

The Word document starts `powershell.exe` which downloads an executable.  The
executable spawns `Wscript.exe` to run the `23.vbs` script.  This script creates
 another `vbs` script that creates a scheduled task named `ChromeUpdate` to run
 on logon.

 There are two HTTP connections observed---one from `powershell.exe` and one
 from `Wscript.exe`:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image010.png)<br><br>

We can see `powershell.exe` downloaded the executable from the `tek-flagman[.]ru`
domain hosted at `92.53.114[.]245`:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image011.png)<br><br>

It reports extracted indicators:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image012.png)<br><br>

As well as observed behaviors that seem suspicious:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image013.png)<br><br>


### Manual Analysis

Thorough manual analysis will provide key information on what the malware is
designed to do which will improve our ability to differentiate between
malicious events and legitimate events.

Viewing the macro in Word confirms it uses heavy obfuscation to hide its
functionality:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image015.png)<br><br>

We can quickly analyze it with `olevba.py` which detects
several suspicious methods being used for obfuscation:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image064.png)<br><br>

There are several good options to look at the code including `--reveal` and
`--deobf` but the main objective is to find the part of the code that
interacts with the operating system:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image065.png)<br><br>

One way to reveal the obfuscated command is to replace the `Shell` method
with one that prints such as `Debug.print`.

Here is the original code:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image061.png)<br><br>

Here is the new code which will print out the command after it's been
deobfuscated:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image062.png)<br><br>

Save the changes, close and reopen the document and run the macro.  By using
`Ctrl-g` we can see what was printed, i.e. what was *intended* to be
passed to the shell for execution.  Cut and paste into a text editor like
Sublime and format for easier reading:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image063.png)<br><br>

We can also execute it in a controlled environment and observe
its interactions with network, files, processes, registry.

With [ProcMon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon),
[Wireshark](https://www.wireshark.org/),
[Network Monitor](https://blogs.technet.microsoft.com/netmon/p/downloads/), and
[Process Hacker](https://github.com/processhacker/processhacker)
running, open the document and enable content.

[Process Hacker](https://github.com/processhacker/processhacker) gives us an initial view of the processes involved:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image023.png)<br><br>

We have full transcription logging enabled so we can look at the
PowerShell command the macro ran and see that `23.exe` was renamed to a
random number between 1 and 65,536 (`17244.exe`):

![](images/Behavioral%20Vs%20Atomic%20Indicators/image024.png)<br><br>

[Network Monitor](https://blogs.technet.microsoft.com/netmon/p/downloads/) shows executable `23.exe` is downloaded from one of the
URLs on the list followed by beaconing to IP address `176.31.22[.]17`:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image025.png)<br><br>

The value of the string parameter being passed is Base64-encoded details
of the victim machine, user, AV suite, and other details:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image026.png)<br><br>

The commands are not encrypted... this agent is currently being told to
sleep:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image027.png)<br><br>

This is an implant or RAT which is allowing the adversary to control the
victim host via HTTP requests.

The scheduled task ensures a VBS file is executed at every logon:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image029.png)<br><br>

[ProcDot](https://www.procdot.com/) shows the `WScript.exe` process created multiple persistence
methods:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image030.png)<br><br>

One of these is a VBScript file created in the Startup folder:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image031.png)<br><br>

By logging out and logging back in, we can see multiple `WScript`
processes calling out to the same C2 IP address:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image032.png)<br><br>

Looking at the command line arguments in [Process Hacker](https://github.com/processhacker/processhacker) shows the
different persistence methods are being used to run the same script:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image033.png)<br><br>

Several different VBScript files were created throughout the system, but
hashing them reveals they are all the same file:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image034.png)<br><br>

Looking more closely at this file, it is heavily obfuscated:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image035.png)<br><br>

Looking at the C2 site from a non-infected computer, we see a link to
another executable:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image036.png)<br><br>

Downloading the EXE as "`9b57.exe`", we can see that it is a different
file than the `23.exe`/`17244.exe`:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image037.png)<br><br>

This executable drops a batch file in the temp directory and spawns an
agent which communicates to a domain over HTTPS.  Since we are in triage, we
won't perform analysis on this new sample yet.

The focus of this stage is to gather the information required to perform
incident response.  After automated and manual analysis, we now have a better
understanding of the attack:

1. The macro in the Word doc uses PowerShell to download `23.exe` into `%TEMP%`
and give it a random name

2. Randomly named EXE (`17244.exe`) creates obfuscated VBScript in
    multiple places and executes them with `WScript.exe`

3. The VBScript modifies schtasks, registry, and filesystem so the obfuscated
		VBS script runs on logon, startup, etc.

4. The `.vbs` file running in the `Wscript.exe` process communicates to
the C2 server over HTTP

<br>

Let's look at the different types of indicators we have at this point:

|Atomic|Behavioral|
|-|-|
|`sudebnii-advokat[.]ru`|Delivery domain|
|`89.253.247[.]44`|Delivery IP address|
|`3.19.114[.]185`|C2 IP address|
|`b5cf5884dc53d7486a3fd7e0308f0dd4`|`Word.exe` spawns PowerShell cradle|
|`b8b032036de65aa404db210752114867`|`23.exe` creates and runs VBScript|
|`86950b51e0816aac50389cb00ddd52c1`|`9b57.exe` establishes C2 over HTTPS|
|`tehnospas74[.]ru`<br>`tek-flagman[.]ru`<br>`telecomserv[.]ru`<br>`telerad[.]ru`<br>`telexon[.]ru`|PowerShell downloads and executes EXE|
|`23.exe`|EXE runs out of `%TEMP%` folder|
|`23.vbs`|`WScript.exe` creates scheduled tasks/registry keys|
|`176.31.22[.]17`|`WScript.exe` makes HTTP requests|
|`yaded[.]ru`|Downloads EXE over HTTP|

<br>

### OSINT Pivoting

Many attacks you will see have already been written about or encountered before by numerous individuals. Even if we have no sample and no access to the system, Commercial and open-source feeds, platforms, reports, and tools can allow us to gather valuable information using OSINT Pivoting:

- [Common Opportunities to Pivot](#common-opportunities-to-pivot)
- [Manual Pivoting and Link Analysis](#manual-pivoting-and-link-analysis)
- [Pivoting and Visualization with Maltego](#pivoting-and-visualization-with-maltego)

#### Common Opportunities to Pivot

Use the Diamond Model to identify new information about infrastructure,
capabilities, victims, and adversaries.  

Here are some common questions about **infrastructure** we need to answer in many investigations:

- When was the domain registered?
- What email address was used to register it?
- What other domains did this email address register?
- Has the domain been associated with a known incident, campaign, or threat actor?
- What subdomains does the domain have?
- What IPs hosted the domain after it was registered by adversary?
- Which of those IPs are most likely dedicated to the adversary?
- What other domains were hosted on the same IP at same time as initial domain?
- What email addresses were used to register these domains?
- Was the malware using a TLS certificate?
- How many other IPs have been seen using that certificate?
- What time was the certificate seen on the suspect IP address?
- What were the expiration dates of the certificate, not before, not after, etc.?
- Were the certificates self-signed, free (Let’s Encrypt, WooSign), or paid?

<br>

And **capabilities**:

- What domains and IPs was the samples associated with?
- When were they observed there?
- What URLs did the samples use?
- What filenames did the samples have?
- Were the samples associated with a TLS/SSL certificate?
- Were the samples observed using a mutex?
- Was the sample associated with an email address?
- Has the sample been associated with a known incident, campaign, or threat actor?

<br>

When queries or analysis provides us these answers, we need to consider
the source, the technique used to obtain it, and how it can help our
investigation.

**Maintain Context**

While pivoting and discovering new relationships, keep in mind some of
the following scenarios regarding context:

- Malicious domains and IPs frequently get taken over and pointed to a
    sinkhole.  Although OSINT tools may report relationships between
    this data point and others, the infrastructure hosting the sinkhole
    and the other "related" domains pointing to the same sinkhole are
    not relevant to our investigation

- IP addresses belonging to VPNs and VPSs are constantly being shared
    by millions of different users every day.  Attempting to pivot to
    samples or infrastructure "related" to one of these IPs will almost
    always be a waste of time

- IP addresses that belong to hosting services and reverse proxies are
    a similar problem---multiple tools will find relationships between
    an IP and the thousands of domains it is hosting, but these are not
    the types of pivots that will lead to related infrastructure and
    samples

- Third party domain registrars like GoDaddy, Hover, and DreamHost
    manage reservations of domain names for many different users.  If
    the adversary uses one of these services, we cannot pivot to other
    users of the service or other domain names registered using the
    service as they are in no way related to our investigation

- If Dynamic DNS is being used and a domain is pointing at multiple
    different IP addresses in a short period of time, pivoting on the IP
    addresses won't give us the information we're after.  Also, the
    registrant information will belong to the DDNS providers

- Compromised legitimate sites being used for Delivery, C2, and Exfil
    will also have registrant information that is not related to the
    adversary

- Information discovered about IPs and domains that were determined to
    be malicious in the past may not hold true today.  Some
    infrastructures change owners/operators frequently which means we
    must understand the historical context of the information we find

### Manual Pivoting and Link Analysis

WHOIS and passive DNS data are two valuable resources to use while
pivoting for indicators.  A number of different sites and tools use this
data---here are a few screenshots of different tools providing different
indicators:

[ThreatCrowd](https://www.threatcrowd.org/) shows our domain resolves to an IP:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image051.png)<br><br>

[PassiveTotal](https://passivetotal.org/)'s Resolutions tab shows a good
timeline of the IP addresses that have hosted a domain:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image050.png)<br><br>

Keep in mind, some of these sites have outdated information.  It's best not to
rely completely on OSINT aggregating tools.

Try to resolve the domain from a non-CIS host or online DNS utility:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image052.png)<br><br>

Turns out [DomainTools](http://whois.domaintools.com/sudebnii-advokat.ru) shows
this domain is currently for sale:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image053.png)<br><br>

[Censys](https://censys.io/) is a great tool for searching certificate information
and website co

![](images/Behavioral%20Vs%20Atomic%20Indicators/image055.png)<br><br>

When services are observed on the target they are shown:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image056.png)<br><br>

It also provides the content being hosted on each service:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image057.png)<br><br>

[ThreatConnect](https://www.threatconnect.com/) has a great pivot dashboard
which makes it easy to choose the site based on the indicator type:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image066.png)<br><br>

At the time of this analysis, there were two different domains hosted at the same
IP address (`lemanva[.]gdn` and `manrovm[.]gdn`).  

Here is our current list of **atomic indicators** after Triage:

|Indicator|Type|Phase|
|-|-|-|
|`sudebnii-advokat[.]ru`|Host|Delivery|
|`89.253.247[.]44`|Address|Delivery|
|`lemanva[.]gdn`|Host|Delivery|
|`manrovm[.]gdn`|Host|Delivery|
|`b5cf5884dc53d7486a3fd7e0308f0dd4`|File|Delivery|
|`3040911d3b3dd7139d40122c67adb6a7c7a5d664`|File|Delivery|
|`tehnospas74[.]ru`|Host|Exploit|
|`tek-flagman[.]ru`|Host|Exploit|
|`telecomserv[.]ru`|Host|Exploit|
|`telerad[.]ru`|Host|Exploit|
|`telexon[.]ru`|Host|Exploit|
|`176.31.22[.]17`|Address|Command and Control|
|`yaded[.]ru`|Host|Action on Objectives|
|`3.19.114[.]185`|Address|-|

<br>

The IP address `3.19.114[.]185` was included in this scenario because it has
nothing to do with the incident.  You will encounter these frequently and must
learn how to separate indicators that are unrelated or useless for our analysis.

![](images/Behavioral%20Vs%20Atomic%20Indicators/image059.png)<br><br>

There are over 3,000 different domains resolving to this IP address recently, the
ownership, activity, and services hosted appear to be normal and legitimate, and
there are no significant ties to any of our samples, malicious infrastructure,
or victim systems.

## Incident Response

Now, how do we use our indicators while implementing our response?

- [Scoping](#scoping)
- [Containment](#containment)
- [Eradication](#eradication)

### Scoping

A sweep with **atomic indicators** can identify additional victims but will most
likely not provide accurate or complete results.  The following command checks
3 systems for running process named `23` and finds one:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image068.png)<br><br>

The presence of atomic indicators *may* indicate a compromised system.  The
absence of atomic indicators *does not prove* a system is uncompromised.

A sweep with **behavioral indicators** will be much more accurate and successful.  
The following command searches each system for `wscript.exe` processes making
network connections:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image067.png)<br><br>

Scoping must be accurate in order to successfully complete the following step,
Containment.

### Containment

The goal of containment is to limit damage and prevent further damage from
occurring.  This usually entails isolating a system or disconnecting it from
the network.

Containment based on **atomic indicators** may work in some instances but is not
the best way to ensure a host is successfully isolated from malicious hosts and
other victim hosts.

Containment based on **behavioral indicators** fully contains a system.  That's
why FireEye HX blocks all network connections that are not used to manage the
HX agent instead of just blocking connections to a list of domains and IP
addresses.

For malware using the network:

- If the host has an endpoint agent, contain 
- If not, PowerShell can be used to change network settings
- If neither, advise ISSO/request to have port disabled
- If AWS, advise ISSO/request isolation via security group or vpc

For malware causing damage:

- If PowerShell access, kill malicious processes
- If not, advise ISSO/FSE physical access may be required

Once the damage is stopped, eradication begins.

### Eradication

Removing malicious content and restoring systems back into operation, possibly wiping and reimaging.

Eradication based on **atomic indicators** should not be used to declare a system
clean and clear.

Eradication based on  **behavioral indicators** is a much more accurate method
and wiping and reimaging nearly eliminates the possibility of malware surviving.

To perform eradication without a wipe/reimage, we need to identify the
techniques being used for persistence.

First try simply deleting the registry key using `regedit.exe`.  [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
was used to locate the entry and delete it. After a reboot however, the host
still created the malicous processes and connected out to its C2.

But the registry key is just a pointer to the file that starts the two
`svchost` processes, `Notepad.exe`, so let's try moving it out of its
directory.

This resulted in a different file being created in its place... this one
named `Bespin.exe`.  The filename changed, but this is still the same original
file just running under a different name again:

![](images/Developing%20TTP-based%20Responses/image029.png)<br><br>

Now let's try deleting it:

![](images/Developing%20TTP-based%20Responses/image030.png)<br><br>

Several different combinations of `Remove-Item` with the `-force` and `-recurse`
flags were tried and were all unsuccessful.  The account has the required
permissions---full control as a member of the Administrators group, why doesn't
this work?

One thing that could cause this is that another process is currently
using the file.  We can easily find our malicious `svchost` processes by
searching only for the ones that are running under session 1:

![](images/Developing%20TTP-based%20Responses/image031.png)<br><br>

Once we kill these processes, the file can be deleted:

![](images/Developing%20TTP-based%20Responses/image032.png)<br><br>

And when the infected system restarts, we see [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) reports the
`Notepad.exe` was not found:

![](images/Developing%20TTP-based%20Responses/image033.png)<br><br>

Another option that works is changing the registry value to "0"

![](images/Developing%20TTP-based%20Responses/image034.png)<br><br>

A reboot confirms that setting the registry key to "0" destroys the
persistence.

We can't spend days tearing apart the malware, we need to
quickly figure out what is required to completely clean this system and
bring it back into production.

In this case, it would be easier and faster to wipe and reimage and know
for sure that the malware is gone. The samples, artifacts, and analysis would be
passed along to FO for further analysis and research during the Threat
Research phase.

## Threat Research

Malware is a capability used by actors.  The actor is the threat. Adversaries
can change the malware they're using at any time and even succeed without
using malware at all.

Because of this, we need to understand the specific behaviors,
motivations, and objectives of actors.  In this phase we are looking for
tactical advantages which we can obtain by learning and studying how the
adversary behaves.

FO collects and organizes knowledge about the different threats to our
environment, configures our tools to use this knowledge for detection, and then
provides our analysts working an incident with this knowledge so they can
respond with improved speed and accuracy.

We use the following cycle to learn about adversary tradecraft and develop
matching detections and responses:

![](images/Using%20A%20Threat%20Based%20Approach/image001.png)<br><br>

|Phase|Description|
|-|-|
|[Discover and Learn Adversary Tradecraft](#discover-and-learn-adversary-tradecraft)|FO is continually discovering, learning, and testing new tradecraft|
|[Build High-Fidelity Detections](#building-high-fidelity-detections)|Use most effective combinations of detection types to build actionable and universal detections|
|[Provide Context and Next Actions](#provide-context-and-next-actions)|Provide required knowledge, tools, and response actions to the analyst|

<br>

Outlined in blue is the part of the process where we learn about techniques
used against us, techniques being used out in the wild that could be used
against us, and what it looks like when the techniques are used in our
environment.  

In orange is where we develop the capability to reliably detect these
techniques being used in our environment.  

In green is where we package all the results of our research and testing so it
can be delivered to the analyst that's working an incident.  

As more incidents are worked and resolved, the cycle repeats itself.

- [Automated Analysis](#automated-analysis)
- [Static Analysis](#static-analysis)
- [Dynamic Analysis](#dynamic-analysis)
- [Memory Analysis](#memory-analysis)
- [Threat Research Summary](#threat-research-summary)

<br>

Remember we discovered a link to what looks like a second stage payload
being hosted on the C2 page:

![](images/Developing%20TTP-based%20Responses/image001.png)<br><br>

Checking again a few days later, there is a new link to another exe:

![](images/Developing%20TTP-based%20Responses/image002.png)<br><br>

Let's look at both files using automated analysis and see what we can
find:

### Automated Analysis

|||
|-|-|
|`9b57.exe`|[9b57071cb66366b192d3abb3710c0ea3841baae1.exe](https://www.hybrid-analysis.com/sample/c7ef5921984770ef607bb8b3893858bad3252834296718e4d42295a9003b8666?environmentId=100)|
|`1fug.exe`|[1fugauqzeihgaxidua.exe](https://www.hybrid-analysis.com/sample/59b2cb2f919c668ac402a42bfbd684c3282740ca7a4416274d75f4f9ca99475c?environmentId=100)|

Right away we see that they are very similar in how they execute.

Both use cmd.exe to execute a Batch file located in the `%TEMP%`
directory.

![](images/Developing%20TTP-based%20Responses/image003.png)<br><br>

![](images/Developing%20TTP-based%20Responses/image004.png)<br><br>

Notice how the old one `9b57.exe` is already identified by AV engines,
but the most recent one `1fug.exe` is not identified by any yet.

This is why these files are regularly modified, to stay ahead of AV
engine detection by hash, filename, etc.

The .bat files are exactly the same size:

![](images/Developing%20TTP-based%20Responses/image005.jpg)

![](images/Developing%20TTP-based%20Responses/image006.jpg)<br><br>

And appear to have the same functionality, to delete the original
executable and itself.

(The original executable was named after its SHA256 value and executed
in the `C:\` directory by the sandbox)

![](images/Developing%20TTP-based%20Responses/image007.png)<br><br>

They also create the same mutant:

![](images/Developing%20TTP-based%20Responses/image008.png)

![](images/Developing%20TTP-based%20Responses/image009.png)<br><br>

There are a few differences between the two... `9b57.exe` generates some
network activity while `1fug.exe` doesn't:

![](images/Developing%20TTP-based%20Responses/image010.png)<br><br>

These IPs both belong to Google so there is not much value in pivoting
on these. We have some good context now that will help us doing static and dynamic
analysis.

### Static Analysis

[Pescanner](https://github.com/hiddenillusion/AnalyzePE/blob/master/pescanner.py) shows both files contain multiple suspicious libraries:

```
GetTickCount
Sleep
IsDebuggerPresent
OutputDebugStringA
GetProcAddress
ShellExecuteExA
LoadLibraryA
```

Here we see a few significant differences between the files...

`9b57.exe` uses the NSIS installer commonly used by Ransomware to avoid
detection described
[here](https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-families-use-nsis-installers-to-avoid-detection-analysis/):

![](images/Developing%20TTP-based%20Responses/image011.png)<br><br>

Besides what we've found, not much additional functionality can be
identified based on the strings contained in the two files.  Let's run the
first sample in a lab environment.

### Dynamic Analysis

After setting up some interactive analysis tools, the first sample
`9b57.exe` is executed on the Desktop.

[RegShot](https://sourceforge.net/p/regshot/wiki/Home/) sees the same two
files we saw in the sandbox report get added and the original sample get deleted:

![](images/Developing%20TTP-based%20Responses/image012.png)

![](images/Developing%20TTP-based%20Responses/image013.png)<br><br>

About 5 minutes later, [Fiddler]() shows a `svchost` process sending HTTPS
traffic to two suspicious domains not provided by our automated
analysis:

![](images/Developing%20TTP-based%20Responses/image014.png)<br><br>

[Process Hacker](https://github.com/processhacker/processhacker) shows strings in memory that appear to be our C2 traffic:

![](images/Developing%20TTP-based%20Responses/image015.png)<br><br>

Allowing the infected system to connect to its C2 confirms the `svchost`
process is being used to download what looks like encrypted commands and
files:

![](images/Developing%20TTP-based%20Responses/image016.png)<br><br>

Notice the HTTP traffic to Google... this explains what we saw in the
sandbox report. The infection persists even after restarting the machine.

Looking at the event logs, we can identify the process timeline of both
infection and persistence:

For **Installation**, `Notepad.exe` is created, creates a copy of itself which then creates two `svchost` processes.  Later, the `cmd.exe` process is called to execute the `.bat` file:

- `9b57.exe`
    - `C:\Users\kbota\Appdata\Roaming\Notepad++\plugins\Notepad.exe`
        - `C:\Users\kbota\Appdata\Roaming\Notepad++\plugins\Notepad.exe`
            - `C:\Windows\SysWOW64\svchost.exe`
            - `C:\Windows\SysWOW64\svchost.exe`
    - `C:\Windows\SysWOW64\cmd.exe`

The `Notepad.exe` is the original file renamed:
                              
![](images/Developing%20TTP-based%20Responses/image017.png)<br><br>

For **Persistence**, `explorer` executes the `Notepad.exe` which creates a copy of itself and starts two `svchost` processes.  One of the svchost processes creates the `updd2c0ce2b.exe` process:

- `Explorer.exe`
    - `C:\Users\kbota\Appdata\Roaming\Notepad++\plugins\Notepad.exe`
        - `C:\Users\kbota\Appdata\Roaming\Notepad++\plugins\Notepad.exe`
            - `C:\Windows\SysWOW64\svchost.exe`
                - `C:\Users\kbota\AppData\Local\Temp\updd2c0ce2b.exe`
            - `C:\Windows\SysWOW64\svchost.exe`

This new executable is located in the `%TEMP%` directory:

![](images/Developing%20TTP-based%20Responses/image018.png)<br><br>

Again, this is just the `9b57.exe` file renamed.

Using [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
from SysInternals, we see an unsigned executable is configured to run on logon:

![](images/Developing%20TTP-based%20Responses/image019.png)<br><br>

### Memory Analysis

We are interested in the Service Hosting Processes (`svchost.exe`) that
are communicating to `manrovm[.]gdn`. Normal `svchost.exe` processes are
created by `services.exe` and run at session 0.

A `pslist` quickly identifies two `svchost.exe` processes that were not
created by `services.exe` and are running at session 1:

![](images/Developing%20TTP-based%20Responses/image020.png)<br><br>

A `pstree` confirms one of the `svchost.exe` processes created the
`updd2c0ce2b.exe` process:

![](images/Developing%20TTP-based%20Responses/image021.png)<br><br>

The parent process with PID 1960 (`0x7a8`) cannot be found but we can look
at our logs to see which process this was:

![](images/Developing%20TTP-based%20Responses/image022.png)<br><br>

Volatility's [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) plugin also finds the persistence:

![](images/Developing%20TTP-based%20Responses/image023.png)<br><br>

The `netscan` plugin shows the connections from the `svchost.exe` (628)
process to the C2 IP address:

![](images/Developing%20TTP-based%20Responses/image024.png)<br><br>

Running `psxview` does not show any indications of hidden processes, so
the malicious code should be in these three processes we've identified.

Dumping executables from process memory with `dlldump` and `malfind` can
be used to obtain artifacts from a memory image when no samples are
available.  

First create a directory and dump each process's listed DLLs into it
with `dlldump`:

![](images/Developing%20TTP-based%20Responses/image025.png)<br><br>

Then dump any hidden DLLs and shellcode to the same directory with
`malfind`:

![](images/Developing%20TTP-based%20Responses/image026.png)<br><br>

### Threat Research Summary

As we've seen in many of our previous exercises, different indicators
are discovered during different phases. The more you understand the actor
and the capabilities used, the more valuable these indicators become.

[Maltego](https://www.paterva.com/) is a tool that can perform pivoting
and link analysis by leveraging the APIs of multiple free and commercial
online investigation tools.

It is also great at giving a visualization of the data points discovered
during an investigation and the relationships between them.  Here's a
picture of what we've learned through triage, OSINT pivoting, and malware
analysis showing the multiple phases of this attack:

![](images/Pivoting%20and%20Link%20Analysis/image010.png)<br><br>

In the next phase, we'll use what we've learned to our advantage.

### Operationalize Intelligence

This is also where we start developing detection content, testing it and tuning
it for use in the next phase.

Everything we learn in the previous stages helps us develop accurate detections
and determine the most effective actions we can take to reduce the overall
impact of incidents involving these techniques.

Passive Total shows both of our newly discovered domains were recently
registered with what looks to be fake information.

The Sample tabs for both domains give us a list of associated sample MD5
hashes with the date they were observed.

![](images/Developing%20TTP-based%20Responses/image035.png)<br><br>

At the time of this writing, `lemanva[.]gdn` was associated with 17
samples and `manrovm[.]gdn` was associated with 3 samples. Just browsing the
file reports on [VirusTotal](https://www.virustotal.com/) and
[Hybrid Analysis](https://www.hybrid-analysis.com/), we were able to
identify some TTPs used by this adversary.

<br>

-------------------------------------------------------------------------------
Out of the 20 samples seen from these domains:

- **11** of them use `cmd.exe` to execute an **11-character BAT file in
    %TEMP% directory** beginning with `upd` delete their executables

- **14** of them are reported as **not having a digital signature**
    (most likely all of them are missing a signature)

From our analysis, we saw that:

- A copy of the original <u>**exe executes in the %TEMP% directory**</u> for
    persistence.

-------------------------------------------------------------------------------

<br>

These are three examples of common TTPs we can use to counter the
majority of malware deployed by this adversary. 

This supports some of the observations we made during automated
analysis, but now we understand how the attack works and can recommend
responses that are more likely to be successful.

For example, a response that prevents the `.bat` file from being created
in a system's `%TEMP%` folder won't necessarily stop the attack itself as
its job is only to delete the executable after it runs along with
itself.

And a response that blocks HTTP/HTTPS traffic from `svchost` processes
would block the attacker's C2 but may also interfere with legitimate
traffic from other `svchost` processes.

Here are several responses that could be used during both analysis and
remediation given what we know so far...

- [AppLocker](#applocker)
- [YARA Rules](#yara-rules)

If a host shows signs of this malware, a great first option would be to
contain with FireEye HX so that all C2 is stopped and you have full
control of the system.

Some things to consider:

- FireEye HX agent may not be installed on the system

- Containment may not be an option depending on the specific system or
    number of systems involved

- If contained, you still need to have a good idea of how to prevent,
    isolate, or eradicate the malware

With this in mind, we'll make an example response based on each of the
common TTPs we observed using AppLocker.

### AppLocker

AppLocker is one of Microsoft's application control tools used to limit
the execution of executables, DLLs, scripts, and installer files.

By defining rules with an AppLocker policy, we can prevent and/or allow
running applications and files based on their path, hash value, or
digital signature.

- [11-character BAT file in TEMP directory](#11-character-BAT-file-in-temp-directory)
- [EXE Executes in Temp Directory](#exe-executes-in-temp-directory)
- [Files Without a Digital Signature](#files-without-a-digital-signature)

<br>

Prerequisites:

- Import the module with `Import-Module AppLocker`
- Start AppIDSvc with `Start-Service AppIDSvc`
- Configure AppIDSvc to start automatically:
    -   Win7    `Set-Service AppIDSvc -StartupType Automatic`
    -   Win10   `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name Start -Value 2`
- Create default AppLocker executable rules (delete the BUILTIN\\Admin ones) and enable rule enforcement using `secpol`


#### 11-character BAT file in TEMP Directory

We know that a BAT file is used to delete the original executable and
itself. 

If we wanted to prevent the malware from deleting these artifacts, we
could create a script rule with AppLocker based on the BAT's file path.

This [Deny-Path.ps1](../scripts/Deny-Path.ps1)
script can be used to create an AppLocker rule that does this by
specifying the file type and path:

![](images/Developing%20TTP-based%20Responses/image036.png)<br><br>

Running this script on a system configures it to preserve artifacts that
would normally be destroyed.

(By choosing `-script`, we are denying the execution of .bat, .js, .ps1,
.cmd, and .vbs files)

![](images/Developing%20TTP-based%20Responses/image037.png)<br><br>

Now when the sample is executed, the BAT file doesn't run---so it can't
delete itself or the original executable:

![](images/Developing%20TTP-based%20Responses/image038.png)<br><br>

Looking at the .bat file, you can see I executed the sample in the `Temp`
folder, the same place the malicious doc's PowerShell command downloaded
`23.exe` to:

![](images/Developing%20TTP-based%20Responses/image039.png)<br><br>

However, vbs scripts in other directories were not affected by the rule
and were allowed to execute:

![](images/Developing%20TTP-based%20Responses/image040.png)<br><br>

#### EXE Executes in Temp Directory

We know the original exe `23.exe` is downloaded by a PowerShell command
into the `$env:temp` directory and executed.

If we wanted to prevent the first stage (`23.exe`), second stage
(`9b57.exe`) and any other executables from running here, we could use
this same script to create an executable rule.

The variable `$env:temp` may refer to different locations on different
machines---it was `%TEMP%` on the analysis VM but `%TEMP%\1` on my
workstation.

AppLocker path rules are recursive so if we make the rule for the `%TEMP%`
directory, it will also work for all of `%TEMP%`'s subdirectories.

Again, we can use the
[Deny-Path.ps1](../scripts/Deny-Path.ps1)
script to do this:

![](images/Developing%20TTP-based%20Responses/image041.png)<br><br>

Now no executable will be allowed to run in the `%TEMP%` folder or any of
its subdirectories.

![](images/Developing%20TTP-based%20Responses/image042.png)<br><br>

If we wanted to let the `9b57.exe` run but prevent the `Notepad.exe`, we
could make the rule for the `Roaming` directory instead.

Also, we can prevent executables from running in both directories by
specifying the `c:\users\cpillar\AppData` directory in the script since
**AppLocker** Path rules are recursive.

We can even create exception rules for programs that are allowed to run
under the `AppData` directory such as Slack, Github Desktop, etc.

Since **AppLocker** path rules are recursive, files running from root
directories such as `C:\` can be problematic.

In this case, a better option might be to build a rule based on
executable's publishers.

#### Files Without a Digital Signature

Since the majority of the samples found do not contain a digital
signature, we can configure the system to only allow signed executables
to run.

This
[Allow-Signed.ps1](../scripts/Allow-Signed.ps1)
script can be used to do this:

![](images/Developing%20TTP-based%20Responses/image043.png)<br><br>

Running this script on a system creates a rule that will prevent any
unsigned executable from running.

![](images/Developing%20TTP-based%20Responses/image044.png)<br><br>

Attempting to run the file anywhere on the system fails and produces
this message:

![](images/Developing%20TTP-based%20Responses/image045.png)<br><br>

Whitelisting publishers or creating exception rules for legitimate
unsigned executables are other ways we implement this.

In all three examples, we're using what we know about how the adversary
operates to develop the best responses that meet IRM's requirements.  
These responses can be implemented using built-in tools like **AppLocker**
or third party endpoint security suites such as **McAfee** and **FireEye HX**.

Knowledge of the attack reveals TTPs and these TTPs can be used to
recommend different responses based on what IRM needs to be
accomplished.  The more you know about the different stages of the attack,
the easier it makes these tasks.

### Yara Rules

Using Artifacts to Create YARA Rules

YARA reads its rules from top to bottom looking for patterns of ASCII,
Unicode, or Hex in static files, memory space, and network traffic.  We
can use these rules to search large collections of files, packet
captures, or to search systems for files that match its criteria.

We've got three artifacts we can use to create our YARA rules:

- [Word Doc with Obfuscated Macro](#word-doc-with-obfuscated-macro)
- [Obfuscated VBScript](#obfuscated-vbscript)
- [Randomly-Named EXE](#randomly-named-exe)

<br>

As we make these rules, if possible we want to avoid using static
attributes which can be bypassed easily such as:

- Strings
- Compiler artifacts
- Exif data
- Library and API imports

<br>

More robust IOCs are created using dynamic attributes such as:

- In-memory strings
- Process handles, mutexes
- Accessed/created files
- Accessed/created registry keys
- Created network traffic

<br>

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

![](images/Improved%20Detections%20YARA%20rules/image018.png)<br><br>

If a Word document contains several of these strings, it is likely that
it is not legitimate.

Here is a very basic YARA rule that looks for a `.doc` with three of the
four suspicious strings we've identified:

![](images/Improved%20Detections%20YARA%20rules/image019.png)<br><br>

Yara identifies the magic number (`$mn`) and that at least three
occurrences of the strings are present:

![](images/Improved%20Detections%20YARA%20rules/image020.png)<br><br>

### Obfuscated VBScript

Although we may not be able to deobfuscate this file entirely, we can
deconstruct it into its basic parts to find unique characteristics.

![](images/Improved%20Detections%20YARA%20rules/image015.png)<br><br>

The script is organized into three main sections:

1. `a = "~033_019~031_008....`

2. `q = strreverse(")601-802(rhc+)302-803(rhc+)89-031(rhc+)331-332(rhc+)86-871(rhc+)612-713...`

3. `Unescape(Escape(UnEscape(Escape(Unescape(Escape(UnEscape(Escape(Unescape(Escape(UnEscape(Escape(execute(UnEscape(Escape(eval(strreverse(")91-131(rhc+)802-913...`

<br>

So the first two sections are variables being declared and the third is nested `escape()` and `unescape()` functions
being used to encode and decode another reversed string.

First we must understand the purpose of the functions:

- Escape() - Return only ASCII characters from a Unicode string
- Unescape() - Return Unicode characters from an escaped ASCII string

<br>

There seems to be no legitimate reason why these two functions should
be nested within each other multiple times, so this is a great technique
to build a detection on.

This YARA rule does a case insensitive search for nested `Escape()` and
`Unescape()` functions:

![](images/Improved%20Detections%20YARA%20rules/image021.png)<br><br>

It finds several occurrences:

![](images/Improved%20Detections%20YARA%20rules/image022.png)<br><br>

### Randomly-Named EXE

We discovered that the executable creates the `23.vbs` script and executes
it with `Wscript.exe`.

**Pedump**, **PEStudio**, and several other tools identify the executable as a
self-extracting archive (SFX).

Looking at the file in a hex editor reveals the emedded RAR and the
contents of the vbs file are visible:

![](images/Improved%20Detections%20YARA%20rules/image023.png)<br><br>

Further down we can see the string reversing section of the VBScript:

![](images/Improved%20Detections%20YARA%20rules/image024.png)<br><br>

We can build a YARA rule that looks for an embedded RAR (magic number in
file body) containing more than 100 "`(rhc+)`" strings that indicate
string reversing:

![](images/Improved%20Detections%20YARA%20rules/image025.png)<br><br>

These were just a few of many possible rules we could make based on
methodology.  The randomly named executable files, the specific registry
keys touched, and the unique network traffic are other ways we can
search to identify adversary techniques across the enterprise.

The capabilities and tactics being used by attackers are changing every
day---we must address threats in a way that will be effective in
numerous attack scenarios with completely different objectives.  

TTPs or methodology detections do this by taking into consideration the
identity, tactics, and techniques of the adversary---things that they do
not often change or are very difficult to change.  To create these we
need to understand the underlying techniques and how they can be detected
in our environment.

## Disseminate Intelligence

This phase is transferring knowledge of adversary capabilities, infrastructure, motives,
goals, and resources to partners, analysts, tools, processes to provide a more
focused approach for defense.

The impact of an incident largely depends on how quickly and accurately we move
from the IDENTIFICATION to the CONTAINMENT phase. The diagram below is a
representation of how we can shrink this window.

![](images/Using%20A%20Threat%20Based%20Approach/image004.png)<br><br>

On the left is the product of all of FO’s work researching particular technique being used in the current incident.  On the right is a representation of moving that incident from IDENTIFICATION to CONTAINMENT.  The goal is to shrink this window by enabling the analyst to respond with maximum [speed](#improving-speed) and [accuracy](#improving-accuracy).

Here is minimal intelligence for this incident:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image070.png)<br><br>

Context is needed for atomic indicators:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image071.png)<br><br>

But atomic indicators *combined* with behavioral indicators and the tools and
resources generated from automated, static, and dynamic analysis
provide the most intelligence:

![](images/Behavioral%20Vs%20Atomic%20Indicators/image072.png)<br><br>


An example of this concept in action is our response to the exercise referenced in [Moving From Detection To Containment](Moving%20From%20Detection%20To%20Containment.md).  In this case over 100 hosts were compromised and in various stages of the adversary lifecycle.  As soon as FO identified the technique being used, a script was developed that would find all processes running the attacker's malicious code on a compromised system so that they could be terminated.  This allowed us to quickly remove attacker control of all compromised hosts while also reducing the time required to move from IDENTIFICATION to CONTAINMENT once a compromised system was identified.

So, how can we improve SPEED and ACCURACY like this for all incidents?

### Improving Speed

We improve speed by having our research, scripts, queries, and response actions staged and ready to provide to the analyst working an incident.  This way the analyst doesn’t have to waste time researching the technique, building the same scripts and queries that have already been built, or trying to determine the best responses for the technique being used.

### Improving Accuracy

We improve accuracy by ensuring the **correctness** and **completeness** of the information we're providing the analyst.  The queries, scripts, and response actions have all been tested and verified as the most effective methods to use in our environment.  These are developed over days and weeks, not created as the incident unfolds.

We also ensure **consistency** with this method by ensuring that all analysts get the same resources, scripts, queries, and response actions. All technical documentation and OSINT sources are carefully selected based on their value to an incident responder.  When everyone is on the same page using the same resources and analysis techniques, the results stay consistent and are more easily used and understood.

With these improvements in SPEED and ACCURACY, the analyst is able to quickly get a clear picture of the incident and is immediately equipped with the most effective actions to take that will reduce its overall impact.

Using a threat-based approach improves the quality of tools and knowledge delivered to the analyst enabling swift, effective responses that have been tested and tuned in our environment.  In the event of a detection, we have high confidence it is a true positive, it contains the context and artifacts needed for reporting and response, and allows management to make time-sensitive decisions.

## Summary

As defenders, our goal is to obtain knowledge that will prevent the adversary
from operating in our environment and meeting their objectives.  Some of this
knowledge comes in the form of indicators which are used differently depending
on the phase.

Final Indicators

- Were initially provided with:

    - Delivery domain sudebnii-advokat[.]ru
    - Sample Canada Post Notice Card.doc

- Used Dynamic Analysis of Canada Post Notice Card.doc to obtain:

    - Delivery domain tehnospas74[.]ru
    - Delivery domain tekflagman[.]ru
    - Delivery domain telecomserv[.]ru
    - Delivery domain telerad[.]ru
    - Delivery domain telexon[.]ru
    - C2 IP address 176.31.22[.]17
    - Sample 23.exe
    - Sample 23.vbs

- Used analysis of 176.31.22[.]17 to obtain:

    - Delivery domain yaded[.]ru
    - Delivery domain uk-sv[.]ru
    - Sample 9b57.exe
    - Sample 1fug.exe

- Used Dynamic Analysis of sample `9b57.exe` to obtain:

    - Sample 7991574
    - Sample System.dll
    - C2 domain manrovm[.]gdn
    - C2 domain lemanva[.]gdn

- Used OSINT (PassiveTotal) for `manrovm[.]gdn` and `lemanva[.]gdn` to obtain:

    - 20 different samples associated with these domains
    - Common TTPs used

<br>

List of good resources:

- [Robtex](https://www.robtex.com/)
- [DomainTools](https://whois.domaintools.com/)
- [Dazzlepod](http://dazzlepod.com/ip)
- [Network-Tools](http://network-tools.com/)
- [DNSstuff](http://www.dnsstuff.com/)
- [VirusTotal](https://www.virustotal.com/)
- [Urlvoid](http://www.urlvoid.com/)
- [IPvoid](http://www.ipvoid.com/)
- [SiteReview](https://sitereview.bluecoat.com/sitereview.jsp)
- [MalwareDomainList](https://www.malwaredomainlist.com/mdl.php)
- [Malwr](https://malwr.com/)
- [PayloadSecurity](https://www.hybrid-analysis.com/)
- [ThreatExpert](http://www.threatexpert.com/)                   
- [RansomwareTracker](https://ransomwaretracker.abuse.ch/tracker/)                                 
- [Urlquery](http://urlquery.net/)
- [ThreatGlass](http://www.threatglass.com/)                       
- [Phishtank](https://www.phishtank.com/)             
- [BlockList](http://www.blocklist.de/en/search.html)
- [ThreatConnect](https://www.threatconnect.com/)
- [ThreatQuotient](https://www.threatq.com/)
- [Anomali](https://www.anomali.com/)
- [CentripetalNetworks](http://www.centripetalnetworks.com/)
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/new)
- [AlienVault OTX](https://otx.alienvault.com/browse/pulses/)
- [Blueliv Threat Exchange Network](https://community.blueliv.com/#!/discover)
- [CRITS](https://crits.github.io/)
- [MISP](https://github.com/MISP/MISP)
- [threat_note](https://github.com/defpoint/threat_Note)

Here is a great collection of threat intelligence resources:  
<https://github.com/hslatman/awesome-threat-intelligence>
