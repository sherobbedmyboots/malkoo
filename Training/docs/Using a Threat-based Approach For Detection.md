# Using a Threat-based Approach For Detection

As a defender, a big part of being successful is coming up with an effective strategy to detect the adversary, the threat, and kick them out of our environment as quickly as possible.  To do this, we need to stay one step ahead of the adversary at all times.  This requires having tactical advantages which we can obtain by learning and studying how the adversary behaves.

The Preparation phase of the IR cycle is where we collect and organize knowledge about the different threats to our environment, configure our tools to use this knowledge for detection, and then provide our analysts working an incident with this knowledge so they can respond with improved speed and accuracy.

Our role in this process is determining the best way to detect and respond to the adversary.  We use a threat-based approach to accomplish this which means we learn and study adversary techniques and then use this knowledge to develop the most effective methods for detection and response when they are used in our environment.  

We can use the following cycle to learn about adversary tradecraft and develop matching detections and responses.

![](images/Using%20A%20Threat%20Based%20Approach/image001.png)<br><br>

|Phase|Description|
|-|-|
|[Discover and Learn Adversary Tradecraft](#discover-and-learn-adversary-tradecraft)|FO is continually discovering, learning, and testing new tradecraft|
|[Build High-Fidelity Detections](#building-high-fidelity-detections)|Use most effective combinations of detection types to build actionable and universal detections|
|[Provide Context and Next Actions](#provide-context-and-next-actions)|Provide required knowledge, tools, and response actions to the analyst|

<br>

Outlined in blue is the part of the process where we learn about techniques used against us, techniques being used out in the wild that could be used against us, and what it looks like when the techniques are used in our environment.  

In orange is where we develop the capability to reliably detect these techniques being used in our environment.  

In green is where we package all the results of our research and testing so it can be delivered to the analyst that's working an incident.  

As more incidents are worked and resolved, the cycle repeats itself.

Malware is evolving every day, so how do we prepare for this?  Malware is a capability used by actors, but the actor is threat. Adversaries succeed without using malware at all so we need to understand the different types of actors out there along with their specific behaviors, motivations, and objectives:

|Type|Description|
|-|-|
|Cybercriminals|Broad-based, financially motivated, exploit kits|
|State-sponsored|Multi-staged, focused on data collection, highly sophisticated, endless resources|
|Insiders|Unpredictable motivations, sophistication varies|
|Hacktivists|Unpredictable motivations, generally less sophisticated|

<br>

The key to success with this model is knowledge of threat behavior.  Whether we’re dealing with state-sponsored groups, cyber criminals, hacktivists or an insider, the goal is always the same---to plan and execute operations against the adversary faster than they can react.  

We accomplish this by doing two things:

- Learning adversary techniques, their "tradecraft", so that we can detect them
- Studying that tradecraft in the context of the Intrusion Defense Chain (IDC) so that when we do detect them, we can quickly determine where they are in the kill chain and what they plan to do next

Now let’s take a closer look at each phase of this process…


## Discover and Learn Adversary Tradecraft

We are continually discovering, learning, and testing new tradecraft.  These are the three stages we use to learn about adversary behavior as we work towards building detections and providing context and next actions to the analyst:

![](images/Using%20A%20Threat%20Based%20Approach/image002.png)<br><br>


- [Past Incident Data](#past-incident-data)
- [Threat Research](#threat-research)
- [Threat Emulation](#threat-emulation)


### Past Incident Data

We start by using valuable data gathered from past investigations to prioritize what we know about our environment and what we’ve seen firsthand, such as:
- What delivery techniques are our users seeing
- What groups have been targeted
- What have our systems and applications been hit with and/or fallen victim to
- What kind of techniques are being used by the malware we’re being targeted with

For each investigation, we look at:
- Indicators obtained externally or those we obtained ourselves through malware analysis 
- Scripts, queries, and tools that were successfully utilized during the investigation
- The methods that were used for scoping and containment

All of these are extremely valuable to an analyst who is working an incident that is similar to or, possibly even related to, a past investigation.


### Threat Research

In the second phase, we begin building on this knowledge using anything we can find about techniques that could be used against us, such as:
- Security blogs
- Technical reports
- Proof of concepts

One of the best resources available is the [Mitre ATT&CK Knowledge Base](https://attack.mitre.org/wiki/Main_Page), a library of known tradecraft with corresponding detections and mitigations.  Mitre's [Technique Matrix](https://attack.mitre.org/wiki/Technique_Matrix) contains hundreds of techniques categorized by different phases of the adversary lifecycle.  

For each technique, resources are provided explaining:
- How it works and how it's used
- Groups that have used it successfully
- Guidance for developing detections and mitigations for that particular technique


### Threat Emulation

In this third phase, we test our enterprise security posture by using or simulating the techniques we’ve learned, and identifying: 
- Gaps in our current tools, processes, or configurations 
- Analysis tools and techniques that give us the best visibility of the technique in use
- How best to scope and contain in our environment if these techniques are being used against us

This is also where we start developing detection content, testing it and tuning it for use in the next phase.

Everything we learn in these three stages helps us develop accurate detections and determine the most effective actions we can take to reduce the overall impact of incidents involving these techniques.  

Now let’s look at how we build high-fidelity detections.


## Build High-fidelity Detections

We’ve studied and tested our techniques, now we need to configure our tools to reliably detect them being used.

- [Configuring Tools For Detection](#configuring-tools-for-detection)
- [Differences in Detection Types](#differences-in-detection-types)
- [Building High-Fidelity Detections](#building-high-fidelity-detections)
- [Using Effective Combinations](#using-effective-combinations)

### Configuring Tools For Detection

The diagram below shows how the four detection types can be used to create detection content for three different tools--Splunk, FireEye HX, and Cisco IDS:

![](images/Using%20A%20Threat%20Based%20Approach/image003.png)<br><br>


Splunk is used to search through indexed logs and data, FireEye HX monitors our endpoints, and Cisco IDS monitors the network.  Each of these tools allow us to provide detection content specific to what we’re looking for.  Each time we provide a tool with content, and it detects activity based on that content, we call that a **detection**.  And every detection falls into one of the four detection types.


### Differences in Detection Types

Here is a description of each type of detection:

|Type|Description|
|-|-|
|[Modeling](#modeling)|Baseline anomalies that stand out from normal activity in the environment|
|[Threat Indicators](#threat-indicators)|IP addresses, domain names, file hashes, etc. known to be malicious|
|[Configuration Changes](#configuration-changes)|New changes on a system such as new processes, new connections, new protocols|
|[Threat Behaviorial Analytics](#threat-behavioral-analytics)|Patterns in logs and data resulting from overall tradecraft used|

<br>

So which types are the best to use?  They all have their own strengths and weaknesses, let’s look at each one:

#### Threat Behaviorial Analytics 

These are patterns in data resulting from adversaries doing what they do.  A common technique used in phishing attacks is emailing the victim a link to an HTA file which will run a malicious PowerShell command on the victim’s system.  The `mshta.exe` process spawning a `powershell.exe` process is an unique pattern that indicates that particular technique in use and we can use that pattern to search for every time this happens in our environment.

[Here]() is an example using Splunk:

```powershell
sourcetype=WinEventLog:Security EventCode=4688 mshta.exe OR (powershell.exe "-encodedcommand")
| transaction host maxspan=3s startswith="mshta.exe" endswith="powershell.exe"
```

#### Configuration Changes

These are new changes that occur on a system.  Using the same example, when a malicious `powershell.exe` process runs, it will most likely attempt to download malicious code from an attacker-owned IP address and run it in memory.  The new network connection is a configuration change we can search for across all systems.

We can use the base64-encoded version of the string "IEX " to look for network connections from `powershell.exe` processes:

![](images/Using%20A%20Threat%20Based%20Approach/image005.png)<br><br>

[Here]() is an example using Splunk:

```powershell
sourcetype=WinEventLog:Security EventCode=4688 powershell.exe "*SQBFAFgAIAA*" | stats count by host
```

#### Threat Indicators

These are files and infrastructure that is known to be associated with malicious activity.  In our same example, good indicators would be the URL used to host the HTA file, the IP address used to deliver the malicious code, or a file hash of the HTA file.  We can search for or configure our tools to alert each time the hash/ip address/domain is seen in our environment.

[Here]() is an example using Splunk:

```powershell
index=proxy r_ip=100.100.100.*
```

#### Modeling

These are baseline anomalies, events or groups of events that are not considered normal for the environment.  Keeping with our example, when the `powershell.exe` process runs an implant in memory, this could be used to run a module that attempts to log on to every host discovered on the network.  This would create an unusually high number of logon attempts for different hosts which we could search for across our environment.

[Here]() is an example using Splunk:

```powershell
sourcetype=WinEventLog:Security user!=*$ (EventCode=4625 Caller_Process_Name="-" Status="0xc000015b") OR 
(EventCode=4656 action=failure Object_Server="SC Manager" Object_Type="SC_MANAGER OBJECT" ) 
| stats dc(host) as rcount by user Source_Network_Address
| where rcount > 100
| sort -rcount
```

### Building High-Fidelity Detections

To build high-fidelity detections we must ensure they are *actionable* and *universal*:

- [Actionable](#actionable) - They must produce something of VALUE, activity that we need to respond to
- [Universal](#universal) - They must catch the full spectrum of adversary skill and effort 


#### Actionable 

We must use two or more detection types together in one detection to produce actionable alerts for the analyst.  Here are some good ways to do this:

- Build in 4 detection types, if at least 3 hit, it fires an alert
- Build in severity... 2 hits produces a LOW alert, 3 hits is a MEDIUM, and 4 is a HIGH
- Build in detection types in order of their IDC phase
	- First the Behavioral detection (Exploitation Phase)
	- Then the Configuration Change detection (Installation) 
	- Then the Threat Indicator detection (C2)
	- And finally the Modeling detection (Actions on Objective)

Each technique will be different and you'll need to try different combinations to get the best results.  Now let's make sure the detection is universal...


#### Universal

We must use the right combinations of detection types in order to catch the low hanging fruit as well as top tier operators and everything in between. To do this, it's necessary to understand the difference between the top two types and bottom two types.

The top two detection types, **Modeling** and **Threat Indicators**, are easily avoidable by a skilled or determined adversary.  Most actors know if they create anomalies in the environment, they’re likely to be caught so they'll make an effort to leverage legitimate programs, utilize approved protocols, and disguise their traffic to look like it originated from a legitimate application.

They also know if they use known malicious files or infrastructure, they’re likely to be caught.  Let’s not forget that adversaries use VirusTotal too, and if someone is serious about targeting us they will not going use a file or domain that returns 40 hits on VT.  They won't use anything that is known to be malicious by reputation.  Instead they will use completely unknown tools and infrastructure to avoid detection.

However, the bottom two are different and are almost impossible for the adversary to get around.

As the adversary attempts to manipulate and control systems, they will be forced to create configuration changes such as new network connections, new processes, and new events on the system.  As they use the various techniques they've become accustomed to, they will create observable patterns in logs and data that we can search for with our tools and use to detect them.

So, to make our detections universal we make sure we include one or more of the bottom two types.  

Here is a simple example of a Splunk search that requires both a behavioral detection and a configuration detection:

```powershell
sourcetype=WinEventLog:Security EventCode=4688 mshta.exe OR (powershell.exe "-encodedcommand")
| transaction host maxspan=3s startswith="mshta.exe" endswith="*SQBFAFgAIAA*"
```

Multiple requirements makes it more actionable, including behavioral and configuration changes makes it more universal.

### Using Effective Combinations

Many SOCs don’t make a distinction between the different types of detections and therefore don’t know the proper way to use each type of detection, but this can be the difference between stopping the adversary at the door and having them embedded in your environment.

One of the most common mistakes we see from other SOCs is relying solely on anomalies and indicators which can be misleading at best, but at worst they can contaminate every phase of IR.

Relying solely on these two types for detections produces false positives that consume an analyst's time and prevent them from working actionable alerts.  Relying solely on these two types for scoping and containment produces false negatives--that means hosts are checked with the detections and established as clean when they are not.  When this happens, the SOC doesn't have a way to find the adversary on a system and therefore can't kick them out. 

We must have a very good understanding of how each detection type can best be utilized and which combinations work for the specific techniques we're studying.  When we’re confident we can reliably detect the use of these techniques, we deploy our detections to our tools and wait for a detection which will trigger an investigation.  

When this happens, analysts have questions that need answers---What does it mean?  What is the impact?  What do I need to do?  At this point, we have everything needed to counter the threat, we just need to get it into the hands of the analyst in a way that allows them to quickly and accurately respond.


## Provide Context and Next Actions

The impact of an incident largely depends on how quickly and accurately we move from the IDENTIFICATION to the CONTAINMENT phase. The diagram below is a representation of how we can shrink this window.

![](images/Using%20A%20Threat%20Based%20Approach/image004.png)<br><br>


On the left is the product of all of FO’s work researching particular technique being used in the current incident.  On the right is a representation of moving that incident from IDENTIFICATION to CONTAINMENT.  The goal is to shrink this window by enabling the analyst to respond with maximum [speed](#improving-speed) and [accuracy](#improving-accuracy).

An example of this concept in action is our response to the exercise referenced in [Moving From Detection To Containment](Moving%20From%20Detection%20To%20Containment.md).  In this case over 100 hosts were compromised and in various stages of the adversary lifecycle.  As soon as we identified the technique being used, a script was developed that would find all processes running the attacker's malicious code on a compromised system so that they could be terminated.  This allowed us to quickly remove attacker control of all compromised hosts while also reducing the time required to move from IDENTIFICATION to CONTAINMENT once a compromised system was identified.

So, how can we improve SPEED and ACCURACY like this for all incidents?

### Improving Speed

We improve speed by having our research, scripts, queries, and response actions staged and ready to provide to the analyst working an incident.  This way the analyst doesn’t have to waste time researching the technique, building the same scripts and queries that have already been built, or trying to determine the best responses for the technique being used.

### Improving Accuracy

We improve accuracy by ensuring the **correctness** and **completeness** of the information we're providing the analyst.  The queries, scripts, and response actions have all been tested and verified as the most effective methods to use in our environment.  These are developed over days and weeks, not created as the incident unfolds.

We also ensure **consistency** with this method by ensuring that all analysts get the same resources, scripts, queries, and response actions. All technical documentation and OSINT sources are carefully selected based on their value to an incident responder.  When everyone is on the same page using the same resources and analysis techniques, the results stay consistent and are more easily used and understood.

With these improvements in SPEED and ACCURACY, the analyst is able to quickly get a clear picture of the incident and is immediately equipped with the most effective actions to take that will reduce its overall impact.


## Summary

As defenders, our goal is to prevent the adversary from operating in our environment and meeting their objectives.  In order to do this successfully, we must learn and understand the methods they will use.  Knowledge of threat behavior leads every investigation no matter what type of actor we're up against.

We perform this in three phases:

- Study and pattern out adversary behaviors, quantify the tradecraft observed, and test the techniques in our environment to build detection content and determine the most effective response actions

- Build high-fidelity detections that are both actionable and universal to ensure accurate alerts that are capable of detecting techniques used by adversaries of all skill levels

- Leverage past investigations, research, and testing to provide key artifacts, the most useful context, and the most effective response actions to the analyst working an incident

Using a threat-based approach improves the quality of tools and knowledge delivered to the analyst enabling swift, effective responses that have been tested and tuned in our environment.  In the event of a detection, we have high confidence it is a true positive, it contains the context and artifacts needed for reporting and response, and allows management to make time-sensitive decisions.