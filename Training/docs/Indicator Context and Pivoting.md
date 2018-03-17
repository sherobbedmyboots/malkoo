# Indicator Context and Pivoting

Part of maintaining a proactive security posture involves obtaining and
processing knowledge about actors and the threat landscape.  Knowledge
of an actor's capabilities, infrastructure, motives, goals, and
resources---commonly referred to as threat intelligence---provides a
more focused approach for defense. 

## Threat Intelligence

The basis of all threat intelligence is adversary actions---what they
are doing and how they are doing it.  We collect raw data, process it,
and perform analysis, identifying relationships between different pieces
of information and drawing correlations as we try to build a complete
picture of adversary operations.  This knowledge is then leveraged for
decision advantages---to predict attacks and determine how, why, and
when they are most likely to occur. 

The majority of this knowledge comes from incident response and
intrusion analysis in the form of indicators.  That means for every
SEN/INC, we have two big opportunities to obtain indicators:

- [Incident Response]() - Working
with DHS ESOC to detect, scope, investigate, contain, and resolve a
security incident

- [Intrusion Analysis]() - Examining files,
traffic, and events to provide technical analysis and build an overall
picture of the incident

Once we have these indicators, we can use them to support:

- [Detection]() - Alerting and/or blocking on firewall/proxy rules, IDS signatures, EDR signatures, Hunting for post-exploitation activity

- [Response and Analysis]() - Validating and giving context to alerts and signatures to support triage, investigations, IOCs/IOAs pivoting and enrichment, determining best courses of action

- [Planning]() - Threat assessments/trending, revealing targeted personnel/assets, adversary intent and objectives, attack forecasting, operations adjustments/long-term prioritization

But to properly use these indicators, we must first have context.

## Indicators and Context

Indicators are unique pieces of information that have some type of
intelligence value.  To have value, an indicator must indicate something---an attack, a
compromise, a specific actor, a specific family of malware, etc.

For example, an IP address can be used to indicate either a suspected
compromised website, an exploit kit landing page, a C2 node, or a data
exfil endpoint... we need to know which one it is.

Also, there is a huge difference between a generic alert and one that is
contextually linked to a threat, indicator, or other data which requires
a higher priority.

In order to have value then, an indicator must have context.

|IP/Domain|Context|Indicator?|
|-|-|-|
|34.208.205\[d\]97|-|No|
|34.208.205\[d\]97|C2 node|YES|
|sadeyedlady\[d\]com|-|No|
|sadeyedlady\[d\]com|Exfil destination|YES|

So whether we obtain an indicator externally or internally, we need to
ensure we understand its context in order to use it correctly.

Then once we have an indicator with context, we can pivot on it to
identify relationships and discover related events, artifacts,
incidents, victims, etc.

Using the following example, let's walk through how you would use this
tool to pivot and collect indicators with their context:

> Host `192.168.2[d]177` is beaconing to a known malicious IP address `35.163.126[d]190`
                    


## Pivoting with the Diamond Model

During incident response, the Diamond Model helps identify indicators
that are related to the incident.

The Diamond Model provides four categories for pivoting:

![](images/Indicator%20Context%20and%20Pivoting/image001.png)


We can use the Diamond Model to fill in knowledge gaps and focus our
approach (victim, adversary, capability, infrastructure).

Back to our example:

First, we know the indicator we've been provided is a C2 IP address, so
we know we can search with it across our proxy logs to identify other
victims that may be reporting to this same IP address.

> You investigate and discover that a second victim, `192.168.2[d]20` is also beaconing to the same IP address.

In our first pivot, we used the C2 IP address (Infrastructure) to
identify an additional victim (Victim).

> You discover a backdoor trojan on this second victim with MD5 hash `b7c380f0c33143d5042b699c0e2710a5`

This would be an example of pivoting from the victim (Victim) to a
malicious file used (Capabilities).

Each pivot gives us a new indicator and we want to try to get indicators
from each category as we go... but we need context for these indicators.

Was this the file that was downloaded by the victim (Delivery), was it a
file designed to exploit a program on the user's system (Exploit), or
was it being used for persistence (Installation)?


                      

## Creating Context with the Kill Chain

During intrusion analysis, the Kill Chain Model allows us to provide
context for indicators.

Kill Chain phases:

|Phase|Description|
|-|-|
|Reconnaissance|Researching the target, scanning, passive recon|
|Weaponization|Preparing a tool for use in intrusion, exploit in PDF, phishing site|
|Delivery|Threat delivers capability to target environment, email with malicious PDF|
|Exploit|Vulnerability or functionality exploited to gather data/gain access|
|Installation|Functionality is modified or installed to maintain persistence|
|Command & Control|Enables threat to interact with target environment|
|Actions on Objectives|Threat works toward its desired goal, exfil, monitoring|

Each indicator can be associated with a phase from the Kill Chain.

To illustrate this, we can use a lightweight investigation notebook
called [threat_note](https://github.com/defpoint/threat_note) that is
now running on the OOB.

To see if it's running, open a terminal and type `docker ps`.

If it's not running already, start it up with:

```bash
cd /opt/threat_note/docker
docker build -t threat_note .
docker run -itd -p 8888:8888 threat_note
```

To log in, browse to localhost:8888, click on `Register`, and enter a
username and password to create your account.

You will then be redirected to the Dashboard.

Continuing with our example, enter in the indicators with their context
for the following steps:

- You investigate and discover that a victim is beaconing to a second
    IP address, `34.208.205[d]97`

- After examining the host you find it has been uploading large
    archive files to `sadeyedlady[d]com` and
    `colddistance[d]com`

- The cause of the malicious C2 and data exfil is determined to be a
    malicious file with MD5 hash `b7c380f0c33143d5042b699c0e2710a5`

- The SHA1 and SHA256 hashes of the malicious file are also documented
    (`a97496080b00097703d1bb58e7dd9742cad7dcf7`,
    `0a18aa47e2118608ba83ee799d27fbcc34efc2fc607cf8d6d2312bd37f16fc56`)

- The investigation reveals the user downloaded this malicious file
    from `unioncentralorchids[d]com` which resolves to IP address
    `34.210.28[d]254`

To enter an indicator, select `New Object`, then:

- Enter in OBJECT: `34.210.28.254`
- Enter in OBJECT TYPE: `IPv4`
- Enter FIRST SEEN: `2017-01-10`
- Enter LAST SEEN: `2017-01-15`
- Enter DIAMOND MODEL: `Infrastructure`
- Enter CAMPAIGN: `SEN2017-00-000`
- Enter CONFIDENCE: `High`
- Enter COMMENTS: `-`
- Enter TAGS: `Delivery` (Enter in the Kill Chain Phase here)
- Select `SUBMIT` to complete        

Now you should have a small collection of indicators with context:

![](images/Indicator%20Context%20and%20Pivoting/image002.png)


By clicking on the `Tags` menu, you can view the indicators by Kill
Chain phase:

![](images/Indicator%20Context%20and%20Pivoting/image003.png)


Click on the `Campaign` menu to view all indicators associated with
the SEN:

![](images/Indicator%20Context%20and%20Pivoting/image004.png)


Click on `Download Indicators` to export to CSV.

Here is what the CSV looks like:

![](images/Indicator%20Context%20and%20Pivoting/image005.png)


Now when we search our environment for the indicators in Splunk, we have
context for each indicator:

![](images/Indicator%20Context%20and%20Pivoting/image006.png)


And can include context with any results returned with a search like this:

```
index=<index> \[inputlookup indicators.csv | rename object AS host | return 100\ host]
| lookup indicators.csv object AS host OUTPUT tags AS killchain, diamondmodel
| table _time ip method host uri_port killchain diamondmodel
```

## Summary

Each model has its own strengths:

The **Diamond Model** gives you a structured way to pivot during IR, helping you discover artifacts and events that are related to your known, vetted indicators.

The **Kill Chain** gives you a structured way to categorize indicators during Intrusion Analysis and provide context with their associated phase.

The idea is to keep enhancing the value of indicators and understand why
their presence in an alert, signature, or search results would have
significance regarding your investigation.

Threat_Note is just one tool that makes this easier, try others such as
MISP, CRITS, etc. and find one that works for you.
