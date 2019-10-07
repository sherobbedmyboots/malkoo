# Common Functions and Data Sources in Splunk

A huge part of analysis and response is sifting through large data sets and identifying what is important and related to a potential or confirmed incident.  Splunk is the tool we use to do this and there are some core functions that we need to be familiar with that help make it more effective in an investigation.

This document will review setting up a test environment with Splunk's [BOTSv1 data set](https://github.com/splunk/botsv1), using some of these core functions in Splunk, and ways to explore the different types of data provided by common data sources.

<br>

- [Set Up Splunk BOTS Environment](#set-up-splunk-bots-environment)
	- [Download and Install Splunk Enterprise](#download-and-install-splunk-enterprise)
	- [Install Splunk Apps](#install-splunk-apps)
	- [Install CTF Scoreboard Apps](#install-ctf-scoreboard-apps)
	- [Download BOTSv1 Data](#download-botsv1-data)
- [Common Functions in Splunk](#common-functions-in-splunk)
	- [Searching](#searching)
	- [Chopping](#chopping)
	- [Joining](#joining)
	- [Replacing](#replacing)
	- [Counting](#counting)
	- [Sorting](#sorting)
	- [Automating](#automating)
- [Common Data Sources in Splunk](#common-data-sources-in-splunk)
	- [IDS Alerts](#ids-alerts)
	- [Firewall Logs](#firewall-logs)
	- [Web Server Logs](#web-server-logs)
	- [Stream Events](#stream-events)
	- [Windows Event Logs](#windows-event-logs)
	- [Endpoint Monitoring Events](#endpoint-monitoring-events)

<br>

## Set Up Splunk BOTS Environment

You will need:
- [Splunk Enterprise](https://www.splunk.com/en_us/software/splunk-enterprise.html)
- [Splunk CTF Scoreboard](https://github.com/splunk/SA-ctf_scoreboard)
- [Splunk CTF Scoreboard Admin](https://github.com/splunk/SA-ctf_scoreboard_admin)
- [SA-investigator](https://www.splunk.com/blog/2018/02/07/being-your-own-detective-with-sa-investigator.html)
- [BOTSv1 Dataset](https://github.com/splunk/botsv1)

<br>

On a Linux host, run the following:

### Download and Install Splunk Enterprise

```
# Create a free account on Splunk.com and download the package splunk-7.1.3-51d9cac7b837-linux-2.6-amd64.deb 

# Install
sudo dpkg -i splunk-7.1.3-51d9cac7b837-linux-2.6-amd64.deb
sudo apt install -f
export SPLUNK_HOME=/opt/splunk
sudo $SPLUNK_HOME/bin/splunk start --accept-license

# Enter password

# Log in to the Splunk server on port 8000 with username admin and your password
firefox localhost:8000
```

### Install Splunk Apps

```
#	Go to Apps and install:
#   - Lookup File Editor
#	- Parallel Coordinates Custom Visualization
#	- Splunk Add-on For Microsoft Windows
#	- Add-on for Microsoft Sysmon
#	- Fortinet FortiGate Add-On for Splunk
#	- Splunk Stream
#	- Splunk TA for Suricata
#	- Timeline - Custom Visualization
#	- Splunk Add-on for Tenable
#	- BOTS Investigation Workshop for Splunk

# For apps like Splunk TA for Suricata, download from Splunk.com then copy
sudo cp -r ~/Downloads/TA-Suricata /opt/splunk/etc/apps/
```

### Install CTF Scoreboard Apps

```
# If you want to use the scoreboard apps, do the following:

# Install the CTF Scoreboard App
sudo mkdir $SPLUNK_HOME/var/log/scoreboard
cd $SPLUNK_HOME/etc/apps
sudo git clone https://github.com/splunk/SA-ctf_scoreboard
sudo git clone https://github.com/splunk/SA-ctf_scoreboard_admin
sudo $SPLUNK_HOME/bin/splunk restart

# Create CTF Answers service account
sudo SPLUNK_HOME/bin/splunk add user cabanaboy -password <password> -role ctf_answers_service -auth admin:<admin_password>

# Configure the custom controller
cd $SPLUNK_HOME/etc/apps/SA-ctf_scoreboard/appserver/controllers
sudo cp scoreboard_controller.config.example scoreboard_controller.config

# Edit scoreboard_controller.config to reflect the following:
USER = cabanaboy
PASS = <password>
VKEY = <random number between 10-20 digits long>

# Log in, go to the Lookup Editor, and import the ctf_questions.csv, ctf_answers.csv, and ctf_hints.csv files
```

### Download BOTSv1 Data

```
# Make sure you have sufficient free space for this huge file

# Download the BOTSv1 Data Set
wget https://s3.amazonaws.com/botsdataset/botsv1/splunk-pre-indexed/botsv1_data_set.tgz -O botsv1_data_set.tgz

# Extract and copy into apps directory
tar zxvf 
sudo cp /path/to/botsv1_data_set /opt/splunk/etc/apps/

# Restart
$SPLUNK_HOME/bin/splunk restart
```

<br>

Try the following search and you should see 22 different sourcetypes available for searching:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image001.png)<br><br>


## Common Functions in Splunk

To get the most out of Splunk, at a minimum you should know at least one way of performing each of the following functions:

|Function|Description|
|-|-|
|[Searching](#searching)|Finding a string or pattern|
|[Chopping](#chopping)|Separating large chunks of data into smaller parts|
|[Joining](#joining)|Combining small chunks of data into larger parts|
|[Replacing](#replacing)|Substituting strings or patterns with other strings and patterns|
|[Counting](#counting)|Counting events and values|
|[Sorting](#sorting)|Putting data in order|
|[Automating](#automating)|Using macros to automate functions|

<br>

### Searching

Learn to use the following to get more and more granular when searching:

- Grepping
- Operators
- Field-Value Expressions
- Subsearches
- Transactions

#### Grepping, Operators, and Field-Value Expressions

"Grepping" is searching for a string across a large collection of data such as `index=botsv1 imreallynotbatman`.  Using operators such as `NOT`, `OR`, and `AND` is a more effective way to filter results:

Adding another string to search in `index=botsv1 imnotreallybatman 40.80.148.42` uses an *implied AND* and reduces events from 78,000 to 75,000.

Using a field-value expression for `src_ip` in `index=botsv1 imnotreallybatman src_ip=40.80.148.42` returns only the events where 40.80.148.42 was the source IP address---38,000 events.

This retruns us events of two different sourcetypes: `stream` and `suricata`.  The search `index=botsv1 imnotreallybatman src_ip=40.80.148.42 sourcetype=suricata` returns only the events that were `suricata` events----17,000 events.

Suricata collects many events but we're most interested in alert events.  The search `index=botsv1 imnotreallybatman src_ip=40.80.148.42 sourcetype=suricata event_type=alert` narrows it down to only 473 events.

#### Subsearches

A subsearch is a search within a search---using the results of an "inner" search as field-value expressions for the "outer" search.  For example, one of the suricata alerts references a web request that created a 501 status code and we'd like to examine the associated web log events.  We can use `return` and `rename` to make the output of the current search a field-value expression:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image020.png)<br><br>

Using the output of this search as a search term for the outer search allows us to search a different sourcetype (`iis`) with the field-value expression `sc_status=501`:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image021.png)<br><br>

This is a TRACE request, possibly an attempt to gather cookies or website credentials.

#### Transactions

A transaction is an event made up of a series of events based on one or more fields.  It is useful for searching for different components of an attack in a specific order.

For example, we can search for two components of the CGI exploit---the check for the vulnerability `(sourcetype=iis allow_url_include)` and the command shell started by the joomla user `(sourcetype=wineventlog EventCode=4688 user=joomla cmd.exe)`.  We use the `transaction` command to look for any host that reports these two events in this order:

```
index=botsv1 (sourcetype=iis allow_url_include) OR (sourcetype=wineventlog EventCode=4688 user=joomla cmd.exe)
| transaction startswith=allow_url_include endswith=cmd.exe
```

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image022.png)<br><br>

When it detects an event, it combines the two events into one and creates a field named `duration` which is the time between the first and last event in the transaction.


### Chopping

Use regular expression commands `rex` and `regex` to chop data into smaller parts.

Question #114 asks which password was used first in the password attack.  We know the username and password are located in the `form_data` field and we want to extract them into fields named `user` and `pass`.  We can use:

`rex field=form_data "username=(?<user>\w+).*&passwd=(?<pass>\w+)"`

Now we have a `user` and `pass` field we can use to create a table:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image010.png)<br><br>

We can use the `regex` command to find events with `pass` fields that contain one or more digits:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image011.png)<br><br>


### Joining

We can join the user and pass fields together with a colon by adding the command `| strcat user ":" pass userpass`:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image012.png)<br><br>


The `eval` command can be used to do the same thing:
```
| eval userpass=user+":"+pass
```

You can also bring in fields from another command (`iplocation`) or lookup table (`lookup`) to add context to the fields in your current search.  Adding the following lines to the search creates `City`, `Region`, and `Country` fields for each event with a `src` value and adds them to the table:

```
| iplocation src
| table _time src City Region Country userpass
```

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image013.png)<br><br>

### Replacing

For replacements, use the `replace` command and specify the original string, the new string, and the field:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image024.png)<br><br>

Or use with the `eval` command:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image023.png)<br><br>


### Counting

The `stats` command is probably the most valuable for getting counts of events and values.  A standard `stats count by` will count the number of unique values of the fields you provide.  Here is a count of events reported by each host:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image025.png)<br><br>

1,760 hosts reported Windows Event logs on 8/10/2016.  Now let's look at how many new `cmd.exe` processes were reported by each host:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image026.png)<br><br>

This narrows our hosts to only two.  Some of these `cmd.exe` processes may use the same command line arguments so we can use `stats dc` to show the distinct count of command line values for these events:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image027.png)<br><br>


The `we1149srv` host has 10 unique command line values for the `cmd.exe` events.  To show these values we can use `stats values`:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image028.png)<br><br>

### Sorting

The `table` command allows you to display the fields that are most relevant to the search:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image029.png)<br><br>

The `sort` command allows you to choose the order of the events displayed.  You may want events in descending order by `_time` for a timeline:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image030.png)<br><br>

Or events ascending by `count` to identify anomalies:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image031.png)<br><br>


## Automating

Use macros to automate one or more commands that you use frequently.  Go to `Settings` --> `Advanced Search` --> `Search macros` --> `Add new` and enter the Name and Definition fields:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image032.png)<br><br>

Now you have a shortcut for the commands you defined:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image033.png)<br><br>


## Common Data Sources in Splunk

The BOTSv1 data set has the following data sources that are common in many environments including ours:

- [IDS Alerts](#ids-alerts)
- [Firewall Logs](#firewall-logs)
- [Web Server Logs](#web-server-logs)
- [Stream Events](#stream-events)
- [Windows Event Logs](#windows-event-logs)
- [Endpoint Monitoring Events](#endpoing-monitoring-events)


A good practice in both hunting and intrusion analysis is to start with alerts or suspicious traffic on the network, trace it back to the source endpoints, find the responsible processes on each endpoint, and then identify the files responsible for each of the processes.  

In the first scenario case we start with a large amount of IDS alerts for traffic to a website.  To get more information, we next investigate web server logs and stream events, and finally examine events on the endpoints involved. 


### IDS Alerts

IDS tools use signature content and generic signature mechanisms to recognize traffic associated with known attacks and anomalies.  When evaluationg IDS alerts, you must keep the following key concepts in mind:

An **attack** is a violation of set policy parameters.  An **alert** is one or more attack instances. In many cases, an alert represents a single detected attack. A multi-attack alert is generated when multiple instances of identical attacks (same source IP, destination IP, and specific attack) are detected within a short time period.

An attack can be:
- **Successful** - the attack was successful
- **Unsuccessful** - the attack had no impact
- **Inconclusive** - not enough environment-specific information (such as OS or application) is known to confirm if the attack was successful or not
- **N/A** - the alert was raised for suspicious, but not necessarily malicious, traffic. This result is common for Reconnaissance attacks due to the nature of port scanning and host sweeping.
- **Blocked** - the attack was blocked by a "Drop packets" sensor response


Many IDSs have a very broad policy for detecting suspicious traffic to reduce the chance of false negatives.  For this reason, alerts almost always require additional investigation and context to determine the nature of the traffic observed.

This requires gathering additional information that will help determine if the reported attack had any chance of being successful:
- What type of attack was detected----name, description, etc.?
- What systems were involved?
- What ports were involved?
- Is there a relevant CVE/security patch?
- What are the possible effects of the attack?
- What are the platforms affected?
- What is the recommended solution?
- Does the attack apply to the OS/application installed on the target host? 
- Does the attack apply to the OS/application version installed on the target host? 

<br>

Using the BOTSv1 dataset, we can see that Suricata IDS is used in this environment.  Across over 5 million events, we can see 5 different event types:  flow, dns, tls, http, and alert:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image002.png)<br><br>

The alerts are what we want to look at first---events that the IDS **thinks** may be an attack.  These occurred on two days----August 10th and 25th.

On the 10th, a quick search shows the host `imreallynotbatman.com` was involved in 489 of the 623 events that day, all of them between 16:36 and 16:53:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image003.png)<br><br>

Further investigation reveals `imreallynotbatman.com` is a website hosted on the `we1149srv` server.  This search shows the IDS events for that server that day grouped by `category` and `src`:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image034.png)<br><br>


**This is the value of IDS alerts**---we've identified a web server that appears to be under attack from IP address `40.80.148.42` and requires further investigation.  The additional information we need will be in firewall logs and server web logs.

### Firewall Logs

Firewall devices also log network traffic and produce alerts based on signatures and behaviors and in this environment they come from a Fortigate firewall.  The most frequent alert message for the 10th was regarding the web scan:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image042.png)<br><br>


If we filter out the scan and login events, we see the tail end of the web scan followed by a backdoor alert involving a new IP address (23.22.63.114):

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image043.png)<br><br>

Investigating all traffic from this IP in the firewall logs reveals it visited two pages---an admin page and a page named `agent.php`:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image044.png)<br><br>

The admin page visits lasted only a minute or two from 16:45-16:46 while the visits to agent.php started a few minutes after the scan ended and continued til 17:21:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image040.png)<br><br>

We now have two IP addresses that appear to be part of the attack.  Web access logs on the victim host may provide more context.

### Web Server Logs

Web server logs contain information about requests and responses to and from web servers.  In this dataset, there is one web server named `we1149srv` (192.168.250.70) which is hosting the website `imreallynotbatman.com`.

This sourcetype includes fields for status, user agent, referer, method, source IP address and port, client, and uri for each request.  Looking at the `c_ip` (client IP) field, we recognize two of the IP addresses that have made requests to this web server:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image007.png)<br><br>

The thousands of unique URIs requested by 40.80.148.42 is another indication of a web application scan.  But the other IP address (23.22.63.114) only visits two unique pages:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image045.png)<br><br>

We want to look closer at these requests, but web logs do not log the actual content being passed, only some basic fields:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image046.png)<br><br>

To see the actual content, we would need full packet capture logging or stream events.

### Stream Events

Stream sourcetypes contain the information from raw packets captured on the wire.  Similiar to how Wireshark operates, each captured packet is examined in an attempt to detect the different applications and protocols being used.  If they are recognized, the packet data and metadata can be correctly parsed into fields and indexed for searching.

The stream sourcetypes in this dataset are categorized by protocol:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image005.png)<br><br>

Each protocol has different fields containing the data and metadata we need from each packet.  Here are the contents of some DNS requests:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image006.png)<br><br>

This is great when you need to inspect the actual data that was passed across the wire that may not be available in other event logs.  

HTTP web logs didn't show the contents of the requests made by (23.22.63.114), but `stream:http` logs reveal the activity from 16:45-16:46 was a password attack:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image047.png)<br><br>

The second period of activity shows base64-encoded data being passed between the attacker and the victim web server with each web request, indicating the attacker successfully uploaded a backdoor:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image041.png)<br><br>

So how did the attacker upload the malicious file?  We can search HTTP stream data for any successful uploads:

```
index=botsv1 sourcetype=stream:http upload successful
```

This returns two events, one containing the entire executable that was uploaded:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image038.png)<br><br>

In this logged event is the name of two files that were uploaded:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image039.png)<br><br>

Next, event logs on the host should be examined.

### Windows Event Logs

These are events from the Security, System, and Application Event Logs on every host.

Important Event Codes:

|EventCode|Description|
|-|-|
|4624|Successful logon|
|4625|Failed logon|
|4688|Process creation|
|4738|Account modification|
|5140|File share access|
|5156|Windows Firewall Network connection by process|
|7045|Service added or modified|
|4663|File access|
|4657|Registry key access|

<br>

The majority of event types in the BOTSv1 dataset are authorization policy changes, process creations/terminations, and logons/logoffs:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image004.png)<br><br>

Shortly after the web scan ends, searching processes started by the joomla user shows a few commands the attacker ran including the one that executes 3791.exe:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image048.png)<br><br>


### Endpoint Monitoring Events

Endpoint monitoring can range from simple policy-based alerting tools like [Tripwire](https://github.com/Tripwire/tripwire-open-source) to fully featured, agent-based live forensics tools like [FireEye HX](https://www.fireeye.com/solutions/hx-endpoint-security-products.html) and [GRR Rapid Response](https://github.com/google/grr).  

Here are some common endpoint monitoring tools:

|Tool|Capabilities|
|-|-|
|FireEye HX|- Signature based and behavior based threat detection<br>- Alerting with proprietary and custom IOCs<br>- Enterprise searching, live forensics, and endpoint containment<br>- Remotely acquire memory, files, and triage packages|
|McAfee VirusScan Enterprise (VSE)|- Performs OAS scans on file objects being accessed<br>- Detects and deletes known malware before it can attempt to install<br>- Evaluates code based on behavior, reputation, and threat correlation (Artemis)<br>- Blocks ports, files, folders, registry actions according to rules|
|McAfee Solidcore|- Blocks unauthorized software and/or allows authorized software<br>- Ensures that only trusted applications run on endpoints<br>- Documents system changes, registry and file creations/deletions/changes<br>|
|McAfee Data Loss Prevention (DLP)|- Monitors removable storage device plugs/unplugs<br>- Detects policy changes|

<br>

In the BOTSv1 dataset, the tool used for monitoring host events is Microsoft Sysinternals [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) which can be configured to detect a number of potentially suspicious system events:

|Event ID|Description|
|-|-|
|0|Sysmon Service Status Changed|
|1|Process Create|
|2|File Creation Time Changed|
|3|Network Connection|
|4|Sysmon Service State Change|
|5|Process Terminated|
|6|Driver Load|
|7|Image Load|
|8|CreateRemoteThread|
|9|RawAccessRead|
|10|Process Access|
|11|File Create|
|12|Registry Object CreateDelete|
|13|Registry Value Create|
|14|Registry Object Rename|
|15|File Create Stream Hash|
|16|Sysmon Configuration Changed|
|17|Pipe Created|
|18|Pipe Connected|
|255|Error|

<br>

Most of the events with this sourcetype are network connections and image loads but you will also see some file/process creations and driver loads:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image014.png)<br><br>

Image Load events can be used to find malicious programs. This search looks for unsigned executables running out of non-standard directories and returns SHA1 and IMPHASH values:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image051.png)<br><br>

The executable has been seen before on VirusTotal:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image052.png)<br><br>

Process Create events can provide details about how these programs ran such as the user, parent process, and command line arguments.

Searching the time period after the scan ended for Sysmon's `Process Create` events, we can filter out a few legitimate processes and observe the process tree associated with the intruder's activity:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image049.png)<br><br>

This shows the backdoor file `3791.exe` spawning a `cmd.exe` process which is used to run several different commands on the server.

Later we can see the PGP-CGI-spawned `cmd.exe` processes being used to deface the web server:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image050.png)<br><br>

Network Connection events are useful for identifying connections to attacker infrastructure and the processes responsible:

![](images/Common%20Functions%20and%20Data%20Sources%20in%20Splunk/image053.png)<br><br>

## Summary

Each sourcetype provides different information---being able to use Splunk to find evidence from each of them and use it to build a complete picture of the incident is required for effective analysis and response in our environment.  The BOTSv1 data is a great way to practice techniques you know and learn new techniques.

The Splunk site has some great articles and examples for additional training:

- https://www.splunk.com/blog/2018/01/17/finding-new-evil-detecting-new-domains-with-splunk.html

- https://www.splunk.com/blog/2018/03/20/hunting-your-dns-dragons.html

- https://www.splunk.com/blog/2017/12/11/tall-tales-of-hunting-with-tls-ssl-certificates.html

- https://www.splunk.com/blog/2018/07/27/i-have-a-fever-and-the-only-cure-for-it-is-more-feedback.html

- https://www.splunk.com/en_us/solutions/solution-areas/security-and-fraud/security-investigation/getting-started.html

- https://www.splunk.com/en_us/form/security-investigation-online-experience-endpoint.html