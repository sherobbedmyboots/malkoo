# Using Indicators for Detection

On a very basic level, we’ve gathered indicators, given them some context, stored and shared them—now it’s time to use them to identify malicious activity by operationalizing this data.

Here are several tools we can use with our indicators to search for evidence of an intrusion/malware:

- [Splunk](#splunk)
- [FireEye HX](#fireeye-hx)
- [Rekall and Yara](#rekall-and-yara)

## Splunk

There are ways to upload STIX and OpenIOC files to Splunk ES, but the easiest way for us to currently search indicators is to upload a CSV lookup and search against it.

There are several starting points:

- Obtain a CSV from external or open source threat information platforms such as ThreatConnect, ScoutVision, etc.
- Export CSV from an internal storage platform such as MISP, CRITs, etc.
- Create your own CSV from different sources

A CSV file is just a text file containing values separated by commas.  This one was created by exporting indicators from our simulated incident in MISP:

![](images/Using%20Indicators%20For%20Detection/image001.png)

It’s important to know the column header of the indicators you’ll be searching.  In this case the header we need is called "value"
To view the CSV, use the `inputlookup` command.  Notice all the indicators under the value field:

![](images/Using%20Indicators%20For%20Detection/image002.png)

Using the `return` command allows us to create a series of "OR" conditions:

![](images/Using%20Indicators%20For%20Detection/image003.png)

You could make different CSVs for each indicator type, or you can just change the value field for each search to match the current field you’re searching in Splunk.

The following string inputs the CSV, renames the column header to the field you want to search, and then returns the top 100 values (this number just needs to be higher than the number of indicators in your CSV file):

![](images/Using%20Indicators%20For%20Detection/image004.png)

Now, we can feed the output of this search into a search across our all proxy logs in our environment:

```
index=proxylogs [inputlookup scenario.csv | return 1000 domain
| table _time client domain 
```

You can search across different fields by changing the field values:

```
index=proxylogs [inputlookup scenario.csv | return 1000 remote_ip]
| table _time client_ip destination_host 
```

And you can search across different sourcetypes by changing the beginning of the search:

```
sourcetype=dnslogs [inputlookup scenario.csv | return 1000 query]
| table _time client query
```

## FireEye HX

With FireEye HX, an indicator is made up of one or more conditions.  When one or more of the conditions are detected on the host, an alert is triggered indicating the specific threat.

There are two types:

- FireEye Source Alerts - Indicators from information supplied by FireEye products (i.e. iSight)     
- Custom Intel - Indicators from HX user, added individually or via list

So we can take our list of indicators and add them to FireEye HX as one combined list.

First take some indicator values and put them in a text file:

![](images/Using%20Indicators%20For%20Detection/image008.png)

On FireEye’s Indicator page click `Create Indicator` and under the `Define Indicator` section click `Browse` to find your text file of indicators.  Once it is selected click `Upload`:

![](images/Using%20Indicators%20For%20Detection/image009.png)

FireEye HX will report that 12 of the conditions were uploaded but one did not have the right format.  To see which one, click on the `Download the list` button:

![](images/Using%20Indicators%20For%20Detection/image010.png)

This will download an `errors.txt` file which shows you which condition was not formatted properly and therefore was not recognized:
You’ll notice that FireEye categorized the MD5 hash correctly but thinks the sha1 and sha256 hashes are hostnames.  To fix this just click on the "x" to remove incorrectly identified conditions.

![](images/Using%20Indicators%20For%20Detection/image011.png)

Add a description for your indicator and finish creating by clicking `Create`

You should now see your indicator on the Indicator page.  If you want to edit any of the conditions in the indicator, check the box beside it, then click Actions --> Edit Indicator.

## Rekall and Yara

Rekall is a live memory forensics tool that branched from the Volatility project in 2011.  It uses a large collection of profiles for Windows, Mac, and Linux OS’s and is designed to run on the same platform it is analyzing.  Rekall’s ability to access live memory makes it a great tool for examining malware in action and can also be used to quickly triage a system without acquiring and transferring large memory images off the target machine for analysis.

Yara rules have traditionally been used to scan static files for binary or textual patterns to identify malware but can also be used in the same way to scan memory space.  Signature scanning in memory is a quick and easy way to detect malicious code during triage and incident response.  In this case we’ll use it with Rekall to search a live system’s memory for the presence of our indicators. 

### 1. Install Rekall

- On your Windows 10 Analysis VM, open a PowerShell window with Admin privileges
- Download Rekall by typing: `wget -usebasicparsing https://github.com/google/rekall/releases/download/v1.6.0/Rekall_1.6.0_Gotthard_x64.exe -O rekall_install.exe`
- When complete, install Rekall by typing `.\rekall_install.exe`
- After it installs, add the Rekall directory to your path by typing `$env:Path += "C:\Program Files\Rekall;"`
- Verify the Rekall directory is in your path by typing `$env:Path`
- Add the Python27 scripts directory to your path by typing `$env:Path += "C:\Python27\scripts;"`
- Verify the Python27 scripts directory is in your path by typing `$env:Path`
- Install virtualenv by typing `pip install virtualenv`
- After it installs, create a directory to run a virtual environment by typing `virtualenv Dev`
- Activate the virtual environment by typing `Dev\scripts\activate`
- Bring up the Rekall help menu by typing `rekal -h`
- Start live memory analysis by typing  `rekal live`

Now you have direct access to the system’s live physical memory.  Run a few commands and get used to the console:
- Type `pslist` to see a list of current processes, their process ids, start times, and other details
- Type `pstree` to see processes in tree form
- Type `dns_cache` to list cached DNS entries
- Type `tokens pids=<pid>` to see the SIDs owning each process token


### 2. Create a YARA rule

A Yara rule has three parts:

- Metadata - Used for documentation
- Strings - Lists named strings, encoded, wildcards, character matching
- Condition - Matching condition that will trigger the rule

Here is a generic rule that we will modify to search for a PowerShell Empire agent in memory:

![](images/Using%20Indicators%20For%20Detection/image012.png)

One general technique is to extract strings from a sample, then pick several that are unique to that malware.

On Windows (`Sysinternals\strings.exe`):

|||
|-|-|
|`strings -a <filename>`|Extracts ASCII only|
|`strings -u <filename>`|Extracts Unicode only|
|`strings <filename>`|Extracts ASCII and Unicode|

On Linux:

|||
|-|-|
|`strings -a <filename>`|Extracts ASCII strings only|
|`strings -a -e l <filename>`|Extracts Unicode strings only|

While choosing the strings you use, keep in mind you want the rule to be both specific and generic. 

The goal is to pick strings that are unique enough to avoid tons of false positives, but not so unique that your YARA rule will only alert on that one sample (like a hash value).

Normally, malware may contain multiple unique strings we could use to identify it—but in this case the executable being used is PowerShell which is present on almost every Windows system.

There are some very good Yara rules out there designed to catch Empire agents, but for this example we’ll just use a couple of unique strings to demonstrate how a basic Yara rule is created and improved.

Remember some of the interesting strings we obtained from memory analysis of our first victim:

![](images/Using%20Indicators%20For%20Detection/image013.png)

The domain name is the most specific, yet still generic string out of all of these…

If it’s present in a system’s memory, there is a very low chance of a false positive.  But it is also generic enough to catch different protocols and page names used by the agent to contact its C2 server.

### 3. Run PowerShell Empire Stager

- Locate the Empire launcher script for this exercise at `/CSIRT/Sample-Files/launcher.bat`
- Move it to your Windows 10 Analysis VM Desktop and double click it.
- Use Process Explorer to verify it created a PowerShell process with a long encoded string in the argument:

![](images/Using%20Indicators%20For%20Detection/image014.png)


Now find the process using Rekall…

The `pstree` plugin shows the parent PIDs and processes involved:        
   
`explorer -> cmd.exe -> powershell.exe (1168)`

![](images/Using%20Indicators%20For%20Detection/image015.png)


Identify the PID of the PowerShell process and use Rekall’s `yarascan` plugin to search for the domain:

![](images/Using%20Indicators%20For%20Detection/image016.png)


Now change the generic Yara file to match the one below which looks for a string of the domain (`$a1`) as well as a regular expression for a .php page with 3 to 7 lowercase characters (`$r1`):

![](images/Using%20Indicators%20For%20Detection/image017.png)


Using this Yara rule returns hits for both the domain and the page name (`get.php`)

![](images/Using%20Indicators%20For%20Detection/image018.png)


There are other characteristics of Empire agents that we can search for, especially if they still have their default configurations.

For example, an Empire agent by default is configured to use the following 3 pages on its C2 server:

```
/admin/get.php
/news.php
/login/process.php
```

We can modify our Yara rule to search for any of these three strings:

![](images/Using%20Indicators%20For%20Detection/image019.png)

And Rekall can use it to find evidence of the agent’s C2 within the PowerShell process:

![](images/Using%20Indicators%20For%20Detection/image020.png)

Wireshark confirms these are the pages being used for C2:

![](images/Using%20Indicators%20For%20Detection/image021.png)
