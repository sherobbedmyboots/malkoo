# Detecting Lateral Movement with Splunk

The vast majority of lateral movement involves authentication.  If an
attacker has compromised an account, the account's access token can be
used to log on to other systems.  If valid credentials are found/stolen
from a different account, they can be used to generate a new access
token which can be used to log on to other systems.  To successfully
pivot, the attacker only has to find or create an access token that has
privileges to authenticate to a second system.

The details of your access token can be viewed with the command `whoami
/all`.  This shows user, group, and privilege information about your
account.  This information can be used with Active Directory queries to
determine which systems can be logged into with your access token.  A
low integrity account, such as a computer account, may not have access
to many systems and could make lateral movement difficult for the
attacker.  However, a high-integrity account, such as an admin account,
could have access to hundreds or thousands of systems and could be used
to pivot almost anywhere in the network. 

## Lateral Movement Techniques

Here are five ways lateral movement could be accomplished in our network
and the event logs created by each:

### 1. Copy file to remote system

Use of cmd.exe or PowerShell to transfer file to remote machine over SMB
(port 445).  This example uses Xcopy to transfer a pcap file to a remote
server:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image001.png)


When I tried to replicate with my non-admin account, I received an
Access Denied message, but only generated logon and logoff events:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image002.png)


Attempts to copy to desktops produced the same types of events.  So
unsuccessful attempts on multiple hosts should create logon and logoff
events on all hosts.

### 2. Start a process with WMI

WMI uses DCOM (port 135, 41952, 41953, 41954) to log on the remote
machine and start a process.  This example uses the wmic command to log
on a remote server and start the `notepad.exe` process:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image003.png)


When I tried to replicate with my non-admin account, I received an
Access Denied message, but only generated logon and logoff events:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image004.png)


               

When I tried to pivot to a desktop, I received an Access Denied
message and generated several failed logon events:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image005.png)


So unsuccessful attempts on multiple hosts should create logon, logoff,
and failed logon events on all hosts.

### 3. Start a process with PowerShell Invoke-Command

PowerShell uses WSMAN, encrypted HTTP over port 5985, to set up a remote
session.  This example creates a remote session to a remote server and
executes the `ipconfig` command:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image006.png)


When I tried to replicate with my non-admin account, I received an
Access Denied message, but only generated logon and logoff events:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image007.png)

When I tried to pivot to a desktop, I received an Access Denied
message and generated several failed logon events:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image008.png)


So unsuccessful attempts on multiple hosts should create logon, logoff,
and failed logon events on all hosts (with no Source Network Address
listed).

### 4. Start a remote session with PSEXEC

Uses remote service manager to start the PSEXEC service over SMB port
445.  This example uses PSEXEC to open a remote session on a server
and run the `net user` command:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image009.png)


When I tried to replicate with my non-admin account, I received an
Access Denied message, but only generated logon and logoff events:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image010.png)


When I tried to pivot to a desktop, I received an Access Denied message
and generated several failed logon events:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image011.png)


So unsuccessful attempts on multiple hosts should create logon, logoff,
and failed logon events on all hosts.

### 5. Start a remote session with PowerShell

PowerShell uses WSMAN, encrypted HTTP over port 5985, to set up a remote
session.  This example creates a remote session to a remote server and
executes the `ipconfig` command:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image012.png)


When I tried to replicate with my non-admin account, I received an
Access Denied message, but only generated logon and logoff events:

       
![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image013.png)


When I tried to pivot to a desktop, I received an Access Denied message
and generated several failed logon events:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image014.png)


So unsuccessful attempts on multiple hosts should create logon, logoff,
and failed logon events on all hosts (with no Source Network Address
listed).

## Detection with Splunk

Although other accounts may behave differently, testing with my admin
and non-admin account on servers and desktops gives us a starting point
of what we need to be looking for:

|Lateral Movement Technique|Successful|Unsuccessful|
|-|-|-|
|Copy file to a remote system|4624, 4634, 4672, 4663|4624, 4634|
|Start a process with WMI|4624, 4634, 4672, 4688, 4634|4624, 4625, 4634|
|Start a process with PowerShell Invoke-Command|4624, 4634, 4672, 4688, 4674|4624, 4625, 4634|
|Start a remote session with PSEXEC|4624, 4634, 4672, 4688, 4674, 7045|4624, 4625, 4634|                                                                             
|Start a remote session with PowerShell|4624, 4634, 4672, 4688, 4674, 4656|4624, 4625, 4634|

Also, the logging of a Source Network Address can indicate the use of
WSMAN (PS remoting/Invoke-Command), or file copy, PSEXEC, and WMI.

So assuming an account is compromised and being used to pivot, a good
rule that will catch successful and unsuccessful attempts of all five
techniques would be:
<br>
**Logons and failed logons to many machines by one
account**
<br>
To put this rule to use in Splunk, we can use a technique called data
stacking, also known as frequency analysis or "long tail analysis."  It
stacks specific field values in order of frequency to identify outliers
and anomalies.  For example, a low number of machines with the
executable `djflkspolfkd.exe` present would indicate the file is not
normal and does not belong on the machine.  The same logic is used with
account logons---a high number of machines logged onto by one account
(especially a non-admin account) is not normal and indicates potential
lateral movement.

Here is how we could do this with Splunk:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image015.png)


This search looked through all domain accounts generating 4624 and
4625 events (with the exception of some service accounts) and returned
the accounts attempting logons to the highest number of unique
systems---the outliers.  My admin account had the most because I used it
to simulate pivot attempts trying one host after another, looking for a
system where I could use my access token to run a command with
`Invoke-Command`.  In this case, my access token did allow me to logon to
nearly all of the hosts and run the command, but as we saw earlier we
should get the same successful logon events with an access token that's
not allowed to run commands on the target system:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image016.png)


Testing with my non-admin account produced Access Denied messages each
attempt, but 4624's were still logged for each target host and my
account was identified as an outlier (not by much).  Obviously, hundreds
of machines touched by a single account would be even more suspicious
but keep in mind there are some accounts that do this for a legitimate
purpose (scans, backups, etc.).

Other searching options:

Filtering on 4672 events instead of 4624's and 4625's:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image017.png)


Filtering on 4688 events gives us a similar output:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image018.png)


Adding the **New_Process_Name** field as an argument gives
us more insight to what command is being run by the accounts on each
system:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image019.png)


But probably the most likely scenario is a non-admin account trying to
find a system it can execute a command on which according to earlier
tests should always produce 4624 (and 4634) or 4625 events.  So I tried
to access a long list of hosts with my non-admin account and ran this
search to find the activity, which does the following:

- Looks at Windows 4624 and 4625 events
- Changes all user values to lower case
- Eliminates duplicate user/host events
- Filters out user values that are in a exclusion list csv
- Finds the distinct count of hosts connected to by each user
- Sorts users with most hosts up top

A search for the day shows my non-admin as a huge outlier, and my admin
account second:

![](images/Detecting%20Lateral%20Movement%20with%20Splunk/image020.png)
