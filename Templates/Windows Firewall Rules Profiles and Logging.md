# Windows Firewall Rules, Profiles, and Logging

 
Windows firewall is a host-based, stateful firewall that is installed by default on all of our Windows systems.
 
This document will review:
 
- Firewall Rules
- Firewall Profiles
- Firewall Logging
- Hosts Using VPN
- Gathering Information
- Scenarios
 
 
## Firewall Rules
 
Rules determine what traffic the host is allowed to send/receive and what traffic it is not. 
 
This is how most firewalls, both network and host-based, manage traffic:
 
- Inbound traffic is blocked unless it matches a rule
 
- Outbound traffic is allowed unless it matches a rule
 
 
Each time an interface sends or receives a packet, the rules are checked to see if the traffic meets a rule condition.
 
- Built in rules                       Default rules to allow services such as RPC, File sharing, etc.
- Local rules                           Rules created on the local host
- Group Policy rules           Rules managed by Group Policy
 
If it matches, it is blocked or allowed per the rule.
 
 
And if the traffic does not match a rule:
 
- All inbound traffic is dropped
 
- All outbound packets are allowed
 
 
 
Rules can be based on IP address, port, protocol, computer, user, program path, or service.
 
Windows 10 hosts have cmdlets such as Get-NetFirewallRule and Get-NetFirewallPortFilter to manage rules.
 
But this command lists all firewall rules on a Windows 10 or Windows 7 machine:
 
Netsh advfirewall firewall show rule name=all
 
 
 
Here I’ve filtered for the rules allowing PowerShell Remoting (WinRM) traffic and specified the lines I want to see before and after the select-string match:
 
Netsh advfirewall firewall show rule name=all | sls 5985 –context 9,4
 
 
 
This shows all the details of each rule including the name, ports, ip addresses, and action.
 
Notice there is a rule for the Domain profile and one for the Private and Public profiles.
 
The rule for the Private and Public profiles requires that the Remote IP address of an inbound WinRM connection belongs to the local subnet.
 
 
 
 
## Firewall Profiles
 
Firewall profiles are used to apply security rules to a computer depending on its network connection.
 
This allows different sets of rules to be used when connecting to trusted and untrusted networks.
 
There are three profile types:
 
- Domain                                Least Restrictive                                               Computer is joined to a domain and is able to detect its domain controller
 
- Private                                                                                                                  User confirms computer is on a trusted network behind a NAT device such as a router or firewall
 
- Public                                    Most restrictive (Default)                             Computer is connected to an untrusted network
 
 
 
If an interface’s profile is set to a less restrictive category such as Domain or Private, the firewall may allow other systems to connect to and interact with its services.
 
 
[connecting to service example]
 
This is expected behavior on our network because the host has connected to its domain and trusts other hosts on the network.
 
Most workstations on our network should have one network connection and it should be set to Domain.
 
 
 
 
## Firewall Logging
 
Windows Firewall logs are stored in the following files by profile type:
 
C:\windows\system32\logfiles\Firewall\domainfirewall.log
                C:\windows\system32\logfiles\Firewall\privatefirewall.log
                C:\windows\system32\logfiles\Firewall\publicfirewall.log
 
 
 
When a system first boots up, the Public profile set while it attempts to find and join its domain or other available networks.
 
Looking at the logs after a reboot is a great way to see how traffic is handled differently depending on the profile category that is set.
 
To see the column names, use the head parameter:
 
To see the most recent logs, use the tail parameter:
 
I rebooted my host and the first log events that were recorded were dropped TCP packets to port 22350 from host x:
 
So most likely Nessus happened to be scanning the entire network for a vulnerability associated with port 22350.
 
Next we see some DHCP broadcast traffic to port 67 in an attempt to obtain (in this case renew) an IP address:
 
Then DNS traffic to 53/UDP:
 
The two destinations are one of several DNS servers on the network:
 
Port 5355/UDP is used for Link-Local Multicast Name Resolution (LLMNR) used to resolve names that can’t be resolved using DNS:
 
More DNS requests:
 
Then we see what looks to be some Domain Controller related traffic:
 
389/TCP – Active Directory
88/TCP – Kerberos
135/TCP – DCE/RPC
 
This must be the host attempting to join the network so naturally the traffic is allowed.
 
We can confirm they are domain controllers with Nslookup:
 
We can see another host tries to connect using DCE/RPC and NetBIOS but my host drops the packets—it is still set to Public Profile:
 
Turns out this was another domain controller:
 
Another host from the local subnet sends NetBIOS to the subnet’s broadcast address but my host drops the traffic:
 
Resolved its address to a name using ping:
 
And discovered it is a printer:
 
When the host was able to join the domain, the profile changed to Domain and logging to the Public profile logs stopped.
 
Now all firewall logging will be stored in the domainfirewall.log file.
 
There are cases though when a host has another interface in addition to the CIS network interface.
 
 
## Hosts Using VPN
 
 
Here is what happens when a user joins the network using a VPN:
 
 
- Host connects to the user’s home network and obtains an IP address (10.0.0.168), this is assigned by the user’s (or ISP’s) routing device:
 
 
- If it is the first time joining this network, the user is asked whether this is a Home (Private), Work (Domain), or Untrusted (Public) network:
 
A non-admin user is forced to choose Public, which is the most secure profile category:
 
 
- The VPN client software connects to the public-facing VPN servers using this interface:
 
 
This connection is a tunnel that the host can now use to communicate with other hosts on the network.
 
 
- The host contacts a domain controller through the tunnel which assigns a IP address to the host:
 
 
- All traffic to and from the network is routed through the encrypted VPN tunnel using this address:
 
 
 
When a host is joined to the domain over a VPN tunnel, the traffic coming to and from the address is monitored by tools on our network.
 
We can look in Splunk and see where they were given an address, the DNS requests that it makes, and the websites visited using proxy logs.
 
However, traffic going to and from the user’s address on his home network will not be available.
 
There are times when our endpoint tools such as FireEye and McAfee may observe an event involving this other interface since they monitor all of the system’s interfaces, not just the one connected to the network.
 
When this happens, we won’t have any logs in Splunk that will help us, we’ll need to rely on information gathered from the endpoint to determine what happened.
 
 
 
 
## Gathering Information
 
The Get-NetConnectionProfile.ps1 script will list the networks being used on a host along with their firewall profile category, IP address, and status.
 
To use it, run it with Invoke-Command.  This host is on the wired network with a profile set to Domain:
 
Hosts using a VPN tunnel to access our network should have two network connections:
 
The connection to the domain is set to Domain.
 
This user’s home network is named ‘ATS-AP02’ and the connection to it is set to Public.
 
 
The Get-FirewallLogs.ps1 script will retrieve firewall logs from a host and return them in objects for sorting and filtering.
 
Use Invoke-Command to run it on a remote host capturing the results in a variable ($log):
 
 
See all logs:
 
Filter on a protocol:
 
Filter on a profile:
 
Filter on date and source ip address:
 
Show remote IPs the host talked to that day:
 
 
## Scenarios
 
There are several scenarios where it helps to obtain a workstation’s firewall logs and network profile categories.
 
One example is if a workstation’s home IP address gets scanned. 
 
McAfee has several alerts that can detect this such as:
 
- Network Intrusion Detected
- TCP Port Scan
- UDP Port Scan
 
Firewall logs will show the IP address of the scanning device and whether the traffic was dropped or allowed.
 
 
 
 
Another scenario is when a VPN user either has no router, or uses a router that allows inbound traffic from the Internet.
 
This can result in McAfee alerts as well and may also cause FireEye alerts if the scanning IP is on a blacklist.
 
 
An example FireEye alert that flagged a blacklisted IP:
 
- Ipv4NetworkEvent/remoteIP equal x.x.x.x
 
The firewall logs will contain events for the traffic from the scanning IP address and whether it was allowed or dropped.
 
 
 
Finally, firewall logs can be used to determine other events we may be interested in including:
 
- Who a host talked to on the domain
- Who a host talked to on their home network
- Who talked to the host and what network they were on
- When the host obtained a DHCP lease
- What protocols the host is sending and receiving
- When the host joined a network
 