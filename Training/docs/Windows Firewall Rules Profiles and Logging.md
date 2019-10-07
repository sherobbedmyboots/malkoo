# Windows Firewall Rules, Profiles, and Logging

Windows firewall is a host-based, stateful firewall that is installed by
default on all of our Windows systems.

This document will review:

- [Firewall Rules](#firewall-rules)
- [Firewall Profiles](#firewall-profiles)
- [Firewall Logging](#firewall-logging)
- [Hosts Using VPN](#hosts-using-vpn)
- [Gathering Information](#gathering-information)
- [Scenarios](#scenarios)

## Firewall Rules

Rules determine what traffic the host is allowed to send/receive and
what traffic it is not. 

This is how most firewalls, both network and host-based, manage traffic:

- Inbound traffic is blocked unless it matches a rule
- Outbound traffic is allowed unless it matches a rule


Each time an interface sends or receives a packet, the rules are checked
to see if the traffic meets a rule condition.

|||
|-|-|
|Built in rules|Default rules to allow services such as RPC, File sharing, etc.|
|Local rules|Rules created on the local host|
|Group Policy rules|Rules managed by Group Policy|

If traffic matches a rule, it is blocked or allowed per the rule.


And if the traffic does not match a rule:

- All inbound traffic is dropped
- All outbound packets are allowed

Rules can be based on IP address, port, protocol, computer, user,
program path, or service.

Windows 10 hosts have cmdlets such as `Get-NetFirewallRule` and
`Get-NetFirewallPortFilter` to manage rules.

But this command lists all firewall rules on a Windows 10 or Windows 7
machine:

```powershell
netsh advfirewall firewall show rule name=all
```


Here I've filtered for the rules allowing PowerShell Remoting (WinRM)
traffic and specified the lines I want to see before and after the
select-string match:

```powershell
netsh advfirewall firewall show rule name=all | Select-String 5985 -context 9,4
```


This shows all the details of each rule including the name, ports, ip
addresses, and action.

Notice there is a rule for the Domain profile and one for the Private
and Public profiles.

The rule for the Private and Public profiles requires that the Remote IP
address of an inbound WinRM connection belongs to the local subnet.

## Firewall Profiles

Firewall profiles are used to apply security rules to a computer
depending on its network connection.

This allows different sets of rules to be used when connecting to
trusted and untrusted networks.

There are three profile types:

Type|Security|Description
-|-|- 
Domain|Least Restrictive|Computer is joined to a domain and is able to detect its domain controller| 
Private||User confirms computer is on a trusted network behind a NAT device such as a router or firewall|
Public|Most restrictive (Default)|Computer is connected to an untrusted network|

If an interface's profile is set to a less restrictive category such as
Domain or Private, the firewall may allow other systems to connect to
and interact with its services.


## Firewall Logging

Windows Firewall logs are stored in the following files by profile type:

```powershell
C:\windows\system32\logfiles\Firewall\domainfirewall.log
C:\windows\system32\logfiles\Firewall\privatefirewall.log
C:\windows\system32\logfiles\Firewall\publicfirewall.log               
```

When a system first boots up, the Public profile set while it attempts
to find and join its domain or other available networks.

Looking at the logs after a reboot is a great way to see how traffic is
handled differently depending on the profile category that is set.

To see the column names, use the head parameter:

```powershell
Get-Content C:\Windows\System32\LogFiles\Firewall\publicfirewall.log -head 5
```


To see the most recent logs, use the tail parameter:

```powershell
Get-Content C:\Windows\System32\LogFiles\Firewall\publicfirewall.log -tail 30
```


When a host joins a domain, the profile changes to
Domain and logging to the Public profile logs stopped.

Now all firewall logging will be stored in the `domainfirewall.log` file.

There are cases though when a host has another interface in addition to
the network interface used on the domain.

## Hosts Using VPN

Here is what happens when a user joins the network using a VPN:

- Host connects to the user's home network and obtains an IP address---this is assigned by the user's (or ISP's) routing
    device

- If it is the first time joining this network, the user is asked
    whether this is a Home (Private), Work (Domain), or Untrusted
    (Public) network.  A non-admin user is forced to choose `Public,` which is the most
    secure profile category

- The VPN client software connects to the public-facing VPN
    servers using this interface. This connection is a tunnel that the host can now use to communicate
    with other hosts on the domain

- The host contacts a domain controller through the tunnel which
    assigns an internal IP address to the host

- All traffic to and from the domain is routed through the
    encrypted VPN tunnel using the internal IP address

When a host is joined to the domain over a VPN tunnel, the traffic
coming to and from the internal address is monitored by tools on the
network.

DHCP logs show where they were given an address, the DNS logs show
requests that it makes, and proxy logs show the websites visited.

However, traffic going to and from the user's IP address on his home
network will not be available.

There are times when endpoint tools such may
observe an event involving this other interface since they monitor all
of the system's interfaces, not just the one connected to the network.

In this scenario, we'll need to rely on information gathered from the endpoint to
determine what happened.


## Gathering Information

The
[Get-NetConnectionProfile.ps1]()
script will list the networks being used on a host along with their
firewall profile category, IP address, and status.

To use it, run it with `Invoke-Command`:

```powershell
Invoke-Command -ComputerName <computer> -FilePath .\Get-NetConnectionProfile.ps1
```


Hosts using a VPN tunnel to access a network should have two network
connections.

The
[Get-FirewallLogs.ps1]()
script will retrieve firewall logs from a host and return them in
objects for sorting and filtering.

Use `Invoke-Command` to run it on a remote host capturing the results in a
variable (`$log`):

```powershell
$log = Invoke-Command -ComputerName <computer> -FilePath .\Get-FirewallLogs.ps1
```


See all logs:

```powershell
$log | select Date,Time,Action,Protocol,SrcIp,SrcPort,DstIp,DstPort,Size,Path | ft -auto
```

Filter on a protocol:

```powershell
$log | ? Protocol -eq UDP | select Date,Time,Action,SrcIp,DstIp,Size,Path | ft -auto
```

Filter on a profile:

```powershell
$log | ? Profile -eq Domain | select Date,Time,Profile,Action,Protocol,SrcIp,SrcPort,DstIp,DstPort,Size,Path | ft -auto
```

Filter on date and source ip address:

```powershell
$log | ? Date -match 2017-12-08 | ? SrcIp -ne 127.0.0.1 | select Time,Profile,Protocol,SrcIp,SrcPort,DstIp,DstPort,Path,Action | ft -auto
```

Show remote IPs the host talked to that day:

```powershell
$log | ? Date -match 2017-12-08 | ? Profile -eq Domain | ? Path -eq SEND | group DstIp | sort count -desc
```

