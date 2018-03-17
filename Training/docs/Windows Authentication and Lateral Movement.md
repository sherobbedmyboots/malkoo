# Windows Authentication and Lateral Movement

Once a system is compromised, the attacker most likely has control of
one or more accounts and will be trying to obtain access to additional
systems on the network.  [There are many
ways](https://attack.mitre.org/wiki/Lateral_Movement) for an attacker to
perform lateral movement including the use of logon scripts, removable
media, shared content, `regsvcs`, `regasm`, etc.  But here are three
common techniques used and the countermeasures for each:

|Technique|Countermeasure|
|-|-|
|Hash/Ticket Stealing|Avoid interactive logons to untrusted hosts|
|Access Token Stealing|Ensure accounts cannot be delegated|
|Network Authentication Attacks|Use Kerberos whenever possible|

Since we regularly respond to potentially untrusted hosts using
privileged accounts, it is important we do not give attackers the
opportunity to hijack our credentials in the process as it could allow
them to execute commands under the security context of our admin
accounts.  These commands can start malicious services, create
persistence, and provide remote execution on additional hosts in the
network.

When using a privileged domain account to access an untrusted host,
there are three techniques that will offer improved protection of your
admin credentials:

- [Avoid Interactive Logons to Untrusted Hosts](#avoid-interactive-logons-to-untrusted-hosts)
- [Disable Delegation for Privileged Accounts](#disable-delegation-for-privileged-accounts)
- [Enforce Kerberos Network Authentication](#enforce-kerberos-network-authentication)


## Avoid Interactive Logons to Untrusted Hosts

When accessing an untrusted host, use network logons (Type 3) with `net use`, WMIC, PowerShell
Remoting, and PsExec (without `-u` alternate credentials) as they will
not store password hashes in memory or on disk on the target machine. 

Here are some Type 3 logon methods we typically use:

|Method|Command|
|-|-|
|net use|`net use x: \\<systemname>\C$`|
|WMIC|`wmic /node:<systemname> process get executablepath`|
|Psexec|`psexec \\<systemname> cmd`|

If these are not available, the next best choice is "Restricted Admin" RDP which only works when the
remote system is Windows 8.1 or Server 2012R2 and does not expose
account credentials on the target machine.  However, pass-the-hash or
pass-the-ticket attacks can still be used against the remote host.

Last choice, and what you should try to avoid at all costs, is
interactive logons with RDP, VNC, RunAs, and PsExec with `-u` as they
expose LM, NT, encrypted passwords, and Kerberos TGTs to the remote
system.  These methods keep the LM hash in memory if the password is
less than 15 characters, regardless of security settings.  Also, an
encrypted version of the clear-text password is kept in memory by
default for SSO to services.

## Disable Delegation for Privileged Accounts

Types of Tokens:

|Token|Description|
|-|-|
|Anonymous|Process can impersonate you as an anonymous user|
|Identification|Process can pull your token to validate credentials|
|Impersonation|Process can perform tasks as a different user only on the local computer|
||Created from remote network logons|
||For SMB, the SMB server is impersonating the privileges of the remote user, to access files and services under the user's security context|
|Delegation|Process can call resources and perform tasks on other computers as a different user (Kerberos double-hop authentication)|
||Created from interactive logons or network logons to certain services such as SharePoint|
||Client authenticates to front-end web server, web server connects to SQL server as the authenticated client|
||Back-end database server then impersonates client to access data (documents, calendars, lists, etc.)|
||EFS also utilizes delegation for encrypting and decrypting files on behalf of the user|


The setting that prevents delegation is "Account is sensitive and cannot
be delegated".  This ensures that if an attacker steals a responder's Delegate-level token, they won't
be able to move laterally throughout the network.  However, an
Impersonate-level token will still be available to an attacker and can
be used for local privilege escalation.

## Enforce Kerberos Network Authentication

Types of network authentication in a Windows domain and applicable
attacks:

|Authentication|Description|
|-|-|
|LM CR|Client response is based on LM hash|
||Rogue server can issue a static challenge and use a pre-computed Rainbow table to determine the password hash and password|
|NTLM CR|Client response is based on either NT hash or both NT and LM hashes|
||Rogue server can issue a static challenge and use a pre-computed Rainbow table to determine the password hash and password|
|LMv2/NTLMv2 CR|Mutual authentication, client response based on NT hash|                          
||Pass-through authentication in domain environments allow a rogue server to be MITM of the authentication exchange|                  
||**Still required for authenticating to servers:**|
||	-- using IP address (which cannot be resolved to its hostname)|
||	-- that belong to a different AD forest using legacy NTLM trust instead of a transitive inter-forest trust|
||	-- that doesn\'t belong to a domain|
||	-- behind a firewall restricting the ports required by Kerberos|
|Kerberos|Mutual authentication, requires NT hash to complete authentication|
||Authentication happens directly between the client and DC, then ticket is presented to server for access|

<br>

Networks should be configured to use Kerberos whenever possible, however
systems may fall back to NTLM or NTLMv2 when Kerberos is not possible as in
the four examples listed above.

So all three security measures can be summed up into the
following rule:

**Use Type 3 Logons with Kerberos whenever possible**


## Example

A service principal name (SPN) is the name by which a Kerberos client
uniquely identifies an instance of a service for a given Kerberos target
computer.  To list Kerberos SPNs registered on a remote host, use the
setspn command:

```powershell
setspn -L <systemname>
```                          

Then depending on what services are available, you can use one of the
following Type 3 logons that authenticate using Kerberos:

- [WSMAN](#wsman)
- [SMB](#smb)


### WSMAN

WS-Management uses ports 5985/5986 and provides WMI data and event collection over encrypted HTTP/HTTPS.

Here are three ways to access a system using WSMAN:

```powershell
winrs -r:<systemname> <command>
```

```powershell
Invoke-Command <systemname> -ScriptBlock { <command> }
```

```powershell
Enter-PSSession <systemname>
```

### SMB

Server Message Block (SMB) is used for file-oriented operations and inter-process communications over port 445/TCP or using the NETBIOS API with ports 137/UDP, 138/UDP, 137/TCP, and 139/TCP. 

Here are three ways to access a system over SMB:

```powershell
start compmgmt.msc /computer:<systemname>
```

```powershell
net use x: \\<systemname>\C$
```

```powershell
psexec \\<systemname> cmd
```


So for example, if I am responding to a potentially compromised server,
I can first check to see what Kerberos services are available:

```powershell
setspn -L <target>
```

Say WSMAN is available. 

I can now PSRemote to the host (a Type 3 Logon) over Kerberos encrypted
HTTP and run commands:

```powershell
Enter-PSSession <target>
Get-Processes
```

You can check the Kerberos tickets you have with the `klist` command.


### References

http://digital-forensics.sans.org/blog/2012/02/21/protecting-privileged-domain-account-safeguarding-password-hashes
https://digital-forensics.sans.org/blog/2012/03/21/protecting-privileged-domain-accounts-access-tokens
https://digital-forensics.sans.org/blog/2012/09/18/protecting-privileged-domain-accounts-network-authentication-in-depth

