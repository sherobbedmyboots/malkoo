# Kerberoasting Revisited

Enterprise users are prime targets for an adversary---if successfully compromised, the attacker will be able to run
commands on the system within the context of a domain user. This provides the ability to scan the entire
AD environment for privilege escalation opportunities.  One of the most effective techniques used in this situation
to obtain access to a privileged account is called Kerberoasting.

[Kerberoasting](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/) is performed by obtaining a service ticket for a service associated with a user account.  Within this ticket
is data that is encrypted with the NTLM hash of the user account's plaintext password. This ciphertext can then be
fed to a tool and cracked offline avoiding failed logon attempts and AD account lockouts.

This training document will review how this technique is used and ways to identify accounts in the environment that would be the most vulnerable:

- [Kerberos and Active Directory](#kerberos-and-active-directory)
  - [Users](#users)
  - [Computers](#computers)
  - [Services](#services)
- [Kerberoasting](#kerberoasting)
  - [Active Directory Recon](#active-directory-recon)
  - [Request Service Ticket](#request-service-ticket)
  - [Crack Encrypted Ticket](#crack-encrypted-ticket)
  - [Use Cracked Password](#use-cracked-password)
- [Roastable Accounts](#roastable-accounts)
  - [Service Principal Name](#service-principal-name)
  - [Kerberos Encryption Type](#kerberos-encryption-type)
  - [Password Strength](#password-strength)

<br>

Previous training:

- [Identifying Accounts Vulnerable To Kerberoasting](./Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting.md)
- [Privilege Escalation Using Active Directory](./Privilege%20Escalation%20Using%20Active%20Directory.md)
- [Authentication Using Smart Cards and Public Key Kerberos](./Kerberoasting%20Revisited.md)


## Kerberos and Active Directory

Two methods of authentication in our environment:

|Authentication Method|Description|
|-|-|
|NTLMv2|Performs mutual authentication with client response based on NT hash<br>**Still required for authenticating to servers:**<br>--- IP address (which cannot be resolved to its hostname)<br>--- belonging to a different AD forest using NTLM trust instead of forest trust<br>--- don't belong to a domain<br>--- behind a firewall restricting the ports required by Kerberos|
|Kerberos|Performs mutual authentication using third party<br>**Authentication happens directly between the client and DC**<br>--- Client requests ticket from DC<br>--- Client presents ticket to server for access|


<br>

In a Kerberos realm, users are given a User Principal Name (UPN) and hosts and services are given
a Service Principal Name (SPN).  The Key Distribution Center (KDC) on a domain controller
authenticates entities with its Authentication Server (AS) and grants tickets
with its Ticket Granting Service (TGS).

In order to access a host or service on the network, an entity must prove their identity to the KDC so
they can receive a Ticket Granting Ticket (TGT).  The TGT is then used for as long as it's valid (10
hours) to prove to hosts and services on the network that it successfully authenticated with
the KDC and is who it claims to be.

Data sent between the KDC and each entity is encrypted using the entity's secret
key (password) so that only someone who has possession of the secret key can decrypt the data.

Three main components to understand:

- [Users](#users)
- [Computers](#computers)
- [Services](#services)

### Users

Each user has a User Principal Name (UPN) in the form of `user@REALM`.  Kerberos
implements Single Sign On (SSO) allowing a user to authenticate once and receive
a Ticket Granting Ticket (TGT) that's good for 10 hours.  This TGT is used to obtain service tickets
which can be presented to services in the domain for access.  

- User logs in as `<user>` and is prompted for Smart Card and PIN
- If successful, KDC issues a TGT good for 10 hours
- User uses TGT to get service tickets for any services on the domain
- See current tickets with `klist`

<br>

Use the [ActiveDirectory](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps) PowerShell module to see UPNs for an account:

![](images/Kerberoasting%20Revisited/image035.png)<br><br>

Or `whoami /upn`:

![](images/Kerberoasting%20Revisited/image034.png)<br><br>

### Computers

Each computer has a machine account in the form of `<hostname>$`. This account
is how the host authenticates to and interacts with Active Directory.
These accounts should be configured with a password that is randomized by default and
rotates every 30 days.

A host's various services are configured in AD such as Terminal Services (`TERMSRV`), PowerShell
Remoting (`WSMAN`), and the `HOST` service which encompasses many other common
services the host provides such as browser, cifs, dcom, rpc, samss, spooler, time, etc.

Use `Get-ADComputer` to see a computer account's attributes:

![](images/Kerberoasting%20Revisited/image002.png)<br><br>

### Services

Each service has a Service Principal Name (SPN) in the form of `Service-class/fqdn@REALM`. When a user
wants to access the `WSMAN/<server>` service:

- `<user>` uses TGT to request a service ticket for `WSMAN/<server>`
- KDC provides a service ticket with `<user>` authenticator message
- Service ticket is encrypted with password of `WSMAN/<server>` account
- `WSMAN/<server>` decrypts ticket and reads authenticator message

<br>

Use the [ActiveDirectory](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps) PowerShell module to see SPNs for a host:

![](images/Kerberoasting%20Revisited/image033.png)<br><br>

Or use `setspn -L <hostname>`:

![](images/Kerberoasting%20Revisited/image032.png)<br><br>

See your current tickets with `klist`:

![](images/Kerberoasting%20Revisited/image001.png)<br><br>

So for a user to access a service on the network, it must first obtain a TGT, then a Service Ticket for that service, then present that Service Ticket to the service.

## Kerberoasting

Kerberoasting is when an authenticated user obtains a service ticket that is encrypted with the NTLM hash of the
user account's password for offline cracking.  Service accounts are common targets since they are typically
non-human user accounts created to run a service and are often configured with simple or known passwords.

- [Active Directory Recon](#active-directory-recon)
- [Request Service Ticket](#request-service-ticket)
- [Crack Encrypted Ticket](#crack-encrypted-ticket)
- [Use Cracked Password](#use-cracked-password)

Let's walk through an exercise using a Hackthebox VM called Active.

First we need a VM with [John the Ripper](https://github.com/magnumripper/JohnTheRipper),
[Impacket](https://github.com/CoreSecurity/impacket),
[OpenVPN](https://openvpn.net/), a Hack The Box connection file (`.ovpn`),
a wordlist, and a few other utilities.  (Commands for installing this on Ubuntu
  at the end..)

Here I'm using Ubuntu on Google Cloud Platform.  First let's check to see our
tools are installed:

![](images/Kerberoasting%20Revisited/image003.png)<br><br>

Next use `tmux` and `openvpn` to connect to the HTB network:

```
tmux new -s vpn
sudo openvpn a.opvn

# Press Ctrl-B then d to detach
```
<br>

![](images/Kerberoasting%20Revisited/image004.png)<br><br>

Add the `active.htb` machine's IP address to your `/etc/hosts` file and ensure
you can ping it:

![](images/Kerberoasting%20Revisited/image005.png)<br><br>


### Active Directory Recon

On this machine, LDAP is open on port 389.  At this point you've obtained a
valid name and password and can query Active Directory using a number of
different tools----here we'll use `ldapsearch`:

```bash
PASS=GPPstillStandingStrong2k18
USERS="cn=users,dc=active,dc=htb"
ldapsearch -h active.htb -D SVC_TGS -w $PASS -b $USERS | grep sAMAccountName
```

![](images/Kerberoasting%20Revisited/image012.png)<br><br>

### Request Service Ticket

Now, use the Impacket tool `GetUserSPNs.py` to query AD for users with SPNs and
for any that are discovered, request the service and obtain the encrypted ticket:

```bash
GetUserSPNs.py -request active.htb/SVC_TGS:$PASS
```

You may get an error related to time offsets:

![](images/Kerberoasting%20Revisited/image006.png)<br><br>

This is because the time sync between the two machines is off.  Check the offset
between the two hosts with `ntpdate`:

![](images/Kerberoasting%20Revisited/image007.png)<br><br>

To fix this, adjust the localhost time to match the remote host's time:

```
# Get remote server time
ntpdate -q active.htb

# Get localhost time
date

# Set localhost time
sudo date --set="07 November 2019 18:26:36"
```

<br>

Now the offset is small and should be good enough to continue:

![](images/Kerberoasting%20Revisited/image008.png)<br><br>

This time it works and we get the encrypted ticket:

![](images/Kerberoasting%20Revisited/image009.png)<br><br>

### Crack Encrypted Ticket

Copy the data and paste it into a file named `ticket.enc`.  Then reveal the
password using `john`:

![](images/Kerberoasting%20Revisited/image010.png)<br><br>

John has found the password to the Administrator account. and we can now use it
to log on to the host.

### Use Cracked Passwords

Another Impacket tool `psexec.py` allows a privileged account to logon as the
user `SYSTEM`:

![](images/Kerberoasting%20Revisited/image011.png)<br><br>


## Roastable Accounts

So how do we know if any of our accounts might be "roastable"?  We check three
characteristics:

- [Service Principal Name](#service-principal-name)
- [Kerberos Encryption Type](#kerberos-encryption-type)
- [Password Strength](#password-strength)

### Service Principal Name

For most environments, *any* user account with an SPN is a potential Kerberoasting
target.  In our environment which is set up for public key Kerberos, non-human
accounts are the most susceptible to this type of attack.

### Kerberos Encryption Type

RC4 encryption is the weakest type used so we look to identify accounts allowing
this type of encryption as the most likely targets for an adversary attempting
to escalate privileges.

### Password Strength

We don't have a way to test how strong a password is, but if it hasn't been
changed in years it may likely be simple, known, or guessable.

Accounts with these three properties can be searched using PowerShell:

```
$names = (Get-NNetUUser | ? {$_.servicePrincipalName}).samaccountname
$rc4 = $names | %{Get-ADUser $_ -pr * | ? KerberosEncryptionType -match 'RC4' | Select samaccountname,PasswordLastSet}
$rc4 | ? samaccountname -NotMatch 'krb'
```

![](images/Kerberoasting%20Revisited/image013.png)<br><br>


And also using Splunk:

```python
index=* sourcetype=ad:users enabled="true" earliest=-2d@d
| regex ServicePrincipalNames="^\S"
| eval lastLogonDate2=strptime(lastLogonDate,"%m/%d/%Y %H:%M:%S")
| eval lastLogon=strftime(lastLogonDate2,"%Y/%m/%d %H:%M:%S")
| eval whenCreated2=strptime(whenCreated,"%m/%d/%Y %H:%M:%S")
| eval Created=strftime(whenCreated2,"%Y/%m/%d %H:%M:%S")
| eval PasswordLastSet2=strptime(PasswordLastSet,"%m/%d/%Y %H:%M:%S")
| eval PasswordLast=strftime(PasswordLastSet2,"%Y/%m/%d %H:%M:%S")
| regex KerberosEncryptionType="(?i)RC4"
| regex PasswordLast!="(?i)2019"
| fillnull value="blank LastLogonDate" lastLogonDate2 lastLogon
| fillnull value="blank" extensionAttribute2 ServicePrincipalNames description
| regex samaccountname!="krbtgt"
| dedup lastLogon Created PasswordLast extensionAttribute2 enabled samaccountname DisplayName KerberosEncryptionType distinguishedName description
| table lastLogon Created PasswordLast extensionAttribute2 enabled samaccountname DisplayName KerberosEncryptionType distinguishedName description
| sort 0 -lastLogon -extensionAttribute2
```

![](images/Kerberoasting%20Revisited/image014.png)<br><br>


## Summary

Kerberoasting targets services that are linked to user accounts and run under that entity's security context.  When authenticating to the service, the KDC sends the client a service ticket that's encrypted with the NTLM hash of the user's password.

When our users authenticate in our environment, the secret keys used are private keys that live on tamper-resistant hardware devices (PIV cards).  Only a user that has the PIV and knows the PIN can authenticate and decrypt data meant for that user.

For non-human users (service accounts and computer accounts) in our environment, passwords are used as the secret key. Anyone who has knowledge of the password can authenticate as that entity and decrypt data meant for that host or service.  

When the user is a computer account, no big deal---the password is randomized by default and rotates every 30 days.  When the user is a user account, password can likely be guessed or cracked with a tool like [JTR]() or [Hashcat]().


Commands:

### tmux

|Keys|Function|
|-|-|
|`Ctrl-B` + `C`       | Create Window    |
|`Ctrl-B` + `,`       | Rename Window    |
|`Ctrl-B` + `W`       | List Windows     |
|`Ctrl-B` + `%`       | Split Vertical   |
|`Ctrl-B` + `:`       | Split Horizontal |
|`Ctrl-B` + `d`       | Detach from session |
|`tmux new -s vpn`    | Start new session |
|`tmux attach -t vpn` | Attach to session |  

<br>

### Installing tools and wordlist

```bash
# Install John the Ripper
sudo apt update
sudo apt install snapd
sudo snap install john-the-ripper
PATH=$PATH:/snap/bin


# Or install Hashcat
sudo apt update && sudo apt upgrade -y
wget https://hashcat.net/files/hashcat-5.1.0.7z
sudo apt install p7zip-full -y
7z x hashcat-5.1.0.7z
hashcat/hashcat46.bin -b

# Install OpenVPN
sudo apt install openvpn -y
PATH=$PATH:/usr/sbin

# Get wordlist
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# get Impacket
sudo apt-get install python-dev python-pip -y
pip install --upgrade pip
sudo pip install pycrypto pyasn1 pyOpenSSL ldapdomaindump
git clone https://github.com/CoreSecurity/impacket.git
cd impacket
sudo python setup.py install
```
