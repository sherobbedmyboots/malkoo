# Authentication Using Smart Cards and Public Key Kerberos

Authentication is the process of assuring the identity of an entity---proving they are who they say the are.  This document is a review of how we authenticate users on our network using Smart Cards, PKI, Kerberos, and Active Directory.

Smart cards with public key Kerberos have become the gold standard for modern Windows Active Directory networks.  Before Kerberos, passwords were required every time a new host or service on the network was accessed.  Kerberos implements Single Sign On (SSO) allowing a user to enter their account password once and recieve a Ticket Granting Ticket (TGT) used to obtain service tickets for accessing hosts and services.  

An extension was added to Kerberos (PKINIT) implementing public key cryptography in the intitial authentication exchange.  This allowed Smart Cards to replace passwords and provided a way to require Two Factor Authentication (2FA) when accessing resources on the network.

Here is a short outline of the process and components involved:  

- [PKI](#pki)
	- Authentication based on [digital certificates](#digital-certificates) and a chain of trust
	- Trusted [certificate authorities](#certificate-authorities) issue X.509 digital certificates to all entities, hosts, and services
	- Entites and resources can now authenticate each other

- [Smart Cards](#smart-cards) 
	- Tamper-resistant hardware devices that store X.509 certificates and private keys
	- Private key can't be read or exported---cryptographic operations performed on the card
	- A PIN is required to unlock and use the private key providing 2FA

- [Kerberos](#kerberos)
	- A SSO mechanism which uses a third party (KDC) to authenticate clients and resources
	- KDC verifyies a user's credentials using their digital certificate
	- Finds account in AD and builds a TGT containing their user and group SIDs
	- TGT is sent to user, is valid for 10 hours, and is used to request Service Tickets
	- Service Tickets are used to access hosts and services on the network

- [Active Directory](#active-directory)
	- Contains account info such as group memberships, security identities, user details
	- Used to build TGTs determining access rights for accounts

And a walkthrough of the process using Wireshark, Splunk, and PowerShell:

- [Authentication in Action](#authentication-in-action)

<br>

## PKI

Public Key Infrastructure (PKI) is a framework for providing authentication, confidentiality, integrity, and non-repudiation based on public key certificates and a chain of trust.  A public key certificate, or digital certificate, is like an electronic password that can be used to authenticate entities on a network.  Using a chain of trust allows entities that are unknown to each other to authenticate themselves based on that trust.

There are two primary elements of PKI:


- [Digital Certificates](#digital-certificates) provides encryption and decryption
- [Certificate Authorities](#certificate-authorities) (CAs) verify an entity's identity and issue digital certificates 


### Digital Certificates

A digital certificate is issued by a CA and consists of two keys.  One key is public and given to anyone.  The other is private and kept secret.  

- Data that is encrypted with the **public key** can only be decrypted with the **private key**  
- Data that is encrypted with the **private key** can only be decrypted with the **public key**

Uses:

|Use|Example|
|-|-|
|Authentication and  Non-repudiation|Bob encrypts data with his private key and sends to Alice.  Alice decrypts the data with Bob's public key. Alice knows the data came from Bob and no one else because he is the only one with the private key|
|Confidentiality|Alice encrypts data with Bob's public key and sends to Bob.  Alice is sure that only Bob can decrypt the data because he is the only one with the private key|
|Integrity|Bob sends Alice a file along with a hash of the file signed with his private key. Alice decrypts the hash with Bob's public key and compares it to the hash of the file received.  If they are the same, the file was not altered in transit|

### Certificate Authorities

CAs are the trusted party who verifies the identity of the entity, issues them a certificate, and signs that certificate with their private key.  This allows anyone to use the CA's public key to verify that the certificate was issued by the CA and that the CA vouches for their identity. 

To see the certificates on your Smart Card, open Chrome and go to Settings --> Advanced --> Manage Certificates:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image030.png)<br><br>

Double click on a certificate and select the Certification Path tab to see the Certificate Authorities and chain of trust for each certificate:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image031.png)<br><br>

By trusting the Certification Authorities and chain of trust they create, we can trust that anyone who proves they have the private key for a certificate issued by the CA really is who they say they are.  

## Smart Cards

Our certificates and private keys are stored on Smart Cards for increased security. Using this method, you must have the card and know the PIN in order to use the private key.

Run this command in PowerShell to access the private key on your Smart Card:

```powershell
(ls Cert:\CurrentUser\my | select -First 1).PrivateKey
```

This shows the properties of the private key on the Smart Card:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image027.png)<br><br>

Now remove the Smart Card from the computer and run the command again:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image028.png)<br><br>

It cannot be accessed without the card inserted.

And when it is accessed, it requires entering the PIN to use it:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image029.png)<br><br>

So you must have the Smart Card AND know its PIN in order to authenticate to Kerberos and gain access to hosts and services on the network.


## Kerberos

Kerberos uses a Key Distribution Center (KDC) on a domain controller to authenticate users who need access to network resources.  The KDC authenticates entities with its Authentication Server (AS) and grants tickets with its Ticket Granting Service (TGS).

In order to access a host or service on the network, an entity must prove their identity to the KDC so they can receive a Ticket Granting Ticket (TGT).  The TGT is then used for as long as it's valid (10 hours for us) to prove to hosts and services on the network that it successfully authenticated with the KDC and is who it claims to be.

In a Kerberos realm, each entity is has a User Principal Name (UPN) and each host and service has a Service Principal Name (SPN). 

Use the ActiveDirectory PowerShell module to see UPNs for an account:

```powershell
Get-ADUser z -pr * | select -exp UserPrincipalName
```

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image035.png)<br><br>

Or `whoami /upn`:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image034.png)<br><br>

You can also use the ActiveDirectory PowerShell module to see SPNs for a host:

```powershell
Get-ADComputer z -pr * | select -exp ServicePrincipalNames
```

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image033.png)<br><br>

Or use `setspn -L <hostname>`:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image032.png)<br><br>


So for a user to access a service on the network, it must first obtain a TGT, then a Service Ticket for that service, then present that Service Ticket to the service.  Here is a quick summary of this process:

- [1. Client authenticates to KDC and gets a TGT good for 10 hours]()
	
	- **AS-REQ** sent from Client to KDC
		- Client (LSA process) requests a TGT specifying its name and the name of the service (krbtgt)
		- KDC verifies the user exists in AD, validates the certificate to ensure it's trusted, and builds a TGT using AD info
		- KDC creates a session key
	
	- **AS-REP** sent from KDC to Client
		- First part includes a TGT and TGS session key (encrypted with TGS secret key)
		- Second part includes a TGS name and session key  (encrypted with client public key)
		- Client uses private key to decrypt TGS name and TGS session key
		- Client now has an encrypted TGT and a TGS name and session key

- [2. Client uses TGT to get a Service Ticket for the service]()
	
	- **TGS-REQ** sent from Client to KDC
		- Client (LSA process) requests Service Ticket specifying the service name
		- First part is TGT and TGS session key (encrypted with TGS secret key)
		- Second part is authenticator message containing name and timestamp (encrypted with TGS session key)
		- KDC decrypts both, checks name in AD, verifies name is in TGT
	
	- **TGS-REP** sent from KDC to Client
		- First part is a Service Ticket encrypted with the Service's secret key
		- Second part is Service Session Key encrypted with TGS session key
		- Client decrypts the Service Session Key
		- Client now has an encrypted Service Ticket and a Service Session Key

- [3. Client presents the Service Ticket to the service]()
	
	- **AP-REQ** sent from Client to Service
		- First part is Authenticator message encrypted with Service Session Key
		- Second part is the encrypted Service Ticket received from TGS
		- Service decrypts Service Ticket to get Service Session Key
		- Service decrypts the Authenticator message with the Service Session Key
		- Service verifies ID, timestamps, etc
	
	- **AP-REP** sent from Service to Client
		- Service sends Authenticator message encrypted with Service Session Key


The client now has access to the service.


## Active Directory

Active Directory contains account information used for authorization and can be queried using LDAP.  When building a TGT for an account, Kerberos uses this information to bind the appropriate access rights to that account all across the network.  To see these properties, you can use the Active Directory PowerShell module cmdlet `Get-ADUser`:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image036.png)<br><br>

Or use the command `whoami /all`:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image037.png)<br><br>

Or PowerShell:

```
([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups | % {Write-Host (($_).Translate([System.Security.Principal.NTAccount]))}
```
![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image038.png)<br><br>


## Authentication in Action

When a host connects to the network, the user account must authenticate using Kerberos before accessing any resources.  To do this, the client machine first sends a DNS request for Kerberos services and receives a response containing the names of 7 different DCs which have Kerberos listening on port 88 (`udp.stream eq 5`):

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image001.png)<br><br>

The client then sends a DNS request for LDAP services and receives 7 different DCs available on port 389 (`udp.stream eq 7`):

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image002.png)<br><br>


The client sends a DNS request for one of these DCs () and receives its IP address () (`udp.stream eq 10`):

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image003.png)<br><br>

Client sends an LDAP searchRequest message to the DC on port 389 and receives a successful response.  It then sends a bindRequest message to authenticate and receives a bindResponse success message:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image004.png)<br><br>

Client sends a DNS request for the DC and gets its IP:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image005.png)<br><br>

The client sends the DC an AS-REQ to obtain a TGT, but the DC replies preauth is required and the connection is terminated:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image006.png)<br><br>

The client tries again (`tcp.stream eq 11`), this time including the pre-authentication data which is the user public certificate and the certificate signed with the private key, and this time gets the AS-REP message:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image007.png)<br><br>

Here the DC connects to the client on port 135 looking for services:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image008.png)<br><br>


The client then requests a service ticket for the LDAP service on the DC and receives one (`tcp.stream eq 24`):

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image009.png)<br><br>


Examine the TGS-REP and see it contains the service ticket which is encrypted: 

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image013.png)<br><br>


Now the client connects to the LDAP service and sends a bindRequest to authenticate which contains the encrypted service ticket it received from the TGS and an authenticator message (`tcp.stream eq 12`):

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image014.png)<br><br>

Now the client contacts the same host on port 445 wanting access to the CIFS service.  The service tells the client to authenticate using Kerberos, so the client immediately connects to the KDC on port 88 and requests a service ticket for CIFS on the DC:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image021.png)<br><br>

The KDC sends back an encrypted service ticket in the TGS-REP message:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image019.png)<br><br>

The client now sets up a session with this service using the encrypted service ticket it received:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image020.png)<br><br>

This process is repeated for all services the client needs to access.  By filtering for TGS-REPs by realm, we can see where the client obtained a TGT for the xyz realm followed by Service Tickets for three different services:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image010.png)<br><br>

Each of these tickets is cached and can be viewed with `klist`:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image011.png)<br><br>

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image012.png)<br><br>

4768 events in Splunk show the three TGT requests, but it doesn't show the domains the TGTs were for:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image016.png)<br><br>

But viewing the ticket details you can see the order in which they were obtained:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image015.png)<br><br>

Same for the service tickets which are recorded with 4769 events:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image017.png)<br><br>

Again, it shows the host but not the name of the actual service.  We can use klist to see these details:

![](images/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos/image018.png)<br><br>