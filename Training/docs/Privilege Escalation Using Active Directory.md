# Privilege Escalation Using Active Directory

Active Directory is a hierarchical database used to manage user accounts, computers, and other network resources.  AD objects that make up this database and their attributes are typically accessible by all `Authenticated Users` in all domains within the forest.

This means a compromised non-admin account has the ability to scan the entire AD environment for privilege escalation opportunities.  This document shows [several ways](https://adsecurity.org/?p=3658) to search for AD object relationships that could provide an unintended path to escalation in the event of a successful compromise.

- [Reviewing AD](#reviewing-ad)
	- [Overview](#overview)
	- [Objects](#objects)
	- [Trusts and Permissions](#trusts-and-permissions)
- [Searching AD](#searching-ad)
	- [AD Group Membership](#ad-group-membership)
	- [Local Group Membership](#local-group-membership)
	- [AD Object ACLs](#ad-object-acls)
	- [GPO Permissions](#gpo-permissions) 
	- [User Rights Assignments](#user-rights-assignments) 
- [Using the ADmodule](#using-the-admodule)

## Reviewing AD

- [Overview](#overview)
- [Objects](#objects)
- [Trusts and Permissions](#trusts-and-permissions)


### Overview

An Active Directory environment is implemented as a **forest** which is a collection of domain containers that inherently trust each other.  All domains in the forest share a common global catalog, directory schmea, and directory configuration which allows security principals in one domain to authenticate to all other domains in the forest. 

Each domain controller in the forest maintains a current version of the directory as a database called `NTDS.dit`.  This database is used to provide authentication and directory services for clients and applications.  All changes to directory data are replicated to each domain controller in the forest so that all DCs have the most current version.

Active Directory has several different roles:

|Role|Description|
|-|-|
|Domain Services (AD DS)|Stores and manages information about the network resources|
|Federation Services (AD FS)|Authenticates applications & services outside network|
|Lightweight Directory Services (AD LDS)|Authenticates applications & services with AD|
|Certificate Services (AD CS)|Manages certificates for the network|
|Rights Management Services (AD RMS)|Enforces data access policies|

<br>

Each DC also hosts the `NETLOGON` and `SYSVOL` shares for logon scripts and group policy information respectively:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image009.png)<br><br>

There are four ways for clients and applications to communicate with the directory:

- Lightweight Directory Access Protocol (LDAP)
- Replication (REPL) and domain controller management interface
- Messaging API (MAPI)
- Security Accounts Manager (SAM)

<br>

Windows systems use Active Directory Services Interface (ADSI) to query directory data and obtain information about AD objects and their attributes.


### Objects

In a standard Active Directory configuration, the forest, all its domains, and all security principals and shared resources within them are all represented as objects with attributes.


Here is ADSI being used to view attributes of the `NAT` Organizational Unit (OU) object:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image019.png)<br><br>

The ActiveDirectory PowerShell module has cmdlets that can be used to obtain the same information:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image020.png)<br><br>

Here is our forest object and the domains it contains:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image001.png)<br><br>

With `Get-ADDomain`, we can see that this domain is a child domain of the forest domain:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image002.png)<br><br>

User and computer accounts that operate in the forest are also represented as objects.  For these, use `Get-ADUser` and `Get-ADComputer`:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image003.png)<br><br>

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image004.png)<br><br>

User and computer accounts can be assigned to groups which make granting access to resources to multiple accounts easier.  Use `Get-ADGroup` to see groups and their attributes:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image006.png)<br><br>

See members of a group with `Get-ADGroupMember`:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image008.png)<br><br>

Users, computers, and groups can all be placed into OUs so that they can be managed as one unit for deployment of security settings and policies.

Use `Get-ADOrganizationalUnits` to see OUs and their attributes:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image007.png)<br><br>

Domains, user accounts, computer accounts, groups, and OUs are all just objects of different types. Here is a look at different object types using `Get-ADObject`:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image005.png)<br><br>

### Trusts and Permissions

In an AD forest, all domains implicitly trust each other with two-way trust. This means admins in one domain can control other domains in the same forest.

Here are the other domains our domain trusts:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image017.png)<br><br>

Forests can also have trusts.  Here are other forests our forest trusts:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image018.png)<br><br>

These trusts allow us to get Kerberos ticket-granting tickets (TGTs) for other forests so we can authenticate to and use services in other domains:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image023.png)<br><br>

Discretionary Access Control Lists (DACLs) and Access Control Entries (ACEs) are simliar to file permissions which define who can read and/or modify AD objects.  

Here is one way to show DACLs for an AD object:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image021.png)<br><br>

Another way is using the `ActiveDirectory` PowerShell module:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image022.png)<br><br>

Together, trusts and permissions can be used to map out object relationships in an AD environment that could allow privilege escalation or lateral movement.  

## Searching AD

An adversary that has successfully compromised a low privileged account will typically search for and target users, computers, and groups that have more access than necessary.  Access to AD objects is determined by a combination of rights the user has which is made up of:

- [AD Group Membership](#ad-group-membership)
- [Local Group Membership](#local-group-membership)
- [AD Object ACLs](#ad-object-acls)
- [GPO Permissions](#gpo-permissions) 
- [User Rights Assignments](#user-rights-assignments) 

As we search, non-admin accounts whose combined rights in Active Directory provide it admin-level privileges would be the highest priority.


### AD Group Membership

Membership in AD Groups such as `Domain Admins`, `Administrators`, and `Enterprise Admins` provides full domain and forest admin rights.  These groups along with the following provide admin functions to their members:

|Group|Description|
|-|-|
|Account Operators|Can create and manage users and groups in the domain. Considered a service administrator group because it can modify Server Operators which can modify domain controller settings|
|Administrators|Has complete and unrestricted access to the computer.  If computer is a domain controller, members have unrestricted access to the domain. Can take ownership of any object in the directory or any resource on a domain controller|
|Allowed RODC Password Replication Group|Manages RODC password replication policy|
|Backup Operators|Can back up and restore all files on a computer, log on, shut down the computer|
|Certificate Service DCOM Access|Can connect to certification authorities in the enterprise|
|Cert Publishers|Can publish certificates for User objects in Active Directory|
|Distributed COM Users|Can launch, activate, and use Distributed COM objects on the computer|
|DnsAdmins|Have admin rights to AD DNS and can run code via DLL on a Domain Controller operating as a DNS server|
|Domain Admins|Full admin rights to the Active Directory domain and all computers|
|Enterprise Admins|Full admin rights to all Active Directory domains in the AD forest|
|Event Log Readers|Can read event logs from local computers|
|Group Policy Creators Owners|Can create, edit, or delete Group Policy Objects in the domain|
|Hyper-V Administrators|Have complete and unrestricted access to all the features in Hyper-V|
|Pre–Windows 2000 Compatible Access|Has read access for all users and groups in the domain|
|Print Operators|Controls printers that are connected to domain controllers. Can locally sign in to and shut down domain controllers. Can load and unload device drivers on all domain controllers|
|Remote Desktop Users|Can remotely connect to a server via RDP|
|Schema Admins|Can modify the AD schema which governs the structure and content of the entire directory|
|Server Operators|Can administer domain servers, sign in interactively, create and delete network shared resources, start and stop services, back up and restore files, format hard drives, and shut down the computer|

<br>

A basic search would be to check if a specific user or group belongs to one of these privileged groups.  Use the `MemberOf` property in the `ActiveDirectory` module:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image010.png)<br><br>

If an account is a member of one of these groups with elevated privileges, it is an opportunity for escalation in the event of a compromise.

### Local Group Membership

GPOs are frequently used to add AD groups to local groups which provide those AD groups admin access.  This shows several AD users and groups that have administrative access to my workstation due to membership in the local `Administrators` group:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image011.png)<br><br>

These are privileged accounts that are not as likely to get compromised as non-admin accounts used for browsing the Internet or a service account with an old or weak password.

This service account hasn't had its password changed in over 4 years and could be an attractive target for an intruder.  Initially it doesn't appear to have admin privileges:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image013.png)<br><br>

It is a member of the XXXX group which contains thousands of non-admin users:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image014.png)<br><br>

But there is a group policy that provides this account admin privileges on specific servers:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image015.png)<br><br>

We can use the following command to create a GPO report for the policy and save it:

```powershell
Get-GPOReport -Guid E638D372-387C-4DCA-865B-EEA9C6D78284 -ReportType html -Path $env:USERPROFILE\report.html
```

<br>

The report shows that when this policy is applied to a computer, this service account and other admin accounts are added to the local Administrators group:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image012.png)<br><br>

We can confirm this on a server where this policy is applied:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image016.png)<br><br>

In the event this service account was compromised, this policy would provide an opportunity for escalation to the Local Administrator group on all systems where this policy is applied.

### AD Object ACLs

Another path to escalation uses accounts with ACLs that provide key privileged actions such as:

|ACL|Description|
|-|-|
|`DS-Replication-Get-Changes-All`|Can replicate all data for an object, including password data. When combined with Replicating Directory Changes, provides the ability to “DCSync” the password data for AD users and computers|
|`DS-Replication-Get-Changes`|Can replicate all data excluding secret domain data. This right provides the ability to pull data from Active Directory regardless of configured AD ACLs|
|`Self-Membership`|Has the ability to add own account to a group|
|`GenericAll`|Provides full rights to the object and all properties (add users to a group or reset user's password)|
|`GenericWrite`|Provides write access to all properties.update object's attributes (i.e logon script)|
|`WriteDACL`|Provides the ability to modify security on an object which can lead to Full Control of the object. modify object's ACEs and give attacker full control right over the object|
|`WriteOwner`|Can take ownership of an object (change object owner to attacker controlled user)|
|`WriteProperty`|Typically paired with specific attribute/property information.Example: The help desk group is delegated the ability to modify specific AD object properties like Member (to modify group membership), Display Name, Description, Phone Number, etc|
|`CreateChild`|Can create an object of a specified type (or "All")|
|`DeleteChild`|Can delete an object of a specified type (or "All")|
|`Extended Right`|Provides additional rights beyond the obvious.Example: All Extended Right permissions to a computer object may provide read access to the LAPS Local Administrator password attribute|
|`Manage Group Policy Link`|Can link an existing Group Policy Object in Active Directory to the domain, OU, and/or site where the right is defined|
|`Create GPOs`|Can be delegated via the Group Policy Management Console (GPMC)|
|`AllExtendedRights`|Can add user to a group or reset password|
|`ForceChangePassword`|Can change user's password|
|`AddMembers`|Can add arbitrary users, groups or computers to the target group|

<br>

An adversary who has compromised a non-privileged account can use a tool like [PowerView]() to search for AD objects with ACLs that allow it to be modified by the compromised account.

A normal non-admin account has ACL entries that allow a forced password reset by several elevated accounts:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image024.png)<br><br> 

But this one has an ACL entry which allows a forced password reset by any authenticated user:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image025.png)<br><br>

So if an adversary was able to compromise any account in the environment, the ACL on this account could be used to take it over as well.

### GPO Permissions

Group Policy Objects (GPOs) are used to define the rights that different accounts have on computers and other shared resources in the environment.  If a compromised account has permission to modify a policy, it can be used to gain elevated privileges on all resources where that policy is being applied.

Normally, elevated rights on Group Policy objects such as `WriteProperty` are only granted to a select few groups:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image029.png)<br><br>

Here we see that a user's admin account and an AD group has been granted those elevated rights to a policy:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image030.png)<br><br>

This means that the admin account and every member of the XXX group can modify this policy:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image031.png)<br><br>

Let's see what this policy does that is possibly being applied to hundreds of machines across our environment:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image032.png)<br><br>

This policy adds AD groups to the Local Administrators group on enterprise workstations.  

So if any one of the 12 admin accounts above is compromised, they could be used to modify this policy and make any group a Local Administrator on all workstations where this policy is applied.

Many of these accounts already had Local Administrator membership on workstations via other group memberships and policies, but this is one example of how Group Policy permissions can provide an unintended path to escalation for an adversary with a compromised account.

### User Rights Assignments

User Rights Assignments define rights that an account has on a computer.  In AD, rights granted to accounts on domain controllers are especially important as they can be used to alter the AD environment.

Here are some key privileges that can be abused to obtain elevated rights:

|Privilege|Description|
|-|-|
|`SeBackupPrivilege`|Read any file on the system regardless of its ACL|
|`SeDebugPrivilege`|Read or write to another process' private memory space|
|`SeLoadDriverPrivilege`|Load or unload kernel drivers|
|`SeTakeOwnershipPrivilege`|Take ownership of files or other objects|
|`SeShutdownPrivilege`|Reboot or shut down the system|
|`SeRemoteInteractiveLogonRight`|Log on through Remote Desktop Services|
|`SeImpersonatePrivilege`|Impersonate a client after authentication|
|`SeEnableDelegationPrivilege`|Enable computer and user accounts to be trusted for delegation|
|`SeSyncAgentPrivilege`|Synchronize directory service data|
|`SeSecurityPrivilege`|Manage auditing and security log|

<br>

We can use `Get-AADOObject` and some regex to see the policies applied to the `Domain Controllers` container:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image026.png)<br><br>

Now we can check each of these policies for user right assignments with `Get-UserRightAssignments`:

```powershell
function Get-UserRightsAssignments ($guid) {
    [xml]$xml = Get-GPOReport -Guid $guid -ReportType xml
    $Rights = $xml.GPO.Computer.ExtensionData.Extension.UserRightsAssignment
    $a = @()
    Foreach ($right in $Rights) {
        $a += New-Object -TypeName psobject -Property @{
            UserRight=$right.Name;
            Users=$right.Member.Name.'#text';
        }
    }
    $a | Select UserRight,Users | ft -auto
}
```

<br>

This policy shows that two domain user accounts have been granted the `SeDebugPrivileges` right on domain controllers where it has been applied.  This allows the users to debug processes owned by other users, including SYSTEM:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image027.png)<br><br>

If an adversary were to compromise one of these two user accounts, they could use this privilege to inject arbitrary code into a SYSTEM process and obtain full control of the domain controller and domain.

Neither of these accounts are in the `Domain Admins` group, but the User Rights Assignments of this policy grant an adversary equivalent opportunities for privilege escalation.

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image028.png)<br><br>

## Using the ADmodule

THe ADModule uses techniques similar to PowerView and is still in development (cmdlets use slightly different names to avoid alerting in endpoint security tools), but here are a few ways it can be used in its current state:

|Cmdlet|Description|
|-|-|
|`Get-NNetUUser`|Gets AD user, equivalent of `Get-ADUser <user> -pr *`|
|`Get-NNetCComputer`|Gets AD computer object, equivalent of `Get-ADComputer <computer> -pr *`|
|`Get-NNetGGroup`|Gets AD group names, similiar to `Get-ADGroup <group> -pr *`|
|`Get-NNetGGroupMMember`|Gets members of AD group, equivalent of `(Get-ADGroup <group> -pr *).Members`|
|`Get-NNetGGpo`|Get all network GPOs, equivalent of `Get-GPO -Domain <domain> -All`|
|`Get-NNetGGpoGGroup`|Get all GPOs that set group memberships|
|`Get-OObjectAAcl`|Get AD object ACL, equivalent of `(Get-ADUser <user> -pr *).nTSecurityDescriptor.Access`| 
|`Convert-NNameTToSSid`|Convert AD name to SID|
|`Convert-SSidTToNName`|Convert SID to AD name|
|`Get-AADOObject`|Get an AD object, equivalent of `Get-ADObject`|
|`Invoke-AACLSScanner`|Searches for ACLs of selected AD objects|
|`Get-AADOObjectIInfo`|Performs several checks for an object's group memberships|
|`Get-UserRightsAssignments`|Checks a policy for any user rights assignments|
|`Get-LinkedGpos`|Get all linked GPOs for an object|

<br>

Find all GPOs being applied to OUs of an object with `Get-LinkedGpos`:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image033.png)<br><br>

Get a quick summary of an account's group memberships and linked GPOs with `GetAADOObjectIInfo`:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image034.png)<br><br>

Get a list of members in a group:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image035.png)<br><br>

Check object ACL for principals that have extended rights on the object:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image036.png)<br><br>

Check object ACL for principals that have `WriteProperty` rights on the object:

![](images/Privilege%20Escalation%20Using%20Active%20Directory/image037.png)<br><br>
