# Web Authentication and Session Management

This is a quick review of the technologies we use when authenticating to our domain and using internal and external web applications.

When using web applications:

- [Multifactor Authentication](#multifactor-authentication) is used to authenticate a user to our domain
- [Single Sign-On](#single-sign-on) is used to prove to web applications that a user has authenticated using MFA
- [Session Management](#session-management) is used to associate authenticated users to actions performed on the web application

A good way to demonstrate the use of all three of these in our environment is with the [AWS Command Line Interface](#aws-command-line-interface).

<br>

## Multifactor Authentication

Multi-factor authentication requires using two or more of the following factors:

|Factor|Description|
|-|-|
|Something you know|password, PIN, answer to a security question|
|Something you have|authenticator application, yubikey, PIV card|
|Something you are|fingerprint, retina scan, voice/face recognition|

<br>

The way we authenticate users has improved over time: 

|Method|Example|Problem|
|-|-|-|
|Password Authentication|Username and Password|Can be guessed, cracked, sniffed, stolen, etc.|
|Public Key Authentication|SSH Private keys|Can be lost, copied, compromised, stolen, etc., not practical for most web apps|
|Multi-Factor Authentication|Password + Time-based One Time Password, SMS|Can be phished for a one time web session|
|MFA with Tamper-resistant Hardware Devices|Smart Card, U2F|Browser compromise required for an unauthorized web session|

<br>

Tamper-resistant hardware devices are designed so that the private key never leaves the device.  This ensures that someone must have possession of the device *and* know its PIN in order to use it.

To implement multi-factor authentication in our environment, we use a PIV card to authenticate users to our domain. The PIV card combines public key authentication (something you have) with password authentication (PIN) and contains the certificates and private keys needed to authenticate the user.  

When a user inserts their card to log in:

- User is prompted for PIN to activate PIV card
- User’s public key certificate is validated (ensures cert was issued by valid CA and for valid time period)
- Domain controller issues a challenge based on the user's public key
- User’s private key is used to generate the challenge response 
- User's identity in the certificate is used to find the account in Active Directory
- A Ticket-Granting Ticket (TGT) for the account is provided to the client

The TGT can now be used to prove to other systems that the user has been properly authenticated using MFA.  This is why we only authenticate with PIV and PIN once when we log on with our non-priv account, and once when we open a program (PowerShell, RDP, etc.) with our admin account---after that, each account has a TGT that is good for 10 hours which is used to obtain tickets which authenticate us to other systems.  This is an implementation of Single Sign-On.


### Single Sign-On

Single Sign-On (SSO) is used to provide access to multiple systems using a single set of credentials.  One advantage is that using a single set of credentials prevents the storing of multiple credentials across multiple databases.  Also, instead of requiring each web application to authenticate a user with MFA, each application simply accepts the provided proof of identity or authorization from a trusted source---in our case an Identity Provider (IdP).

Here are three common methods to implement this in web applications:

|Method|Description|
|-|-|
|[SAML](#saml)|User visits portal and receives a SAML assertion from identity provider, websites that trust identity provider accept SAML token as authentication|
|[OAuth](#oauth)|User authenticates with identity provider, gets token, gives to relying party who can now perform specific functions on behalf of user|
|[OpenID](#openid)|User authenticates with identity provider, gets token, gives to relying party who creates a session|

<br>

Similar to Kerberos where a TGT proves to other systems that the user has been properly authenticated, authenticating with an IdP to obtain a SAML assertion can be used to prove to web applications that the user has been properly authenticated using MFA. 

To use a web application in our environment, a user must first visit [SSO Portal]() and submit a TGT proving the user has properly authenticated using a PIV and PIN.  If successful, the user can now request a SAML assertion for one of the web services listed such as [AWS]() and authenticate to it.  

SSO for web apps in our environment using SAML looks like this:

- User opens browser and visits the [SSO Portal]() portal
- A Kerberos TGT is used to authenticate the user to [SSO Portal]()
- [SSO Portal]() portal reports authentication was successful, provides links to web apps
- User clicks on chosen web app, browser requests a SAML assertion for the web app
- Browser receives a SAML assertion from [SSO Portal]() and sends it in a POST request to the web app
- Web app verifies SAML assertion is valid and allows access
- Web app extracts identity information from SAML assertion to set permissions for the user

Once authenticated, the web application needs a way to track what actions the user performs which leads us to session management.

## Session Management

After a user authenticates, an application needs a way to track the session. 

Two common ways of doing this are:

|Method|Description|
|-|-|
|Cookie Based Authentication|Stateful, Authenticated user recieves a cookie which is tracked and recorded on the server|
|Token Based Authentication|Stateless, Authenticated user receives a signed token containing all required information |

<br>

Cookie Based Authentication in action:

- User authenticates
- Server verifies and creates a session
- Cookie with session ID is placed in browser and stored on server
- For each request, session ID is included and verified in database
- Session is destroyed upon logout

<br>

Token Based Authentication in action:

- User authenticates
- Server verifies and returns a signed token
- Token is only stored client-side
- All future requests include the signed token
- Server decodes token and if valid processes request
- Client destroys token on logout

<br>

Token based session management is less overhead for the web application.  No record is maintained on server and each request contains a signed token which has all required information about the user.  The web application is only required to sign tokens after successful authentication and validate a token is signed before processing each request.

One way to demonstrate token based authentication is by using the AWS Command Line Interface.

## AWS Command Line Interface

With the AWS Command Line Interface (CLI), we can interact with AWS resources from the command line allowing for the use of scripting and automation.  AWS CLI needs valid credentials which can be configured with `aws configure` or stored in the `~\.aws\credentials` file.  Since we have access to roles from multiple AWS accounts, we'll be using the `credentials` file to store the required credentials:

|Credential|Description|
|-|-|
|Access Key ID|Used to identify the role|
|Secret Access Key|Used by the AWS CLI client to authenticate|
|Session Token|Proves user authenticated using MFA and is used to track session|

<br>

Roles are AWS identities built with least privilege in mind so that the user that assumes the role can only perform the actions necessary to do their job.  AWS roles do not have long-term credentials.  The [AWS Security Token Service](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) dynamically generates temporary credentials so that an IAM User, EC2 instance, or SAML-authenticated user can assume a role. 

AWS roles are not uniquely associated with one person.  A role can be assumed after authenticating through an individual AWS account or by proving proper authentication using an external identity provider (such as using SAML). The traditional way to do this is to visit the [SSO Portal]() portal with a browser, select the [AWS]() link, and choose the **ReadOnlyAccess** role for an account.


At this point, the browser has authenticated the user to the IdP and has submitted a SAML assertion to AWS who has validated it.  Once a role is selected, AWS provides the browser temporary credentials that will allow you to browse AWS resources using the role for that account.  There is a second way to obtain these credentials so that we can use them with the AWS CLI tool instead of a browser.

AWS CLI's `assume-role-with-saml` can be used to obtain temporary credentials by specifying the role we want to assume, the SAML identity provider, and a SAML assertion proving we have authenticated properly using a PIV: 

```
aws sts assume-role-with-saml --role-arn <role-arn> --principal-arn <principal-arn> --saml-assertion <saml-assertion>
```

<br>

Since we need to access multiple accounts and are required to store a set of temporary credentials for each, I created the [Get-TempAWSCreds.ps1](scripts/Get-TempAWSCreds.ps1) script to automate this process.  Run the script without any arguments to see the accounts we can access:


Run the script with the account you want temporary credentials for as an argument, and it does the following:

- Checks to see if the AWS CLI tool is installed, if not it exits
- Checks to see if a `credentials` file exists, if not it creates an empty one
- Starts IE and requests a SAML assertion to use with AWS from [SSO Portal]()
- Submits the SAML asserstion, role, and identity provider to AWS STS
- Saves the AWS Key Id, Secret Access Key, and Session Token to the `~\.aws\credentials` file

If successful, we receive temporary credentials for the ReadOnlyAccess role of that account:

![](images/Web%20Authentication%20and%20Session%20Management/image003.PNG)<br><br>

The script automatically stores the temporary credentials it receives in your `~\.aws\credentials` file.  You can run the script multiple times for multiple accounts and the newest set of credentials for each account will always be available for use:

![](images/Web%20Authentication%20and%20Session%20Management/image002.PNG)<br><br>

Here I have requested credentials for several different accounts.  To perform an operation with one of the accounts, just specify with the `--profile` parameter:

![](images/Web%20Authentication%20and%20Session%20Management/image004.PNG)<br><br>

## Summary

Practice using the AWS CLI to query resources and get familiar with how to search these logs in Splunk.

Here is an example search that displays every time I requested temporary credentials on this day showing the Access Key ID I was granted and the session token I used to prove I authenticated using MFA:

![](images/Web%20Authentication%20and%20Session%20Management/image006.png)<br><br>

This search shows all the times temporary credentials were requested for a specific account:

![](images/Web%20Authentication%20and%20Session%20Management/image007.png)<br><br>

This search shows all actions I performed with those credentials:

![](images/Web%20Authentication%20and%20Session%20Management/image008.png)<br><br>
