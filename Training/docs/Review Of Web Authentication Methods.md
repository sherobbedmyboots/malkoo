# Review Of Web Authentication Methods

During web authentication, there is an initial process where the user proves they have possession of the secret required for access---either a password or both a password and an access code if configured for 2FA.  If successful, the user's browser is provided a cookie or token to use for the duration of the session.  When the session ends or the token expires, the user will need to prove once again they have possession of the secret in order to regain access.  

Just as browsers are given temporary access via a cookie/token, other applications can be provided temporary access to a web service using access tokens.  This is commonly used in combination with *delegated authorization* to ensure a third party application only has permissions to take specific actions on the web service.

From a security perspective, these common web authentication methods provide several different attack vectors for adversaries attempting to gain unauthorized access to a user's account.  Access to one or more **secret(s)** can provide complete access.  Access to a user's or application's **cookie or access token** can temporarily provide full or partial access.

This training document reviews each of these web authentication processes and the primary security risks they present.


- [Single Factor Authentication](#single-factor-authentication)
	- [Basic Authentication](#basic-authentication)
	- [Digest Authentication](#digest-authentication)
	- [Windows Integrated Authentication](#windows-integrated-authentication)
	- [Form-based Authentication](#form-based-authentication)
	- [Certificate Authentication](#certificate-authentication)
- [Second Factor Authentication](#second-factor-authentication)
	- [One-Time Passwords](#one-time-passwords)
	- [Hardware Tokens](#hardware-tokens)
	- [Tamper-resistant Hardware Devices](#tamper-resistant-hardware-devices)
- [Session Management](#session-management)
	- [Cookies](#cookies)
	- [Tokens](#tokens)
- [Delegated Authorization](#delegated-authorization)
	- [OAuth](#oauth)
- [Security Considerations](#security-considerations)
	- [Single Factor Compromise](#single-factor-compromise)
	- [Second Factor Compromise](#second-factor-compromise)
	- [Session Compromise](#session-compromise)
	- [Delegation Compromise](#delegation-compromise)



## Initial Authentication

For most web services, users first need to authenticate by proving they have knowledge or possession of one or more **secrets**.  The most common secret used is credentials--typically a username and password--using one of the following authentication methods:

- [Basic Authentication](#basic-authentication)
- [Digest Authentication](#digest-authentication)
- [Windows Integrated Authentication](#windows-integrated-authentication)
- [Form-based Authentication](#form-based-authentication)
- [Certificate Authentication](#certificate-authentication)


### Basic Authentication

A web page that is configured with Basic Authentication requires a username and password included in the request.  If not included, the server sends a response with a `WWW-authenticate` attribute in the header.

There are no logins or logouts---with every HTTP request, the Base-64-encoded username and password are included and used to authenticate the user.  This is a problem for HTTP traffic since it can be monitored and the credentials captured by unauthorized users and reused.  

The [PT-Domain](../scripts/PT-Domain.ps1) script uses Basic Authentication when authenticating to the Passive Total API:

![](images/Review%20Of%20Web%20Authentication%20Methods/image007.png)<br><br>


### Digest Authentication

HTTP Digest Authentication uses hashes while sending the username and password to the server. If not included, the server sends a response with a `WWW-authenticate` attribute in the header and a nonce.

The nonce is a random string that changes each request and is used to perform hashing functions with the username and password.  The result of the hashing is sent with the next request and if it matches the hashing function result the server produces with the same inputs, access is granted.

### Windows Integrated Authentication

Windows Integrated Authentication formerly known as NTLM authentication or NT LAN Manager is an authentication scheme from Microsoft which supports both NTLM and Kerberos.

When a protected web page is requested, the server sends two `WWW-Authenticate` headers---Negotiate (Kerberos) and NTLM so that the browser can use one of these methods to authenticate to the server.

In this example, the server replies with `WWW-authenticate` header requesting NTLM authentication and issues a challenge by sending a nonce.  The browser uses the nonce to complete hashing functions and returns the response:

![](images/Review%20Of%20Web%20Authentication%20Methods/image008.png)<br><br>

This Base64-encoded response contains username, hostname, domain, service, and the results of the hashing functions which the server can validate with the domain controller:

![](images/Review%20Of%20Web%20Authentication%20Methods/image009.png)<br><br>


### Form-based Authentication

Authentication with forms relies on code external to the HTTP protocol for authenticating the user. The application is left to deal with taking the user credentials, verifying them, and deciding their authenticity.

The simplest implementation of this method is to have a login form that prompts the user for a username and password. These values are then compared with the username and the password stored in the database.

This console uses form-based authentication on the login page:

![](images/Review%20Of%20Web%20Authentication%20Methods/image010.png)<br><br>

Look at the page source to see what values are submitted in a POST request when the **Sign In** button is clicked:

![](images/Review%20Of%20Web%20Authentication%20Methods/image011.png)<br><br>

You can inspect the POST request with Chrome Debugger and see the username, password, and other values being passed to the application for authentication:

![](images/Review%20Of%20Web%20Authentication%20Methods/image012.png)<br><br>


### Certificate Authentication

When authenticating with certificates, the client holds a certificate with a private key and the remote web application maps that certificate's public key to an account.  The certificate must be valid and trusted and the bearer must prove they have the certificate's private key.

Several certificates have already been imported into your browser.  You can view them in Chrome by going to **Settings** and then **Advanced Settings** --> **Manage Certificates**:

![](images/Review%20Of%20Web%20Authentication%20Methods/image027.png)<br><br>

You can view each certificate and find the one that is used to prove your identity to remote computers:

![](images/Review%20Of%20Web%20Authentication%20Methods/image028.png)<br><br>

The certificate can be exported to a Base64-encoded `.cer` file:

![](images/Review%20Of%20Web%20Authentication%20Methods/image029.png)<br><br>

When a client authenticates, it sends its certificate to the application.  This one is being transmitted in a cookie:

![](images/Review%20Of%20Web%20Authentication%20Methods/image030.png)<br><br>

![](images/Review%20Of%20Web%20Authentication%20Methods/image031.png)<br><br>

The server verifies the client's certificate using the following steps:

- digital signature check
- certificate chain check
- expiration/activation date and the validity period check
- revocation status check


If the checks pass, the client is issued a session cookie and can now access the application:

![](images/Review%20Of%20Web%20Authentication%20Methods/image032.png)<br><br>


## Two Factor Authentication

The problem with single factor authentication is that if that single factor is exposed, an unauthorized user may be able to obtain complete access to the account.  To mitigate this risk, many web applications require two factors of authentication before providing access.

Three common methods:

- [One-Time Passwords](#one-time-passwords)
- [Hardware Tokens](#hardware-tokens)
- [Tamper-resistant Hardware Devices](#tamper-resistant-hardware-devices)

### One-Time Passwords

One-time passwords are shared on-the-fly between two digital entities using an out-of-band (OOB) communication such as SMS, email, or application. After a server validates the username and password, it generates an OTP that can only be used once and sends it to the client via the chosen OOB method.

Here is a text containing a temporary access code used as a second factor to log in:

![](images/Review%20Of%20Web%20Authentication%20Methods/image033.jpg)<br><br>


### Hardware Tokens

The hardware token contains an algorithm, a clock, and a seed or a unique number which is used to generate the numbers displayed for a specific time window.  A user must provide the hardware token's current value along with username and password to gain access to the application.

FireEye's [Threat Intelligence Portal](https://intelligence.fireeye.com/sign_in) allows you to associate a virtual hardware token such as Google Authenticator as a second factor for authentication.

![](images/Review%20Of%20Web%20Authentication%20Methods/image023.png)<br><br>

The virtual hardware token provides the value needed for access:

![](images/Review%20Of%20Web%20Authentication%20Methods/image024.jpg)<br><br>


### Tamper-resistant Hardware Devices

Smart Cards and U2F devices can store X.509 certificates and private keys that can't be read or exported---all cryptographic operations are performed on the card.  Physical possession of the device is required as well as knowledge of a PIN in the case of Smart Cards.

To login to this application you must have possession of your Smart Card.  First, you're prompted to choose a certificate on it:

![](images/Review%20Of%20Web%20Authentication%20Methods/image025.png)<br><br>

Then you must enter the correct PIN:

![](images/Review%20Of%20Web%20Authentication%20Methods/image026.png)<br><br>


## Session Management

Once initial authentication is complete, a different method is required for subsequent requests so the secret(s) aren't passed each time a request is made to the server.  This is achieved by storing something on the client side which is usually a browser.

**Stateful** authentication uses [Cookies](#cookies) to do this while **stateless** authentication uses [Tokens](#tokens).


### Cookies

A web server uses cookies to keep track of active sessions in a database. After initial authentication, a cookie with the session ID is placed in the users browser using the `Set-Cookie` header.  

Here is a web application setting a cookie containing a session ID.  The `HTTPOnly` flag prevents it from being accessed by JavaScript and the `Secure` flag ensures it's only sent over an HTTPS connection:

![](images/Review%20Of%20Web%20Authentication%20Methods/image013.png)<br><br>

For all subsequent requests, the browser includes the cookie in the `Cookie` header.  The session ID is verified against the database to ensure it is a valid request.

![](images/Review%20Of%20Web%20Authentication%20Methods/image015.png)<br><br>

When a user logs out, the session is destroyed on both the client side and server side.

When using cookies, the browser decides when to send the cookie. Since cookies are associated with a domain, whenever the browser makes any request to a domain which it has a cookie for, it sends the cookie in the request.

### Tokens

Token-based authentication is stateless. The server does not keep a record of which users are logged in or which tokens have been issued. Instead, every request to the server is accompanied by a token which the server uses to verify the authenticity of the request.

When a web application receives a token, it validates the token using the secret key that was used to create it.  This is faster than using cookies which requires talking to a database or cache on the backend.

Most modern web services use [JSON Web Tokens](https://jwt.io/introduction/) or JWTs.  A JSON token is just JSON data with a signature.

The basic process consists of the following:

- Clients authenticate against an authentication API and get back a JWT
- Clients include this JWT to send requests to other API services
- API services check the JWT of each request to ensure user is trusted and can perform some action without needing to perform a network validation

Once a client is issued a token, each request to the web app will include an `Authorization` header containing the token.  Here is a request to the [Microsoft Azure](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0) portal after initial authentication:

![](images/Review%20Of%20Web%20Authentication%20Methods/image016.png)<br><br>

The token is a Base64-encoded JSON file containing user information and a signature:

![](images/Review%20Of%20Web%20Authentication%20Methods/image017.png)<br><br>

Tokens are also used for delegating authorization with protocols such as Oauth...

## Delegated Authorization

[OAuth](https://oauth.net/2/) provides web application access to third party applications.  It has nothing to do with authentication as it doesn't care who presents the access token, only that the bearer has access to the resources associated with the token.

### OAuth

Here is the basic flow of granting a third party application a scope of permissions via Oauth:

- a third party application needs authorization
- browser gets redirected to an authorization server where the user gives consent
- third party application receives an access token or a code that can be used to get an access token
- third party application uses access token to perform actions on behalf of user


Using [GitHub Desktop](https://desktop.github.com/) to perform actions on our Git repository is a great example of this in action.  During setup for this application, the user is provided an opportunity to sign into an Enterprise GitHub server:

![](images/Review%20Of%20Web%20Authentication%20Methods/image034.png)<br><br>

![](images/Review%20Of%20Web%20Authentication%20Methods/image035.png)<br><br>

After logging into our Enterprise GitHub, we're asked to authorize the Github Desktop application to access public and private repositories and user data:

![](images/Review%20Of%20Web%20Authentication%20Methods/image036.png)<br><br>

An email notification reports the authorization being granted to the application:

![](images/Review%20Of%20Web%20Authentication%20Methods/image038.png)<br><br>

This is documented in the account history as well:

![](images/Review%20Of%20Web%20Authentication%20Methods/image039.png)<br><br>

And the user has the ability to revoke this authorization at any time:

![](images/Review%20Of%20Web%20Authentication%20Methods/image040.png)<br><br>

Now the GitHub Desktop application has its own token it can use to make authenticated requests to the Git server and perform actions on behalf of the user:

![](images/Review%20Of%20Web%20Authentication%20Methods/image037.png)<br><br>


## Security Considerations

- [Single Factor Compromise](#single-factor-compromise)
- [Second Factor Compromise](#second-factor-compromise)
- [Session Compromise](#oauth-compromise)
- [Delegation Compromise](#delegation-compromise)		


### Single Factor Compromise

Username and password combinations are the most commonly used and stolen credentials.  These can be discovered on the Internet or obtained via social engineering.  Many services require a client to only present this information to gain access and perform actions on behalf of the user.

API keys are similar to a username and password but sometimes only require just one piece of information for access--a key.  AWS requires an API key and a secret key for access and these are frequently compromised via public code repositories such as [GitHub]() and [GitLab]().

Single factors of authentication can be discovered, phished, stolen, or guessed.

### Second Factor Compromise

Phishing and man-in-the-middle attacks can be used steal codes generated by a token generator if the user has to type it in.

Tools like [Modlishka](https://blog.duszynski.eu/phishing-ng-bypassing-2fa-with-modlishka/) and [ReelPhish](https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html) can be used to intercept and use both factors of authentication to obtain unauthorized access to a user account.

### Session Compromise

When using cookies and tokens, a user's secret(s) are only used once and are better protected. However, if a cookie or an access token is stolen, it can temporarily provide an unauthorized user access to the application.

Cookies can be used to perform unintended operations on a remote server via CSRF.  Both cookies and access tokens can be stolen and used to hijack a session via XSS.

For example, an access token was given to the browser after authenticating to the [Azure](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/SignIns) portal.  This token can be given to any application:

![](images/Review%20Of%20Web%20Authentication%20Methods/image018.png)<br><br>

Any application that has this token (`powershell.exe` in this example) can now access the web application in the context of the user, bypassing the two-factor authentication that was required to obtain the token:

![](images/Review%20Of%20Web%20Authentication%20Methods/image019.png)<br><br>

### Delegation Compromise

Tools like [PwnAuth](https://www.fireeye.com/blog/threat-research/2018/05/shining-a-light-on-oauth-abuse-with-pwnauth.html) and [Office 365 Attack Toolkit](https://www.mdsec.co.uk/2019/07/introducing-the-office-365-attack-toolkit/) can be used to trick users into authorizing malicious third party applications to access a web service.

If rights are granted to any application, it now has the ability to access the account without any multi-factor authentication and perform actions on behalf of the user.
