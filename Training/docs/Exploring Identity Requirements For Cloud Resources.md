# Exploring Identity Requirements For Cloud Resources

The traditional perimeter of an organization's network has all but disappeared.  A modern organization has resources that exist both on premise and hosted on cloud provider networks spread across the world.  Users are able to access these resources with multiple devices and applications by proving their identity.  

Therefore, any user or application that satisfies the proof of identity requirements can access these resources.  In some cases this proof is possession of a PIV card and knowledge of its PIN.  In other cases it is just a single password, API key, or access token.

In this training document, we will look at several common ways an adversary can meet proof of identity requirements and gain unauthorized access to our cloud resources.

- [Web Services](#web-services)
  - [Internal Web Services](#internal-web-services)
  - [External Web Services](#external-web-services)
- [Ways To Exploit Single Factor](#ways-to-exploit-single-factor)
  - [Find It](#find-it)
  - [Guess It](#guess-it)
  - [Phish It](#phish-it)
  - [Bypass It](#bypass-it)
- [Ways To Exploit Session Cred](#ways-to-exploit-session-cred)  
  - [Steal It](#steal-it)
  - [Forge It](#forge-it)
- [Summary](#summary)

## Web Services

Users utilize both [Internal Web Services](#internal-web-services) and [External Web Services](#external-web-services).  Let's look at examples of both types and which of the following credential types can be used to obtain access:

|Type|Description|
|-|-|
|U/P|Username and password||
|API|API key||
|TK|Token||
|SSO|Single Sign On|Kerberos ticket good, get SAML assertion|
|PIV|PIV must be inserted and PIN typed|

<br>

### Internal Services

Here are some web services hosted on the internal network:

|Service|URL|Credentials|
|-|-|-|
|[]()|``|PIV|
|[]()|``|SSO, TK|
|[]()|``|SSO, API, TK|
|[]()|``|SSO|
|[]()| ``|U/P|

<br>

Anyone who has access to the internal network and can meet the service's proof of identity requirements can access these resources.

### External Services

Here are some services hosted on external networks:

|Service|URL|credentials|
|-|-|-|
|[AWS](https://signin.aws.amazon.com)|`https://signin.aws.amazon.com`|SSO, U/P, API|
|[Slack](https://slack.com)|`https://slack.com`|SSO, U/P, API, TK|
|[Tenable.io](https://cloud.tenable.com)|`https://cloud.tenable.com`|SSO, U/P, API|
|[]()|``|SSO, U/P|
|[CloudCheckr](https://app.cloudcheckr.com)|`https://app.cloudcheckr.com`|SSO|
|[]()|``|SSO|
|[Microsoft Azure](https://portal.azure.com)|`https://portal.azure.com/`|SSO|
|[]()|``|SSO|
|[]()|``|SSO|
|[]()|``|U/P, API|

<br>

With external cloud services, there is no need to be on premise, all that's needed is credentials.  Anyone who can meet the service's proof of identity requirements can access these resources.

## Ways To Exploit Single Factor

A single factor is one piece of data that can be used to access a web service in an authenticated context. They can be discovered by scanning and reconnaissance techniques, guessed if a password or key, phished with various social engineering methods, or bypassed using account recovery procedures.

The term *single factor* is commonly used when referring to a username and password pair or an API key. For example, a [Tenable.io](https://cloud.tenable.com) account can be accessed with username and password at `https://cloud.tenable.com`:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image054.png)<br><br>

This resource allows anyone with the username and password to access to large amounts of sensitive information:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image055.png)<br><br>

An API key can be generated and used from anywhere as well:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image057.png)<br><br>

Here are the most common ways an adversary will obtain a single factor in order to gain unauthorized access to a web service:

 |Method|Description|
 |-|-|
 |[Find It](#find-it)|Breaches, dumps, repos, scanning |
 |[Guess It](#guess-it)|Common, reuse, default |
 |[Phish It](#phish-it)|Email, SMS, chat |
 |[Bypass It](#bypass-it)|Email, SMS, security questions |

<br>

### Find It

Single factor credentials like passwords, API keys, and private keys can be discovered through breached sites and pastes, internet scanning, and/or more focused reconnaissance techniques.  

Tools like [Have I Been Pwned?](https://haveibeenpwned.com) check to see if credentials have been found in a data breach or paste:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image058.png)<br><br>

The site shows the breach or paste containing the credential:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image059.png)<br><br>

Tools like [Gitrob](https://github.com/michenriksen/gitrob) and [TruffleHog](https://github.com/dxa4481/truffleHog) search through GitHub repositories for credentials and other sensitive information.

For example, this organization has many repositories that could mistakenly contain credentials for various cloud resources:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image045.png)<br><br>

[Gitrob](https://github.com/michenriksen/gitrob) can quickly enumerate each of the users under this organization and began searching their repositories for sensitive files:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image046.png)<br><br>

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image047.png)<br><br>

[Gitrob](https://github.com/michenriksen/gitrob) will report files discovered, their location, and what they commonly contain of interest:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image048.png)<br><br>

Once a repo requiring additional investigation is identified, it can be searched more closely using [TruffleHog](https://github.com/dxa4481/truffleHog):

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image049.png)<br><br>

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image050.png)<br><br>

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image051.png)<br><br>

These could potentially be used by anyone who discovered them to access our systems and network.

### Guess It

People are not great at picking random, complex passwords and there are many lists of commonly used passwords that will help an adversary gain access to an account protected by only a weak password.

Because passwords and keys can and often are reused, credentials found in breaches, pastes, and repos may also grant unauthorized access to additional services associated with a user.

For example, an adversary may obtain a username and password for an account using an email address from a paste.  The next step would be to try that same username and password on other services the user likely uses:

Slack's web service allows multiple password guesses:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image026.png)<br><br>

However, if successfully guessed, Two Factor Authentication is enabled on this account and will prevent unauthorized access:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image028.png)<br><br>

CloudCheckr's web service is using a different type of control by restricting logons to SAML only, which requires two factors to use:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image025.png)<br><br>

The AWS console allows multiple guesses:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image027.png)<br><br>

Which can be detected using CloudTrail logs:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image029.png)<br><br>

### Phish It

Phishing is the use of fake emails, chats, or SMS messages designed to appear as they were sent from reputable organizations to lure a user into running a program or revealing sensitive information such as usernames, passwords, and other account credentials.

Phishing can be used to run malware that will steal user credentials:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image021.png)<br><br>

It can also be used to impersonate a cloud provider login page and obtain user credentials:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image022.png)<br><br>

The goal can be accessing a users financial web services:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image023.png)<br><br>

Or gaining access to an individual users email, file storage, and other cloud resources:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image024.png)<br><br>


Tools like [ReelPhish](https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html), [PwnAuth](https://www.fireeye.com/blog/threat-research/2018/05/shining-a-light-on-oauth-abuse-with-pwnauth.html), and [Okta Watering Hole](https://github.com/praetorian-code/Okta_Watering_Hole) can be used to obtain second factor credentials if required.


### Bypass It

If the single factor cannot be found, guessed, or phished, it often can be bypassed using some other implicitly-trusted service such as email, SMS, or a series of security questions.  Most services have an account recovery process where the password can be changed and used to gain access.

Access to a user email account is the most common recovery method used. This account's password can be changed by requesting a reset link via email:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image056.png)<br><br>

This means the application is now using access to the user's email account to authenticate a user rather than the normal authentication process:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image018.png)<br><br>

If the adversary can read the email or the reset link, he can obtain full access to the account.

## Ways To Exploit Session Cred

Once a user performs initial authentication and receives a session credential, this cookie or token is all that is needed to access the service and can therefore also be considered a single factor.

Here are two common ways an adversary can obtain a session credential to gain unauthorized access to a web service:

|Method|Description|
|-|-|
|[Steal It](#steal-it)|Cross Site Scripting (XSS)|
|[Forge It](#forge-it)|Cross Site Forgery Request (CSRF)|

<br>

### Steal It

With Cross Site Scripting (XSS), the adversary executes code in the victim's browser to redirect browsing and/or steal credentials and other sensitive information for later use.

There are three types of XSS:

|Type|Description|
|-|-|
|Stored XSS|Website or application contains the untrusted code|
|Reflective XSS|Link contains code that's echoed back to the browser and executed|
|DOM XSS|Client-side JavaScript dynamically modifies a rendered page based on content in the URL|

<br>

The main concern with XSS is if the adversary can run JavaScript in the browser, the cookie or session token can be sent to a remote server and used to create an authenticated session from there.

Here is an example of this from [JavaScript Analysis Tools and Methodology](Javascript%20Analysis%20Tools%20and%20Methodology.md) where Stored XSS is used to send a user's cookie to a remote system:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image052.png)<br><br>

#### Session Cookies

If the session is being tracked with a cookie, there are a few mitigations that can be used:

|Mitigation|Description|
|-|-|
|`HttpOnly` |Ensures client scripts cannot access cookies to mitigate XSS attacks|
|`secure=true` |Ensures cookies can only be set over an encrypted connection|
|**Signed Cookies**|Prevents clients from modifying cookies|

These work together to ensure the cookie is not sent by JavaScript, only with requests to its domain and only over a secure HTTPS connection.

<br>

#### Session Tokens

If the session token is stored with JavaScript, the `localStorage` and `sessionStorage` variables are typically used.  

Both of these use essentially the same security policy as cookies---i.e a domain cannot access `localStorage` data that was created under a different domain.  The difference here is that they can be accessed from the local JavaScript context and potentially sent to a remote server for exploitation.

Let's look at [Tenable.io](https://cloud.tenable.com) as an example.  After initial authentication (using either SSO or username and password), the `iron.js` script is loaded and runs in the browser issuing the user a token labeled `X-Cookie`:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image061.png)<br><br>

This token gets saved in `localStorage`:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image062.png)<br><br>

Since it is stored in `localStorage`, any JavaScript that runs in the DOM can access it:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image063.png)<br><br>


In this scenario, two important conditions for a successful session hijack via XSS are now met:

1. All that's required to access the account now is the token
2. The token can be accessed by any JavaScript running in the browser

<br>

If an adversary can get JavaScript to run in the victim's browser and steal the token, he can then use the token to access the account from anywhere using any application.  

Here's an example using PowerShell:

```powershell
$url = "https://cloud.tenable.com/workbenches/assets"
$tok = "token=d0d2671bb5524af51abab3ca09f580598a6f6c8cb06126b038f5e71f73e54173"
$r = Invoke-RestMethod $url -Headers @{'X-Cookie'=$tok}
$r.assets | Select -First 1

```

<br>

This web request returns sensitive information for hundreds of assets:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image060.png)<br><br>

Alternatively an adversary may choose to carry out the attack in-place from the victim's browser using CSRF rather than from their own machine.

### Forge It

[Cross Site Request Forgery (CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29) occurs when a malicious site, email, or application causes a user's web browser to perform unwanted actions on a trusted site while the user is authenticated.

As long as the user is authenticated, requests automatically include any credentials associated with the site (session cookies, tokens, IP address, etc.).  If an adversary can cause the client to make arbitrary requests, the trusted site cannot distinguish between the requests initiated by the adversary and legitimate requests initiated from the victim.

Here is a CSRF example from [JavaScript and Browser-Based Malware](JavaScript%20and%20Browser-Based%20Malware.md#cross-site-request-forgery) where a password change operation is performed on a remote server by an adversary using JavaScript:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image014.png)<br><br>


For example, this `update_user` page is where you can change your password in the xxx application:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image010.png)<br><br>

This page contains a form with id of `changePassword` that allows you to enter data and submit it with a POST request:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image011.png)<br><br>

This form can be accessed by any JavaScript running inside the browser using the `document.getElementById` or other methods:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image012.png)<br><br>

When the button is clicked, the POST is submitted and the exchange can be watched in the Chrome Debugger:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image013.png)<br><br>

Here you can also see that the POST data submitted contains the new password values:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image015.png)<br><br>

The application response contains confirmation the password was changed:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image017.png)<br><br>

If a browser is being used, it is displayed in the browser:

![](images/Exploring%20Identity%20Requirements%20For%20Cloud%20Resources/image016.png)<br><br>

But this entire process can take place without the user navigating to the page---JavaScript running in the DOM initiated by an adversary can also make this password change.  And since the victim's browser is already authenticated, it can be performed without needing to find and submit session credentials.

There are several ways to mitigate these attacks:

|Mitigation|Description|
|-|-|
|`SameSite=strict`|Ensures cookie can only be sent with requests originating from the same site|
|Anti-CSRF Tokens|Token unique to each request ensure they come from a trusted source|
|Session ID in Headers|Using HTTP Headers not accessible to the attacker for session management|

We'll take a closer look at the mitigations for this technique more closely in a later document.

<br>

## Summary

An organization's network boundaries are now defined by the identities that can access these cloud resources.

- Current credentials can be searched for, discovered, and used to access accounts protected by only a single factor

- Users often employ weak or duplicate passwords that can be guessed or brute-forced

- Users can be tricked into providing credentials to an adversary or running malware that steals them

- Account recovery procedures can allow an adversary to bypass the normal authentication process

- With XSS, the adversary is using the ability to run JavaScript in the victim's browser to send a cookie or session token to a remote server so they can create an authenticated session from there.

- With CSRF, the adversary is taking advantage of the browser being authenticated to a target site.  If the victim is logged in, any request made to the site originating from the victim's browser will be successful.

<br>

Best practices for both corporate and personal cloud accounts:

- Use a long, complex password with 2FA enabled
- Verify accurate and up-to-date account recovery info such as email, phone
- Review recent activity, authorized/logged in devices
- Review payments, subscriptions, 3rd party access authorizations

We'll begin looking at each of these techniques more closely and identify potential opportunities for an adversary to obtain credentials to internal and external services we use.
