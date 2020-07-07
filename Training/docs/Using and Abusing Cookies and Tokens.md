# Using and Abusing Cookies and Tokens

There are three methods we frequently see used to access web applications either after or without completing the full authentication process:

|Method |Description|
|-|-|
|Cookies |Client receives a cookie after authentication which is passed in subsequent requests|
|Session JWTs |Client receives a token after authentication which is passed in subsequent requests|
|OAuth Tokens |Client is given a token which is used to perform actions on behalf of a user|

<br>

The use of these methods presents several different opportunities for abuse if cookies and tokens are not stored and transmitted securely.  This training document provides examples of how these methods are used normally and some of the ways they can be abused if cookies and tokens are exposed to unauthorized users or applications.

- [Cookies](#cookies)
  - [Cookie Use](#cookie-use)
  - [Cookie Abuse](#cookie-abuse)
  - [Cookie Best Practices](#cookie-best-practices)
- [JSON Web Tokens](#json-web-tokens)
  - [JWT Use](#jwt-use)
  - [JWT Abuse](#jwt-abuse)
  - [JWT Best Practices](#jwt-best-practices)
- [OAuth Tokens](#OAuth-tokens)
  - [OAuth Token Use](#OAuth-token-use)
  - [OAuth Token Abuse](#OAuth-token-abuse)
  - [OAuth Token Best Practices](#OAuth-token-best-practices)


## Cookies

- [Cookie Use](#cookie-use)
- [Cookie Abuse](#cookie-abuse)
- [Cookie Best Practices](#cookie-best-practices)

### Cookie Use

HTTP cookies are used for tracking and personalization, but here we'll talk about their use in session management.  Used in this way, they allow a server to associate actions and settings with a particular user and session.

After initial authentication, the server sends the client one or more cookies via the `Set-Cookie` header.  Log into [App](https://app/) and you can check the `Application` tab in Chrome Debugger to see the current cookies for the site and their associated attributes:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image009.png)<br><br>

The browser begins sending these cookies with every request in the `Cookie` header:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image010.png)<br><br>

This is how the server tracks which requests are coming from authenticated users and which require authentication.  A client requesting a protected page like `My Account` without sending the required cookies will be redirected to the `Log In` page:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image011.png)<br><br>

### Cookie Abuse

However, with possession of cookies associated with an authenticated session, any application can make web requests that the server will think belong to that authenticated session.

Using PowerShell, build a web client and add the cookie as a header:

```
$wc = New-Object Net.WebClient
$wc.Headers['Cookie']="BALANCEID=balancer.thin0; WSMD=IMjbz%2Bs9ZM2WJSjcIBxekaq1o9nhRwwohbshmrOvGkWeAC4%3D; _session_id=0baf39834d38e385ac15119b47a70469"
```

<br>

Now request the same page, this time providing the server with the cookies from the browser's current authenticated session, and the protected `My Account` page can be reached:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image012.png)<br><br>

A completely different user/application (PowerShell) can now interact with the web application and impersonate the user, hijacking the users current session.  

There are opportunities where this can happen on our network.

Here, request headers are being logged which contain cookies with session IDs:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image022.png)<br><br>

A normal web request redirects an application to the SSO login page so the user can provide authentication via CAC card:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image023.png)<br><br>

But adding the cookie with session ID bypasses authentication and allows the application to reach the protected page:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image024.png)<br><br>

This demonstrates how important it is to safely store and transmit session cookies.

### Cookie Best Practices

The following attributes can be used to harden cookies:

|Attribute|Description|
|-|-|
|`Secure`|Only send cookie to server over an encrypted (SSL/TLS) connection|
|`HttpOnly`|Prevents scripts from accessing the cookie via the DOM `document.cookie` object|
|`SameSite=Strict`|Prevents cookie from being sent with cross site requests|
|`Domain`|Only send cookie to a specific domain|
|`Path`|Only send cookie to a specific path|
|`Max-Age`, `Expires`|Cookie is persistent, valid until expires|

<br>

Additional recommendations:

- Use non-persistent cookies for session management so session IDs aren't stored on disk by browsers
- If logging headers, ensure session identifiers are removed or obscured
- Implement user-unique CSRF tokens to prevent cross site requests
- Use custom request headers
- Set cookies to have short lifetimes


## JSON Web Tokens

- [JWT Use](#jwt-use)
- [JWT Abuse](#jwt-abuse)
- [JWT Best Practices](#jwt-best-practices)

### JWT Use

JSON Web Tokens (JWTs) are  cryptographically signed JSON strings containing user-specific information known as "claims".  They are made up of a Base64-encoded header, payload, and signature.  The header and payload are hashed with a key and the resulting value is appended to the token as the signature so the server can verify that the token is valid and trusted.

|Section|Description|
|-|-|
|Header|Type of the token and the hashing algorithm|
|Payload|Contains the claims|
|Signature|Calculated hash of payload and header with key|

<br>

A typical JWT contains information about the user and metadata like when it was issued and when it expires.  Use the `Get-JWT` function from the [IRModule](../scripts/Modules/IRmodule.psm1) to quickly decode a JWT and display the information it contains:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image013.png)<br><br>

The function saves the original token as the `$tok` variable and the contents of the JWT as objects as the `$obj` variable:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image014.png)<br><br>

Tokens are traditionally passed in the `Authorization` header, however this token is seen being passed as the `auth` parameter in a URL that was logged:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image015.png)<br><br>  

Inspecting the JWT shows its contents:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image016.png)<br><br>

As expected, accessing the application using the expired token redirects to a `logout` page reporting that the session is no longer active:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image017.png)


### JWT Abuse

Here is a token that is issued to a user to download a file being passed in the URL:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image018.png)<br><br>

Inspecting the token reveals it doesn't have an expiration date:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image019.png)<br><br>

As expected, trying to access the file without the token returns a `401 Unauthorized`:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image020.png)<br><br>

But providing the token in the URL downloads the file and grants access to sensitive documents:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image021.png)<br><br>

JWTs are great for authorization but if obtained by an unauthorized user or application, can be used to bypass initial authentication like in this example.

### JWT Best Practices

To mitigate/prevent Token Sidejacking:

- Avoid passing token in URL, instead pass token in `Authorization` header with `Bearer eyJhb...`
- If logging headers, ensure tokens are removed or obscured
- Integrate user context into tokens such as a random string generated during the authentication phase
- Set tokens to have short lifetimes
- Use token blacklisting to revoke compromised tokens or logged out users

Additional recommendations:

- Encrypt JWTs to protect user-specific information it contains
- Store in `sessionStorage` rather than `localStorage`
- Have clients sign tokens to prevent reuse
- Sign with complex symmetric keys to prevent dictionary attacks

JWTs are good for API services in which clients make frequent requests in a limited scope.  They also work well for validating a user's identity via a third party such as in the OAuth protocol.

## OAuth Tokens

- [OAuth Token Use](#OAuth-token-use)
- [OAuth Token Abuse](#OAuth-token-abuse)
- [OAuth Token Best Practices](#OAuth-token-best-practices)

### OAuth Token Use

Many web services provide the ability to create OAuth tokens and issue them to third party users and applications for the purpose of performing actions of a limited scope on behalf of the user.  

For example, the Github Desktop application on my workstation has been granted an OAuth token to access Github and perform actions on behalf of my account:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image001.png)<br><br>

This token is stored safely in the application, but there are still ways to access it in process memory:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image002.png)<br><br>

Any application or user in possession of this token can use it to perform actions in an authenticated context:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image003.png)<br><br>

The headers returned will often provide the token's scope:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image008.png)<br><br>

### OAuth Token Abuse

An exposed token allows anyone who has access to it the ability to impersonate that user.

This Splunk search shows GitHub tokens being logged in URL requests:

```
index=* sourcetype=syslog access_token
| rex field=_raw "(?<token>[a-z0-9]{40})\s"  
| where len(token)=40
| stats count by token host
```

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image004.jpg)<br><br>

The tokens are being passed in the URLs of both POST and GET requests to our GitHub Enterprise API:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image005.jpg)<br><br>

Here I’ve put a token in an `Authorization` header and can make API calls as the user `xxxxx`:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image006.jpg)<br><br>

There are a number of ways API access can be abused by an unauthorized user---for example listing, adding, and deleting SSH keys:

![](images/Using%20and%20Abusing%20Cookies%20and%20Tokens/image007.jpg)<br><br>

### OAuth Token Best Practices

- Do not hard-code tokens into scripts or applications
- Do not transmit tokens in query strings of URLs in GET requests
- Regularly rotate and expire tokens
- Use the most limited authorization scope required when issuing tokens

## Summary

Cookies and tokens allow users and applications to bypass initial authentication and gain unauthorized access to web applications.  For this reason, they must be protected in storage and in transit.
