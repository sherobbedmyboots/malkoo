# Searching For Credentials With Splunk

Credentials come in several different forms so searching for them requires a good understanding of the different types and how each type is used.  This training document reviews some basic ways to search for the following types of credentials commonly seen in our environment:

- [Plaintext Passwords](#plaintext-passwords)
- [API Keys](#api-keys)
- [Basic Authentication](#basic-authentication)
- [HTTP Cookies](#http-cookies)
- [JSON Web Tokens](#json-web-tokens)


## Plaintext Passwords

Plaintext passwords are usually found in URLs, configuration files, and endpoint logs.  Here is a base plaintext password search with a few modifications to filter out false positives:

```
index=* "password" OR "pass"
| rex field=_raw "(?i)(pass)?(word)[\=\:]{1}?([\s\"])(?<password>[^\"^\s\=,]+)"
| rex field=_raw "(?i)(username|user\sid|user)[\=\:]{1}?([\s\"])(?<uname>[^\"^\s^\,]+)"
| where len(password) > 3 AND len(uname) > 0
| regex uname!="(password)|(VALUEOF)|(String)"
| regex password!="(nessus)|(^'${)|(^<)|(\)$)|(INVALID)|(must)|(PROTECTED)|(REDACTED)|(FILTERED)|(Credential)|(LOGGING)|(PRODUCT)|(null)|(\*\*\*\*\*)|(command)|(Cannot)|(changed)|(hostname)"
| dedup sourcetype uname password
| table sourcetype uname password
```

![](images/Searching%20For%20Credentials%20With%20Splunk/image007.png)<br><br>


## API keys

API keys are another type of credential that provide access to any user that presents it to a service.  This search looks for API keys that are discovered in logs labeled with the strings `apikey` or `api_key`:

```
index=* "apikey" OR "api_key"
| rex field=_raw "(?i)(apikey)\=(?<apikey>[a-zA-Z0-9\_\/\+]+)[\s\W]"
| where len(apikey) > 10
| stats count by sourcetype apikey  
```

![](images/Searching%20For%20Credentials%20With%20Splunk/image005.png)<br><br>

If you know the lengths of vendor- or application-specific keys like AWS (20 character keys and 40 character secrets), you can use regular expressions to narrow the search:

```
index=* 
| rex field=_raw "[\=\s]{1}(?<access_key>A[KS]{1}IA[A-Z0-9]{16})\W"
| rex field=_raw "[\=\s]{1}(?<secret_key>[A-Za-z0-9\/\+]{40})\W"
| where len(secret_key) = 40 AND len(access_key) = 20  
| dedup sourcetype access_key
| table sourcetype access_key secret_key
```

![](images/Searching%20For%20Credentials%20With%20Splunk/image001.png)<br><br>

Once the sourcetypes and keys have been identified, additional searches can provide the details required for remediation.

## Basic authentication

Basic authentication requires usernames and passwords to be Base64 encoded and included in the `Authorization` header.  Logging HTTP headers exposes the credentials to anyone who can access the logs:

```
index=* Basic
| rex field=_raw "Basic\s(?<encodedpw>[a-zA-Z0-9\=]{5,})"
| `base64dec(encodedpw)`
| regex encodedpw_ascii="\:"
| where len(encodedpw_ascii) > 6
| stats count by encodedpw_ascii
| sort -count
```

![](images/Searching%20For%20Credentials%20With%20Splunk/image002.png)<br><br>


## HTTP cookies

Logging of HTTP request headers also exposes HTTP cookies:

```
index=*  "Cookie" NOT "cookie=\"-\""  NOT "cookie.js" NOT "cookie.min.js" NOT "document.cookie" NOT "cookie_store.rb" NOT "lb_cookie"
| rex field=_raw "(?i)(cookie)[\:\s\"]{2,4}(?<cookie>[^\"\]]+)"
| where len(cookie) > 10
| table sourcetype cookie
```

![](images/Searching%20For%20Credentials%20With%20Splunk/image006.png)<br><br>


## JSON Web Tokens

JSON Web Tokens may be observed in URLs or in request headers that are being logged. Here is a base search that looks for the base64-encoded beginning of every JWT, then decodes the token and puts it into the field `token_ascii`:

```
index=* "eyJ*"
| rex field=_raw "(?<token>eyJ[a-zA-Z0-9]+[\.]{1}[a-zA-Z0-9]+[\.]{1}[a-zA-Z0-9]+)"
| where len(token) > 0
| `base64dec(token)`
| stats count by sourcetype token_ascii
```

![](images/Searching%20For%20Credentials%20With%20Splunk/image004.png)<br><br>


```
index=* "eyJ*"
| rex field=_raw "(?<token>eyJ[a-zA-Z0-9]+[\.]{1}[a-zA-Z0-9]+[\.]{1}[a-zA-Z0-9]+)"
| where len(token) > 0 AND len(hostname) > 0
| stats values(sourcetype) AS sourcetypes values(hostname) AS hostnames values(index) AS indexes dc(token) AS uniqueTokens by POC
| sort -uniqueTokens
| table sourcetypes indexes uniqueTokens POC
```

![](images/Searching%20For%20Credentials%20With%20Splunk/image003.png)<br><br>
