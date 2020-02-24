# Dealing With Ads, Trackers, and Script Servers

When a modern webpage loads, it loads content from dozens, sometimes hundreds of other sources.  Advertising, tracking, and scripts from third-party servers make up a large percentage of these.  During dynamic analysis of a website, it is important to be able to quickly and efficiently identify and isolate all traffic to and from third party servers.  

This traffic generally falls into three categories:

- [Advertisements](#advertisments)
- [Trackers](#trackers)
- [Script Servers](#script-servers)

## Advertisements

Advertisements have been a method for companies to generate revenue for a long time.  ISPs have been observed in the past using several different techniques including selling user clickstream data, selling phone location data, and using DNS redirects to splash pages containing ads:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image014.png)<br><br>

On a typical website serving advertisements, ads are displayed as images, buttons, or HTML elements on the web page.  The actual files do not reside on the page’s host server, but on a server belonging to the advertising company---a third party server. 

When an application such as an email reader or web browser loads the content, it requests to download the image from the advertiser's server rather than the host server.  This request can contain identifying information about the user, browser, and computer to the advertiser.

Visiting [CNN](www.cnn.com)'s website shows only 46 of the 172 requests made by the browser were to the `cnn.com` domain:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image021.png)<br><br>

You can use a tool like [LightBeam]() to see a visualization of all third party sites contacted after visiting a website:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image016.png)<br><br>

Browse to multiple sites to see the common third-party servers that these sites use:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image000.png)<br><br>

One option to isolate all ad traffic to third party servers is to use AdBlockers like [uBlock Origin](https://www.ublock.org/) and [Ghostery](https://www.ghostery.com/).

[uBlock Origin](https://www.ublock.org/) blocks third-party ads and trackers based on URL parameters:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image003.png)<br><br>

It provides an explanation for each page if you try to access it directly:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image007.png)<br><br>

You can also view the list of URL parameters that showed a match and led to blocking the traffic:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image008.png)<br><br>

[Ghostery](https://www.ghostery.com/) also blocks ad and tracker traffic to third party servers:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image001.png)<br><br>

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image002.png)<br><br>

You can click on each one to see information for each company:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image004.png)<br><br>


## Trackers

Tracking is when these third-party sites collect and organize information about users browsing to multiple different websites. This information shows trends on where a specific user browses and what they do at each website.

Companies that own large advertising networks like Google and Facebook can track users not only by browsing history, but also through all the services they provide (Facebook, Google Search, YouTube, Instagram, Gmail, Chrome, etc). This data can be combined and mined to make user profiles so that personalized ads can be served via ad networks (Adsense, Admob, and DoubleClick) that are embedded in millions of websites.

Here are four common methods used for tracking:

- [Cookies](#cookies)
- [Web Bugs](#web-bugs)
- [Fingerprinting](#fingerprinting)
- [Supercookies](#supercookies)


### Cookies

[Cookies](https://en.wikipedia.org/wiki/HTTP_cookie) and [local storage](https://en.wikipedia.org/wiki/Web_storage) are two common ways companies track users.  Cookies are set either by scripts running in the page using an API call, or by HTTP responses that include a `Set-Cookie` header.  Local storage is a feature of HTML5 that allows a browser to store information using Javascript.

The user-specific cookie is set and stored in a user's browser stored, and can then be retrieved and transmitted to third-party domains.  Here are two common scenarios:

|Type|Example|Process|
|-|-|-|
|Third-party analytics|Google Analytics (GA)|- Website embeds the GA script <br> - GA sets a site-owned cookie <br> - Subsequent requests to GA from that website will include that cookie|
|Third-party tracking|DoubleClick (DC)|- Website embeds DC script <br> - DC sets a tracker-owned cookie <br> - Subsequent requests to DC from any website will include that cookie|


The same concept applies with social widgets as with advertisements:

- User logs into Facebook and is issued a cookie
- User visits site #1 that has embedded a **Like** button and sends cookie with request
- User visits site #2 that has embedded a **Like** button and sends cookie with request
- User visits site #3 that has embedded a **Like** button and sends cookie with request

Using this method, Facebook can track the user across any site that embeds the **Like** button.

This site embeds a request to a third party server that hosts a script that will make the browser set a cookie and transmit it:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image025.png)<br><br>

The GET request is made along with some information passed as URL parameters: 

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image022.png)<br><br>

Along with the URL parameters, the UserAgent and Referer header is also sent to the third-party server:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image023.png)<br><br>

Th `ui` parameter is one of the pieces of information that is sent, which is the cookie that was set:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image024.png)<br><br>

A similar technique tracks users without the use of cookies...

### Web Bugs

Web bugs have traditionally been small digital image files that were embedded in a web page or email.  Additional methods include graphics, banners, buttons, and other HTML elements such as frames, styles, scripts, input links, etc.

When a user opens a page or email with a web bug, their web browser or email reader automatically downloads the resource which requires the user’s computer to send a request to the third-party server.  This request contains identifying information about the user, browser, or computer which allows the host to keep track of the user.

Email marketers, spammers, and phishers use web bugs to verify that an email is read.  An email containing a web bug is sent to a large list of email addresses and requests for the embedded resource identify which email addresses are valid and also that the email made it past spam filters.

Outlook provides the option for users to download embedded resources:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image026.png)<br><br>

When the **Download Images** option is selected, requests go out for the embedded content:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image027.png)<br><br>

Inspection with Fiddler shows several parameters are passed in one of the requests:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image028.png)<br><br>

The value of the `mid` parameter is base64-encoded identifying information:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image029.png)<br><br>


### Fingerprinting

Unlike tracking with cookies, fingerprinting is used to build user profiles based only on observed patterns of characteristics associated with your browser.  Fingerprinting distinguishes and recognizes individual browsers by collecting and analyzing various information that can be obtained from the browser such as:

- User agent string
- HTTP ACCEPT headers sent by the browser
- Screen resolution and color depth
- Timezone your system is set to
- Browser extensions/plugins, like Quicktime, Flash, Java or Acrobat, that are installed in the browser, and the versions of those plugins
- Fonts installed on the computer, as reported by Flash or Java.
- Whether browser executes JavaScript
- Acceptance of cookies and "super cookies"
- Hash of the image generated by canvas fingerprinting
- Hash of the image generated by WebGL fingerprinting
- Do Not Track (DNT) header set
- System platform (e.g. Win32, Linux x86)
- System language (e.g. en-US)
- Touchscreen support


Combined, this information can create a kind of fingerprint — a signature that can be used to identify you or your computer and track your activity across multiple websites.  Since this information is collected passively, tools that focus on behavioral indicators such as [Privacy Badger](https://www.eff.org/privacybadger) are the most effective.

[Privacy Badger](https://www.eff.org/privacybadger) looks for third parties tracking user across multiple websites.  If a site does not seem to be tracking, traffic to it is allowed (green).  If a site is observed tracking you on 3 or more websites, traffic to it is blocked (red).  If the site is tracking but also provides functionality required for proper website operation, it blocks the tracking-related functions and allows the functions required for website operation (yellow).

[Privacy Badger](https://www.eff.org/privacybadger) allows you to adjust settings for each domain:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image005.png)<br><br>

All requests to blocked domains fail:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image006.png)<br><br>


## Supercookies

*Supercookies* or [zombie cookies](https://en.wikipedia.org/wiki/Zombie_cookie) are any technology other than a standard HTTP Cookie that is used by a server to identify clients.  Examples include Flash LSO cookies, DOM storage, HTML5 storage, and other methods of storing information in caches or etags.

Using a tool like [EverCookie](https://samy.pl/evercookie/) is a great way to become familiar with supercookie techniques. 
Go to the site and click the button to create an evercookie in your browser:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image030.png)<br><br>

Several techniques will succesfully be used to assign your browser a random number which simulates a tracking ID:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image031.png)<br><br>

See how many techniques you can find:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image032.png)<br><br>

Delete as many as you can, then click one of the options to have the cookies automatically "rediscovered":

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image033.png)<br><br>

Bet you can't get them all...

## Script Servers

Script servers are used by third-party servers for many different purposes including tracking, serving ads, serving website content, or all of the above.  

Tools like [NoScript](#https://noscript.net/) can be used to identify and block traffic to these servers and allow an analyst to control the execution of third-party scripts.

Install the plugin in your browser and visit a site with many third-party servers such as [CNN](www.cnn.com). At first no scripts will be allowed to run:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image034.png)<br><br>

You can then configure which domains your browser is allowed to run scripts from:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image035.png)<br><br>


## Summary

Practicing browsing privacy and security is a great way to get familiar with ads, trackers, and script servers.  Here are a few more browsing technologies to play around with:

You can turn on the **Do Not Track** header (i.e., stop collecting cookies, supercookies, fingerprints) in your browser's settings but many companies ignore this.

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image010.png)<br><br>

This setting ensures a DNT value is sent with all web requests:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image015.png)<br><br>

To avoid web bugs, either read emails offline or force your reader to display emails in plain-text. The contents of plain-text email messages are not interpreted as embedded HTML code so opening them does not initiate any communication.

You can test your browser using tools like [Panopticlick](https://panopticlick.eff.org/):

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image011.png)<br><br>

After testing, it reports how well your browser stops tracking techniques:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image012.png)<br><br>

And gives you information on what was discovered using your browser configuration:

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image013.png)<br><br>

Also try testing with [Browser Leaks](https://browserleaks.com/):

![](images/Dealing%20With%20Ads%20Trackers%20and%20Script%20Servers/image036.png)<br><br>
