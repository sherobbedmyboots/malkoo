# Filtering Expected Web Traffic in Splunk

The majority of compromises involve a victim host reaching out to an attacker-controlled domain or IP.  Looking at a host’s web traffic in Splunk and trying to identify which remote hosts are possibly malicious is a difficult task because of the large volume of web traffic logged.  To make this task easier, we can use a Splunk lookup and macro to filter out expected traffic.

The lookup is a csv file I created with the hosts I want to filter out and their category.

To see the contents, use the following command:

```
inputlookup webfilter.csv
```

The `webfilter` macro is like a shortcut for a saved search.

You can view it by going to **Settings** --> **Advanced Search** --> **Search macros**.


The webfilter lookup and the macro can be used to filter out expected traffic such as:

- [Allow-listed Websites and Tools](#allow-listed-websites-and-tools)
- [Certificate Checks](#certificate-checks)
- [Advertisements and Analytics](#advertisements-and-analytics)
- [Safebrowsing Updates](#safebrowsing-updates)
- [Connectivity Checks](#connectivity-checks)
- [Social Networking](#social-networking)
- [Meeting and Chat Software](#meeting-and-chat-software)
- [Google and Microsoft Services](#google-and-microsoft-services)


## Allow-listed Websites and Tools

When searching for malicious infrastructure, we need to filter out traffic to authorized infrastructure and external services.

The `webfilter` macro contains the following filters:

```splunk
cs_host!=*.<domain>
cs_host!=<ip-range>
```

## Certificate Checks

**Certificate Revocation Lists** (CRL) are used to validate the status of a digital certificate using hosts such as:

- crl.microsoft.com
- mscrl.microsoft.com

**Online Certificate Status Protocol** (OCSP) is an alternative method for verifying digital certificates and uses hosts such as:

- ocsp.verisign.com
- ocsp.thawte.com
- ocsp.comodoca.com
- ocsp.msocsp.com
- ocsp.verisign.com
- ocsp.thawte.com

The `webfilter.csv` lookup contains many of these hosts.

## Advertisements and Analytics

Categories such as "Web Ads/Analytics" filter out the majority of traffic aimed at ad delivery and tracking visits to websites including traffic to/from hosts such as:

- google-analytics.com
- googletagservices.com
- scorecardresearch.com
- doubleclick.net
- addthis.com
- connatix.com
- springserve.com
- nr-data.net
- snackly.co
- optimizely.com
- adnxs.com

The `webfilter` macro contains filters such as:

```
category!="Web Ads/Analytics"
```

## Safebrowsing Updates

Every half hour or so IE, Chrome, and Firefox browsers update with the latest potentially unsafe URLs, reported attack sites, and web forgeries using the following hosts:

|Browser|Host|
|-|-|
|Chrome|safebrowsing-cache.google.com|
||safebrowsing.google.com|
||safebrowsing.googleapis.com|
|Firefox|shavar.services.mozilla.com|
|IE|urs.microsoft.com|

<br>

The `webfilter.csv` lookup contains these hosts.

## Connectivity Checks

Different browsers use different URLs for testing Internet connectivity and detecting captive portals using the following URLs:

|Browser|URL|
|-|-|
|IE / Windows|www.msftncsi.com/ncsi.txt|
|Firefox|detectportal.firefox.com/success.txt|
|Safari|captive.apple.com/hotspot-detect.html|               
|iOS|www.apple.com/library/test/success.html|
|Chrome|clients1.google.com/generate_204|
|Android|connectivitycheck.android.com/generate_204|

<br>

The `webfilter.csv` lookup contains these hosts.

## Social Networking

Traffic to social media platforms create a ton of noise in the logs.  When searching for attacker-owned infrastructure, we can filter out traffic to hosts such as:

- youtube.com
- twitter.com
- facebook.com
- pintrest.com
- linkedin.com
- instagram.com

The webfilter.csv lookup contains many of these hosts and the `webfilter` macro contains the following filters:

```
category!="*Social Networking*"
cs_host!=*.youtube.com
```

## Meeting and Chat Software

Adobe, Disqus, Gravatar and other software used for blogs, chat and online meeting applications require traffic to hosts such as:

- disqus.com
- gravatar.com
- reddit.com
- delphiforums.com
- adobeconnect.com
- peoplesupport.com
- verizonbusiness.com

The `webfilter.csv` lookup contains many of these hosts and the `webfilter` macro contains filters such as:    

```
category!="Newsgroups/Forums"
category!="Online Meetings"
```

## Google and Microsoft Services

This is a combination of Google- and Microsoft-owned hosts used to sync services, integrate third party services, and deliver miscellaneous content.

The `webfilter` macro contains the following filters:

```splunk
cs_host!=*.googleusercontent.com 
cs_host!=*.googlevideo.com 
cs_host!=*.googleapis.com 
cs_host!=*.google.com 
cs_host!=*.gstatic.com 
cs_host!=*.microsoftonline.com
cs_host!=*.microsoft.com 
cs_host!=*.live.com
```
<br>

## Example Walkthrough

The lookup and macro will be added to and improved over time but let’s walk through how you might use it to investigate an alert for a malicious domain.

We receive an alert for a user visiting a domain that matches an IOC.
 
The network identifier shows it was a compromised website and further research reveals a successful attack would force the victim’s system to request a payload from attacker-owned infrastructure.

The next step then is to see what other web requests were made while the user was visiting pages on the website that has been reported as compromised.

A basic search to start with would involve all the user's web traffic.
 
The first visit to the compromised site was at 6:34 PM and the last visit to the compromised site was at 6:50 PM.

So we want to search for suspicious hosts contacted during this period.

A quick search shows we have 43 events to investigate involving 16 different hosts.

Now let’s use the `webfilter` macro to filter out expected traffic that is normal for our environment:

![](images/Filtering%20Expected%20Web%20Traffic%20in%20Splunk/image007.png)<br><br>

Notice the backtick ( ` ) character before and after the word webfilter.
 
Now we have only 11 events involving 5 hosts… 

We cannot see the files that were requested, but let’s look closely at the user’s interactions with each host.

First, let’s get a better idea of the exact times when the compromised site was visited.

By doing a stats count on the time field, we have 17 different times the compromised site was being visited by the user:

We can further group these individual times into a few small timeframes that we are concerned about:

|Time|Count|
|-|-|
|18:34:15|16|
|18:35:42|44|
|18:36:49|51|
|18:38:44|45|
|18:39:29|31| 
|18:45:07|08| 
|18:50:10|11|

<br>

Now looking at the first unknown host, the times it was visited do not match up with the times we’re concerned about:

Research shows the domain is a video hosting service and is reported to be a legitimate.  Let’s filter it out and look at the next one.
 
This one happened just after a visit to the compromised site, so it could be what we’re looking for.

Looking more closely at those few seconds shows it may have been redirected from the compromised site.

Used the [Search-ForQuery.ps1]() script to verify the site contains links to the page:

You can do this manually with a Google keyword search:

You can click on the green arrow on the second link to view a cached version of the webpage.

Viewing the source shows on December 19th there were many references to the compromised site including 2 links to the site. 

The pages appear to be legitimate and the site and URLs check out clean.  With only one visit to the domain, there is not any evidence this was a malicious event.

The third and last site involved multiple requests:

Let’s look at the first visit:

Just before the first visit, the user requested a form.js file from the compromised site.

We can use a site like urlscan.io to view the contents of this script:

Doesn’t seem to be related… researching myeffecto.com shows it is a WordPress plugin for using emoticons on blogs.

Used the Search-Sites.ps1 script to verify the site looks to be running a version of WordPress:

Additional research shows it is a legitimate domain and requests to it while browsing a site running WordPress is normal and expected.

And now we can say with high confidence that the user was not a victim of an attack like the ones associated with the compromised domain referenced in the IOC.
