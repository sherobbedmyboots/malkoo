# DNS Prefetching

DNS prefetching is when the browser resolves domain names
before a user tries to follow a link. These DNS requests are normal
queries logged by Infoblox and searchable in Splunk.  The only
difference is that the domains queried are **not visited** by
the user.

The purpose of this browser feature is to already have all the domains
on the page resolved when the user decides to click on a hyperlink. 
This will end up saving the time it takes to query and resolve the
domain of the selected link which is usually around 200 milliseconds. 
The problem this creates for us is that sometimes suspicious domains
will be queried by the user's system but not actually visited.

A query to the suspicious site
"taurancoci\[.\]mylftv\[.\]com" was reported by the Malicious Site
Dashboard:

![](images/DNS%20Prefetching/image001.png)

Your first priority is to find out **why** the user's system
queried the site.

First, check if the user made a web request to the site, because that is
the usual reason to query a site:

![](images/DNS%20Prefetching/image002.png)


No indications the user made web requests to the site.  Next check sites
that were (successfully) visited just prior to the queries to the site:

![](images/DNS%20Prefetching/image003.png)


You will notice many requests do not have a `cs_Referer` field... this is
because the referrer isn't logged for redirects from https sites.

But for now, let's look at the web pages that we know for sure were
loading content seconds before the query:

![](images/DNS%20Prefetching/image004.png)


This shows two different domains (msn.com and etonline.com) that are
interesting to us---one of them most likely hosts a web page with a
link to the suspicious site "taurancoci\[.\]mylftv\[.\]com"

An easy way to check this is to use Google's "site" operator.  You can
use this to search across all URLs that have been indexed for a specific
domain.

To search the msn.com domain:

![](images/DNS%20Prefetching/image005.png)


Let's try searching the second domain:

![](images/DNS%20Prefetching/image006.png)


This is a URL that the user visited and the suspicious site was present
on the web page when Google indexed it.

This is sufficient to explain why the site was queried, but further
investigation would reveal that it was a comment posted to the page that
contained a link to the suspicious site:

![](images/DNS%20Prefetching/image007.png)


So we know the user did not visit the suspicious site and we can explain
why it was queried:

![](images/DNS%20Prefetching/image008.png)

> DNS Prefetching is a browser feature that resolves domain names of links on a web page 
> before they are clicked to prevent delays odue to DNS resolution time.
> The user's browser queried this site as part of its DNS Prefetching feature.  
> When the user visited the page, the browser scanned the entirepage for links 
> and queried each one in xccase the user clicked one.  A comment on the page 
> contained a link to the suspicious site.

