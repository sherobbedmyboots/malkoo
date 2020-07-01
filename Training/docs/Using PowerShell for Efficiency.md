# Using PowerShell for Efficiency

Here are some examples of how PowerShell helps us perform tasks more
efficiently:

- [Obtaining the Hash of a Suspicious File](#obtaining-the-hash-of-a-suspicious-file)
- [Viewing Event Logs on a Remote System](#viewing-event-logs-on-a-remote-system)
- [Querying Group Policy Objects](#querying-group-policy-objects)
- [Determining the Source of DNS Prefetching](#determining-the-source-of-dns-prefetching)
- [Obtaining Information About Multiple Web Pages](#obtaining-information-about-multiple-web-pages)
- [Obtaining WHOIS Info for Multiple Domains](#obtaining-whois-info-for-multiple-domains)
- [Obtaining Passive DNS Data for a Domain](#obtaining-passive-dns-data-for-a-domain)



## Obtaining the Hash of a Suspicious File

Many of our dashboards are designed to report on events involving
possibly malicious files:

![](images/Using%20PowerShell%20for%20Efficiency/image001.png)


For this type of event we would typically log onto the host, navigate to
the file's location and get a file hash to submit to VirusTotal and
other reputation engines.

With PowerShell, we can log in to the remote host and get the file hash
with one command:

![](images/Using%20PowerShell%20for%20Efficiency/image002.png)


## Viewing Event Logs on a Remote System

When you need to read a system's event logs, using the `Show-EventLog`
cmdlet is much faster than requesting event logs via FireEye or logging
in to the remote system to copy over.

To use it, just specify the system name:

![](images/Using%20PowerShell%20for%20Efficiency/image003.png)


And Event Viewer will open allowing you to browse the remote system's
event logs:

![](images/Using%20PowerShell%20for%20Efficiency/image004.png)


## Querying Group Policy Objects

The `Get-GPO` cmdlet lets you search all GPOs in a domain.  If you don't
have the module, import it:

![](images/Using%20PowerShell%20for%20Efficiency/image005.png)


To see a list of GPOs for a domain, use:

![](images/Using%20PowerShell%20for%20Efficiency/image006.png)


To view specific GPOs, you can filter by DisplayName:

![](images/Using%20PowerShell%20for%20Efficiency/image007.png)


Many times we want to see the resultant set of policies on one
computer. 

You could log on to the host and run `rsop.msc`, but a faster way is to
generate a report with `Get-GPResultantSetOfPolicy`:

![](images/Using%20PowerShell%20for%20Efficiency/image008.png)


Storing the contents of the report in a variable will help us parse and
display the fields we're interested in:

![](images/Using%20PowerShell%20for%20Efficiency/image009.png)


You can then display different GPO properties  by specifying the
appropriate objects of the `$xml` variable:

![](images/Using%20PowerShell%20for%20Efficiency/image010.png)


### Determining the Source of DNS Prefetching

A common scenario is a FireEye alert for a query to a suspicious site:

![](images/Using%20PowerShell%20for%20Efficiency/image011.png)


Since the suspicious domain was never visited, the cause of the query is
most likely DNS Prefetching.

Searching proxy traffic during the time of the query shows a number of
domains that could have caused this query:

![](images/Using%20PowerShell%20for%20Efficiency/image012.png)


Using Google's site operator to search for the string would eventually
reveal the domain and web pages which may have caused the query:

![](images/Using%20PowerShell%20for%20Efficiency/image013.png)


The page source for each page shows the link to the queried site:

![](images/Using%20PowerShell%20for%20Efficiency/image014.png)


This may require dozens of searches using a web browser depending on the
scenario.  A faster way to do this is by using a PowerShell script.

This [Search-ForQuery.ps1](../scripts/Search-ForQuery.ps1) script uses Google's site operator to search Google for each domain listed in a file looking for pages that contain the queried site:

![](images/Using%20PowerShell%20for%20Efficiency/image015.png)


To use it, copy and paste the results from the Splunk search into a file
named `sites.txt`:

![](images/Using%20PowerShell%20for%20Efficiency/image016.png)


Then pass it as an argument to the PowerShell script along with the
string that was queried:

![](images/Using%20PowerShell%20for%20Efficiency/image017.png)


Now we can see if the user visited one of the web pages that contained
the string.

The results show an HTTPS connection to **casas.mitula\[.\]mx** three
seconds after the query (we frequently see https connections logged
seconds after the start of the session).

We can't see the exact page that was visited since it was HTTPS, but we
can see it was most likely one of the three above hosted on
**casas.mitula\[.\]mx**:

![](images/Using%20PowerShell%20for%20Efficiency/image018.png)


## Obtaining Information About Multiple Web Pages

Another common scenario is analyzing web traffic to suspicious domains. 

At first glance there doesn't seem to be any connection between the
suspicious domains and the websites that referred users to them:

![](images/Using%20PowerShell%20for%20Efficiency/image019.png)


![](images/Using%20PowerShell%20for%20Efficiency/image020.png)


Here's a summary of the potentially malicious redirects:

|Suspicious Domain|Referring Websites|
|-|-|
|70544678930485396474982\[d\]win|www\[d\]google\[d\]com|
|fix-fonts\[.\]com|jammin1015\[d\]com, libertyparkpress\[d\]com|                   
|font-packs\[d\]com|station-21\[d\]com|
|font-update\[d\]com|tuffabels\[d\]com, myfamilysurvivalplan\[d\]com|
|fonts-pack\[d\]com|lightersideofrealestate\[d\]com, www\[d\]whythingshurt\[d\]com|
|update-fonts\[d\]com|encoreresorthomes\[d\]com, equallywed\[d\]com|


Notice that all of these except one referred by Google
(70544678930485396474982\[d\]win)  are requests for a small,
generic-named .js file including an "x" parameter which contains the
base64-encoded site that referred them:

![](images/Using%20PowerShell%20for%20Efficiency/image021.png)


So one theory would be that all of these websites were affected by the
same style of attack---maybe even by the same actor. 

The next step would be to check all of the referring web pages looking
for redirects to one of the suspicious domains but I found nothing. 
Maybe because they've all been fixed? 

Searching the source code of one of the referring (potentially
compromised) sites showed it was running an old version of WordPress...

![](images/Using%20PowerShell%20for%20Efficiency/image022.png)


You could check this on each one of the nine web pages by visiting each
page in your browser, right clicking and choosing 'View page source',
and checking for a WordPress version.

A more efficient way to do this though would be to automate it with
PowerShell.

This command makes PowerShell request the web page, search for the word
"wordpress", and show us the results:

![](images/Using%20PowerShell%20for%20Efficiency/image023.png)


It found the string but let's see if we can get more information.

By adding in a regular expression to the search term:

	"wordpress.{0,10}[`'|`"]"

We can search for the string followed by a version number:

![](images/Using%20PowerShell%20for%20Efficiency/image024.png)


Now we see it is very likely this website is running WordPress version
4.4.10.

We can use this command to see how many of the other sites have the word
"wordpress" in them, and a version number if present.

First create a file named `sites.txt` with all the websites:

![](images/Using%20PowerShell%20for%20Efficiency/image025.png)


And use this [Search-Sites.ps1](../scripts/Search-Sites.ps1) script to loop through each site looking for the regex term:

![](images/Using%20PowerShell%20for%20Efficiency/image026.png)


Now the script will request and search each webpage providing us with
the results:

![](images/Using%20PowerShell%20for%20Efficiency/image027.png)


The fact that all nine referring websites were all running similar
versions of WordPress is a good indication that they were all
compromised by the same or similar exploit.

## Obtaining WHOIS Information on Multiple Domains

We can take a similar approach in order to get WHOIS data on the
suspicious domains.

The fact that the same parameters were used ("x") and base64-encoded
referring sites indicates the sites may have been compromised by the
same actor, campaign, or toolkit.

The suspicious .js files are not being hosted anymore but we can still
use passive DNS records, WHOIS data, and other open source information
to support our theory.

For the first domain, font-packs\[.\]com,
 [PassiveTotal](https://passivetotal.org/home) shows the Registrar, the
email address used to register the domain, and the date it was created.

But the name and organization is protected:

![](images/Using%20PowerShell%20for%20Efficiency/image028.png)


We could look at PassiveTotal's search results for each of the five
domains individually, but what if next time it's twenty sites.. or one
hundred?

Again, let's automate this so it's faster, and also so we can look at
the information for all of the domains together for a good comparison.

First create a file containing the domains:

![](images/Using%20PowerShell%20for%20Efficiency/image029.png)


Then use this [PT-Domain-File.ps1](../scripts/PT-Domain-File.ps1) script to query all the domains on the list for WHOIS information and display our chosen fields for comparison:

![](images/Using%20PowerShell%20for%20Efficiency/image030.png)


Here we see that all five sites were registered with the same registrar
(Reg.ru), on the same day (May 1st )---all using WHOIS privacy
protection:

![](images/Using%20PowerShell%20for%20Efficiency/image031.png)


This is a strong indication the five suspicious domains were registered
and are operated by the same actor.

## Obtaining Passive DNS Data for a Domain

A similar script, [PT-Domain.ps1](../scripts/PT-Domain.ps1) can be used to obtain Passive DNS data for each domain:

![](images/Using%20PowerShell%20for%20Efficiency/image032.png)


By passing a domain as an argument and specifying the fields we want to
see, we can see the frequency this domain changes IP addresses:

![](images/Using%20PowerShell%20for%20Efficiency/image033.png)


This could support the theory that the actors are using IP blacklisting
evasion techniques such as Fast-flux hosting infrastructures typically
seen with malware operations and various scams.

## Summary

In all these examples, PowerShell helped us gather important details
quickly that help provide context and allow improved analysis.

Here are some great PowerShell resources:

- [Getting Started with
PowerShell](https://channel9.msdn.com/Series/GetStartedPowerShell3)

- [Why Learn
PowerShell](https://blogs.technet.microsoft.com/heyscriptingguy/2014/10/18/weekend-scripter-why-learn-powershell/) by
Ed Wilson

- PowerShell Web Docs: [Basic
cookbook](https://msdn.microsoft.com/en-us/powershell/scripting/getting-started/basic-cookbooks)

- [Leveraging
PowerShellBasics](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20workshops/DEFCON-25-Carlos-Perez-Leveraging-PowerShell-Basics.pdf)

- [Leveraging PowerShell for Red
Teams](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20workshops/Carlos%20Perez%20-%20Principals%20on%20Leveraging%20PowerShell%20for%20Red%20Teams-UPDATED/DEFCON-25-Workshop-Carlos-Perez-Leveraging-PowerShell-Basics-UPDATED.pdf)

- [PowerShell
eBook](http://powershell.com/cs/blogs/ebookv2/default.aspx) from
PowerShell.com

- [PowerShell-related
Videos](https://channel9.msdn.com/Search?term=powershell#ch9Search) on
Channel 9

- [Learn PowerShell Video
Library](http://powershell.com/cs/media/14/default.aspx) from
PowerShell.com

- [PowerShell Quick Reference
Guides](http://www.powershellmagazine.com/2014/04/24/windows-powershell-4-0-and-other-quick-reference-guides/) by
PowerShellMagazine.com

- [PowerShell 5 How-To
Videos](https://blogs.technet.microsoft.com/tommypatterson/2015/09/04/ed-wilsons-powershell5-videos-now-on-channel9-2/) by
Ed Wilson

- [PowerShell TechNet
Resources](https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx) from
ScriptCenter
