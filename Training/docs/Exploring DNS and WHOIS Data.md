# Exploring DNS and WHOIS Data

The Domain Name System (DNS) is a naming structure for online resources and
mapping those names to the addresses where the resources reside.

The WHOIS database is a directory of the registered users for Internet
resources such as domain names, IP address blocks, and autonomous systems (AS).


- [DNS](#dns)
  - [DNS Query](#dns-query)
  - [DNS Caching](#dns-caching)
  - [Reverse Lookup](#reverse-lookup)
  - [DNS Over HTTPS](#dns-over-https)
- [WHOIS Data](#whois-data)
  - [WHOIS Query](#whois-query)
  - [WHOIS Over HTTPS](#whois-over-https)
  - [WHOWAS Data](#whowas-data)
- [Example](#example)
  - [Resolve Domains](#resolve-domains)
  - [Add WHOIS Data](#add-whois-data)
  - [Use For Enrichment](#use-for-enrichment)
- [Summary](#summary)

<br>

## DNS

We use IP addresses to route traffic to and from local and remote hosts and
networks.  Since the addresses are hard to remember and frequently change, we
use domain names that point to IP addresses.

When we interact with another system over the network, we give our browser or
another application a domain name.  DNS servers are used to resolve this domain
name to an IP address which is used for communication.

Before DNS, systems kept a host file with the address of every host it needed
to contact.  This is still the first way a system tries to resolve a name and
you can view your hosts file at the following location in Windows:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image014.png)<br><br>

And Linux:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image015.png)<br><br>

If a name can't be resolved using the hosts file, a DNS query is used to
identify its address.

- [DNS Query](#dns-query)
- [DNS Caching](#dns-caching)
- [Reverse Lookup](#reverse-lookup)
- [DNS Over HTTPS](#dns-over-https)


### DNS Query

A Uniform Resource Locator (URL) refers to a web address which uniquely identifies
a document.  This document can be a web page, image, video, etc. In order to
access the document, the address of the host must be identified with a DNS query.

A query proceeds in this order:

1. Client queries one of 13 mirrored root servers for `www.example.com`
2. Root server returns address for `.com` name server
3. Client queries `.com` name server for `www.example.com`
4. The `.com` server returns address for the `example.com` name server
5. Client queries `example.com` name server for `www.example.com`
6. The `example.com` name server returns address for `www.example.com`

<br>

A client can make **iterative** queries and perform this entire process itself, or
make **recursive** queries which request the DNS server perform this process and
return only the response.

**Authoritative** responses come from a name server that has authority over the
record. **Non-authoritative** answers come from other servers or a cache.

Use the `host` command to find the IP address

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image006.png)<br><br>

Or use the `Resolve-DnsName` cmdlet:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image008.png)<br><br>

### DNS Caching

Both DNS clients and servers cache names and IPs that have been recently resolved
to prevent repeated queries for the same host.  Use `Get-DNSCache` cmdlet to see
entries in your system's cache:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image007.png)<br><br>

Clear your DNS cache with one of the following to ensure you get the most
current DNS information when you perform a query:

- Windows: `ipconfig /flushdns`
- Linux: `sudo /etc/init.d/nscd restart`

<br>

DNS records frequently change:

- Domain names are bought and sold
- Domain names are hosted on different infrastructures in different locations
- Dynamic DNS allows systems to update a DNS server with their latest IP

Standard DNS queries are called forward queries and their responses provide
the address where the host is *currently* pointing.  

Sometimes you'll only have the IP address and you want to know the hostname of
the system at that address. This is called a reverse lookup.

### Reverse Lookup

A simple way to do this in Windows is:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image011.png)<br><br>

With Linux use the `host` command:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image012.png)<br><br>

In order to identify all the domains that point to the address, you'll need a
tool that provides passive DNS data such as [PassiveTotal](https://community.riskiq.com/search/54.243.0.60)
which shows hundreds of domains recently resolving to IP address `54.243.0.60`:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image001.png)<br><br>

### DNS Over HTTPS

DNS queries can also be performed using HTTPS.  Using PowerShell to interact
with Cloudflare's [DNS Over HTTPS](https://developers.cloudflare.com/1.1.1.1/dns-over-https/)
is a great example of this:

```powershell
$u = "https://cloudflare-dns.com/dns-query?name=example.com"
$h = @{'accept'='application/dns-json'}
(irm -Headers $h -Uri $u).Answer
```
![](images/Exploring%20DNS%20and%20WHOIS%20Data/image003.png)<br><br>


We can make these few lines of code into a function:

```powershell
function Resolve-NameExt ($name) {
    $u = "https://cloudflare-dns.com/dns-query?name=$name"
    $h = @{'accept'='application/dns-json'}
    (irm -Headers $h -Uri $u).Answer
}
```

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image004.png)<br><br>


Passive DNS is extremely valuable when investigating incidents. [Robtex](https://www.robtex.com)
has a free API which we can leverage to obtain Passive DNS data for an address:

```powershell
function Get-IpPassiveDns ($ip) {
    $u = "https://freeapi.robtex.com/ipquery/$ip"
    $pdns = (irm -Uri $u).pas
    foreach ($p in $pdns){
      $time = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
      $time = $time.AddSeconds($p.t)
      $p | Add-Member -NotePropertyName Time -NotePropertyValue $time
      $p | Add-Member -NotePropertyName Name -NotePropertyValue $p.o
    }
    $pdns | Select Name,Time | Sort -Desc Time
}
```

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image009.png)<br><br>

As we gather information during an incident, we also need to know who is
responsible for various IP addresses.


## WHOIS Data

- [WHOIS Query](#whois-query)
- [WHOIS Over HTTPS](#whois-over-https)
- [WHOWAS Data](#whowas-data)

### WHOIS Query

There are several different [WHOIS databases](https://www.apnic.net/about-apnic/whois_search/about/what-is-in-whois/which-whois/) that contain ownership information for IP addresses and Autonomous Systems (AS).

This database can be queried to get information such as country name, country
code, city, state or region, zip or postal code, ISP and Organization, time zone,
latitude/longitude, hostname, and name servers.

A WHOIS lookup is traditionally performed with the `whois` program:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image005.png)<br><br>


### WHOIS Over HTTPS

We can also do WHOIS queries over HTTP and HTTPS.

This function gets basic WHOIS data using [DazzlePod](http://dazzlepod.com/ip/):

```powershell
function Get-WHOISDazzle ($ip) {
  $u = "http://dazzlepod.com/ip/$ip.json"
  irm -Headers $h -Uri $u
}
```

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image010.png)<br><br>


This function gets more information using the [WHOIS Restful Web Service](https://www.arin.net/resources/registry/whois/rws/api/):

```powershell
function Get-WHOISData ($ip) {
    $h = @{'accept'='application/json'}
    $u = "https://whois.arin.net/rest/ip/$ip"
    (irm -Headers $h -Uri $u).net
}
```

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image002.png)<br><br>

### WHOWAS Data

Ownership of infrastructure changes over time as well and there are tools such as
[WHOWAS](https://www.apnic.net/static/whowas-ui/#124.15.22.52) that can provide
a history of changes for some IP addresses and ranges.

Here is an example entry showing a timeline of changes made to the record of an
IP range and what information was deleted with the most recent change:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image013.png)<br><br>

We can also find historical WHOIS data using [PassiveTotal](https://community.riskiq.com/search/sadeyedlady.com):

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image025.png)<br><br>

## Example

Here is a situation in which you might use these functions.  A recent
investigation of a phishing document provided multiple domains and IP addresses
of interest:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image017.png)<br><br>

We can add contextual information to these domains and addresses by doing
the following:

- [Resolve Domains](#resolve-domains)
- [Add WHOIS Data](#add-whois-data)

### Resolve Domains

First, put all domains in an array:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image016.png)<br><br>

Then put all addresses in an array:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image018.png)<br><br>

Get current IP addresses for domains with `Resolve-NameExt`:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image019.png)<br><br>

Two things we need to fix here.  First is that a type 5 response (CNAME or alias) has given us
another domain.  Query this domain to get the address:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image020.png)<br><br>

The second thing is that one domain resolves to local address `127.0.0.1`:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image021.png)<br><br>

When did this happen?  [PassiveTotal](https://community.riskiq.com/search/thematrix-one.info) can show us:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image022.png)<br><br>

On the 8th it resolved to `94.237.77[.]152`.  Now we can make these corrections in our array:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image023.png)<br><br>

### Add WHOIS Data

We can add WHOIS data with the following:

```powershell
$r | %{
 Add-Member -InputObject $_ -MemberType NoteProperty -Name asn -Value $(Get-WHOISDazzle $_.data).asn
 Add-Member -InputObject $_ -MemberType NoteProperty -Name country -Value $(Get-WHOISDazzle $_.data).country
 Add-Member -InputObject $_ -MemberType NoteProperty -Name hostname -Value $(Get-WHOISDazzle $_.data).hostname
 Add-Member -InputObject $_ -MemberType NoteProperty -Name org -Value $(Get-WHOISDazzle $_.data).organization
}
```

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image024.png)<br><br>

You may need to add domains/IPs manually:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image026.png)<br><br>

Now we have all 12 domains:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image027.png)<br><br>

And we can add our two IP addresses used for C2:

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image028.png)<br><br>

This shows the different types of infrastructure being used by the malware and
can be used to identify patterns and relationships as more data points are added.

### Use For Enrichment

There are many different scenarios where DNS and WHOIS data can be used to
enrich indicators and provide additional information during an investigation.

This search looks for SQLI attempts and appends WHOIS data from a CSV:

```
index=proxy c_ip!=10.0.0.0/8 c_ip!=192.168.0.0/16 sc_status=200 "SELECT"
| eval cs_uri_query=urldecode(cs_uri_query)
| regex cs_uri_query="(?i)UNION\sALL\sSELECT|UNION\sSELECT|SELECT\sCOUNT\(\*\)|SELECT\s\*\sFROM|SELECT\s.*\sFROM.*\sWHERE|SELECT\s.*CASE\s.*WHEN|SELECT.*\sORDERBY.*\sNULL|UNION\sSELECT\s\d|1\=1\sUNION\sSELECT|substring\(\@\@version|length\(database\(\)\)\=|\ssleep\(\d{1,3}\)"
| iplocation c_ip
| lookup dnslookup clientip AS c_ip OUTPUT clienthost as nslookup
| lookup whois.csv Address AS c_ip OUTPUT Organization,Email,OrganizationName,AdminName,Telephone
| fillnull value="N/A" nslookup Email Telephone Country
| stats count by date cs_host c_ip Organization OrganizationName Telephone Email Country nslookup
| sort –date
```

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image029.png)<br><br>


This search looks for high numbers of 404 Not Found responses and adds WHOIS Data:

```
index=proxy c_ip!=10.0.0.0/8 c_ip!=192.168.0.0/16 sc_status=404
| lookup dnslookup clientip AS c_ip OUTPUT clienthost as nslookup
| lookup whois.csv Address AS c_ip OUTPUT Organization,Email,OrganizationName,AdminName,Telephone
| iplocation c_ip
| fillnull value="N/A" nslookup Email Telephone Country
| stats count by date cs_host c_ip Organization OrganizationName Email Telephone Country nslookup
| where count > 100
| sort –date
```


![](images/Exploring%20DNS%20and%20WHOIS%20Data/image030.png)<br><br>


This search looks for high numbers of 401/403 Forbidden responses and adds WHOIS Data:

```
index=proxy c_ip!=10.0.0.0/8 c_ip!=192.168.0.0/16 sc_status=401 OR sc_status=403 
| lookup dnslookup clientip AS c_ip OUTPUT clienthost as nslookup
| lookup whois.csv Address AS c_ip OUTPUT Organization,Email,OrganizationName,AdminName,Telephone
| iplocation c_ip
| fillnull value="N/A" nslookup Email Telephone Country
| stats count by date cs_host c_ip Organization OrganizationName Email Telephone Country nslookup
| where count > 100
| sort -date
```

![](images/Exploring%20DNS%20and%20WHOIS%20Data/image031.png)<br><br>


## Summary

DNS and WHOIS data are important to have when identifying systems during an
investigation.  Use local and online tools to find current DNS mappings,
passive DNS data, and current/past WHOIS data for all addresses and domains
involved in an incident.  When possible, use this data for enrichment to
assist incident investigations.
