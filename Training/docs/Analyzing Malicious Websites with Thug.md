# Analyzing Malicious Websites with Thug

Malicious websites fall into three general categories:

| | |
|-|-|
|Phishing|User is tricked into submitting credentials, authorizing access, or giving up other private information|
|Malware via Social Engineering|User is tricked into installing malware on victim host|
|Malware via Exploit|Browser or plugins are exploited to install malware on victim host|

When investigating the first two types, obtaining artifacts for analysis
tends to be more straight forward as the success of the attack depends
on visitors being able to easily find and download a program they think
is legitimate or enter their credentials into a fake login page.

Malicious sites that host exploits can be more difficult to analyze
especially when they use:

- Encoding and encryption to hide shellcode data and script content

- Obfuscation and anti-sandbox techniques to evade analysis and
    reverse engineering

- System profiling to identify and deny/redirect repeat visitors,
    security analysts, and systems that cannot be exploited

If a malicious site is using one or more of these techniques, it may be
difficult to obtain a sample of the payload and provide a complete
analysis of what happens when a visitor's system is exploited.

A tool called [Thug](https://buffer.github.io/thug/doc/index.html) makes
this easier by mimicking the behavior of a vulnerable browser.

## Example Scenario

In this scenario, a user was redirected to a malicious site which led to
their system being compromised.  No logs or pcap is available but during
the time of analysis, the malicious site still appeared to be active. 

For a complete analysis of incidents like these, we need to be able to
explain what the malicious website did to the victim's browser.

One common option is to examine the web page's code...

In this case I downloaded the malicious page with wget and inspected the
page source in a text editor using REMnux's alias for SciTE, "notepad":

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image001.png)


No encoding or obfuscation was used so we can read the code that a
visiting browser will run.

Sometimes just looking at the page's source code will reveal much of its
functionality:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image002.png)


When inspecting the site with [URLSCAN.IO](https://urlscan.io/), it was
able to make two HTTP transactions but gives no analysis of what may
have happened to a vulnerable browser:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image003.png)


Visiting the site with one of the OOB analysis VMs would allow you to
better replicate the victims visit to the site--but what if the site
doesn't behave the same because it:

- is able to determine you're using a virtual machine?

- detects one of the many analysis tools we have installed?

- does not attempt to exploit the browser/plugins you're using?

- determines that you're a repeat visitor?

## Using Thug

Thug is a honey client that emulates a vulnerable web browser, fetches
and executes any internal or external JavaScript, follows all redirects,
downloads all files, and collects the results for analysis.

You can choose which user agent string will be used, a referrer site,
versions of third-party plugins, and even the option to use the
VirusTotal API.

Here is a list of common options:

#### Logging
| | |
|-|-|
|-F|File logging|
|-Z|JSON logging|
|-M|maec11 logging|
|-n|Log output directory|

#### Headers
| | |
|-|-|
|-u|useragent|
|-i|list available user agents|
|-r|specify a referrer|

#### Virus Total
| | |
|-|-|
|-y|query VirusTotal|
|-b|VirusTotal API key|

#### Plugins
| | |
|-|-|
|-S|specify Shockwave Flash version|
|-J|specify Java plugin version|
|-A|specify Adobe Reader version|

To use it, in a terminal in REMnux type the following:

`mkdir ~/logs ~/files`

`chmod 777 ~/logs ~/files`

`sudo docker run -rm -it -v ~/logs:/home/thug/logs -v ~/files:/home/thug/files remnux/thug bash`

The first time you pull down the Docker container image, it will take a
few minutes.  After this, it is saved locally and the next time you
build a container of this app it doesn't take as long.

When the image has been downloaded and the container is built, your
command prompt will look like this:

`thug@[container id]:~$`

Now you are running commands inside the Thug Docker container and
everything that goes into the "logs" and "files" directories will be
shared with your REMnux host machine.

To run Thug and conduct analysis completely inside the container, use:

`thug -FZM  -n . "http://evil[d]com"`

After analysis, type `ls -la` to see the new directories created:
"analysis" and directories for [MIME
types](http://www.iana.org/assignments/media-types/media-types.xhtml)
observed such as "application", "image" and "text".

The analysis directory contains an interaction graph as well as JSON and MAEC log files:

| | |
|-|-|
|graph.svg|A visual analysis of requests, redirects, and downloads|
|analysis.json|Analysis data in JSON format|
|maec|MAEC xml file|


The application directory contains all resources downloaded during URL analysis:

| | |
|-|-|
|x-java-jnlp-file|Java Web Start application file|
|java-archive|.jar file|
|pdf|Adobe PDF documents|
|x-shockwave-flash|multimedia file|
|octet-stream|An unknown binary file|
|javascript|.js file   |



The image directory contains:

| | |
|-|-|
|gif|GIF images|
|jpeg|JPEG images|
|png|PNG images|
|svg+xml|SVG images (vector images)   |                                   



The text directory contains:

| | |
|-|-|
|plain|An unknown text file|
|html|HTML web page|
|xml|XML web page |


There are limited commands to run in the container, to use tools
installed on REMnux you must copy the files to one of the directories
that is shared with the host system:

For example, copy over the graph file:

`cp /analysis/graph.svg ~/logs`

Now from another terminal you can open the graph.svg file with firefox:

`firefox graph.svg`

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image004.png)


You can now see all the additional pages that were requested and what
caused each request.

Metadata for all these connections are contained in the analysis.json
file which can be imported to various tools or parsed for the fields you
want to display.

In this case I installed the program "jq" with `sudo apt-get install
jq` and used it to pull info on the iframe, redirect, and window open
events associated with the `HQqermb` page:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image005.png)


Here jq is used to show the URL, timestamp, user agent strings, plugin
versions, and referrer page used:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image006.png)


Looking at the `~/text/html` directory, we see Thug was able to obtain 21
different files, all named after their MD5 hash value:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image007.png)


The sizes and contents of a few indicate the presence of embedded .jar
files:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image008.png)


The files can be copied over to the `~/files` directory and inspected
with various REMnux tools:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image009.png)


None of the files were flagged by AV.

You can also submit the hashes of each file to VirusTotal with this
command (using your VirusTotal API key):

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image010.png)


Nothing detected.

Let's focus on one of the suspicious files...

This shows the landing page delivered a .jar file named `IajSVq.jar`:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image011.png)


Using the `-l` switch with `grep`, we have two files that contain the
unique string "IajSV":

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image012.png)


One is a "Not Found" web page while the other contains the embedded jar:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image013.png)


We can extract the hex encoded jar file by simply cutting and pasting
the hex into a file named `input.txt`.

Then we can convert it into a binary file using the `xxd` program:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image014.png)


Now running an AV scan on the extracted file gives us different results:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image015.png)


[Trojan detected!]()

Submitting to VirusTotal shows it contains Meterpreter code:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image016.png)


You can do this with additional files, run them in a lab environment, do
static and dynamic analysis, etc. to demonstrate what most likely
happened with the victim's machine.

When your analysis is complete, at the container prompt, type:

`exit`

This will destroy the Thug Docker container and all its files,
processes, and network connections, but the files you saved in the
shared directories will still exist on the REMnux host.

## Exercise

We can use a Metasploit Docker container to quickly create a "malicious"
website, visit it with Thug, and then destroy it when we're finished.

First, open a REMnux terminal and type:

`sudo docker run -rm -it -p 8080:8080 remnux/metasploit`

Docker will download the Metasploit image and build the container out.

After several minutes, you should see the following prompt:

`root@[container-id]:/tmp/data#`

Now create the website by typing:

`msfconsole -x "use auxiliary/server/browser_autopwn;set LHOST 172.17.0.1;run"`

MSF will start up, kick off the autopwn module, and you will see the URL
of the malicious webpage:

![](images/Analyzing%20Malicious%20Websites%20with%20Thug/image017.png)


Use Thug to investigate this website and see how many malicious files
you can obtain and identify.
