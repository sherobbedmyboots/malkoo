# OOB Analysis of a WebShell

When malicious files are detected on one of our systems, it's our job to explain what it is, how it got there, and the potential impact it may have had to our users, systems, and networks. This is a walkthrough of the steps taken while investigating the source of a webshell that FireEye detected on a user's workstation:

- [Gather Information About Alert](#gather-information-about-alert)
- [Identify the URL](#identify-the-url)
- [Create Windows Instance with Docker](#create-windows-instance-with-docker)
- [Create IIS Container Using Webshell](#create-iis-container-using-webshell)
- [Test Capabilites of Webshell](#test-capabilities-of-webshell)
- [Analysis](#analysis)

<br>

### Gather Information About Alert

The first task in any investigation is to gather information from our tools.  The alert originated from the agent on the host for detection of a known malicious file:

![](images/OOB%20Analysis%20of%20a%20WebShell/image001.png)<br><br>

We can look at proxy logs during that time with Splunk and see that the file could have been acquired from several different websites:

```
index=proxy c_ip=10.10.10.10 `webfilter` | table _time cs_method cs_host cs_uri_path bytes
```

![](images/OOB%20Analysis%20of%20a%20WebShell/image002.png)<br><br>


[VirusTotal](https://www.virustotal.com/#/file/d94804ba831329dfbd54c91686d9c82728443808c2847469d0228c29a57625ed/details) was searched for the hash and shows additional details:

![](images/OOB%20Analysis%20of%20a%20WebShell/image003.png)<br><br>


This VT page also shows some of the code the file contains:

![](images/OOB%20Analysis%20of%20a%20WebShell/image028.png)<br><br>


In the comments, the THOR scanner matched the sample to a file on a GitHub repo:

![](images/OOB%20Analysis%20of%20a%20WebShell/image004.png)<br><br>


The `aspydrv.asp` file from the [Github page](https://github.com/nikicat/web-malware-collection/blob/master/Backdoors/ASP/aspydrv.asp) contains some of the exact same code shown on the VT page:

![](images/OOB%20Analysis%20of%20a%20WebShell/image029.png)<br><br>

Now we have an idea of what we're looking for... but where did it come from?

### Identify the URL

FireEye may be able to provide a copy of the file for analysis, but we still need to know which website was hosting the webshell and the full URL of the file.  By browsing each site using the OOB and inspecting all embedded content loaded by each site, the webshell can be identified.

After examining a few sites, the website `www.qualitasspaistanbul[.]com` was discovered to load an image named `arama-buton.jpg` which shows in the DevTools console to be 0 bytes with no dimensions listed:

![](images/OOB%20Analysis%20of%20a%20WebShell/image024.png)<br><br>

Further inspection of this file reveals it has a GIF header but contains the code we saw earlier:

![](images/OOB%20Analysis%20of%20a%20WebShell/image025.png)<br><br>

When attempting to open the file in Sublime, it tries to render it as an image:

![](images/OOB%20Analysis%20of%20a%20WebShell/image026.png)<br><br>

Rename the file to `.asp` and it will open and be formatted correctly:

![](images/OOB%20Analysis%20of%20a%20WebShell/image027.png)<br><br>

We can read through the code, organize it, and pick out parts that are designed to interact with the web server it's installed on, but sometimes it's easier (and faster) to simulate it in a lab environment.

We'll do this using an IIS container on an EC2 instance to host this file and see what it does when we visit it with a browser.

### Create Windows Instance with Docker

First get AWS API credentials:

![](images/OOB%20Analysis%20of%20a%20WebShell/image006.png)<br><br>

Then create an instance using a Windows AMI optimized for Docker:

```powershell
# Create key
(New-EC2KeyPair -ProfileName temp -Region us-east-1 -KeyName "webshell").KeyMaterial | Out-File ~\webshell.pem

# Create instance
New-EC2Instance -ProfileName temp -Region us-east-1 -ImageId ami-0ed2f29599018e745 -InstanceType m1.large -KeyName webshell

# Get instance IP address
(Get-EC2Instance -ProfileName temp -Region us-east-1).Instances

# Get Administrator password
Get-EC2PasswordData -ProfileName temp -Region us-east-1 -InstanceId i-0234804661f5f32f3 -Pemfile ~\webshell.pem
```

We now have a Docker-optimized Windows instance with a public IP address:

![](images/OOB%20Analysis%20of%20a%20WebShell/image005.png)<br><br>

Ensure the security group assigned to the instance allows inbound RDP and HTTP:

![](images/OOB%20Analysis%20of%20a%20WebShell/image037.png)<br><br>

RDP to the instance, turn off Windows Defender, and download the webshell file:

```powershell
# Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true

# Download webshell
New-Item -Type Directory -Path C:\webshell; cd C:\webshell
Invoke-WebRequest <file-url> -Outfile <file-name>
```

### Create IIS Container Using Webshell

Create a Dockerfile and build an ASP-capable IIS image with the following:

```powershell
$content = @'
FROM microsoft/iis
SHELL ["powershell","-command"]
RUN Install-WindowsFeature Web-ASP
COPY <filename> C:\\inetpub\\wwwroot\\<filename>
'@
Set-Content -Value $content -Path Dockerfile
docker build -t webshell .
```


![](images/OOB%20Analysis%20of%20a%20WebShell/image007.png)<br><br>

Run with `docker run -d -p 80:80 webshell` and access the page on port 80.  When the browser loads the file however, it tries to load it as an image.  Renaming the file to a `.asp` extension makes it load correctly:

![](images/OOB%20Analysis%20of%20a%20WebShell/image009.png)<br><br>

We see from the code that the password is embedded in the code:

![](images/OOB%20Analysis%20of%20a%20WebShell/image010.png)<br><br>

After entering the password, we now have access to the console:

![](images/OOB%20Analysis%20of%20a%20WebShell/image011.png)<br><br>

### Test Capabilities of Webshell

Now we can simulate how the tool may be used when hosted by a compromised web server.  There's a panel used to upload files to the server:

![](images/OOB%20Analysis%20of%20a%20WebShell/image013.png)<br><br>

This docker container is configured correctly and write permissions are denied for the service account hosting the page.  But we want to simulate a vulnerable server so we'll adjust the permissions with:

```powershell
$perm = "EVERYONE","FULLCONTROL","ContainerInheritObjectInherit","None","ALLOW"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule $perm
$acl = Get-Acl C:\inetpub\wwwroot
$acl.SetAccessRule($rule)
Set-ACL -Path C:\inetpub\wwwroot -AclObject $acl
```

Now we can use the webshell to write to the server's filesystem.  Here is a panel for creating directories and copying files:

![](images/OOB%20Analysis%20of%20a%20WebShell/image015.png)<br><br>

Successfully uploaded a file:

![](images/OOB%20Analysis%20of%20a%20WebShell/image012.png)<br><br>

This panel allows you to download files from the server:

![](images/OOB%20Analysis%20of%20a%20WebShell/image017.png)<br><br>

You can also edit files:

![](images/OOB%20Analysis%20of%20a%20WebShell/image014.png)<br><br>

There is a function that shows available drives:

![](images/OOB%20Analysis%20of%20a%20WebShell/image016.png)<br><br>

Each one of these actions performed on the server by the webshell is a web request over HTTP and can therefore be observed over the network:

![](images/OOB%20Analysis%20of%20a%20WebShell/image018.png)<br><br>

Here is the file upload:

![](images/OOB%20Analysis%20of%20a%20WebShell/image019.png)<br><br>

Here is the `getDRVs` function being called to list available drives:

![](images/OOB%20Analysis%20of%20a%20WebShell/image020.png)<br><br>

Each of these actions is the webshell code executing on the server:

![](images/OOB%20Analysis%20of%20a%20WebShell/image021.png)<br><br>

When finished, stop and terminate the instance with:

```powershell
Stop-EC2Instance -ProfileName temp -Region us-east-1 -InstanceId i-0234804661f5f32f3 -Terminate
```

![](images/OOB%20Analysis%20of%20a%20WebShell/image022.png)<br><br>


### Analysis

So we have the code, we know what it does, and we see what it looks like over the network.

Was our user using the webshell?

![](images/OOB%20Analysis%20of%20a%20WebShell/image038.png)<br><br>

With only one visit to the webshell page and no arguments passed with it, it's safe to say the page was requested by mistake and no commands were attempted.
