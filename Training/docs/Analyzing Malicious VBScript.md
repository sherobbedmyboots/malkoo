﻿# Analyzing Malicious VBScript
 
 
VBScript is an Active Scripting language based on Visual Basic that utilizes COM objects to interact with Windows systems. 
 
Two files using VBScript were recently analyzed on the OOB:
 
- [HTA](#hta)
- [VBE](#vbe)
 
 
## HTA
 
An HTA is an HTML application that uses embedded VBscript or Javascript to execute code on a Windows host.
 
An ICE host was recently observed downloading a file named `memo.hta` .  The file was then retrieved from an analysis VM on the OOB while the traffic was captured.
 
The pcap showed two files being downloaded:  `memo.hta` and `memo`
 
 
Let’s look at the first one, `memo.hta`:
 
 
This file declares dozens of variables using obfuscation to hide the ascii values of the content.
 
![](images/Analyzing%20Malicious%20VBScript/image001.png)
 
 
 
Using the first number as an example, this is a tricky way of disguising the letter “u”.
 
Once the numbers are added they become 117.  117 translates to the ASCII character “u”:
 
![](images/Analyzing%20Malicious%20VBScript/image002.png)
 
 
 
Here are the steps I used to convert every obfuscated character in the file:
 
 
Stored the contents of the HTA file in a variable called “fullfile”
 
Stripped out the “&” and “chr” strings and stored the results in the “removedvars” variable:
 
![](images/Analyzing%20Malicious%20VBScript/image003.png)
 
 
Used regex to match all the numbers (one open parenthesis, one to thirty digits, pluses, or minuses, and one closed parenthesis)
 
Converted the numbers to bytes, and then to their character values before replacing them with the ASCII values to make a new file called `decoded.txt`:
 
![](images/Analyzing%20Malicious%20VBScript/image004.png)
 
 
We now have a file full of what looks to be more heavily obfuscated code:
 
![](images/Analyzing%20Malicious%20VBScript/image005.png)
 
 
 
Searching the file for interesting characters and strings such as “shell” or “.” reveals the malicious code:
 
![](images/Analyzing%20Malicious%20VBScript/image006.png)
 
 
 
This shows the HTA file creates a shell object using Wscript and uses it to execute two hidden, encoded powershell commands (which are the same), then closes the document.
 
 
Looking at the decoded PowerShell command with [CyberChef](https://gchq.github.io/CyberChef/), you can see its purpose is to download and execute a file named `memo`:
 
 
 
 
 
The memo file can also be exported from the packet capture:
 
![](images/Analyzing%20Malicious%20VBScript/image007.png)
 
 
 
The file does two main things:
 
	- Creates a new memory stream object using an encoded Base64 string

	- Decompresses the stream and runs it using IEX
 
![](images/Analyzing%20Malicious%20VBScript/image008.png)
 
 
 
Creating the memory stream object and examining its properties shows us the code that was executed:
 
![](images/Analyzing%20Malicious%20VBScript/image009.png)
 
 
 
Putting the code in a text file allows us to organize it and determine what it accomplishes.  The code appears to execute a base64-encoded blob:
 
![](images/Analyzing%20Malicious%20VBScript/image010.png)
 
 
 
Decoding it shows the C2 IP address and a user agent string which indicates it is machine code which creates a network connection over HTTP or HTTPS:
 
 
 
 
 
 
## VBE
 
Similar to PowerShell using Base64 encoding, VBScript can utilize Script Encoding which makes the code unreadable but still able to execute.
 
This encoded VBScript file:
 
![](images/Analyzing%20Malicious%20VBScript/image011.png)
 
 
Dynamic analysis showed it made web requests to a site that appeared to be down, but what else does the script do?
 
 
A python decoder from [here](https://blog.didierstevens.com/2016/03/29/decoding-vbe/) was used to decode to reveal the actual VBScript code:
 
![](images/Analyzing%20Malicious%20VBScript/image012.png)
 
 
 
 
Now let’s try to determine what the code does…
 
 
 
Format it a little first:
 
![](images/Analyzing%20Malicious%20VBScript/image013.png)
 
 
Adding indentations will really help organize the different parts of the code.
 
 
 
Let’s take first part:
 
 
![](images/Analyzing%20Malicious%20VBScript/image014.png)
 
 
 
This wscript process is what Windows uses to execute the VBScript.
 
To demonstrate, we can start a wscript on our system with no arguments and verify its argument length of 0:
 
 
 
 
 
 
So if Wscript is called by itself, execute it with “WScript.ScriptFullName”&” uac”, “”, “runas”,1
 
If not called by itself, the function named “download” is defined and called:
 
 
![](images/Analyzing%20Malicious%20VBScript/image015.jpg)
 
 
This function downloads the file hosted at the web page “visita” and saves it to the Startup folder under the name “winlogon.vbe”
 
In this case, there are just two bytes at that page:
 
![](images/Analyzing%20Malicious%20VBScript/image016.jpg)
 
 
 
The next part changes the DNS servers and sets their search order:
 
![](images/Analyzing%20Malicious%20VBScript/image017.png)
 
 
 
Next, the presence of a file is checked `RECs.txt`, then an email message is constructed and sent containing the victim computer’s name, username, and the time:
 
![](images/Analyzing%20Malicious%20VBScript/image018.png)
 
 
 
The `RECs.txt` file was successfully created on the VM but was empty:
 
![](images/Analyzing%20Malicious%20VBScript/image019.jpg)
 
 
 
 
Finally, a message is shown to the user and one last function (PingFlush) is defined and called:
 
![](images/Analyzing%20Malicious%20VBScript/image020.png)
 
 
 
This function creates a shell object, opens command prompt and runs `ipconfig /flushdns` several times before disabling IPv6.
 
 
These commands were also successful:
 
![](images/Analyzing%20Malicious%20VBScript/image021.jpg)
 
![](images/Analyzing%20Malicious%20VBScript/image022.png)
 
