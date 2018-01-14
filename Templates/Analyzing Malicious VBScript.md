Analyzing Malicious VBScript

 

 

VBScript is an Active Scripting language based on Visual Basic that utilizes COM objects to interact with Windows systems. 

 

Two files using VBScript were recently analyzed on the OOB:

 

-          HTA

-          VBE

 

 

HTA

 

An HTA is an HTML application that uses embedded VBscript or Javascript to execute code on a Windows host.

 

An ICE host was recently observed downloading a file named “memo.hta” .  The file was then retrieved from an analysis VM on the OOB while the traffic was captured.

 

The pcap showed two files being downloaded:  “memo.hta” and “memo”

 

 

Let’s look at the first one, memo.hta:

 

 

This file declares dozens of variables using obfuscation to hide the ascii values of the content.

 

cid:image001.png@01D31BDC.6D6113B0

 

 

 

Using the first number as an example, this is a tricky way of disguising the letter “u”.

 

Once the numbers are added they become 117.  117 translates to the ASCII character “u”:

 

cid:image003.png@01D31BDD.D484C630

 

 

 

Here are the steps I used to convert every obfuscated character in the file:

 

 

Stored the contents of the HTA file in a variable called “fullfile”

 

Stripped out the “&” and “chr” strings and stored the results in the “removedvars” variable:

 

cid:image002.png@01D31BDB.D4B84430

 

 

Used regex to match all the numbers ( one open parenthesis, one to thirty digits, pluses, or minuses, and one closed parenthesis)

 

Converted the numbers to bytes, and then to their character values before replacing them with the ASCII values to make a new file called decoded.txt:

 

cid:image005.png@01D31BDB.D4B84430

 

 

We now have a file full of what looks to be more heavily obfuscated code:

 

cid:image006.png@01D31BDB.D4B84430

 

 

 

Searching the file for interesting characters and strings such as “shell” or “.” reveals the malicious code:

 

cid:image007.png@01D31BDB.D4B84430

 

 

 

This shows the HTA file creates a shell object using Wscript and uses it to execute two hidden, encoded powershell commands (which are the same), then closes the document.

 

 

Looking at the decoded PowerShell command with CyberChef, you can see its purpose is to download and execute a file named “memo”:

 

 

 

 

 

The memo file can also be exported from the packet capture:

 

cid:image004.png@01D31BDD.D484C630

 

 

 

The file does two main things:

 

1.       Creates a new memory stream object using an encoded Base64 string

2.       Decompresses the stream and runs it using IEX

 

cid:image009.png@01D31BDE.D7A8CD10

 

 

 

Creating the memory stream object and examining its properties shows us the code that was executed:

 

cid:image010.png@01D31BE2.03502820

 

 

 

Putting the code in a text file allows us to organize it and determine what it accomplishes.  The code appears to execute a base64-encoded blob:

 

cid:image012.png@01D31BE3.1D2AB2A0

 

 

 

Decoding it shows the C2 IP address and a user agent string which indicates it is machine code which creates a network connection over HTTP or HTTPS:

 

 

 

 

 

 

INC0744592 VBE

 

Similar to PowerShell using Base64 encoding, VBScript can utilize Script Encoding which makes the code unreadable but still able to execute.

 

This encoded VBScript file (xxxxx.vbe) was analyzed yesterday on the OOB:

 

cid:image013.png@01D31BEF.05EEB4E0

 

 

Dynamic analysis showed it made web requests to a site that appeared to be down, but what else does the script do?

 

 

 

A python decoder from here was used to decode to reveal the actual VBScript code:

 

cid:image014.png@01D31BEF.05EEB4E0

 

 

 

 

Now let’s try to determine what the code does…

 

 

 

Format it a little first:

 

cid:image016.png@01D31BFA.CFAC8400

 

 

Adding indentations will really help organize the different parts of the code.

 

 

 

Let’s take first part:

 

 

cid:image018.jpg@01D31C06.479A9190

 

 

 

This wscript process is what Windows uses to execute the VBScript.

 

To demonstrate, we can start a wscript on our system with no arguments and verify its argument length of 0:

 

 

 

 

 

 

So if Wscript is called by itself, execute it with “WScript.ScriptFullName”&” uac”, “”, “runas”,1

 

If not called by itself, the function named “download” is defined and called:

 

 

cid:image020.jpg@01D31C06.479A9190

 

 

This function downloads the file hosted at the web page “visita” and saves it to the Startup folder under the name “winlogon.vbe”

 

In this case, there are just two bytes at that page:

 

cid:image024.png@01D31C01.94FA1A00

 

 

 

The next part changes the DNS servers and sets their search order:

 

cid:image028.png@01D31C01.94FA1A00

 

 

 

Next, the presence of a file is checked (RECs.txt), then an email message is constructed and sent containing the victim computer’s name, username, and the time:

 

cid:image025.jpg@01D31C06.479A9190

 

 

 

The RECs.txt file was successfully created on the VM but was empty:

 

cid:image030.png@01D31C01.94FA1A00

 

 

 

 

Finally, a message is shown to the user and one last function (PingFlush) is defined and called:

 

cid:image027.jpg@01D31C06.479A9190

 

 

 

This function creates a shell object, opens command prompt and runs ipconfig /flushdns several times before disabling IPv6.

 

 

These commands were also successful:

 

cid:image032.png@01D31C01.94FA1A00

 

cid:image033.png@01D31C01.94FA1A00

 