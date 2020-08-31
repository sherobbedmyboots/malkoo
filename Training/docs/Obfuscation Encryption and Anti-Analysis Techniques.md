# Obfuscation, Encryption, and Anti-Analysis Techniques

Self-defending malware can use a variety of evasion techniques to
conceal its functionality and prevent reverse engineering and analysis. 
The ability to counter these techniques provides insight into the nature
of the attack and how to detect and contain it which significantly
increases the quality and speed of analysis and response. 

Tools that are used to alter malware's original binary data in order to
bypass detection and prevent analysis generally fall into three
categories:

|Category|Description|
|-|-|
|Packer|compresses a file's original data to conceal information such as strings and imports|
|Crypter|uses obfuscation and encryption to hide information such as file paths, URLs, shellcode, etc.|
|Protector|uses anti-analysis techniques such as anti-debugging, anti-virtualization, anti-dumping, and anti-tampering to prevent reverse engineering and analysis|

In [Analyzing a Packed Executable](Analyzing%20a%20Packed%20Executable.md)
we looked at how stepping through the packed executable with a debugger
allowed us to access the unpacked code and obtain interesting strings
and functions used.  Searching for strings and data in memory gave us
additional indicators/TTPs.  Here we'll look at some techniques that
Crypters and Protectors use to hide a program's functionality and
prevent analysis by security tools and analysts.

- [Crypters](#crypters)
    - [Obfuscation](#obfuscation)
    - [Encryption](#encryption)
- [Protectors](#protectors)
    - [Anti-debugging](#anti-debugging)
		- [Debugger Checks](#debugger-checks)
		- [Analysis Tool Checks](#analysis-tool-checks)
    - [Anti-sandbox](#anti-sandbox)
    	- [Human Interaction](#human-interaction)
		- [Environment-specific](#environment-specific)
		- [Configuration-specific](#configuration-specific)
    - [Anti-virtualization](#anti-virtualization)
		- [Registry Keys](#registry-keys)
		- [Processes and Services](#processes-and-services)
		- [Default Paths and Files](#default-paths-and-files)


## Crypters

Crypters use obfuscation and encryption to hide a program's
functionality and prevent analysis.  Strings and suspicious instructions
that signature-based tools would detect as malicious are modified
without affecting the malicious program's original functionality
creating a new file that passes signature scans.  The program then
decodes/decrypts the malware at runtime either saving it to a directory
to execute or loading it directly into memory for execution.  The
addition of junk code in the program also slows down code analysis of
the malware by making it unreadable or hard for humans to understand.

### Obfuscation

Obfuscating shellcode is one common way to make detection and analysis
difficult.

An attacker's goal is to get a vulnerable
program---or in the case of phishing attacks, a user-initiated
program---on the victim machine to execute his malicious code. 

Many times an attacker only has a small space to work with and can't
get the entire malicious program to execute at one time.  In this case, a small string of shellcode called a "stager" is fed to
a program to be executed. 

This shellcode usually consists of commands to the computer to connect
back to an attacker's machine and begin loading the rest of the
malware. 

Strings and shellcode are disguised using many different methods
including:

|||
|-|-|
|XOR|Exclusive OR operations|
|Base64|Base64 encoding|
|ROT13|Rotating character positions by 13|

For example, let's use `wxHexEditor` in REMnux to
examine some shellcode.

This is shellcode that downloads the file at http://34.210.28[d]254/d6Xj:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image001.png)


Notice the IP address and page name are clearly visible.

This is the same shellcode, but each byte has been
XOR'ed with the key `0x04`:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image002.png)


Notice the IP address and page name are no longer
visible. 

Searching the executable for strings does not reveal them:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image003.png)


Also the machine code used to download the file has been changed and
would not be caught by signature-based tools.

When the program begins running in memory, it uses the
XOR key to convert the shellcode back to its original form and executes
it.

Once it's running, dynamic analysis tools show that it sends an HTTP
request for `/d6Xj` at 34.210.28.254:4443:

**Fiddler:**

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image004.png)


**Microsoft Network Monitor:**

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image005.png)


**FakeNet-NG:**

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image006.png)


**Xorsearch** and **Xorstrings** are two tools that allow us to do static
analysis on a program like this.

Using **Xorsearch**, we can identify the XOR key used (0x04), while
**Xorstrings** uses the key to show the XOR-encoded strings in the file:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image007.png)


To save a version of the file XOR'd with each key
detected, use the `-s` flag with Xorsearch.

Another way to do this is to use FLOSS (`floss sc.exe`)
which automatically detects and decodes XOR-encrypted strings:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image008.png)


### Encryption

A Crypter can also encrypt the portions of or an entire binary
executable file creating a new file that can bypass AV and other
signature-based tools.  The new, encrypted file can then decrypt
itself on startup and execute its original content.  This also makes
reverse engineering and analysis of the binary very difficult. 
Encryption methods used can include ARC4, TEA, LCG, DES, AES,
Blowfish, and others.

This executable (`aes_crypt.exe`) contains AES-encrypted shellcode that
is decrypted at runtime, injected it into memory, and executed:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image009.png)

The encryption key used can be shown in memory using **Process Hacker**:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image010.png)


## Protectors

Protectors can combine features from both packers and crypters but also
are known to perform Anti-Analysis checks such as:

- [Anti-debugging](#anti-debugging)
- [Anti-sandbox](#anti-sandbox)
- [Anti-virtualization](#anti-virtualization)

To demonstrate these, I used the [Veil-Evasion
Framework](https://www.veil-framework.com/veil-3-0-release/) and
[Pafish](https://github.com/a0rtega/pafish) (Paranoid Fish) which use
the same techniques many malware families use to detect VM, sandbox, and
analysis environments.

### Anti-debugging

Performs various checks to detect and avoid debugging
and other analysis tools.

- [Debugger Checks](#debugger-checks)
- [Analysis Tool Checks](#analysis-tool-checks)

#### Debugger Checks                                                    

Malware can use APIs, perform manual checks, or look for the presence of debugger-related artifacts:

- Check for Debugger using APIs IsDebuggerPresent, CheckRemoteDebuggerPresent,
NtQueryInformationProcess, OutputDebugString

- Check manually using BeingDebugged flag, ProcessHeap flag, NTGlobalFlag

- Check for artifacts such as Registry keys, findwindow


Here is **PaFish** calling the IsDebuggerPresent API:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image011.png)


And reporting that a debugger was detected:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image012.png)


#### Analysis Tool Checks                                        

Checking for the presence of tools that would indicate an analysis environment:

- Network analyzers such as Wireshark, tcpview, fiddler, netmon

- Process/File/Registry monitoring like ProcessHacker, Procmon, Procexp, apimonitor, Regshot, CaptureBat


### Anti-sandbox

Performs various checks to detect and avoid automated analysis.

- [Human Interaction](#human-interaction)
- [Environment-specific](#environment-specific)
- [Configuration-specific](#configuration-specific)

#### Human Interaction                                                 

Using various techniques to ensure the presence of a human user

- Mouse clicks, movement, speed, one or more mouse clicks to indicate human

- Dialogue boxes used to activate malware only after message box is clicked

- Scrolling monitored so that malware activates when user scrolls to second page


This program is configured to prompt a user prior to execution:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image013.png)


#### Environment-specific

Specific app versions, environment settings, etc.

|||
|-|-|
|Memory size|Only execute if physical memory is greater than 1 GB|
|Number of processors|Only execute if number of processors is greater than 2|                                
|Hard drive size|Only execute if hard drive is greater than 60 GB|
|Version checks|Execute only if certain OS or application version is present|
|Embedded code/iframes|Hiding code or iframes in GIFs, Flash, JPEGs|
|Embedded executables|Hiding executables in GIFs, PNGs, etc.|
|Office recent files|Require a number of recent files to execute|
|DLL loaders|Requiring specific loader to execute|
|Various|Screen resolution, wallpaper, username, hostname, USB Drive, printer|
|OS uptime|checking uptime using GetTickCount|


Here is **PaFish** detecting hard drive size:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image014.png)


Here is **PaFish** detecting number of processors:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image015.png)


#### Configuration-specific            

Checking for common sandbox configurations such as:

|||
|-|-|
|Extended sleep|Most sandboxes have a defined time for the analysis, malware will use a Sleep function with a big time|
|Onset Delay|Malware can delay execution in order to avoid analysis or detection|
|Stalling|Stalling code is typically executed before any malicious behavior|
|Detecting Time Changes|Determine if a sleep call is patched using GetTickCount|
|UTC Time Check|Checks to see if host is running on UTC time|
|Time triggers|Execute malware only before or after a certain time|
|Filenames|Checks its own name looking for common strings such as "sample"|
|File size limit|Creating file size greater than the default limit for most sandboxes|
|Volume serial numbers and info|Looks for volume information used in known sandboxes|
|Execution after reboot|Execute malware only after a reboot which sandboxes traditionally do not do|


Here is a program configured to check the time via NTP:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image016.png)


### Anti-virtualization

Using VM-related files, registry keys, processes and other settings to detect virtual environments.

- [Registry Keys](#registry-keys) - checking for presence of virtual software-related keys
- [Processes and Services](#processes-and-services) - vmtools, vmxnet, vboxtray, vmrawdsk, vmusbmouse, vmvss, vmscsi, vmx_svga, vmmemctl, vboxservice, vmhgfs
- [Default Paths and Files](#default-paths-and-files) - Virtual unique files such as vmware mouse driver
- [Others](#others) - MAC address, CPU timestamp counters (rdtsc), Hypervisor bit in cupid feature bits, Vmx communication port
             

#### Registry Keys

Here is **PaFish** checking for the presence of various VirtualBox
registry keys:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image017.png)


And reporting that VirtualBox keys were detected:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image018.png)


#### Processes and Services

Here is **ProcMon** showing **PaFish** checking for VirtualBox default files:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image019.png)


![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image001.png)


#### Default Paths and Files

Here is **ProcMon** showing **PaFish** checking for VirtualBox default files:

![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image020.png)


![](images/Obfuscation%20Encryption%20Anti-Analysis%20Techniques/image021.png)

       

## Exercise

Examine the following file using REMnux and a Windows analysis VM and
see if you can identify all the evasion techniques it uses:

    /CSIRT/Sample-Files/memupdaterpro.exe
