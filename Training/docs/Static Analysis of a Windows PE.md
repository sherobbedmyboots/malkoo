# Static Analysis of a Windows PE

An executable, or binary, is a file containing tasks for the computer to perform in machine code along with information required for the operating system to load and manage the executable code.  

Static analysis is using tools that extract this information and convert the machine code into assembly code in order to discover how the program operates without running its code.

This document will review:

- [PE Core Concepts](#pe-core-concepts)
    - [Formats](#formats)
    - [Creation](#creation)
    - [Execution](#execution)
- [Hex Editors](#hex-editors)
    - [View Raw Contents](#view-raw-contents)
    - [Modify Raw Contents](#modify-raw-contents)
- [Binary Format Tools](#binary-format-tools)
    - [Characteristics](#characteristics) - Examine file properties and metadata 
    - [Reputation](#reputation) - Determine if file or parts of file have been seen before
    - [Behavior](#behavior) - Identify use of suspicious APIs, packing, obfuscation
- [Disassemblers](#disassemblers)


Files used:

    artifact.exe
    guidance.dll

## PE Core Concepts

- [Formats](#formats)
- [Creation](#creation)
- [Execution](#execution)


### Formats

There are different executable formats for different operating systems:

|OS|Format|Dependencies|
|-|-|-|
|Windows|Portable Executable (PE)|May depend on shared libraries (`.dll`) from the OS|
|Unix/Linux|Executable and Linkable Format (ELF)|May depend on shared objects (`.so`) provided by OS|
|macOS|Mach Object (Mach-o)|May depend on shared objects (`.so`) provided by OS|

<br>

Windows PEs can have the following extensions:

|||
|-|-|
|`.exe`|Executable|
|`.dll`|Dynamic Link Library|
|`.sys`|System File|
|`.ocx`|ActiveX Control|
|`.cpl`|Control Panel|
|`.scr`|Screensaver|


### Creation

Once source code is written in a high level language, it is turned into an executable in two stages:

1. **Compilation** - A compiler converts the source code to machine code creating object files

2. **Linking** - Linkers combine the object files with the program's dependencies to form an executable

During this process, *sections* are used to group code with code and data with data so that similar code and data have similar memory permissions:

|Section|Name|Description|
|-|-|-|
|`.text`|executable code|the program's code which should be readable and executable|
|`.data`|initialized data|initialized data which should be readable and writable|
|`.rdata`|read only data|data that is read only|
|`.bss`|uninitialized data|undefined variables|
|`.idata`|import address table|used to resolve pointers to functions inside libraries at runtime|
|`.edata`|export information|functions that the PE exports|
|`.reloc`|relocation information|needed if code can't be loaded at its preferred base address|
|`.rsrc`|resources|a filesystem containing icons, embedded binaries, etc.|
|`.tls`|thread local storage|data that is private to each thread|
|`.CRT`|C runtime|support libraries for C runtime|
|`.debug`|debug|debugging information|

<br>

Executables can be statically linked or dynamically linked---either the file contains all the code it requires to execute (static) or it requests external libraries that the OS loader must provide (dynamic).

If dynamically linked, then external libraries need to be loaded by another program for their code to execute.  These are called **imports**.

Libraries may have a function that is automatically executed at load time (`DllMain` for Windows, `init()` for Linux).  These are called **exports**.

A modern Windows PE is built with the following file structure: 

- **DOS Header** contains a stub DOS program which prints out the string "This program cannot be run in DOS mode"
- **PE Header** contains information about the physical layout and properties of the file
    - Machine
    - NumberOfSections
    - TimeDateStamp
    - PointerToSymbolTable
    - NumberOfSymbols
    - SizeOfOptionalHeader
    - Characteristics
- **Optional Header** contains information about the logical layout of the file
    - EntryPoint
    - ImageBase
    - SectionAlignment
    - FileAlignment
    - SizeOfImage
    - SizeOfHeaders
    - DataDirectory
- **Sections**
    - .text
    - .data
    - .rdata
    - .idata
    - .rsrc


### Execution

When an executable runs, the OS loader:

- Copies the executable into memory using file header specs and sets permissions
- Loads all the DLLs the executable needs
- Resolves the required function addresses and puts in Import Address Table (IAT)
- Calls each DLL's entry point
- Transfers execution to any TLS callbacks
- Transfers execution to the executable's entry point

The executable code then begins to run and calls various functions to perform its tasks.

*Runtime Importing* - Malware may omit certain libraries and functions it intends to use from the IAT and obfuscate their names throughout the file in an attempt to thwart static analysis.  Once the executable is loaded, it will deobfuscate the function names and load them dynamically using [LoadLibrary](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175.aspx) and [GetProcAddress](https://msdn.microsoft.com/en-us/library/windows/desktop/ms683212.aspx). 

<br>

Files are a combination of code and data.  When investigating a potentially malicious file, we must determine what tasks the file's code and data are designed to perform.  It is easy to see what a program is capable of when looking at its source code, but the following tools are required when the program has been compiled:

- [Hex Editors](#hex-editors)
- [Binary Format Tools](#binary-format-tools)
- [Disassemblers](#disassemblers)

## Hex Editors

A hex editor shows the true content of the entire file in raw format.  Its two primary uses are:

- [View raw contents](#view-raw-contents)
- [Modify raw contents](#modify-raw-contents)


### View Raw Contents

Type `wxHexEditor guidance.dll` to open the `guidance.dll` file with [wxHexEditor](http://sourceforge.net/projects/wxhexeditor/):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image001.png)<br><br>

The hex numbers are the actual values that make up the file. On the right of these are the textual representations of these hex values using ASCII encoding. The address offsets show where each value is in the file.  

Notice the values that are meant to be interpreted as ASCII strings are readable:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image002.png)<br><br>

If you scroll through the file, you can see other bytes that are ASCII-encoded:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image003.png)<br><br>

Anything you cannot read is either encoded using a non-ASCII method or is machine code:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image004.png)<br><br>

File attributes such as the file's compiler timestamp are represented by bytes and placed in metadata fields at specific offsets (this one is at `0x248`):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image005.png)<br><br>

In this case, these 4 bytes represent a UNIX time value which we can convert to a readable date and time:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image006.png)<br><br>

There are many metadata fields and flags within a PE.  Instead of converting each one of these into readable file attributes manually, we can use [binary format tools](#binary-format-tools) to automate this process. 


### Modify Raw Contents

There are times when metadata fields and flags within a PE file must be modified in order to run or to be recognized by an analysis tool.  To demonstrate this we'll use the [file](http://www.linfo.org/file_command.html) tool, a standard utility on Linux systems used to identify filetypes based on filesystem, magic number, and language tests.  

The [file](http://www.linfo.org/file_command.html) command is an example of a very basic binary format tool.  It searches for and tests the bytes in a file to provide file information for the analyst.

Type `wxHexEditor guidance.dll` to open the file with [wxHexEditor](http://sourceforge.net/projects/wxhexeditor/) and change the first two bytes to `00 00`. Close and save the file.

Type `file /sbin/ifconfig` to see how a normal executable is identified.  Now type `file guidance.dll` and notice that the modified file is identified as only "data":

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image007.png)<br><br> 

Since it doesn't contain the magic number "MZ" at the beginning of the file, [file](http://www.linfo.org/file_command.html) does not identify the modified `guidance.dll` as a PE32 executable.

Type `wxHexEditor guidance.dll` to open the file with [wxHexEditor](http://sourceforge.net/projects/wxhexeditor/) and change the first two bytes back to `4D 5A`.  

Now [file](http://www.linfo.org/file_command.html) will correctly identify the file:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image008.png)<br><br> 

Binary format tools have many additional capabilities such as hashing, unpacking, and querying reputation services, but they generally operate by reading and interpreting the bytes present in the target file.  When specific bytes have been removed to hinder analysis or can't be located for some reason, it may be necessary to modify the fields and flags of a PE to enable static analysis. 


## Binary Format Tools

Binary Format Tools such as [CFF Explorer](http://www.ntcore.com/exsuite.php), [PeStudio](https://www.winitor.com/), [EXEInfo PE](http://exeinfo.atwebpages.com/), and [readpe.py](https://github.com/crackinglandia/pype32) traverse an executable's internal structure, parse the data, interpret what the bytes represent, and organize it for the analyst.  

Binary format tools are generally used to examine the following:

|Name|Description|
|-|-|
|[Characteristics](#characteristics)|compile time, compiler used, console or GUI application, DLL or EXE, version info, CRC, processor machine it runs on, section names and properties, embedded resources|
|[Reputation](#reputation)|file hash, section hash, fuzzy hash, import hash, digital signature, mutex, ascii and unicode strings| 
|[Behavior](#behavior)|suspicious libraries and functions, packing, obfuscation, anti-debug, anti-vm, TLS callbacks| 


### Characteristics

When performing static analysis, it's important to first get some basic information about the file using tools such as [readpe](https://github.com/crackinglandia/pype32) and [pecheck.py](https://blog.didierstevens.com/2013/04/19/3462/) on REMnux or [CFF Explorer](http://www.ntcore.com/exsuite.php), [PeStudio](https://www.winitor.com/), and [EXEInfo PE](http://exeinfo.atwebpages.com/) if you're using Windows.

Here [readpe](https://github.com/crackinglandia/pype32) parses and interprets `guidance.dll`'s DOS header:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image009.png)<br><br> 

And the file header:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image010.png)<br><br> 

This shows the file is a DLL designed to run in a 32-bit environment.  It also shows the compiler timestamp we discovered earlier in UTC format.

It also parses and interprets the image header:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image011.png)<br><br> 

As well as the data directories:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image012.png)<br><br> 

On Windows, [PeStudio](https://www.winitor.com/) scans `artifact.exe` and organizes all the information it discovers into different tabs including sections, imports, resources, etc. to examine individually:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image104.png)<br><br> 

[CFF Explorer](http://www.ntcore.com/exsuite.php) organizes this information in a similar fashion:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image103.png)<br><br> 

The more information you obtain about the PE file, the easier it will be to identify anomalies, the use of malicious techniques, and attempts to evade detection.

### Reputation

Next determine if the file has been seen before and if so, what was reported by checking for hashes, digital signatures, and embedded strings.

- [Classic Fuzzy Import Hashes](#classic-fuzzy-import-hashes)
- [Digital Signatures](#digital-signatures)
- [Embedded Strings](#embedded-strings)


#### Classic Fuzzy Import Hashes

A classic hash search can be used to identify a file or parts of a file that have been observed and analyzed before.  Use [pehash](http://pev.sourceforge.net/) to calculate hashes of the file, its headers, and its sections:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image017.png)<br><br> 

Perform a classic hash search on the file using VirusTotal's API with `vt -fs <filename>`. Submit a file using `vt -f <filename>`:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image018.png)<br><br> 

Since altering a single bit of data in a file will significantly change the file's hash value, detection from a classic hash search is easy to avoid.  However, fuzzy hashing can be used to identify files that have been slightly changed but still contain a high percentage of similarities.  

Compare multiple files with [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html) using `ssdeep -lp <filename1> <filename2> <filename3>`:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image019.png)<br><br>

To demonstrate, copy the `guidance.dll` file as `copy.dll`.  Open `copy.dll` with [wxHexEditor](http://sourceforge.net/projects/wxhexeditor/) and change the first two bytes of the file `4D 5A` to `00 00`.  Save and close `copy.dll`.  Note that the MD5 hash values are radically different, but [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html) identifies them as being 99% the same file:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image101.png)<br><br>

[Import hashing](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html) uses a hash of a file's imported libraries and functions to identify files that have matching import tables and therefore were most likely compiled from the same source code.  Compare import tables using imphash with [pescanner](https://code.google.com/p/malwarecookbook/source/browse/trunk/3/8/pescanner.py) or other similiar tool:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image020.png)<br><br>

#### Digital Signatures

A digital signature can also be used to check a file's reputation and compare it to other files that use the same signature or trust chain.  [PeStudio](https://www.winitor.com/) and others will detect embedded digital signatures and extract their details:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image102.png)<br><br> 

On REMnux, you can check for and extract a digital signature with [disitool](http://blog.didierstevens.com/programs/disitool/):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image022.png)<br><br> 

Had it extracted one, we could use `openssl` to view:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image023.png)<br><br> 


#### Embedded Strings

Embedded strings can also be used to identify a known malicious file or similarities to known malware families and post-exploitation tools.  Unique strings can be utilized in YARA rules to identify similar files while suspicious file names, file paths, registry keys, domain names, etc. can be used to detect potentially malicious functionality.

Many binary format tools will have a built-in strings utility.  Here [PeStudio](https://www.winitor.com/) recognizes multiple "blacklisted" strings in the file:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image109.png)<br><br> 

You can also use [pestr](http://pev.sourceforge.net) or [strings](http://www.linfo.org/strings.html):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image031.png)<br><br> 

With [pestr](http://pev.sourceforge.net) you can specify offsets (`-o`) and sections (`-s`) where each string is found in the file:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image030.png)<br><br> 

Searching for common strings shows the file contains both standard and custom Base64 encoding tables.  [base64dump.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/base64dump.py) will attempt to decode each string as if it was Base64-encoded:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image032.png)<br><br> 

YARA rules check files for specific byte patterns (text, hex, or regex).  This one identifies `guidance.dll` as being related to the [Wilted Tulip](https://securityaffairs.co/wordpress/61363/apt/copykittens-operation-wilted-tulip.html) campaign:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image021.png)<br><br> 


### Behavior

- [Imports and Exports](#imports-and-exports)
- [Packing and Obfuscation](#packing-and-obfuscation)


### Imports and Exports

[Here](https://zeltser.com/reverse-engineering-malicious-code-tips/) is a list of common capabilities used by malware and the functions that can be used to perform each one:

|Capability|Functions|
|-|-|
|Code Injection|[CreateRemoteThread](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682437.aspx), [OpenProcess](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320.aspx), [VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx), [WriteProcessMemory](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674.aspx), [EnumProcesses](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682629.aspx)|
|Dynamic DLL Loading|[LoadLibrary](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175.aspx), [GetProcAddress](https://msdn.microsoft.com/en-us/library/windows/desktop/ms683212.aspx)|
|Memory Scraping|[CreateToolhelp32Snapshot](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682489.aspx), [OpenProcess](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320.aspx), [ReadProcessMemory](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553.aspx), [EnumProcesses](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682629.aspx)|
|Data Stealing|[GetClipboardData](https://msdn.microsoft.com/en-us/library/windows/desktop/ms649039.aspx), [GetWindowText](https://msdn.microsoft.com/en-us/library/windows/desktop/ms633520.aspx)|
|Keylogging|[GetAsyncKeyState](https://msdn.microsoft.com/en-us/library/windows/desktop/ms646293.aspx), [SetWindowsHookEx](https://msdn.microsoft.com/en-us/library/windows/desktop/ms644990.aspx)|
|Embedded Resources|[FindResource](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648042.aspx), [LockResource](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648047.aspx)|
|Unpacking/self-injection|[VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx), [VirtualProtect](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366898.aspx)|
|Query Artifacts|[CreateMutex](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682411.aspx), [CreateFile](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858.aspx), [FindWindow](https://msdn.microsoft.com/en-us/library/windows/desktop/ms633499.aspx), [GetModuleHandle](https://msdn.microsoft.com/en-us/library/windows/desktop/ms683199.aspx), [RegOpenKeyEx](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724897.aspx)|
|Execute a Program|[WinExec](https://msdn.microsoft.com/en-us/library/windows/desktop/ms687393.aspx), [ShellExecute](https://msdn.microsoft.com/en-us/library/windows/desktop/bb762153.aspx), [CreateProcess](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425.aspx)|
|Web Interactions|[InternetOpen](https://msdn.microsoft.com/en-us/library/windows/desktop/aa385096.aspx), [HttpOpenRequest](https://msdn.microsoft.com/en-us/library/windows/desktop/aa384233.aspx), [HttpSendRequest](https://msdn.microsoft.com/en-us/library/windows/desktop/aa384247.aspx), [InternetReadFile](https://msdn.microsoft.com/en-us/library/windows/desktop/aa385103.aspx)|

<br>

Here [readpe](https://github.com/crackinglandia/pype32) lists the DLL's exports:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image014.png)<br><br> 

And the libraries and functions imported via name and ordinal:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image013.png)<br><br> 


When functions are imported by ordinal rather than by name, the function names will not appear in a strings output.


Use a tool such as [pecheck.py](https://blog.didierstevens.com/2013/04/19/3462/) to show the names of the functions that are imported by ordinal:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image015.png)<br><br> 

Here [portex](https://katjahahn.github.io/PortEx/) lists each function found with a brief description:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image016.png)<br><br> 

Here [peframe](https://github.com/guelfoweb/peframe) also reports some suspicious API calls:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image024.png)<br><br> 

Use [pedump](http://pedump.me/) and [pescanner](https://code.google.com/p/malwarecookbook/source/browse/trunk/3/8/pescanner.py) to look at the file's sections for any suspicious characteristics:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image025.png)<br><br> 

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image026.png)<br><br> 




### Packing and Obfuscation

Tools such as [signsrch](http://aluigi.altervista.org/mytoolz.htm) can be used to scan for signatures and identify the use of encryption or packing.

Here, [signsrch](http://aluigi.altervista.org/mytoolz.htm) finds the use of encryption in the `guidance.dll` file:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image027.png)<br><br> 

Use [xorsearch](http://blog.didierstevens.com/programs/xorsearch/) to search the ascii string "POST", and two XOR keys are found:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image028.png)<br><br> 

Use [grep](https://www.gnu.org/software/grep/manual/grep.html) to see the XOR-encoded data:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image029.png)<br><br> 

This gives us potential indicators that were undetectable while XOR-encoded.

Packing is used to compress executables to save disk space.  Once loaded in memory, the executable decompresses itself and runs normally.  Malware utilizes packing to prevent identification of suspicious code and data using static analysis.

Packing is also a behavior common in malicious PE files.  There are several good tools for detecting packing such as [Bytehist](https://www.cert.at/downloads/software/bytehist_en.html), [packerid](https://github.com/sooshie/packerid), [Detect It Easy](http://ntinfo.biz/index.html), and [Exeinfo PE](http://exeinfo.atwebpages.com/) by using signatures or entropy analysis.

Here [pepack](http://pev.sourceforge.net/) shows the `guidance.dll` file is not packed, but identifies packing in another sample:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image033.png)<br><br> 

Open up `artifact.exe` with [CFF Explorer](http://www.ntcore.com/exsuite.php).  A look at the sections shows this file is packed using UPX:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image105.png)<br><br>

CFF Explorer has a built in UPX Utility which we can use to unpack the file:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image106.png)<br><br>

After clicking `Unpack` to unpack the file, we can now see the normal sections present in an executable file (`.text`, `.data`, etc):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image107.png)<br><br>

Selecting the `.text` section shows the file's entry point and allows us to view the machine code that will execute when the file first runs:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image108.png)<br><br>

Identifying the file's characteristics, reputation, and behavior required binary format tools to organize the file's **data** and make it readable.  Now we need a disassembler to make the file's **code** readable.


## Disassemblers

A disassembler converts binary code into assembly code so that the control flow of the program can be read and understood.  Understanding how the program executes provides context for how the suspicious strings and API calls found are being used.  There are several great disassemblers available such as [Ida Pro](https://www.hex-rays.com/products/ida/), [Radare2](https://github.com/radare/radare2), [Hopper](https://www.hopperapp.com/), [Binary Ninja](https://binary.ninja/index.html), and [objdump](https://sourceware.org/binutils/docs-2.19/binutils/objdump.html).

Stream disassemblers like [Udis86](https://github.com/vmt/udis86) and [ndisasm](https://linux.die.net/man/1/ndisasm) will disassemble any data you give it starting from the first byte of the file:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image035.png)<br><br>

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image037.png)<br><br>

With [objdump](https://sourceware.org/binutils/docs-2.19/binutils/objdump.html) you can specify a section to disassemble:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image038.png)<br><br>

Or specify the address you want to start disassembling such as the file's entry point:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image039.png)<br><br>

Disassemblers with additional features like [Vivisect](https://github.com/vivisect/vivisect) and [bokken](https://inguma.eu/projects/bokken) will analyze the file and allow navigation or even emulation.

Here is [Vivisect](https://github.com/vivisect/vivisect):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image034.png)<br><br>

And [bokken](https://inguma.eu/projects/bokken):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image036.png)<br><br>

[CFF Explorer](http://www.ntcore.com/exsuite.php) has a disassembler utility which we can use to examine the first instructions in the `.text` file.  Click on the `Quick Disassembler` tab, ensure the Base Address reads `0004014B0` and select `Disassemble`.  The opcodes at each address are now translated to assembly instructions:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image110.png)<br><br>

We could go through each of the thousands of instructions to understand what the code is doing or we can let [IDA Pro](https://www.hex-rays.com/products/ida/) analyze the file and identify all the standard library functions it finds in the assembly code.  


Open the file with [IDA Pro](https://www.hex-rays.com/products/ida/) and wait for it to complete its initial autoanalysis:

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image111.png)<br><br>

When complete, all the functions that IDA discovered are listed in the [Functions]() window.  The functions that IDA recognized with pattern-matching are named accordingly (`memcpy`, `malloc`, `strlen`...) and the ones that weren't recognized are given generic names based on their address (`sub_4022B0`, `sub_402350`, `sub_4023D0`...):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image112.png)<br><br>

[IDA Pro](https://www.hex-rays.com/products/ida/) also allows us to interactively change the names of functions, variables, and data structures as we identify them which makes analysis much faster and much easier.

Another similar tool is [Binary Ninja](https://binary.ninja/index.html):

![](images/Static%20Analysis%20of%20a%20Windows%20PE/image113.png)<br><br>

As you can see, disassemblers like [IDA Pro](https://www.hex-rays.com/products/ida/) and [Binary Ninja](https://binary.ninja/index.html) are more than just a list of opcodes derived from a sequence of bytes.  Next week we'll take a closer look at interactive disassemblers like these which provide an opportunity for better analysis as they augment the disassembled code with information about the functions and datatypes discovered.
