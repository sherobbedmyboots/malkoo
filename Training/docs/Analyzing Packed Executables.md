# Analyzing Packed Executables

Most of our indicators and TTPs gained through examining malware will
come from static and dynamic analysis using our Windows VM and REMnux. 
Each of these types of analysis gives valuable insight into the
malware's capabilities, how it works, and what characteristics can be
used to identify it. 

In some cases malware will make use of tools such as packers, crypters,
and protectors, to prevent proper static and code analysis.  In other
cases, it may not be possible to run the malware sample in a lab
environment in order to simulate the infection and perform dynamic
analysis.  There are a number of defensive measures malware can use, and
there are different tools available that can be used to bypass these
techniques to perform analysis.

The file used in this exercise can be found on the CSIRT OOB at this
location:

	/CSIRT/Sample-Files/mnemonic1.exe

               

## Packers

Packers are tools that compress an executable to reduce its size, and by
doing this can conceal a malicious program's code.  This helps the
attacker in several ways:

- Makes it harder for anti-malware tools to generate and detect
    signatures

- Protects the file from many static analysis techniques

- Makes it difficult to disassemble and debug which slows code
    analysis

When a packer is used, the clear text version of the file never exists
on disk.  When it is executed, the unpacking code extracts the original
program to RAM and runs it in memory.  Some legitimate programs are
packed so the presence of a packer doesn't necessarily indicate a
malicious file. 

One indication that a file might be packed is if there are very few
strings, imports, or recognizable functions available. 

Open the file named mnemonic1.exe in PEStudio and pay special attention
to the types of strings visible and the number and type of imports that
are found:

![](images/Analyzing%20Packed%20Executables/image001.png)


![](images/Analyzing%20Packed%20Executables/image002.png)


There are normally a lot more interesting strings and imported functions
that an executable needs to run...

Open up PowerShell and run strings on the file by typing `strings mnemonic1.exe`

To look for common imports, search for strings that contain the words
File and Get by typing `strings mnemonic1.exe | sls -casesensitive
'^Get|File$'`

You should see one imported function named **GetProcAddress** which is
required so the program can retrieve the addresses of exported
functions.

This is unusual as most normal executables will have multiple imported
functions with names containing Get and File.

So the executable has an unusually low number of imports and interesting
strings...  let's assume it is packed.

To extract the original file in its unpacked form, we have a few
options:

1. [Try to Unpack Program](#try-to-unpack-program)

	Determine the packer used and use it to unpack the program

2. [Dump to File](#dump-to-file)

	Run the program in memory and dump it to a file

3. [Live Analysis](#live-analysis)

	Run the program in memory and do live analysis


### Try to Unpack Program

There are several automated unpacking tools available such as
WSUnpacker, QuickUnpack, Ether, and EUREKA that can successfully extract
the original program.  Another option is to identify the packer used and
try to use it to unpack the executable to its original form for
analysis. 

Looking at the strings in the packed program, there are several
occurrences of UPX.  UPX is a free, packer frequently utilized by
malware to conceal its malicious code.  Others used are Armadillo, FSG,
Themida, and other custom packing programs.

Let's try to unpack the executable with UPX:

In PowerShell, download and install the UPX program by typing `choco install upx`

After install is complete, unpack the program by typing `upx -d mnemonic1.exe -o'mnemonic.exe'`

Now open the unpacked file mnemonic.exe with PEStudio:

![](images/Analyzing%20Packed%20Executables/image003.png)


![](images/Analyzing%20Packed%20Executables/image004.png)


Notice we can see some interesting strings now and all the imports the
executable will use are visible.

To look for common imports again, type `strings mnemonic1.exe | sls
-casesensitive '^Get|File$'`

Now you should see 20 or so names of imported functions instead of the
one we saw before.

Another way the packer can be identified is to use pescanner on REMnux.

Typing `pescanner mnemonic1.exe` will tell you that UPX is the packer
used.

Unpacking the executable with the default UPX settings worked for this
file, however the malware author could have scrambled the UPX headers,
used a custom version of UPX, or used another packer all together
preventing us from unpacking it in this way.

In this case, another option is to let the packer load the malware into
memory and then extract the program in its unpacked form to the file
system, or "dump" the program from memory.

### Dump To File

OllyDbg is a free 32-bit assembler level analyzing debugger for Windows.

Install the OllyDbg debugger by opening up an admin PowerShell window
and typing `choco install ollydbg`

After install is complete, download the OllyDumpEx plugin by typing
```powershell
wget -UseBasicParsing https://low-priority.appspot.com/ollydumpex/OllyDumpEx.zip -o OllyDumpEx.zip
```

Unzip it to the OllyDbg directory by typing 
```powershell
7z e OllyDumpEx.zip -o'C:\Program Files (x86)\OllyDbg\'
```

When prompted to replace existing files type "N" for No

Click on the Start menu and select OllyDbg

Click File --> Open and select `menmonic1.exe`

You will now see the assembly commands representing the packed
executable along with the hex and ascii representations of the binary
file's data.  But since this is the code of the packed program, we
cannot see any interesting strings or code.  In order to see these
strings, we need to step through the program and allow it to unpack
itself.

The highlighted command below is the first instruction of the packed program:

![](images/Analyzing%20Packed%20Executables/image005.png)


The goal is to slowly step through the program until we reach the point
where the unpacked code begins.

Execute just the first instruction by pressing F7.

On the upper right section (Registers), select the ESP, right click on
it, and select "Follow in Dump"

Highlight the top address in the lower left section (Dump area), right
click, and select Breakpoint --> Hardware, on write --> Word

This tells OllyDbg to stop execution at that point of the program.

Resume execution by pressing F9.  When prompted about compressed code,
click No.

You should now see we are on a `PUSHAD` instruction in a different section
of the program:

![](images/Analyzing%20Packed%20Executables/image006.png)


Again, execute only the current instruction by pressing F7.

On the upper right section (Registers), select the ESP, right click on
it, and select "Follow in Dump"

Highlight the top address in the lower left section (Dump area), right
click, and select Breakpoint--> Hardware, on write --> Word

Resume execution by pressing `F9`. 

You should now see we are on another instruction in a different section
of the program:

![](images/Analyzing%20Packed%20Executables/image007.png)


The `JMP mnemonic.00409074` instruction right before all of the `0000  ADD
BYTE PTR DS:[EAX],AL` instructions will take us to the first instruction of the
unpacked code.  So, highlight it, right click on it, and
click on Breakpoint --> Memory, on write

Resume execution by pressing `F9`. 

Now we have made it to the OEP (Original Entry Point) of the program,
where the original program's code (that is now unpacked) begins:

![](images/Analyzing%20Packed%20Executables/image008.png)


Right click on this first line and select Dump process (OllyDumpEx)

Click on the button **Get EIP as OEP** then click **Dump**

Choose where to save

Then click **Finish**

Now run some string searches on the dumped executable to verify it is no
longer packed:

To look for common imports again, type `strings mnemonic1_dump.exe |
sls -casesensitive '^Get|File$'`

You should see twenty or so imported functions

To look for keywords or commands, type `strings mnemonic1_dump.exe |
sls powershell`

You should see a long, encoded powershell command

### Live Analysis

Another option is to run the program and do live analysis in memory.

Before we execute the packed file, open up Process Hacker.

Now open up an admin Powershell command window and execute the packed
program by typing `.\mnemonic1.exe`

You'll notice in Process Hacker that the executable runs, immediately
starts a new powershell process, and then exits. 

The PowerShell process will continue to run for 20 seconds or so and
then it exits itself.

Start the executable again, but this time immediately right click on the
new powershell process and select **Suspend**.

Then go to the process, right click and select **Properties**.

Select the Memory tab and click on the **Strings** button.  Click **OK** on
minimum length.

Click on the **Filter** button, then on **Contains**, and enter the string:    
`https://`

Hit **Enter** and you should see something like this:

![](images/Analyzing%20Packed%20Executables/image009.png)


               

Not only is it unpacked, but now we can see the decoded powershell
command and the URLs that this process is attempting to reach.

We can also right click on the process and select **Create dump file** to
dump its memory to a file on disk.

Searching the .dmp file for the same string produces the same results:

![](images/Analyzing%20Packed%20Executables/image010.png)


Select the Token tab and you can see what SIDs the process was running
under and the privileges obtained/enabled.

![](images/Analyzing%20Packed%20Executables/image011.png)


Process Hacker has many more capabilities, navigate through some of the
other tabs and menu options to see\... 

## Summary

Stepping through the packed executable with a debugger allowed us to
access the unpacked code and obtain interesting strings and functions
used.  Searching for strings and data in memory gave us additional
indicators/TTPs.  The ability to work around the tools used by
self-defending malware significantly increases the quality and speed of
analysis and response. 

In part two, we'll look at some other defensive tools such as crypters
(obfuscation/encryption) and protectors (anti-debugging techniques) that
attempt to prevent analysis in similar ways.
