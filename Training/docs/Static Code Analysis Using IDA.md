# Static Code Analysis Using IDA

Understanding the capabilities of malware we encounter is critical for generating threat intelligence, tracking and responding to incidents, and improving defenses.  Static code analysis is an important step in this process.  

A disassembler provides graphical and structural views of disassembled code that helps explain what the program does, and can help identify severity, impact, and remediation efforts.  This training document reviews basic operation of [IDA](https://www.hex-rays.com/products/ida/), a programmable, interactive disassembler and debugger.


- [Static Code Analysis Review](#static-code-analysis-review)
- [IDA Operation](#ida-operation)
- [Starting With Data](#starting-with-data)
- [Starting With Code](#starting-with-code)


## Static Code Analysis Review

These are the general steps we take during malware analysis, discovering and extracting TTPs and indicators during each one:

|Step|Description|
|-|-|
|Automated Analysis|Sandbox check for suspicious APIs, reputation, dropped files, connections, SSL certs, mutexes|
|Static Analysis|Closer inspection of file structure, strings, imports, exports, metadata, encryption, obfuscation|
|Dynamic Analysis|Run file in controlled environment to observe file, registry, process, and network activity|
|Static Code Analysis|Fully map malware capabilities without running its code|
|Dynamic Code Analysis|Fully map malware capabilities by running and interacting with its code|
|Memory Analysis|Run malware and observe how samples interact with system memory|


In the Static Code Analysis step, we've completed our initial assessment and triage and have identified suspicious code and data.  Now we want to understand the binary on a lower level as well as obtain any information it could be hiding.  We do this by examining its logic structures and control flow in order to understand decision points and report unique characteristics and capabilities.

On a basic level we do this by:

- Locating the suspicious code and data
- Use cross-referencing to identify relationships between the code and data
- Determine how the program uses the code and data

For a review on Assembly, see [Debugging a Windows Program](./Debugging%20a%20Windows%20Program.md)

Let's walk through an example using a simple program `GoTeam.exe`:

![](images/Debugging%20Windows%20Programs/image001.png)<br><br>


## IDA Operation

- [Autoanalysis](#autoanalysis)
- [Names](#names)
- [Signatures](#signatures)
- [Functions](#functions)


### Autoanalysis

A disassembler distinguishes code from data and converts the code to assembly language.  IDA goes further by analyzing the file to obtain detailed knowledge about its internal structure so it can display recognized functions, cross references for strings, and global and local variables.

Open the `GoTeam.exe` file with [IDA](https://www.hex-rays.com/products/ida/) and wait for it to complete its initial autoanalysis:

![](images/Static%20Code%20Analysis%20Using%20IDA/image001.png)<br><br>

The first instruction that will execute in a program is called its entry point.  IDA labels this address as `start` and takes you to this location to begin analysis.

The main window is the **IDA-View** window, or the disassembly window.  You can toggle this window between Graph View and Text View using the `SPACE` bar.  Hit `SPACE` to go to the Text View:

![](images/Static%20Code%20Analysis%20Using%20IDA/image002.png)<br><br>

All the functions that IDA discovered during autoanalysis are listed in the **Functions** window.  The functions that IDA recognized with pattern-matching are named accordingly ([IsProcessorFeaturePresent](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent)) and the ones that weren't recognized are given generic names based on their address (`sub_401B1B`, `sub_401CB2`, `sub_401CD0`...):

![](images/Static%20Code%20Analysis%20Using%20IDA/image003.png)<br><br>


### Names

When IDA analyzes a file, it assigns a virtual address to every location in the program.  Instead of using virtual addresses to reference these locations, IDA gives every location a name using the following:

|||
|-|-|
|sub_XXXXXX|subroutine at address XXXXXX|
|loc_XXXXXX|instruction location at address XXXXXX|
|byte_XXXXXX|8-bit data at location XXXXXX|
|word_XXXXXX|16-bit data at location XXXXXX|
|dword_XXXXXX|32-bit data at location XXXXXX|
|unk_XXXXXX|data of unknown size at location XXXXXX|

<br>

Open the **Names** window by going to `View > Open Subviews > Names` or pressing `Shift+F4`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image009.png)<br><br>

These are symbolic descriptions that IDA gives to all referenced locations.  If the location is referenced in the program's symbol table, IDA uses it.  If it is not, IDA creates a name for it based on its type and address of the location:

|Code|Type|
|-|-|
|*f*|regular functions|
|**L**|library function|
|**->**|imported name|
|**i**|named code|
|**D**|data|
|**A**|string data|

<br>

Strings are shown in the **Strings** window by going to `View > Open Subviews > Strings` or pressing `Shift+F12`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image005.png)<br><br>

Functions are shown in the **Functions** window by going to `View > Open Subviews > Functions` or pressing `Shift+F3`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image017.png)<br><br>

### Signatures

Open the **Signatures** window by going to `View > Open Subviews > Signatures` or pressing `Shift+F5`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image011.png)<br><br>

This view is used to work with code that IDA doesn't recognize.  This view currently shows that IDA has applied the `vcseh` signature to the binary and 3 functions were recognized and identified.

Right click to apply a new signature:

![](images/Static%20Code%20Analysis%20Using%20IDA/image012.png)<br><br>

Adding the `vc32rtf` signature allows IDA to recognize 102 additional functions:

![](images/Static%20Code%20Analysis%20Using%20IDA/image013.png)<br><br>

We can apply several more:

![](images/Static%20Code%20Analysis%20Using%20IDA/image016.png)<br><br>

Now there are many more functions labeled with their correct names:

![](images/Static%20Code%20Analysis%20Using%20IDA/image018.png)<br><br>

The more functions we can make IDA identify, the easier analysis will be.  

### Functions

Identifying the relationships between a program's functions is key to understanding its capabilities.  IDA's Graph view shows the program's code as control flow graphs by separating its functions into *code blocks* which are sequences of instructions that execute together without branching.  

Hit `SPACE` again and go back to Graph View.  In Graph View functions are displayed one at a time with arrows representing the jumps between the different code blocks within the function.  Conditional jumps are shown in either GREEN (branch taken) or RED (branch not taken).  If there is only one next code block to be executed, the arrow is BLUE:

![](images/Static%20Code%20Analysis%20Using%20IDA/image004.png)<br><br>

Let's try some basic static code analysis techniques with `GoTeam.exe`.

## Starting With Data

One technique is to start with data such as an interesting string, and then find the code that uses it and observe how it is being used.  Pick a string from the **Strings** window and double-click on its address to see it in the Disassembler View:

![](images/Static%20Code%20Analysis%20Using%20IDA/image006.png)<br><br>

Notice each string has a comment out to the right that shows the function that references it.  To go to the function that references the string `Enter your favorite sports team: `, double-click on the string's cross reference (XREF) which is function `sub_401020`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image007.png)<br><br>

This takes you to the Disassembler view of the function that uses that string, `sub_401020`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image008.png)<br><br>

We can now see our string, named by IDA as `aEnterYourFavor`, is pushed to the stack before the program calls function `sub_401110`.

Double-clicking on `sub_401110` shows us the assembly code of this function:

![](images/Static%20Code%20Analysis%20Using%20IDA/image019.png)<br><br>

We could inspect these instructions and determine what it does but there's an easier way.  At this point we've already identified through Dynamic Analysis that the `aEnterYourFavor` string gets printed to the console so we can safely assume function `sub_401110` is a type of `print` function.

Press `ESC` to go back and let's label it with `Right Click > Rename`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image020.png)<br><br>

Using the same logic, we can rename the next called function to `SomeScanFunc`. 

Further down is a function called `sub_401000`.  Double-click to navigate to its code:

![](images/Static%20Code%20Analysis%20Using%20IDA/image022.png)<br><br>

This function pushes the string `Go %s\n!` to the stack before printing it.  Press `ESC` to go back and rename this one to `PrintGoFunc`.

Now the flow of the program's code is starting to become clearer:

![](images/Static%20Code%20Analysis%20Using%20IDA/image021.png)<br><br>

So the flow for this part of the program is:
- Print string `aEnterYourFavor` to user
- Scan user's response as `%s`
- Compare response with string `saints`
- If a match, print string `Go <response>!`
- If not, print string `Who dat!`

<br>

Let's try this on a slightly more complex program.  Load up the `AgentSim.exe` program into IDA and add some 64-bit CRT signatures so IDA will recognize more functions:

![](images/Static%20Code%20Analysis%20Using%20IDA/image010.png)<br><br>

Select `View > Open Subviews > Strings` to generate a list of strings.  This PowerShell cradle is a good place to start:

![](images/Static%20Code%20Analysis%20Using%20IDA/image036.png)<br><br>

Double-click on the string's address to bring up Disassembly view:

![](images/Static%20Code%20Analysis%20Using%20IDA/image037.png)<br><br>

Double-click on the string's cross reference `sub_14007F990` to view it in Graph view.  Now that we know what is at this address, we can rename to `stager_code`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image038.png)<br><br>

Graph view shows the order of some interesting functions being called--first [OpenProcess](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess), then [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualallocex), and finally the stager code is used by [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-writeprocessmemory):

![](images/Static%20Code%20Analysis%20Using%20IDA/image039.png)<br><br>

These three APIs together in this order indicate process injection, but they are usually followed by [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethread) which can't be found in this case.  We can assume that the code only gets written and not executed.

Start with another interesting string: `This program cannot be run in DOS mode`.  Hit `Ctrl+f` in the **Strings** view and search for the string `DOS mode`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image040.png)<br><br>

Double-click the second one to navigate to the location in Disassembly view and note that this executable is prepended by many lines of machine code which we can assume is designed to load the program into a remote process from memory.

Scroll up to the address where the machine code starts to find its cross reference (`sub_14007E200`) and double-click on it:

Now we are taken to a function in which we see the following functions called in this order:

- [OpenProcess](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [IsWow64Process](https://docs.microsoft.com/en-us/windows/desktop/api/wow64apiset/nf-wow64apiset-iswow64process)
- [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [VirtualProtectEx](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualprotectex)
- [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethread)

We can now inspect each of the arguments to be passed to each function and get a good understanding of what this portion of the program is designed to perform.


### Starting With Code

Another method is to start with code such as a suspicious function. Each function indicates a specific capability that a program may have, but closer inspection of the program's flow is required to explain when and how each is used.

For example, if you're interesting in learning about the module-stomping capabilities of this program, you'll want to inspect its use of the [NtUnmapViewOfSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwunmapviewofsection) API:

![](images/Static%20Code%20Analysis%20Using%20IDA/image025.png)<br><br>

Hit `Ctrl-x` to see its cross references and double-click on `j_NtUnmapViewOfSection`. Hit `Ctrl-x` once again to see that function's cross references and there are two:

![](images/Static%20Code%20Analysis%20Using%20IDA/image026.png)<br><br>

Double-click on one of these to open the function in Graph view.  Look at the code block before this one where the [OpenProcess](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess) function is called---if it's successful, the path to `loc_14007EA8B` is taken and [NtUnmapViewOfSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwunmapviewofsection) is called.  If it's not, the program takes the path to `sub_14006380B` and eventually exits:

![](images/Static%20Code%20Analysis%20Using%20IDA/image027.png)<br><br>

Now look at the code block that comes after--if the [NtUnmapViewOfSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwunmapviewofsection) function is successful, the path to `loc_14007EB12` is followed and [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualallocex) is called.  If not, the path to `sub_14006380B` is taken:

![](images/Static%20Code%20Analysis%20Using%20IDA/image028.png)<br><br>

And in the code block after that, if [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualallocex) is successful, [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-writeprocessmemory) is called:  

![](images/Static%20Code%20Analysis%20Using%20IDA/image029.png)<br><br>

We can follow the argument passed to [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-writeprocessmemory) to see what gets written by double-clicking on the name `unk_1401706B0`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image030.png)<br><br>

This is the loading code and reflective DLL that AgentSim injects into the memory of a remote process.  Using `Ctrl-x` to find cross references to this code shows that five functions reference it:

![](images/Static%20Code%20Analysis%20Using%20IDA/image031.png)<br><br>

We can now rename this unknown location to `reflective_dll_code` now since we know what it is.  Following one of the cross references reveals another function that uses it:

![](images/Static%20Code%20Analysis%20Using%20IDA/image032.png)<br><br>

Looking at the code blocks before the one referencing `reflective_dll_code`, we can see that this path is used by the program's sleep test.

A portion of this function loops over and over again every five seconds.  Zoom out and IDA does a good job of displaying this loop in Graph view:

![](images/Static%20Code%20Analysis%20Using%20IDA/image033.png)<br><br>

Let's back up even further... how does this sleep function get called?  Scroll up to the first code block and hit `Ctrl-x` and navigate to the function that calls it.  You'll find that function is referenced by two functions:

![](images/Static%20Code%20Analysis%20Using%20IDA/image034.png)<br><br>

These code blocks have strings that reveal what capability the program is running:  `EVADE > SLEEP > PID` or `EVADE > SLEEP > BINPATH`:

![](images/Static%20Code%20Analysis%20Using%20IDA/image035.png)<br><br>

In this way we can explore the different paths a program can take and discover the purpose of each path and the data that is used.

## Summary

IDA provides high quality disassembly by implementing capabilities from a number of different inspection and analysis tools and augmenting disassembled code with information about the functions and datatypes it discovers.  

IDA can be used to investigate malware as well as reverse engineering and vulnerability analysis on internal proprietary applications.  

Start with interesting ***data*** and determine what *code* is using it and why.  Start with interesting ***code*** and determine what it does and what *data* it uses.

**IDA Shortcuts**

|||
|-|-|
|Strings window|`Shift+F12`|
|Text search|`Alt+t`|
|Insert comment|`;`|
|Return to previous view|`Esc`|
|Follow jump or call|`Enter`|
|Go to next view|`Ctrl+Enter`|
|Show diagram of function calls|`Ctrl+F12`|
|List Entrypoints|`Ctrl+e`|
|Got to address|`g`|
|Rename variable or function|`n`|
|Show cross-references|`Ctrl-x`|
