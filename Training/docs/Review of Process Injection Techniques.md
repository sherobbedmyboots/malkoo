# Review of Process Injection Techniques

When a process is injected, arbitrary code is written to the process's memory and executed in the context of the victim process as a way to hide from tools searching for untrusted programs.

This training document will review writing, compiling, and running programs and several common methods of performing process injection to run arbitrary, untrusted code:

- [Review of Programs](#review-of-programs)
	- [Write It](#write-it)
	- [Build It](#build-it)
	- [Run It](#run-it)
	- [Inject It](#inject-it)
- [Process Injection Techniques](#process-injection-techniques)
	- [Shellcode Injection](#shellcode-injection)
	- [Reflective DLL Injection](#reflective-dll-injection)
	- [Module Overwriting](#module-overwriting)
	- [.NET Assembly Injection](#.net-assembly-injection)


## Review of Programs

- [Write It](#write-it)
- [Build It](#build-it)
- [Run It](#run-it)
- [Inject It](#inject-it)

### Write It

The majority of code that is executed on systems is written in a high-level language such as C, C++, or C#.  Let's take another look at the source code of the simple C program `GoTeam.c`:
 
![](./images/Debugging%20Windows%20Programs/image001.png)<br><br>
 
### Build It

A compiler like GCC is used to convert the source code into an executable containing machine code which are low-level instructions for a CPU.  

We can look at these instructions using several different tools.  Note the hex representations for each line of opcodes.  With `objdump` you don't have to execute the program:

![](./images/Review%20of%20Process%20Injection%20Techniques/image009.png)<br><br>

We can also see this machine code with a hex editor:

![](./images/Review%20of%20Process%20Injection%20Techniques/image010.png)<br><br>

### Run It

A debugger allows you to inspect the code as the program runs.  Open the file with a debugger such as GDB and show functions with `info functions`:

![](./images/Review%20of%20Process%20Injection%20Techniques/image006.png)<br><br>

Change to intel with `set disassembly-flavor intel` then do `disas main`:

![](./images/Review%20of%20Process%20Injection%20Techniques/image007.png)<br><br>
 
If you slowly step through the code, you'll see the stack is set up, then a string is moved.  Let's see what's at that address with `x/s <address>` which means examine that address as a string:

![](./images/Review%20of%20Process%20Injection%20Techniques/image008.png)<br><br>

Another way...open x32dbg, open `GoTeamInC.exe` and press `F7` once and the debugger will break on the first instruction of the program:
 
![](./images/Review%20of%20Process%20Injection%20Techniques/image005.png)<br><br>

To stop the program when it begins to start the `main()` function, we put a breakpoint on it.  We already know its address, we set it in the debugger with `bp 4015fc` and hit `F7` until it stops there:

![](./images/Review%20of%20Process%20Injection%20Techniques/image011.png)<br><br>

Right click on the first address and select `Follow in Dump --> Selected Address`.  Highlight the hex characters, Right click and select `Data Copy` and you will have the shellcode available to copy in a number of different formats:

![](./images/Review%20of%20Process%20Injection%20Techniques/image012.png)<br><br>

This is the `Main()` function of the program which prompts a user for a team, evaluates the input, and takes a specific action based on that input.  This is a super simple version of a malicous agent running in memory.

### Inject It

We now have machine code (shellcode) from an untrusted program that can be written to the memory space of a legitimate remote process and made to run under that process's context using injection.  

![](./images/Review%20of%20Process%20Injection%20Techniques/image013.png)<br><br>

There are a few problems with this though... 

1. This shellcode would need to find addresses of DLLs for the functions it needs to use (printf, scanf, etc.)

2. There are null bytes in this shellcode that would cause it to fail 

<br>

So for this example, we're going to use a small piece of position-independent [Message Box Shellcode](https://github.com/SkyLined/w32-msgbox-shellcode/blob/master/w32-msgbox-shellcode.asm) that just pops up a box saying "Hello World":

```c#
0x66, 0x81, 0xE4, 0xFC, 0xFF, 0x31, 0xF6, 0x56, 0x64, 0x8B, 0x76, 0x30, 0x8B, 0x76, 0x0C, 0x8B,
0x76, 0x1C, 0x8B, 0x6E, 0x08, 0x8B, 0x36, 0x8B, 0x5D, 0x3C, 0x8B, 0x5C, 0x1D, 0x78, 0x01, 0xEB,
0x8B, 0x4B, 0x18, 0x67, 0xE3, 0xEC, 0x8B, 0x7B, 0x20, 0x01, 0xEF, 0x8B, 0x7C, 0x8F, 0xFC, 0x01,
0xEF, 0x31, 0xC0, 0x99, 0x32, 0x17, 0x66, 0xC1, 0xCA, 0x01, 0xAE, 0x75, 0xF7, 0x66, 0x81, 0xFA,
0x2A, 0xB6, 0x74, 0x09, 0x66, 0x81, 0xFA, 0xAA, 0x1A, 0xE0, 0xDB, 0x75, 0xC5, 0x8B, 0x53, 0x24,
0x01, 0xEA, 0x0F, 0xB7, 0x14, 0x4A, 0x8B, 0x7B, 0x1C, 0x01, 0xEF, 0x03, 0x2C, 0x97, 0x85, 0xF6,
0x74, 0x15, 0x68, 0x33, 0x32, 0x20, 0x20, 0x68, 0x75, 0x73, 0x65, 0x72, 0x54, 0xFF, 0xD5, 0x95,
0x31, 0xF6, 0xE9, 0xA0, 0xFF, 0xFF, 0xFF, 0x56, 0x68, 0x72, 0x6C, 0x64, 0x21, 0x68, 0x6F, 0x20,
0x77, 0x6F, 0x68, 0x48, 0x65, 0x6C, 0x6C, 0x54, 0x87, 0x04, 0x24, 0x50, 0x50, 0x56, 0xFF, 0xD5,
0xCC
```


## Process Injection Techniques

Let's take a closer look at some of the process injection techniques used by AgentSim:

- [Shellcode Injection](#shellcode-injection)
- [Reflective DLL Injection](#reflective-dll-injection)
- [Module Overwriting](#module-overwriting)
- [.NET Assembly Injection](#.net-assembly-injection)


### Shellcode Injection

A target process is made to run machine code using the following functions:

|Function|Description|
|-|-|
|`OpenProcess`|Grabs handle to target process|
|`VirtualAllocEx`|Allocates a new chunk of memory with PAGE_EXECUTE_READWRITE protection|
|`WriteProcessMemory`|Writes code/payload into target process|
|`CreateRemoteThread`|Starts a new thread to execute the payload|


<br>

Let's look at an example written in C#.  The first part of the source code (`inject_test.cs`) imports the Windows API functions that will be needed to perform process injection:

![](./images/Review%20of%20Process%20Injection%20Techniques/image032.png)<br><br>


The second part defines the shellcode and calls each function:

![](./images/Review%20of%20Process%20Injection%20Techniques/image033.png)<br><br>


Compile it with `csc.exe`, start a 32-bit process, and run the program providing its PID:

![](./images/Review%20of%20Process%20Injection%20Techniques/image031.png)<br><br>


You can now find the shellcode that ran at the address that was allocated:

![](./images/Review%20of%20Process%20Injection%20Techniques/image034.png)<br><br>



### Reflective DLL Injection

With RDI, a target process is made to run a malicious DLL which loads itself into memory:

|Function|Description|
|-|-|
|`OpenProcess`|Grabs handle to target process|
|`VirtualAllocEx`|Allocates a new chunk of memory|
|`WriteProcessMemory`|Copies the DLL into the allocated memory space|
|`CreateRemoteThread`|Starts execution of the DLL using a reflective loader function as entry point|

<br>

This time we'll build a DLL that pops a message box and modify it so that it can load itself into memory. 

First write the source file (`inject_test2.cs`):

![](./images/Review%20of%20Process%20Injection%20Techniques/image035.png)<br><br>

And save it as a `.cs`.  Compile it with:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:inject_test2.dll inject_test2.cs
```

<br>

If you try to run the DLL with `rundll32`, you'll get an error:

![](./images/Review%20of%20Process%20Injection%20Techniques/image036.png)<br><br>

This is because the `doIt` function is not exported.  To do this, use:

```powershell
ildasm /out:inject_test2.il inject_test2.dll
```

This disassembles the DLL into an intermediate language (IL) file which we need to add the line `.export ` to export the function:

![](./images/Review%20of%20Process%20Injection%20Techniques/image037.png)<br><br>

Now we assemble with:

```powershell
ilasm inject_test2.il /DLL /output=inject_test2.dll
```

And we now can use a PE analysis tool to view the DLL's export `doIt`:

![](./images/Review%20of%20Process%20Injection%20Techniques/image038.png)<br><br>


Now you can run it with `rundll32`:

![](./images/Review%20of%20Process%20Injection%20Techniques/image039.png)<br><br>

To allow us to load it reflectively, we'll use a script called [ConvertTo-Shellcode](https://github.com/monoxgas/sRDI/blob/master/PowerShell/ConvertTo-Shellcode.ps1) from 
[Silent Break Security](https://silentbreaksecurity.com/srdi-shellcode-reflective-dll-injection/):

```powershell
$url = "https://raw.githubusercontent.com/monoxgas/sRDI/master/PowerShell/ConvertTo-Shellcode.ps1"
$wc = New-Object Net.WebClient
$wc.DownloadString($url) | IEX
$bytes = ConvertTo-Shellcode -File C:\Users\Public\inject_test2.dll
$hex = $bytes | %{"{0:X2}" -f $_} | %{"0x" + $_}
for ($i=0; $i -lt $hex.length; $i+=24){$j=$i+23;[array]$z+="$($hex[$i..$j] -join ', '), "}
$z | Set-Clipboard
```

<br>

We can now have the shellcode copied to our clipboard and can paste it into our sc buffer in `inject_test.cs` so that it will run the reflective DLL when recompiled:

![](./images/Review%20of%20Process%20Injection%20Techniques/image040.png)<br><br>


Compile into DLL with:

```powershell
csc /out:inject_refl_test.exe inject_test.cs`
```

![](./images/Review%20of%20Process%20Injection%20Techniques/image042.png)<br><br>

Find the code that loads the reflective DLL at the beginning of the allocated memory:

![](./images/Review%20of%20Process%20Injection%20Techniques/image041.png)<br><br>

Scroll further down to see the actual DLL code:

![](./images/Review%20of%20Process%20Injection%20Techniques/image043.png)<br><br>


An easier example is building a DLL using C++ like this one used in AgentSim:

![](./images/Review%20of%20Process%20Injection%20Techniques/image044.png)<br><br>


Compile with `gcc` or `cl` and test with `rundll32`

![](./images/Review%20of%20Process%20Injection%20Techniques/image045.png)<br><br>

We can convert this to shellcode and inject into a remote process too:

```powershell
$bytes = ConvertTo-Shellcode -File C:\Users\Public\rdi.dll
$hex = $bytes | %{"{0:X2}" -f $_} | %{"0x" + $_}
for ($i=0; $i -lt $hex.length; $i+=24){$j=$i+23;[array]$z+="$($hex[$i..$j] -join ', '), "}
$z | Set-Clipboard
```

<br>

After you replace the shellcode, don't forget to remove the last comma in the buffer.  Also, this time you must pick a 64-bit process to inject into since `rdi.dll` is a 64-bit DLL:

![](./images/Review%20of%20Process%20Injection%20Techniques/image046.png)<br><br>



### Module Overwriting

Once you understand basic shellcode and DLL injection, try writing a program that loads a legitimate module and then overwrites it with your shellcode.  This causes common detection methods to fail as the custom-written code appears to be backed by a legitimate, signed image on disk.  

The functions for this technique are:

|Function|Description|
|-|-|
|`OpenProcess`|Grabs handle to target process|
|`LoadLibrary`|Load DLL|
|`NtUnmapViewOfSection`|Unmap DLL|
|`VirtualAllocEx`|Allocates memory at DLL's old address|
|`WriteProcessMemory`|Copies the DLL into the allocated memory space|
|`CreateRemoteThread`|Starts execution of the DLL using a reflective loader function as entry point|

<br>

This technique is similar to the last two, but instead of asking for ANY address with `VirtualAllocEx`, we load an unnecessary (but legitimate) DLL from disk, clear out its place in process memory, and ask for the address space that was previously occupied by the legitimate DLL.

This creates the appearance that code executing from this address belongs to a legitimate module mapped to disk.

### .NET Assembly Injection

For this technique, instead of the the injected DLL popping a message box, it loads the Common Language Runtime (CLR) into the remote process which runs a .NET assembly.

Let's look at the `remote_Dotnet_Inject.cpp` file to see what APIs are used:

![](./images/Review%20of%20Process%20Injection%20Techniques/image030.png)<br><br>


The [CLRCreateInstance](https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/clrcreateinstance-function) function is used along with the 
[GetRuntime](https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/iclrmetahost-getruntime-method), [GetInterface](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/dd233135%28v%3dvs.100%29), and [ExecuteInDefaultAppDomain](https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/iclrruntimehost-executeindefaultappdomain-method) methods.

So these functions are used:

|Function|Description|
|-|-|
|`OpenProcess`|Grabs handle to target process|
|`VirtualAllocEx`|Allocates memory at DLL's old address|
|`WriteProcessMemory`|Copies the DLL into the allocated memory space|
|`CreateRemoteThread`|Starts execution of the DLL using a reflective loader function as entry point|
|`CLRCreateInstance`|Loads the Common Language Runtime|

<br>

When `remote_Dotnet_Inject.dll` is injected into a process, it makes the process load:

- CLR Class Library (`mscorlib.ni.dll`)
- CLR Runtime (`clr.dll`)
- .NET JIT Compiler (`clrjit.dll`)
- .NET Assembly (`DotnetJob.exe`) 

<br>

![](./images/Review%20of%20Process%20Injection%20Techniques/image047.png)<br><br>

The .NET assembly that runs is only designed to pop a message box:

![](./images/Review%20of%20Process%20Injection%20Techniques/image048.png)<br><br>

But injected .NET assemblies are usually designed to execute a specific task such as a PowerShell runner that executes PowerShell commands without using `powershell.exe`.

The `PsJob.exe` .NET assembly is an example:

![](./images/Review%20of%20Process%20Injection%20Techniques/image049.png)<br><br>

The `PsJob.exe` will run any PowerShell command passed to it:

![](./images/Review%20of%20Process%20Injection%20Techniques/image051.png)<br><br>

But the  `remote_Ps_Inject.dll` is hard-coded to pass the `ls` command when running the assembly:

![](./images/Review%20of%20Process%20Injection%20Techniques/image052.png)<br><br>

When the `remote_Ps_Inject.dll` is injected into a process, the process loads the CLR which loads the `PsJob.exe` assembly and runs it with the `ls` command:

![](./images/Review%20of%20Process%20Injection%20Techniques/image050.png)<br><br>
