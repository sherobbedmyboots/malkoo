# Phishing To Injection Techniques

Many consider phishing to be the most effective technique for gaining a foothold on a network while memory injection is one of the best ways to remain on a compromised machine undetected.  Several methods of payload delivery combine both of these techniques in order to compromise a system without writing to disk.  This training will review memory injection techniques, common ways that malware accesses the Windows API, and several payload delivery techniques that can be used with phishing to deploy memory-only malware on a system.


- [Memory Injection Techniques](#memory-injection-techniques)
	- [Shellcode Injection](#code-injection)
	- [Reflective DLL injection](#reflective-dll-injection)
	- [Memory Module](#memory-module)
	- [Process Hollowing](#process-hollowing)
	- [Module Overwriting](#module-overwriting)
- [Windows API Access](#windows-api-access)
	- [Using Built-In Programs](#using-built-in-programs)
	- [Using Compiled Programs](#using-compiled-programs)
	- [Using COM Objects](#using-com-objects)
	- [Using Dynamic DotNet Assemblies](#using-dynamic-dotnet-assemblies)
		- [Platform Invoke](#platform-invoke)
		- [PSReflect](#psreflect)
- [Payload Delivery Techniques](#payload-delivery-techniques)
	- [VBA Code Injects into Created Process](#vba-code-injects-into-created-process)
	- [COM Object to Injected PowerShell Process](#com-object-to-injected-powershell-process)
	- [COM Object to DotNet Injects into Created Process](#com-object-to-dotnet-injects-into-created-process)


## Memory Injection Techniques

Over the last decade, there has been a gradual shift from malware utilizing executables on disk to leveraging legitimate programs to keep all untrusted code entirely in memory.  Many of these operations involve performing memory injection.

When a process is injected, malware writes malicious code to the process's memory and runs it in the context of the victim process.  Here are five different methods of performing memory injection:   

- [Shellcode Injection](#code-injection)
- [Reflective DLL injection](#reflective-dll-injection)
- [Memory Module](#memory-module)
- [Process Hollowing](#process-hollowing)
- [Module Overwriting](#module-overwriting)


### ShellCode Injection

A target process is made to run malicious machine code using the following functions:

|Function|Description|
|-|-|
|`OpenProcess`|Grabs handle to target process|
|`VirtualAllocEx`|Allocates a new chunk of memory with PAGE_EXECUTE_READWRITE protection|
|`WriteProcessMemory`|Writes code/payload into target process|
|`CreateRemoteThread`|Starts a new thread to execute the payload|

<br>

### Reflective DLL Injection

With RDI, a target process is made to run a malicious DLL which loads itself into memory:

|Function|Description|
|-|-|
|`OpenProcess`|Grabs handle to target process|
|`VirtualAllocEx`|Allocates a new chunk of memory|
|`WriteProcessMemory`|Copies the DLL into the allocated memory space|
|`CreateRemoteThread`|Starts execution of the DLL using a reflective loader function as entry point|

<br>

### Memory Module

A target process is made to run a malicious DLL which is loaded into memory using an injector or loader that mimics the `LoadLibrary` function:

|Function|Description|
|-|-|
|`OpenProcess`|Grabs handle to target process|
|`VirtualAllocEx`|Allocates a new chunk of memory|
|`WriteProcessMemory`|Copies the DLL into the allocated memory space|
|`CreateRemoteThread`|Starts execution of the DLL using a reflective loader function as entry point|

<br>

### Process Hollowing

A new process is started in a suspended state, replace with malicous code, and resumed using the following functions:

|Function|Description|
|-|-|
|`CreateProcess`|Target process is suspended with CREATE_SUSPEND option|
|`ReadRemotePEB`|Process Environment Block (PEB) is located|
|`NtUnmapViewOfSection`|Target process is hollowed| 
|`VirtualAllocEx`|Allocates a new chunk of memory to host malicious code|
|`WriteProcessMemory`|Writes the malicious code into the allocated memory space|
|`SetThreadContext`|Sets context of process|
|`ResumeThread`|Target process is resumed|

<br>

### Module Overwriting

A legitimate module is loaded and then overwritten with a malicious module.  This causes common detection methods to fail as the malicious module appears to be backed by a legitimate image on disk.  In order to find this technique in use, the modules on disk must be compared with the modules in memory to reveal discrepancies.  This method requires an additional hook that monitors events to both the malicious module and original module so that the malicious module can continue receiving events like a normal, registered module.

<br>

## Windows API Access

The Windows API is a collection of functions and methods that are already built into the operating system via system DLLs.  Programs load the appropriate DLLs into their process memory and call the functions they provide with the required arguments.  This is the way that programs can access and manipulate the operating system.  

For example, when a text editor needs to open a file, it may call the [NtOpenFile](https://msdn.microsoft.com/en-us/library/bb432381.aspx) function from `ntdll.dll` and provide the following required parameters:

```
NTSTATUS NtOpenFile(
  _Out_ PHANDLE            FileHandle,
  _In_  ACCESS_MASK        DesiredAccess,
  _In_  POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_ PIO_STATUS_BLOCK   IoStatusBlock,
  _In_  ULONG              ShareAccess,
  _In_  ULONG              OpenOptions
);
```

<br>

Adversaries also manipulate the OS of a victim system using the Windows API.  Traditionally this has been accomplished by creating a malicious program which the user or a vulnerable program is tricked into running on the system.  When the program runs, it loads its required DLLs and begins executing its code, using function calls from the loaded DLLs to make changes to the system.  

Here are the most common ways to interact with the Windows API:

- [Using Built-In Programs](#using-built-in-programs)
- [Using Compiled Programs](#using-compiled-programs)
- [Using COM Objects](#using-com-objects)
- [Using Dynamic DotNet Assemblies](#using-dynamic-dotnet-assemblies)
	- [Platform Invoke](#platform-invoke)
	- [PSReflect](#psreflect)


### Using Built-In Programs

GUI applications like `explorer.exe` and `iexplore.exe` and command line programs such as `net.exe`, `netsh.exe`, `ipconfig.exe`, and `shutdown.exe` are built into the OS and use Windows API functions to interact with the system.

Looking at the `ipconfig` program with CFF Explorer or PEStudio shows the 26 DLLs it loads and the 107 functions they provide:

![](images/Phishing%20To%20Injection%20Techniques/image003.png)<br><br>



### Using Compiled Programs

Programs can be written and compiled to interface with the Windows API.

Here is a simple program written in C which calls the [GetCurrentProcessId](https://msdn.microsoft.com/en-us/library/windows/desktop/ms683180.aspx) function:

![](images/Phishing%20To%20Injection%20Techniques/image001.png)<br><br>


Compile it using `gcc`.  If `gcc` is not installed, install with:

```powershell
choco install mingw -y
refreshenv
```

Compile the program using:

```powershell
gcc get-id.c -o get-id.exe
```

When executed, it prints its current process ID:

![](images/Phishing%20To%20Injection%20Techniques/image002.png)<br><br>

Looking at the program with CFF Explorer or PEStudio shows the 2 DLLs it loads and the 55 functions they provide:

![](images/Phishing%20To%20Injection%20Techniques/image004.png)<br><br>


### Using COM Objects

DLLs are written to interface with C programs or programs that understand the C language.  Component Object Model (COM) objects were created to allow DLLs to be accessed from any programming language.  Scripting languages like PowerShell, VBA/VBScript, and JScript use COM objects in order to interact with the Windows API.

For example, you can create an instance of Internet Explorer using Powershell with:

```powershell
$ie=New-Object -com InternetExplorer.Application
```

<br>

Once the object is created, you can then call its methods to perform actions with it:

![](images/Phishing%20To%20Injection%20Techniques/image005.png)<br><br>


The same APIs are being called when creating an IE instance using JScript:

```javascript
var ie = new ActiveXObject("InternetExplorer.Application");
```

<br>

As well as with VBA and VBScript:

```vbscript
Dim ie
Set ie = CreateObject("InternetExplorer.Application")
```

<br>


### Using Dynamic DotNet Assemblies

.NET is Microsoft's managed execution environment for building and running applications written in different programming languages. It consists of an execution engine, the Common Language Runtime (CLR), and a collection of classes providing access to the Windows environment.

- .NET programs are compiled to Intermediate Language (IL) instead of assembly code
- The IL code is kept in a ".NET assembly" along with metadata that describes the classes, methods and attributes of the program’s code 
- The CLR runs the .NET assembly and compiles it to machine code as methods are called (JIT compiling)

Using .NET's `System.Reflection` namespace, it is possible to create a dynamic assembly running directly from memory that can be used to call Windows API functions.

PowerShell is a great way to demonstrate this since it is built on the .NET Framework.  Here are two different ways PowerShell can use .NET to call Windows API functions:

- [Platform Invoke](#platform-invoke)
- [PSReflect](#psreflect)


#### Platform Invoke

PowerShell can compile C# on the fly.  The Platform Invoke service allows DLL functions to be called through .NET with the `Add-Type` cmdlet.

The following defines a method using C#:

```powershell
$GetCurrentProcessId = @'
[DllImport("kernel32.dll")]
public static extern uint GetCurrentProcessId();
'@

$Kernel32 = Add-Type -MemberDefinition $GetCurrentProcessId -Name 'Kernel32' -Namespace 'Win32' -PassThru
```


When the method is called, the code is compiled and sent to the CLR which loads the `kernel32` DLL and calls the `GetCurrentProcessId` function:

![](images/Phishing%20To%20Injection%20Techniques/image006.png)<br><br>

But using the Platform Invoke method calls the C# compiler `csc.exe` and writes temporary files to disk.  This is very easy for defenders to detect so a more OPSEC-friendly option is used when malware must not touch disk.


#### PSReflect

[PSReflect](https://github.com/mattifestation/PSReflect) is a script created by Matt Graeber that uses .NET reflection to dynamically define methods that call Windows API functions.

Here we use it to define a method that calls the `GetCurrentProcessId` function:

```powershell
IEX (new-object net.webclient).downloadstring('//eno-rs-c1-01/home$/atstaple/scripts/PSReflect.psm1')
$Mod = New-InMemoryModule -ModuleName Win32
$FunctionDefinition = (func kernel32 GetCurrentProcessId ([IntPtr]) @())
$Types = $FunctionDefinition | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Kernel32::GetCurrentProcessId()
```


The API is called from memory without leaving any artifacts on disk:

![](images/Phishing%20To%20Injection%20Techniques/image030.png)<br><br>


Here are several examples of .NET assemblies being used to access the Windows API:

- Post-Exploitation tools such as [Empire](https://github.com/EmpireProject/Empire) and [Cobalt Strike](https://www.cobaltstrike.com/) can inject a .NET assemblies (PowerShell runner DLLs) into any process in memory 

- Multiple [Application Whitelisting Bypasses](https://github.com/api0cradle/UltimateAppLockerByPassList) exist where signed applications that call the `Assembly.Load()` method like `MSBuild.exe` and `InstallUtil.exe` are made to run unsigned .NET assemblies which can access Windows APIs

- JScript tools such as [DotNetToJScript](https://github.com/tyranid/DotNetToJScript), [Starfighters](https://github.com/Cn33liz/StarFighters), and [CactusTorch](https://github.com/mdsecactivebreach/CACTUSTORCH) run .NET assemblies in memory providing Windows API access

<br>

## Payload Delivery Techniques

Phishing campaigns frequently utilize scripts and Office documents as containers for payloads.  Here are several ways a script or an Office document can be used to launch a memory injection attack:

- [VBA Code Injects into Created Process](#vba-code-injects-into-created-process)
- [COM Object to Injected PowerShell Process](#com-object-to-injected-powershell-process)
- [COM Object to DotNet Injects into Created Process](#com-object-to-dotnet-injects-into-created-process)


These examples use an HTML Application (HTA) as the container but many different file types can be used in the same way including `.js`, `.jse`, `.vbs`, `.vbe`, `.vba`, `.sct`, and `.wsf` files.

The payloads were generated with Cobalt Strike and some custom string replacements were used to help identify the code in memory:

![](images/Phishing%20To%20Injection%20Techniques/image007.png)<br><br>


### VBA Code Injects into Created Process

The `evil-vba.hta` file uses VBA code to create a new process (`rundll32.exe`) and inject shellcode into it which will download and reflectively inject a DLL (Cobalt Strike Beacon) in memory.

This type of VBA code is commonly delivered via Office macro---in this case VBScript is used to create an invisible Excel COM Object, add a VBA macro to it, and run it.

![](images/Phishing%20To%20Injection%20Techniques/image031.png)<br><br>


The VBA code starts a process, allocates memory space in the process (RWX), writes shellcode to it, and starts execution with `CreateRemoteThread`.  The shellcode is usually a stager, a tiny program that allocates memory for a payload, downloads it, writes it to process memory, and passes execution to it.  The reflectively loaded DLL then initializes itself in memory and runs in the injected process.

After running the `evil-vba.hta` file, the `Get-InjectedThread` script finds the `rundll32.exe` process contains injected code:

![](images/Phishing%20To%20Injection%20Techniques/image016.png)<br><br>

We need to convert the base address to hex format:

![](images/Phishing%20To%20Injection%20Techniques/image017.png)<br><br>

And find the area in memory using Process Hacker:

![](images/Phishing%20To%20Injection%20Techniques/image018.png)<br><br>

This is the shellcode that was injected:

![](images/Phishing%20To%20Injection%20Techniques/image019.png)<br><br>

If the full payload is successfully downloaded, there are two more areas of memory written:

![](images/Phishing%20To%20Injection%20Techniques/image020.png)<br><br>

The first is the entire stage (DLL plus loader) being written to memory:

![](images/Phishing%20To%20Injection%20Techniques/image021.png)<br><br>

And when called, the loader function writes the DLL to memory and initiates itself:

![](images/Phishing%20To%20Injection%20Techniques/image022.png)<br><br>




### COM Object to Injected PowerShell Process

The `evil-ps.hta` file uses a COM Object to create a PowerShell process which injects shellcode that will download the payload into memory.

A shell COM Object is created which runs an encoded PowerShell command that injects shellcode into memory:

![](images/Phishing%20To%20Injection%20Techniques/image032.png)<br><br>

After running the `evil-ps.hta` file, the `Get-InjectedThread` script finds a PowerShell process along with the encoded command:


![](images/Phishing%20To%20Injection%20Techniques/image015.png)<br><br>


The area of memory the thread started from is Private and RWX:

![](images/Phishing%20To%20Injection%20Techniques/image008.png)<br><br>

We must convert the base address to hex:

![](images/Phishing%20To%20Injection%20Techniques/image009.png)<br><br>

Then find that address in process memory using Process Hacker:

![](images/Phishing%20To%20Injection%20Techniques/image010.png)<br><br>

At this memory address we can find the shellcode that was injected:

![](images/Phishing%20To%20Injection%20Techniques/image011.png)<br><br>


If the full payload is downloaded, there are two more areas of memory written:

![](images/Phishing%20To%20Injection%20Techniques/image014.png)<br><br>

The first is the entire stage (DLL plus loader) being written to memory:

![](images/Phishing%20To%20Injection%20Techniques/image012.png)<br><br>

And when called, the loader function writes the DLL into memory, initiating itself:

![](images/Phishing%20To%20Injection%20Techniques/image013.png)<br><br>




### COM Object to DotNet Injects into Created Process

The `evil-torch.hta` file uses a COM Object to run a .NET assembly in memory which injects shellcode into a created process (`rundll32.exe` in this example).

![](images/Phishing%20To%20Injection%20Techniques/image033.png)<br><br>

While the first two examples used stagers for their payloads, this one is "stageless" meaning it includes the entire payload in the file.  The Reflective DLL is prepended with a loader which does some of the same things `LoadLibrary()` would do.

After running the `evil-torch.hta` file, the `Get-InjectedThread` script reports that the `rundll32.exe` process has injected code:

![](images/Phishing%20To%20Injection%20Techniques/image023.png)<br><br>

We convert the base address to hex format:

![](images/Phishing%20To%20Injection%20Techniques/image024.png)<br><br>

And find that area in memory using Process Hacker:

![](images/Phishing%20To%20Injection%20Techniques/image025.png)<br><br>

This time, no stager was used so we find the entire DLL and loader that was injected:

![](images/Phishing%20To%20Injection%20Techniques/image026.png)<br><br>

If we search for other RWX areas in memory, we can find where the Reflective DLL was written into memory and executed.  Notice the size of the memory region found has RWX permissions and is close to the custom size of 999,999 bytes that was set:

![](images/Phishing%20To%20Injection%20Techniques/image027.png)<br><br>

At this address is the Reflective DLL with the `MZ` removed:

![](images/Phishing%20To%20Injection%20Techniques/image028.png)<br><br>

If we know a unique string present in the executable, we can search for it to reveal the two instances of the executable code in memory:

![](images/Phishing%20To%20Injection%20Techniques/image029.png)<br><br>



## Summary

The injection techniques described in this document require access to Windows API functions such as `VirtualAllocEx` and `WriteProcessMemory`.  API access is traditionally reserved for processes running on the system that were started from executables present on the filesystem.   

Scripting languages used for system administration like PowerShell, VBA/VBScript, and JScript can access Windows APIs using COM objects.  The .NET Framework is used to run managed code and can also access the Windows API.  Because of these capabilities, scripts and .NET assemblies are frequently used by malware to perform memory injection.  

The following payload delivery techniques can be used to access the Windows API functions required for memory injection:

- Script or Office Doc that runs VBA code 

- Script or Office Doc that calls PowerShell

- Script or Office Doc that runs a .NET assembly

<br>

Run the following files and examine them in memory.  Understand how they are able to write code into another process and practice finding the injected code with tools like `Get-InjectedThread.ps1`, Process Hacker, Volatility, and Rekal:

- `evil-vba.hta`

- `evil-ps.hta`

- `evil-torch.hta`




 

