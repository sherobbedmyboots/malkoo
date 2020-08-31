# Working with PowerShell Script Modules

PowerShell scripts allow us to automate tasks and obtain system information quickly and efficiently.  Script modules are a way to package related functions together for easier loading and sharing.  This document will walk through the process of building and using a script module from some of the scripts we frequently use to interrogate our endpoints.

- [Scripts and Functions](#scripts-and-functions)
- [Creating Script Modules](#creating-script-modules)
- [Importing and Using a Script Modules](#importing-and-using-script-modules) 


## Scripts and Functions

A script is a file containing instructions describing how to accomplish a set of tasks.  The `Invoke-Greeting.ps1` script for example queries the day of the week and uses it to greet five people:

![](images/Working%20with%20PowerShell%20Script%20Modules/image008.png)<br><br>


When the same set of tasks is performed repeatedly, it is more efficient to place pieces of the code into functions.  The functions can be defined at the beginning of the script, and when that set of tasks needs to be performed, the function is called with any arguments it requires:

![](images/Working%20with%20PowerShell%20Script%20Modules/image009.png)<br><br>


This makes the code easier to reuse and also to read and understand.

When a function is defined and called in a script, it first only exists in the script file.  When PowerShell runs the script, it reads all the functions in the file into memory and begins executing code that will call those functions.

If we "dot source" the script, the script contents are loaded into memory and run.  But now, for the rest of this session, we can call any of the functions the script contains without running the entire script:

![](images/Working%20with%20PowerShell%20Script%20Modules/image010.png)<br><br>

You can see all the functions loaded into memory for your current session by typing:

```powershell
Get-ChildItem -Path Function:
```

<br>

We can load the functions from the script without running the script at all by modifying the script file to only contain the functions.  Remove the call to the [DoIt]() function at the end of the script and save the file.  This time when we dot source the script, PowerShell loads the functions into memory and they are available to call for the rest of the session:

![](images/Working%20with%20PowerShell%20Script%20Modules/image011.png)<br><br>

This is a simple example of how a script module works.  It is a collection of functions we can load into memory and call when required.  PowerShell provides several cmdlets to work with modules:

|Cmdlet|Description|
|-|-|
|[Get-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-module?view=powershell-6)|Shows module information|
|[New-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-module?view=powershell-6)|Creates a dynamic module in memory|
|[Import-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module?view=powershell-6)|Adds a module to the current session|
|[Remove-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/remove-module?view=powershell-6)|Removes a module from the current session|

<br>

Use [Get-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-module?view=powershell-6) to see information about loaded modules:

![](images/Working%20with%20PowerShell%20Script%20Modules/image002.png)<br><br>


Use [New-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-module?view=powershell-6) to load a function into memory from a script block:

![](images/Working%20with%20PowerShell%20Script%20Modules/image001.png)<br><br>
 

To load multiple, complex functions into memory and to make sharing them easier, we will need to make a script module (`.psm1`) that contains or points to all the functions that will be loaded.


## Creating Script Modules

We will create a script module using functions from some of the scripts we use frequently such as `Get-ActiveProcesses.ps1` and `Get-InjectedThread.ps1`.  This way we'll have all the functions we need loaded into memory and can run them on remote hosts without having to search for and run each individual script.

When you import a module with [Import-Module](), PowerShell looks for the module in all of the directories listed in the `$env:PSModulePath` variable. To see the directories, call the variable and split it with the `;` character:

```
$env:PSModulePath.split(';')
![](images/Working%20with%20PowerShell%20Script%20Modules/image003.png)<br><br>
```


There are two primary paths we'll be dealing with:

```powershell
# User only
$env:USERPROFILE\Documents\WindowsPowerShell\Modules

# System wide
C:\Program Files\WindowsPowerShell\Modules
```

<br>

If you want the module only available to your user account, use `$env:USERPROFILE\Documents\WindowsPowerShell\Modules`.  If you want it to be accessible by any account on the system, place it in `C:\Program Files\WindowsPowerShell\Modules`.

For this example, we'll use the first path.  If you don't have a `Modules` directory, create one and then inside it create a directory named `Interrogate-Endpoint` which will contain all files that make up the new module:

```powershell
cd ~\Documents\WindowsPowerShell
mkdir Modules
cd Modules
mkdir Interrogate-Endpoint
cd Interrogate-Endpoint
```

<br>

First let's copy over all the scripts we want to include in the module:

|Script|Description|
|-|-|
|[Get-FileSignature.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-FileSignature.ps1)|Check to see if a file is digitally signed (catalog or embedded)|
|[Get-ActiveProcesses.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-ActiveProcesses.ps1)|Get active processes on a system|
|[Get-DnsCache.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-DnsCache.ps1)|Retrieve contents of system dns cache|
|[Get-FileSystemChanges.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-FilesystemChanges.ps1)|Find files recently created, accessed, or written|
|[Get-FirewallLog.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-FirewallLog.ps1)|Retrieve firewall logs from a system|
|[Get-ForensicAlternateDataStream.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-ForensicAlternateDataStream.ps1)|Find all alternate data streams on a system|
|[Get-ForensicPrefetch.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-ForensicPrefetch.ps1)|Search for prefetch files on a system|
|[Get-ForensicShimcache.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-ForensicShimcache.ps1)|Search for shimcache artifacts on a system|
|[Get-ForensicUserAssist](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-ForensicUserAssist.ps1)|Search for UserAssist artifacts on a system|
|[Get-InjectedThread.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-InjectedThread.ps1)|Find threads that were created as a result of code injection|
|[Get-LogonDetails.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-LogonDetails.ps1)|Pull logon details from 4624, 4648, and RDP Client logs|
|[Get-NetConnectionProfile.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-NetConnectionProfile.ps1)|List networks on a system and their firewall profile category|
|[Get-Netstat.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-Netstat.ps1)|Get active network connections on a system|
|[Get-PSAutoRun.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-PSAutoRun.ps1)|Retrieve information on system persistence mechanisms|
|[Get-ShadowCopies.ps1](training/docs/files/Working%20with%20PowerShell%20Scripting%20Modules/Interrogate-Endpoint/Get-ShadowCopies.ps1)|Lists all volume shadow copies available on a system|


<br>

You can select individual scripts to copy over and download them one at a time, or if you are set up to interface with our repos using Git, copy them all over at once using:

```bash
mkdir -p ~/Documents/WindowsPowerShell/Modules/Interrogate-Endpoint
cd ~/Documents/WindowsPowerShell/Modules/Interrogate-Endpoint
git init <reponame>
cd <reponame>
git remote add origin ssh://git@<repo>
git config core.sparsecheckout true
echo "training/docs/files/Working with PowerShell Scripting Modules/Interrogate-Endpoint/*" >> .git/info/sparse-checkout
git pull --depth=1 origin master
cp training/docs/files/Working\ with\ PowerShell\ Scripting\ Modules/Interrogate-Endpoint/* ../
cd ..
rm -rf <reponame>
```

<br>

You should now have the `Interrogate-Endpoint` directory from our git repo copied into your `Modules` directory:

```
ls Interrogate-Endpoint
![](images/Working%20with%20PowerShell%20Script%20Modules/image016.png)<br><br>
```

Notice there are two files above that are not `.ps1` files... these are the script module (`.psm1`) file and the module manifest (`.psd1`) file.

The script module (`.psm1`) file can contain all of the functions that will be loaded or act as a pointer to scripts that contain the functions that will be loaded.  In this example we are using 15 different scripts so it makes sense to keep each script's functions in their own script file and point to these files using the `.psm1` file.

Here is the script module file named `Interrogate-Endpoint.psm1` which just lists the `.ps1` files in the current directory and loads them into memory:

```powershell
Get-ChildItem $PSScriptRoot -Filter '*.ps1' |
     % {. $_.FullName}
```

<br>

The module manifest (`.psd1`) file contains information describing the module and any system requirements.  You can create a template file to add your module's specific information by using the [New-ModuleManifest]() cmdlet:

```powershell
New-ModuleManifest Interrogate-Endpoint.psd1
``` 

<br>

After the `.psd1` file is created, open it up and make two changes:

**1. Uncomment the "Root Module" parameter and assign the "Interrogate-Endpoint.psm1" file to it:**

![](images/Working%20with%20PowerShell%20Script%20Modules/image012.png)<br><br>


**2. Enter in the functions that will be exported:**

![](images/Working%20with%20PowerShell%20Script%20Modules/image013.png)<br><br>


Now that we have the components of our new module in the `Modules\Interrogate-Endpoint` directory, we can import it and call its functions.


## Importing and Using Script Modules

Use [Import-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module?view=powershell-6) to load the module into memory and see the functions that are now available with [Get-Command](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/Get-Command?view=powershell-6):

![](images/Working%20with%20PowerShell%20Script%20Modules/image014.png)<br><br>

Now run any of these functions on the local system by calling them:

```
Get-Netstat | ? State -eq LISTENING | select ProcessId,ProcessName,Src_Port
![](images/Working%20with%20PowerShell%20Script%20Modules/image006.png)<br><br>
```

But how do we run these functions on remote systems which do not have our module loaded in memory?

To do this, we need to give [Invoke-Command](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/Invoke-Command?view=powershell-6) a copy of the function in the form of a variable.  Using `${ }` works in this case as it can be used to declare a variable with non-standard characters in it:

![](images/Working%20with%20PowerShell%20Script%20Modules/image004.png)<br><br>


Here, we can use it to place the function we want to use into a variable that [Invoke-Command](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/Invoke-Command?view=powershell-6) will accept:

```
$n = Invoke-Command -ComputerName <hostname> -ScriptBlock ${function:Get-Netstat}
$n | ? State -eq LISTENING | select ProcessId,ProcessName,Src_Port
![](images/Working%20with%20PowerShell%20Script%20Modules/image007.png)<br><br>
```

In addition to passing the function to the remote system, we also need to be able to pass any arguments that are required.  For example, to run the [Get-FileSignature]() function, we need to also pass the name of the file:

![](images/Working%20with%20PowerShell%20Script%20Modules/image005.png)<br><br>

To pass an argument to a remote system, use the `-ArgumentList` parameter:

```
Invoke-Command <hostname> -ScriptBlock ${function:Get-FileSignature} -ArgumentList '<filepath>'
![](images/Working%20with%20PowerShell%20Script%20Modules/image015.png)<br><br>
```

If you want the module imported whenever PowerShell starts, you can configure this in your PowerShell profile.  The `$profile` variable contains the path of this file.  Use the following to check for its presence and create one if it doesn't exist:

```powershell
# Check if exists
Test-Path $profile

# If False, create one
New-Item -Path $profile -Type File -Force
```

<br>

```
$profile
Test-Path $profile
New-Item -Path $profile -Type File -Force
![](images/Working%20with%20PowerShell%20Script%20Modules/image017.png)<br><br>
```

Now add the command `Import-Module Interrogate-Endpoint` to the `$profile` file:

![](images/Working%20with%20PowerShell%20Script%20Modules/image018.png)<br><br>


Then start a new PowerShell session to make sure it worked:

```
# Open PowerShell 
![](images/Working%20with%20PowerShell%20Script%20Modules/image019.png)<br><br>
```

The profile was successfully loaded and we immediately have access to all functions from the Interrogate-Endpoint module.


## Summary

- Work more efficiently by creating PowerShell scripts for tasks you find yourself performing repeatedly

- Utilize functions when writing scripts so that their code is more easily reused and understood

- Create script modules which allow you to load multiple functions into memory at once and more easily share them with others

- Automate the importing of modules by creating and configuring a PowerShell profile
