# Working with Portable Scripts and Programs

Sometimes it's necessary to run scripts and programs from a remote host.  In some cases, we need to configure credentials in order to perform tasks on other remote hosts such as file copies, IR scripts, and artifact collection.

This training document reviews the following:

- [Configuring Credentials](#configuring-credentials)
- [Copying Files](#copying-files)
- [Using Modules](#using-modules)
- [Saving Artifacts](#saving-artifacts)

## Configuring Credentials

With the RemoteApp Server, we're already running a PowerShell process in the context of our admin account.  But there are several scenarios that will require us to use explicit credentials to perform a task.

One example is when DNS is not working...

My workstation currently has ip address `10.10.10.10`.  If I try to start a PS Remoting session I get this error:

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image015.png)<br><br>

This is because DNS is incorrectly resolving the hostname to `10.10.10.11`:

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image016.png)<br><br>

Pinging the hostname gives the same results:

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image017.png)<br><br>

One workaround would be to edit the hosts file, but there's a better way---starting a PS remoting session using the hosts's IP address.

Connecting to a workstation using its IP address requires using explicit credentials PLUS one of the following:

1. HTTPS connection
2. Destination is in TrustedHosts list 

We'll use the second option.

Use the `Get-Credential` cmdlet to save your credentials as `$creds`:

```powershell
$creds = Get-Credential
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image002.png)<br><br>


Then obtain the workstation's IP address and use one of the following to add it to the TrustedHosts list:

```powershell
# Single host
Set-Item WSMan:\localhost\Client\TrustedHosts -Value <ipaddress> -Force

# All hosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
```

<br>

Now you can start a PowerShell Remoting session with:

```powershell
Enter-PsSession 10.10.10.11 -Credential $creds
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image003.png)<br><br>

Now that you have your admin credentials saved as `$creds`, you can use PowerShell Remoting to perform many different tasks on remote hosts.

### Copying Files

To copy a single file from the workstation to <host> use:

```powershell
$sess = New-PsSession 10.10.10.11 -Credential $creds
Copy-Item -FromSession $sess -Path "C:\Scripts\Run-BackupJob.ps1" -Destination "C:\Scripts"
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image001.png)<br><br>

You can also use a session to copy a folder from the workstation to <host>:

```powershell
$dest = "C:\"
$src = "C:\Scripts"
Copy-Item -FromSession $sess -Path $src -Destination $dest -Recurse
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image005.png)<br><br>

<br>

To copy a file or folder from <host> to the remote workstation, use `-ToSession` instead of `-FromSession`:

```powershell
Copy-Item -ToSession $sess -Path ".\test.txt" -Destination "C:\" 
```

<br>

### Using Modules

Import them:

```powershell
(Get-ChildItem .\Scripts\Modules\*.psm1).FullName |%{Import-Module $_}
```

<br>

Use them on remote hosts:

```powershell
$p = Invoke-Command -ComputerName 10.10.10.11 -ScriptBlock {Get-ActiveProcesses} -Credential $creds
```
![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image014.png)<br><br>


To import them automatically every time you logon, create a PowerShell profile file using:

```powershell
New-Item -Path $Profile -Force
```

<br>

Then add lines for each module:

```powershell
Add-Content -Path $Profile -Value "Import-Module IRModule"
```

<br>

Make sure your all your module directories are in your PS module path:

```powershell
ls $env:PSModulePath.split(':')[0]
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image001.png)<br><br>

```powershell
cat $profile
```

Check to make sure your profile has the `Import-Module` commands and any other commands you want to run at logon such as setting environment variables:

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image006.png)<br><br>

Now when you log in to a new session, the modules will be loaded:

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image007.png)<br><br>

And environment variables are set:

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image008.png)<br><br>

### Saving Artifacts

Many of our PowerShell modules save artifacts to memory which we lose when the session ends. 

For example, this saves all network connections for a workstation into variable `$n`:

```powershell
$n = Invoke-Command -ComputerName 10.10.10.11 -ScriptBlock {Get-Netstat} -Credential $creds
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image009.png)<br><br>

With this information represented as objects, we can easily sort and filter:

```powershell
$n | ? state -eq Established | Select ProcessId,ProcessName,Dst_Addr
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image010.png)<br><br>

To save this variable as an artifact and so that we can use it in future sessions, use the `Export-CliXml` cmdlet:

```powershell
$n | Export-Clixml -Path ~\netstat.xml
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image011.png)<br><br>

This creates an XML-based representation of the objects and stores it in a file:

```powershell
cat netstat.xml
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image012.png)<br><br>

Now in future sessions we can use `Import-CliXml` to recreate the original netstat objects:

```powershell
$n = Import-Clixml netstat.xml
```

![](images/Working%20with%20Portable%20Scripts%20and%20Programs/image013.png)<br><br>
