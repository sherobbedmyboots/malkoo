# Endpoint Interrogation with PowerShell Part Two

As an investigation proceeds, we can continue to interrogate systems
with PowerShell to obtain additional evidence to support theories that
may explain what happened.

Here are some common follow-up questions:

- What executables were run recently?  [ShimCache](#shimcache)

- What executables were started by explorer?  [UserAssist](#userassist)

- Are there any hidden files on the system?  [Alternate Data Streams](#alternate-data-streams)

- Do any processes have injected threads?  [Injected Threads](#injected-threads)

- Are there any historical copies of the filesystem available for analysis?  [Volume Shadow Copies](#volume-shadow-copies)



## ShimCache

The
[Get-ForensicShimcache.ps1]()
script from PowerForensics exports a system's Shimcache providing full
paths of executables that were run on the system and when they ran.

To use it, run it on a remote system and capture the
results in a variable (`$sc`):

```powershell
$sc = Invoke-Command -ComputerName <target> -FilePath .\Get-ForensicShimcache.ps1
```

Get the contents of the variable, select properties, and
sort by last modified time:

```powershell
$sc | select LastModifiedTime,Path | sort -desc LastModifiedTime
```

Filter out system folders to reveal executables that ran
out of user directories and other unusual locations:

```powershell
$sc | select LastModifiedTime,Path | ? Path -notmatch 'System32|Program Files|Windows' | sort -desc LastModifiedTime
```


## UserAssist

The
[Get-ForesnsicUserAssist.ps1]()
script is also from the PowerForensics project and provides a list of
applications executed during interactive sessions.

To run it on a remote host, use `Invoke-Command` and
capture the results in a variable (`$ua`):

```powershell
$ua = Invoke-Command -ComputerName <target> -FilePath .\Get-ForensicUserAssist.ps1
```

Get the contents of the variable and select the
following properties sorting by LastExecutionTimeUtc:

```powershell
$ua | select ImagePath,User,RunCount,LastExecutionTimeUtc | sort -desc LastExecutionTimeUtc
```

Use `Where-Object` to filter specific property values,
such as user:

```powershell
$ua | select ImagePath,User,RunCount,LastExecutionTimeUtc | ? User -eq <user> | sort -desc LastExecutionTimeUtc
```


## Alternate Data Streams

The
[Get-ForensicAlternateDataStream.ps1]()
from the PowerForensics project searches for alternate data streams on a
system.

These are separate files distinct from their host files and can be used
to hide configuration files, payloads, exfil data, and more.

For example, create a normal file:

```powershell
Add-Content -Path .\normal.txt -Value 'This is a normal file with normal text.'
```

Now add a stream to it containing a PowerShell encoded
"payload":

```powershell
$stream = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host `"The PowerShell script was successfully executed!`""))
Add-Content -Path .\normal.txt -Value $stream -Stream HiddenStream
```


Adding the stream doesn't change the file's size, it
just adds an attribute which you must specify in order to access:

```powershell
cat .\normal.txt
cat .\normal.txt:HiddenStream
```

The payload inside the stream can be called and
executed:
          
```powershell
powershell -enc $(cat .\normal.txt:HiddenStream)
```

To run the script on a remote system, use
`Invoke-Command` and capture the output into an object (`$ads`):

```powershell
$ads = Invoke-Command -ComputerName <target> -FilePath .\GetForensicAlternateDataStream.ps1
```

The variable now contains all alternate data streams
discovered on the system:

```powershell
$ads
```               

The script will return many results because Internet
Explorer and other browsers use streams named `Zone.Identifier` to
identify files downloaded from the Internet.

To examine one of these alternate data streams, log on
the remote host and use `Get-Item` with the `-stream` parameter:

```powershell
Get-Item ~\Pictures\xxx.png -stream *
```

Once you know the name of the stream (`Zone.Identifier`),
you can cat it out and read it like this:

```powershell
cat ~\Pictures\xxx.png:Zone.Identifier
```

This file was given this ZoneId (3) because it was
downloaded from the Internet.

You can produce a much smaller list to work with by
filtering out stream names of `Zone.Identifier` with `Where-Object` (?):

```powershell
$ads | ? StreamName -notmatch 'Zone.Identifier'
```

Add conditions such as file size, name, last write time,
etc. that are relevant to the incident to find suspicious streams:

```powershell
$ads | ? StreamName -notmatch 'Zone.Identifier' | ? {(ls $_.FullName).LastWriteTime -gt $(Get-Date).AddDays(-3)} 2>$null
```

This is the only ADS modified/written to the system in the last 3 days.

## Injected Thread

The
[Get-InjectedThread.ps1]()
script from Jared Atkinson, creator of PowerForensics, looks for threads
that were created as a result of memory injection.

An implant may get an initial foothold in a process that
gets inspected frequently, such as PowerShell.  A common technique is
for the implant to inject itself into another process in an attempt to
hide.

For example, here a PowerShell Empire agent checks in
with its C2 and is running in the victim system's PowerShell process id
2972:

![](images/Endpoint%20Interrogation%20PowerShell%202/image017.png)

Then a different process is selected for injection. 
Notice only two threads are shown under the notepad process by Process
Hacker:

![](images/Endpoint%20Interrogation%20PowerShell%202/image018.png)

Using the psinject command, a second Empire agent is
injected into the notepad process and it immediately checks in with its
C2:

![](images/Endpoint%20Interrogation%20PowerShell%202/image019.png)

Now you see much more activity in the notepad process. 
This is the second Empire agent running in memory:

![](images/Endpoint%20Interrogation%20PowerShell%202/image020.png)

We also see some DLLs that do not belong in a
non-PowerShell process :

![](images/Endpoint%20Interrogation%20PowerShell%202/image021.png)

The first Empire agent is killed leaving one agent
hiding in what appears to be a non-PowerShell process:

![](images/Endpoint%20Interrogation%20PowerShell%202/image022.png)

But the `Get-InjectedThread.ps1` script is able to detect
the injected thread in the notepad process:

![](images/Endpoint%20Interrogation%20PowerShell%202/image023.png)

To run this on a remote system, use `Invoke-Command`
and capture the results in a variable (`$i`):               

```powershell
$i = Invoke-Command -ComputerName <target> -FilePath .\Get-InjectedThread.ps1
```

If the variable is empty, no injected threads were
discovered.

## Volume Shadow Copies

The
[Get-ShadowCopies.ps1]()
script will search a system for volume shadow copies and report the
dates they were created.

Volume Shadow Copies can be used to recover a deleted file or restore
previous versions of files and directories.

To list the available shadow copies on a remote system,
run the script using `Invoke-Command`:

```powershell
Invoke-Command -ComputerName <target> -FilePath .\Get-ShadowCopies.ps1
```

Once you choose a shadow copy instance, log in to the
remote system and create a device object which you can mount to the file
system with a symbolic link:

```powershell
$shadow = Get-WmiObject Win32_ShadowCopy | ? {$_.ID -eq '{xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}'}
$device = $shadow.DeviceObject + "\"
cmd /c mklink /d C:\ShadowCopy "$device"
```

Now the shadow copy of the system's C drive which was created on that
date (10/21) can be browsed using both the GUI and command line:

To remove the mounted Shadow Copy:

```powershell
cmd /c rmdir C:\ShadowCopy
```
