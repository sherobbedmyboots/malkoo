# Privilege Escalation in Windows

The majority of client side attacks fall into the following two
categories:

- Exploit - Application is exploited such as the browser, Java, PDF reader, or MS Office

- Social Engineering - User is tricked into running malicious Java applet, macro, executable, hta, script, etc.
                    

In both cases, either a user or an application runs the malicious code
on the system.  If the code executes successfully, the attacker will be
able to run commands on the system within the context of the user or
application, which most of the time will be as a regular user without
administrative privileges.  After this initial compromise, the attacker
will most likely begin looking for opportunities to become an
administrative user in order to obtain complete control over the victim
machine.  This process is called privilege escalation.

In modern Windows systems, processes run at three different integrity
levels:

|||
|-|-|
|High|Administrator|
|Medium|Standard|
|Low|Restricted                          

In each of these examples, a compromised account is used to exploit a
vulnerability in order to escalate integrity levels.

- [Unquoted Service Paths](#unquoted-service-paths)
- [DLL Order Hijacking](#dll-order-hijacking)
- [Auto-Elevation](#auto-elevation)


## Unquoted Service Paths

On a Windows 10 VM, I configured one of the services to simulate a
vulnerable service having an unquoted path, then searched all services
to find it:

![](images/Privilege%20Escalation%20in%20Windows/image001.png)


Notice the path to the binary for the first service, AdobeARMService,
the Adobe Acrobat Update Service, is not enclosed in quotes.

Because of this, the service path can be hijacked and made to run a
binary that the attacker chooses.

First, a malicious executable is generated with Metasploit that's made
to create a new user account "eviladmin" and add it to the local
Administrators group.

The executable is renamed `Common.exe` and placed in a higher directory
within the service's binary path that contains spaces.  In this case
we're exploiting the space in the directory `Common Files`:

![](images/Privilege%20Escalation%20in%20Windows/image002.png)


The service is then stopped and started so it will be forced to perform
a new search for its binary.  If the user doesn't have permissions to
change the state of the service, another option is rebooting the system
which will also force a new search for the binary:

![](images/Privilege%20Escalation%20in%20Windows/image003.png)


Now when the Adobe ARM Service is started, it will first search for
`C:\Program.exe`... when nothing is found it will then search `C:\Program
Files\Common.exe` and if there will execute it.

Since the service is running with SYSTEM privileges, the executable runs
with SYSTEM privileges, creates the account, and adds it to the
Administrators group:

![](images/Privilege%20Escalation%20in%20Windows/image004.png)


![](images/Privilege%20Escalation%20in%20Windows/image005.png)


## DLL Order Hijacking

If a program's file path has weak file or folder permissions, an
attacker can force the program to load a malicious DLL.

For example, an attacker can place a malicious DLL in one of several
different places and it may be found and loaded by a vulnerable program:

Windows (32 bit) first searches for "known DLLs", such as Kernel32.dll
and User32.dll, then it searches in the following order:

1. The directory from which the application loaded

2. 32-bit System directory (`C:\Windows\System32`)

3. 16-bit System directory (`C:\Windows\System`)

4. Windows directory (`C:\Windows`)

5. The current working directory (CWD)

6. Directories in the PATH environment variable (system then user)


To simulate this attack, first a malicious DLL is generated with Metasploit or similar framework
and configured to send a Meterpreter shell to the attacker's machine.

Now we need to find a vulnerable program---one which will load our DLL
and uses a directory we can write to.

The first part can be performed with Process Monitor by filtering the
results with following two rules:


	Path     ENDS WITH   .dll
	Result   IS          NAME NOT FOUND


This will return programs that are attempting to load DLLs but are
unable to find them:

![](images/Privilege%20Escalation%20in%20Windows/image006.png)


Here is a good candidate as non-default directories in `C:\` give write
access to authenticated users:

![](images/Privilege%20Escalation%20in%20Windows/image007.png)


The second part can be performed with icacls which shows Authenticated
Users have Modify Access (M) permissions to the folder:

![](images/Privilege%20Escalation%20in%20Windows/image008.png)


The malicious DLL is then placed in the folder:

![](images/Privilege%20Escalation%20in%20Windows/image009.png)


And when the program is started, it finds the kernel.dll it was looking
for and loads it.  If the program is running in an Administrators
context, the attacker now has administrative privileges on the machine:

![](images/Privilege%20Escalation%20in%20Windows/image010.png)


Process Hacker confirms the process is running in a High context:

![](images/Privilege%20Escalation%20in%20Windows/image011.png)


And the attacker can verify he has all administrative privileges:

![](images/Privilege%20Escalation%20in%20Windows/image012.png)


## Auto-Elevation

There are various ways to get a program to run in an elevated
context---one of these is the presence of the AlwaysInstallElevated
registry keys.

If the following keys are present on the system and their value is "1",
all programs are installed in an elevated context:

```powershell
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

For this example, they are present on our system:

![](images/Privilege%20Escalation%20in%20Windows/image013.png)


For this example, a malicious install package was created
(`New_Program.msi`) that will open a command shell on port 4444 on the
local system.  Since it will be installed with administrative
privileges, the shell will also have administrative privileges.

To replicate this scenario, you'll need to enable UAC on the host using
`secpol.msc`:

- Type `WindowsKey + x` and select "Run"

- Enter `secpol.msc` and click "OK"

- Go to Local Policies --> Security Options --> User Account Control: Use Admin Approval Mode for the built-in Administrator Account --> Enable

- Go to Local Policies --> Security Options --> User Account
Control: Run all Administrators in Admin Approval Mode --> Enable

- Then reboot

Now the malicious package is moved to the victim machine and installed
with a quiet option.

Notice the user's `cmd.exe` is at medium integrity, but the
`New_Program.exe` runs at high integrity (with SYSTEM privileges):

![](images/Privilege%20Escalation%20in%20Windows/image014.png)


Checking the listening ports shows port 4444 is open:

![](images/Privilege%20Escalation%20in%20Windows/image015.png)


And when the attacker connects to it with `netcat`, it produces a shell
with SYSTEM privileges:

![](images/Privilege%20Escalation%20in%20Windows/image016.png)

