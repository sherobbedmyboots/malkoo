# Privilege Escalation on macOS
 
 
The majority of client side attacks fall into the following two categories:
 
| | |
|-|-|
|Exploit|Application is exploited such as the browser, Java, PDF reader, or MS Office|
|Social Engineering|User is tricked into running malicious Java applet, macro, executable, hta, script, etc.|                      
 
In both cases, either a user or an application runs the malicious code on the system.  If the code executes successfully, the attacker will be able to run commands on the system within the context of the user or application, which most of the time will be without administrative privileges.  After this initial compromise, the attacker will most likely begin looking for opportunities to become an administrative user in order to obtain complete control over the victim machine.  This process is called privilege escalation.
 
This week we’ll look at three common ways an attacker could obtain privilege escalation on a Mac and how these techniques can be identified in the system logs:
 
- [Sudo Commands](#sudo-commands)
- [SUID and SGID Permissions](#suid-and-sgid-permissions)
- [Wildcards](#wildcards)
 
I created a low privilege account for these exercises named ‘low-priv-user’ with the following commands:
 
```bash
sudo dscl . –create /Users/low-priv-user
sudo dscl . –create /Users/low-priv-user UserShell /bin/bash
sudo dscl . –create /Users/low-priv-user RealName “Low Priv”
sudo dscl . –create /Users/low-priv-user UniqueID “1010”
sudo dscl . –create /Users/low-priv-user PrimaryGroupID “80”
sudo dscl . –create /Users/low-priv-user NFSHomeDirectory /Users/low-priv-user
sudo dscl . –passwd /Users/low-priv-user <password>
``` 
 
## Sudo Commands
 
The sudo command stands for “superuser do” and is used by non-privileged user accounts to execute a command in an elevated context. 
 
The commands that are allowed to be called with sudo are listed in the sudoers file located at `/etc/sudoers`.
 
The format used is:

`user <hosts>=(<users>:<groups>) <commands>`
 
Groups are preceded with a percent sign:

`%admin ALL=(ALL:ALL) ALL`
 
So the following line placed in `/etc/sudoers` would allow jdeere to execute any command using sudo:

`jdeere  ALL=(ALL:ALL) ALL`
 
But we are only allowing the lowprivuser account to use sudo with certain commands.  You can see a user’s allowed sudo commands by typing `sudo -l`.
 
![](images/Privilege%20Escalation%20on%20macOS/image001.jpg) 
 

### Privilege Escalation with Sudo
 
Sudo commands that contain parameters for execution can be used to create a root shell.  A root shell prompt contains the “#” symbol while a non-root shell prompt contains the “$” symbol.
 
In each one of these examples, lowprivuser is using sudo to run the program in an elevated context (as root) and is using that program to spawn a command shell which is also created in an elevated context:
 
 
Find: `sudo find /tmp -exec bash -i \;`

![](images/Privilege%20Escalation%20on%20macOS/image002.jpg) 


Awk: `sudo awk 'BEGIN {system("/bin/sh")}'`

![](images/Privilege%20Escalation%20on%20macOS/image003.jpg) 


Vim: `sudo vim`, `:shell`

![](images/Privilege%20Escalation%20on%20macOS/image004.jpg) 
 
         
Vi: `sudo vi`, `:shell`

![](images/Privilege%20Escalation%20on%20macOS/image005.jpg) 
 
More/Less: `sudo more long_file.txt`, `!bash` OR `sudo less long_file.txt`, `!bash`
 
![](images/Privilege%20Escalation%20on%20macOS/image006.jpg)  


Python: `sudo python –c ‘import pty;pty.spawn(“/bin/sh”)’` OR `sudo python –c “import os;os.system(‘/bin/sh”)’`

![](images/Privilege%20Escalation%20on%20macOS/image007.jpg) 

Perl: `sudo perl –e ‘exec “/bin/sh”;’`

![](images/Privilege%20Escalation%20on%20macOS/image008.jpg) 

Ruby: `sudo ruby –e ‘exec “/bin/sh”’`

![](images/Privilege%20Escalation%20on%20macOS/image009.jpg) 

 
 
 
### Evidence of Privilege Escalation
 
MacOS Sierra (10.12) introduces Unified Logging which stores the logs in binary format and must be accessed using the “log” command.
 
To find these events in the logs, we use the log command and specify the style (syslog), process (sudo), and timeframe (last hour):

![](images/Privilege%20Escalation%20on%20macOS/image010.jpg)  
 
We can see the account low-priv-user successfully launched several commands as the root user.
 
 
 
 
## SUID and SGID Permissions
 
Another common way to escalate privileges on a Mac is by using SUID (SetUID) and SGID (SetGID) executables. 
 
Normally when a user executes a program, that program runs in the context of the user having the same permissions as the user.  If an executable has SUID permissions, a non-privileged user can execute it in the context of the owner of the program.  If the executable has SGID permissions, a non-privileged user can execute it in the context of the group.
 
A file’s permissions are represented by 10 characters:
 
You can see these by typing `ls –l <filename>`:

![](images/Privilege%20Escalation%20on%20macOS/image011.jpg)  
 
The second, third, and fourth characters `rw-` represent Read, Write, and Execute permissions for the file owner.  
 
The fifth, sixth, and seventh characters `r--` represent Read, Write, and Execute permissions for the file group.  
 
The eighth, ninth, and tenth characters `r--` represent Read, Write, and Execute permissions for others, or everyone else.  
 
 
Here we can see that the `/etc/passwd` file is owned by root, the group is wheel, and the file is readable and writable by the user, and only readable by the group and others.
 
Here are some other examples:
 
| | |
|-|-|
|`-r-xr-xr-x`|means the owner, group, and others can all read and execute|
|`-rwxr-xr-x`|means only the owner can read, write, and execute, group and others can only read and execute|
|`-rw-------`|means only the owner can read and write to it.  Group and others cannot access|
|`-rwsr-xr-x`|Notice the “s” where an “x” usually is… This means when it executes, it executes with the privileges of the owner|
 
 
To see a list of SUID files on the system, type:
 
```bash
find / -perm –u=s -type f 2>/dev/null -exec ls -l {} \;
``` 
 
This searches the entire filesystem for any file with SUID set and executes an `ls –l` (list, long format) on each result.
 
 
SGID is the same but with groups:
 
| | |
|-|-|
|`-r-xr-sr-x`|means when it executes, it executes with privileges of the group|
 
To see a list of these on the system type:
 
```bash
find / -perm -g=s -type f 2>/dev/null -exec ls -l {} \;
``` 
 
 
The problem with these occurs when an attacker finds a way to get an SUID/SGID program to run a command with higher privileges than those of the attacker.
 
This may be a program that was incorrectly given SUID/SGID permissions that could be exploited by an attacker such as:
 
| | |
|-|-|
|`/bin/cp`|could be used to copy any file on the system using root privileges|
|`/bin/mv`|could be used to change or overwrite any file on the system using root privileges|
 
 
 
Another possibility is the attacker could find an insecure program that has the SUID/SGID bit set and exploit it.
 
For example, if an executable runs a command without specifying its full path, the attacker can substitute his own command and make it run within the context of the executable’s owner/group.
 
Let’s review the PATH environment variable:
 
 
The PATH environment variable tells the shell which directories to search for executable files.
 
To see your path, type `$PATH`

![](images/Privilege%20Escalation%20on%20macOS/image012.jpg) 


This shows when an executable is run, the shell will first look in `/usr/local/bin`, then `/usr/bin`, then `/bin`, then `/usr/sbin`, and finally `/sbin`.
 
So when a user types `ifconfig` to see network configurations, the shell looks in all these directories until it finally finds it in the `/sbin` directory:
 
![](images/Privilege%20Escalation%20on%20macOS/image013.jpg)  
 
If we made our own executable named “ifconfig” and added its directory to our path before `/sbin`, the shell would find our new ifconfig first and execute it.
 
For example, type the following to make an ifconfig executable that will echo the phrase “Escalate my privileges!”:
 
```bash
echo ‘echo Escalate my privileges!’ > ifconfig; chmod +x ifconfig
``` 
 
This creates the new file and makes it executable (+x).
 
Normally, we’d need to specify the current directory to execute our new ifconfig file by preceding the filename with “./”
 
```bash
./ifconfig
```

But we don’t need to specify the current directory (.) if we make it the first entry in our PATH variable:
 
```bash
Export PATH=.:$PATH
``` 
 
Now check your path again and notice the first entry:

![](images/Privilege%20Escalation%20on%20macOS/image014.jpg)  
 
This means that the shell will check your current directory for ifconfig first—and will find the new ifconfig before it finds the real ifconfig in `/sbin`.
 
We can verify by using the which command:
 
![](images/Privilege%20Escalation%20on%20macOS/image015.jpg) 
 
And now when we run `ifconfig`, our new file will execute.
 
So if an attacker can find an executable that uses an unspecified path, the current directory can be added to the beginning of the PATH variable to run any file the attacker chooses—in the context of the account the executable is running under.
 
 
### Privilege Escalation with SUID Executable
 
               
Administrative user jdeere has created an SUID executable called “mac-stats” which runs under root and checks various system conditions logging the results to a file.
 
Running strings on the executable reveals the full path of one of the commands used (ifconfig) is not specified:
 
![](images/Privilege%20Escalation%20on%20macOS/image016.jpg)                 
 
Since the executable does not specify the full path of ifconfig, an attacker can create his own ifconfig containing “/bin/bash” and add his current directory to his path:
 
![](images/Privilege%20Escalation%20on%20macOS/image017.jpg)     
 
Then run the executable causing it to run as the root user and run the attacker’s ifconfig which spawns a root shell:
 
![](images/Privilege%20Escalation%20on%20macOS/image018.jpg)                 
               
We don’t see any output from the commands because the program pipes it to the log file, but we know it is a root shell because of the # symbol.
 
Looking at the log shows the outputs of the two commands right after netstat completes:
 
![](images/Privilege%20Escalation%20on%20macOS/image019.jpg)  
 
### Evidence of Privilege Escalation
 
This privilege escalation left very little evidence in the logs.  Examining low-priv-user’s bash history revealed the commands that were run as root:
 
![](images/Privilege%20Escalation%20on%20macOS/image020.jpg) 

But actually exploiting the program and taking over the root account did not create any specific log events.
 
 
 
## Wildcards
 
Using wildcards to pass a command arguments can also be used to obtain root or another user’s privileges.
 
 
### Privilege Escalation with Wildcards
 
For example, Mac user “jdeere” has scheduled an hourly job that runs all the *.sh files in his scripts directory and logs the output in a results file:
 
![](images/Privilege%20Escalation%20on%20macOS/image021.jpg)  
 
Since this cronjob is running as jdeere, if an attacker gets it to run another script or command, it too will run under jdeere.
 
An attacker can simply create his own executable script ending in .sh, place it in the scripts directory, and it will be executed along with the others:
 
![](images/Privilege%20Escalation%20on%20macOS/image022.jpg) 
 
Now when the scheduled job runs, the attacker’s script is run which creates a bind shell on local port 8888.
 
When the attacker connects to it, he is given a shell with the privileges of the jdeere account:
 
![](images/Privilege%20Escalation%20on%20macOS/image023.jpg)  
 
### Evidence of Privilege Escalation
 
Again, this one doesn’t leave many suspicious events in the logs.  We can see the script run right at 09:33 and seconds later the ncat process queries “localhost”:
 
![](images/Privilege%20Escalation%20on%20macOS/image024.jpg)  
 
A script initiating a network connection may be legitimate but we would need to confirm by reviewing each script that was run.
 
Reviewing the compromised account’s bash history reveals a few of the commands he used to perform the attack, but not the commands run as jdeere:
 
![](images/Privilege%20Escalation%20on%20macOS/image025.jpg)  
 
 
## Summary
 
If an attacker gains access to a Mac with insecure programs or configurations, root or another user’s privileges can be quickly obtained with a number of different techniques.
 
Try to replicate these attacks on the macOS VM and see if you can find additional evidence in syslog, bash history, and other event logs.
 
 
 
