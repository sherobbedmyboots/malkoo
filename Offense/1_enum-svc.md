# Enumerate Services

- [FTP](#ftp)
- [SSH](#ssh)
- [SMB](#smb)
- [SNMP](#snmp)
- [RPC](#rpc)
- [SMTP](#smtp)
- [IMAP](#imap)
- [MOUNTD](#mountd)
- [NFS](#nfs)
- [POP3](#pop3)
- [HTTP/S](#http/s)
- [MSSQL](#mssql)
- [MYSQL](#mysql)
- [ORACLE](#oracle)
- [RDP](#rdp)
- [VNC](#vnc)


## FTP

nmap -sV -Pn -vv -p 21 --script=ftp-* $ip

## SSH

nmap -sV -Pn -vv -p 22,2200 --script=ssh* $ip

## SMB

nmap -v -p 139,445 --script=smb-check-vulns $ip

enum4linux -v $ip

python /usr/share/doc/python-impacket/examples/samrdump.py $ip

export SMBHASH=<hash value> && pth-winexe -U backup% //$ip cmd 
     
login with PTH-WINEXE

winexe -U backup //$ip cmd

wmiexec.py user:password@$ip

smbclient -L \\$ip -N

## SNMP

for x in $(seq 200 254); do echo $192.168.15.$x; done > ips.txt && onesixtyone -c strings.txt -i ips.txt

snmpwalk -c public -v1 $ip

nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-* $ip

## RPC

nmap -v -p 135,1025 --script=rpc-* $ip

## SMTP

nmap -vv -sV -Pn -p 25 --script=smtp* $ip

## IMAP

nmap -vv -sV -Pn -p 143,220 --script=imap* $ip

## MOUNTD

## NFS

nmap -p 111 --script nfs-showmount,nfs-ls $ip

## POP3

nmap -vv -sV -Pn -p 110 --script=pop3* $ip

## HTTP/S

nmap -sV -Pn -vv -p 80,3339,7778,8080 --script=http-* $ip

nmap -sV -Pn -vv -p 443 --script=ip-https-* $ip

nmap -p 443 --script ssl-heartbleed $site

heartbleed.py $site | less

strings dump.bin

## MS-SQL

nmap -vv -sV -Pn -p 1433,1434 --script=ms-sql-* $ip

nmap -p1433 --script=ms-sql-brute -script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt $ip

## MY-SQL

nmap -w -sV -Pn -p 3306 --script=mysql-* $ip

## ORACLE

nmap -Pn -p 1038,1521,1748,1754,1808,1809,2030,2100,3339,4443,7778,8080 --script=oracle-* $ip

## RDP

nmap -v -p 3389 --script=rdp-* $ip

## VNC

nmap -sV -Pn -vv -p 5800,5900 --script=realvnc-* $ip

nmap -sV -Pn -vv -p 5800,5900 --script=vnc-* $ip

