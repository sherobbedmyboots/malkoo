<# 

* Compromised Site    colddistance.com       -->   54.183.24.66
* C2 Staging          sadeyedlady.com        -->   13.57.142.226                    
* C2 Operations       cdn.az.gov             -->   sadeyedlady.com       -->     13.57.142.226
* C2 Persistence      concretebeard.com      -->   54.177.129.201        -->     13.57.142.226


                        # 54.153.96.177 
                        # 13.56.28.226 



iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination <REMOTE-HOST-IP-ADDRESS>:80
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -I FORWARD -j ACCEPT
iptables -P FORWARD ACCEPT
sysctl net.ipv4.ip_forward=1



sudo certbot --apache --register-unsafely-without-email



#>

Param ($File)
 
Function Convert-ToMarkdown ( $File )
{
    $content = (gc $File -encoding UTF8) -replace "(^\d\.)(\s+)",'$1 '
    $content = $content -replace "(^\-)(\s+)",'$1 '
    $content = $content -replace "(^o)(\s+)",'    - '
    $content = $content -replace "(cid:\w+\d+\.\w{3}\@.*)","![](images/$File/image001.png)"
    $content = $content -replace "\n",""
    $content = $content -replace '\u00E0','-->'

    $content | Out-File ".\New-File.md"
        
}
Convert-ToMarkdown -File $File