<# 
* Compromised Site    colddistance.com       -->   54.183.24.66
* C2 Staging          sadeyedlady.com        -->   13.57.142.226                    
* C2 Operations       cdn.az.gov             -->   sadeyedlady.com       -->     13.57.142.226
* C2 Persistence      concretebeard.com      -->   54.177.129.201        -->     13.57.142.226
                        # 54.153.96.177 
                        # 13.56.28.226 
sudo iptables -I INPUT -p tcp -m tcp --dport 443 -j ACCEPT
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 13.57.142.226:443
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
sudo iptables -I FORWARD -j ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo sysctl net.ipv4.ip_forward=1
sudo certbot --apache --register-unsafely-without-email
# create
docker pull empireproject/empire
docker run -ti empireproject/empire
# drop into bash
docker run -ti --entrypoint bash empireproject/empire
# maintain persistence
docker create -v /opt/Empire --name data empireproject/empire
docker run -ti --volumes-from data empireproject/empire
docker run -ti --volumes-from data -p 10.0.0.207:80:80 empireproject/empire
#>
Param ($File)
 
Function Convert-ToMarkdown ( $File )
{
    $basename = (ls $File).basename
    $withspaces = $basename.replace("_"," ")
    $urlencoded = $withspaces.replace(" ","%20")
   
    $content = (gc $File -encoding UTF8) -replace "(^\d\.)(\s+)",'$1 '
    $content = $content -replace "(^\-)(\s+)",'$1 '
    $content = $content -replace "(^o)(\s+)",'    - '
    $content = $content -replace "(cid:\w+\d+\.\w{3}\@.*)","](images/$urlencoded/image001.png)"
    $content = $content -replace "\n",""
    $content = $content -replace '^height.*',""
    $content = $content -replace "\\_","_"
    $content = $content -replace "\\-","-"
    $content = $content -replace "\\<","<"
    $content = $content -replace "\\>",">"
    $content = $content -replace "\*\*","``"
    $content = $content -replace "\\\[","\["
    $content = $content -replace "\\\]","\]"
    $content = $content -replace "\\\$","\$"
    $content = $content -replace "\\~","~"
    $content = $content -replace "\\\\","\\"
    $content = $content -replace "\\\|","\|"
 
    $filename = $withspaces + '.md'
    $content | Out-File $filename
       
}
Convert-ToMarkdown -File $File