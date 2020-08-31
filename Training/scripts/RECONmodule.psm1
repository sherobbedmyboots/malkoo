function Add-ToArray {

    param (
        [string]$http           = '-',
        [string]$org            = '-',
        [string]$InternalIp     = '-',
        [string]$category       = '-',
        [string]$name           = '-',
        [string]$address        = '-',
        [array]$path            = '-',
        [string]$https          = '-',
        [array]$logging         = '-',
        [string]$df             = '-',
        [string]$ver            = '-',
        [string]$hhr            = '-'
    )

    New-Object -TypeName psobject -Property @{
        HTTP        = $http;
        Org         = $org;
        InternalIp  = $internalip;
        Category    = $category;
        Name        = $name;
        Address     = $address;
        Path        = $path;
        HTTPS       = $https;
        Logging     = $logging;
        DF          = $df;
        VER         = $ver;
        HHR         = $hhr;
    }
}

$proxy_list = $proxy | %{Get-DomainIpOrg $_}
$asa_list = $asa | %{Get-DomainIpOrg $_}

$asa_list | %{$_.HTTPS="Unknown"}
$asa_list | %{$_.HTTP="Unknown"}
$asa_list | %{if ($403.contains($_.Name)){$_.HTTPS="403"}}
$asa_list | %{if ($302.contains($_.Name)){$_.HTTPS="302"}}
$asa_list | %{if ($200.contains($_.Name)){$_.HTTPS="200"}}
$asa_list | %{if ($http302.contains($_.Name)){$_.HTTP="302"}}

$asa_list | %{if ($asa_ips.contains($_.Name)){$_.InternalIp=$($asa_ips.Item($_.Name))}}

$proxy_list | %{if ($ppoe.contains($_.Name)){$_.Category="+ + O E"}}
$proxy_list | %{if ($ppve.contains($_.Name)){$_.Category="+ + V E"}}
$proxy_list | %{if ($ppvi.contains($_.Name)){$_.Category="+ + V I"}}
$proxy_list | %{if ($mpvi.contains($_.Name)){$_.Category="- + V I"}}
$proxy_list | %{if ($mmvi.contains($_.Name)){$_.Category="- - V I"}}
$proxy_list | %{if ($mpve.contains($_.Name)){$_.Category="- + V E"}}

$proxy_list | Select Category,Name,Address,Org

# "(\.search\.msn\.com$)|(\.internet\-census\.org$)(\.shodan\.io$)|(\.censys\.io$)"


$wc = New-Object Net.WebClient
$wc.Headers['User-Agent']="xxxxxx"
$wc.DownloadString('https://xxxxxx')

#>

function Get-Headers {

    param(
      [Parameter(ValueFromPipeline=$true)]
      [string] $Url
    )
    $request = [System.Net.WebRequest]::Create( $Url )
    $headers = $request.GetResponse().Headers
    $headers.AllKeys |
         Select-Object @{ Name = "Key"; Expression = { $_ }},
         @{ Name = "Value"; Expression = { $headers.GetValues( $_ ) } }
}



function Get-ShodanDomainInfo {

    param($domain)

    $erroractionpreference = 'SilentlyContinue'
    $ip = getIp $domain 
    
    if ($ip -match '^192\.168\.|^10\.|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)'){
        $vulns = "n/a"
    }

    else {
        $vulns = ((Get-ShodanHostService -IPAddress $ip 2>$null).Data.vulns | gm -MemberType NoteProperty).Name
        $vulns = $vulns -join(', ')
    }

    $res = New-Object -TypeName psobject -Property @{
        Domain      = $domain;
        Address     = $ip;
        Vulns       = $vulns;
    }
    $res | Select Domain,Address,Vulns | ft -auto 
}

function getIp {

    param ($hname)

    try {
        $response = [System.Net.Dns]::GetHostAddresses($hname).IPAddressToString 2>$null
    }
    catch {
        $response = "none"
    }
    $response
}

function Get-DomainIpOrg {

    param([string]$domain)

    $a = Resolve-NameExt $domain
    $a | %{
        if ($_.Address){

            if ($_.Address.Count -gt 1){
                $_.Address = $_.Address[0]
            }
            
            $check = Get-FinalDestination $_.Name 
            if (($check) -and ($check -ne $_.Address)){
                $_.Address = $check 
            } 

            $b = (Get-WHOISDazzle $_.Address).organization
            $_ | Add-Member -NotePropertyName Org -NotePropertyValue $b

        }
        else {
            $_.Address = "N/A"
            $_ | Add-Member -NotePropertyName Org -NotePropertyValue "N/A"
        } 
    }
    $a
}

function Resolve-NameExt {
    param (
        [string]$name,
        [switch]$whois
    )
    $u = "https://cloudflare-dns.com/dns-query?name=$name"
    $h = @{'accept'='application/dns-json'}
    $a = (irm -Headers $h -Uri $u).Answer | ? data -match '^\d'
    
    New-Object -TypeName psobject -Property @{
        Name      = $name;
        Address   = $a.data
    }

}

function Add-IpObject {
    param (
        [psobject]$o
    )

    try {
        $ip = [ipaddress]$($o.Address)
    }
    catch {
        $ip = 'N/A'
    }     
    $o | Add-Member -NotePropertyName IpAddress -NotePropertyValue $ip -Force 

}

function Add-HostCategory {
    param (
        [array]$HostList,
        [psobject]$ObjectList,
        [string]$category
    )

    Foreach ($o in $ObjectList){
        if ($HostList.contains($o.Name)){
            $o | Add-Member -NotePropertyName Category -NotePropertyValue $category -Force
        }
    }
}


function Get-FinalDestination {
    param([string]$domain)

    $domain = 'https://' + $domain
    try {
        $r = iwr $domain -MaximumRedirection 0 -ErrorAction SilentlyContinue
        if ($r.Headers.Location) {
            $newurl = $r.Headers.Location
            $a = $newurl.split('/')[2]
            $b = (Resolve-NameExt $a).Address  
            if ($b.Count -gt 1){
                $b = $b[0]
            }
            return $b
        } 
    }
    catch {} 
}

function Get-ReverseLookup {

    param([string]$ip)

    $names = (irm -Uri https://freeapi.robtex.com/ipquery/$ip).pas
    if ($names.count -gt 1){
            $name = (($names| Sort t)[-1]).o
    }
    else {
        $name = $names.o
    } 
    $name
}


function Get-IpPassiveDns ($ip) {
    $u = "https://freeapi.robtex.com/ipquery/$ip"
    $pdns = (irm -Uri $u).pas
    foreach ($p in $pdns){
      $time = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
      $time = $time.AddSeconds($p.t)
      $p | Add-Member -NotePropertyName Time -NotePropertyValue $time
      $p | Add-Member -NotePropertyName Name -NotePropertyValue $p.o
    }
    $pdns | Select Name,Time | Sort -Desc Time
}

function Get-WHOISDazzle ($ip) {
  $h = @{'accept'='application/json'}
  $u = "http://dazzlepod.com/ip/$ip.json"
  irm -Headers $h -Uri $u -UserAgent 'xxxxxx'
}

function Get-WHOISData ($ip) {
    $h = @{'accept'='application/json'}
    $u = "https://whois.arin.net/rest/ip/$ip"
    (irm -Headers $h -Uri $u -UserAgent 'xxxxx').net
}


function Get-HostInfo {

    param (
        [cmdletbinding()]
        [parameter(ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [string]$hname
    )

    $ip = getIp $hname
    if ($ip -match '^192\.168\.|^10\.|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)'){
        $int_ip = $ip
    }
    else {
        $ext_ip = $ip
    }

    if ($ip -eq "none"){
        $cert = "none"
    }
    else {
        $cert = getCert $ip
    }

    if (!($ext_ip)) {
        $ext_ip = $cert.IP
    }

    if ($ext_ip -match '^192\.168\.|^10\.|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)'){
        $ext_ip = "none"
    }

    $info = New-Object -TypeName psobject -Property @{
        Hostname = $hname
        IntAddress  = $int_ip
        ExtAddress  = $ext_ip
        Certificate = $cert
    }
    $info
}

function getCert {

    param (
        [string]$ip,

        [switch]$obj
    )
    
    $uri = "https://$ip"
    $request = [System.Net.HttpWebRequest]::Create($uri)
    $request.KeepAlive = $False
    $request.UserAgent = "xxxxxx"
    $request.UseDefaultCredentials = $true 

    try { $vv = ($request.GetResponse().Headers).GetValues('Server') }
        catch  { $vv=@('none') }
    
    try { $request.GetResponse().Dispose() 
          $cert = $request.ServicePoint.Certificate
          $site = $cert.Subject.split(',')[0].trim('CN=')
          $expd = $cert.GetExpirationDateString()
          $effd = $cert.GetEffectiveDateString()
    }
    catch {        
        $site = 'none'
        $cert = 'none'
        $expd = 'none'
        $effd = 'none'
    }

    $request=''

    try {
        $resp = New-Object -TypeName psobject -Property @{
            IP      = $ip
            Site    = $site
            Cert    = $cert
            ExpDate = $expd
            EffDate = $effd
            Version = $vv[0]
        }
        
        if ($obj){
            return $resp
        }
        
        else {
            Write-Host `n"Destination Site"`t $($resp.Site)
            Write-Host "Effective Date"`t`t $($resp.EffDate)
            Write-Host "Expired Date"`t`t $($resp.ExpDate)
            Write-Host "Server Version"`t`t $($resp.Version)

            Write-Host `n"[+] Certificate saved as `$cert variable"`n
            $global:cert = $resp
        }
    }
    catch {}   
}

Function Get-PassiveTotalWhois {

    param (
        [string]$query,

        [string]$username,

        [string]$api
    )

    $pair = "${username}:${api}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"
    $uristring = "https://api.passivetotal.org/v2/whois?query=$query"
    $headers = @{ Authorization = $basicAuthValue;
                  ContentType  = "application/json" 
                }
            
    $data = irm -proxy http://10.10.10.10 -uri $uristring -useragent 'xxxxxx' -method GET -headers $headers

    $a = New-Object -TypeName psobject -Property @{
            Address=$query;
            Email=$data.contactEmail;
            AdminName=$data.admin.name;
            Telephone=$data.admin.telephone;
            Organization=$data.organization;
            OrganizationName=$data.name;
    }
    $a
}

Function Get-LastIp {

    param (
        [string]$hhost,

        [string]$username,

        [string]$api
    )

    $pair = "${username}:${api}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"
    $uristring = "https://api.passivetotal.org/v2/dns/passive?query=$hhost"
    $headers = @{ Authorization = $basicAuthValue;
                  ContentType  = "application/json" 
                }
            
    $data = irm -proxy http://10.10.10.10 -uri $uristring -useragent 'xxxxxx' -method GET -headers $headers
    
    $last = $data.results | Sort -desc LastSeen | Select -First 1

    $a = New-Object -TypeName psobject -Property @{
            Host=$last.value;
            LastSeen=$last.lastSeen;
            Address=$last.resolve;
    }
    $a
}

function checkMemory ($hname) {
    <#
    .SYNOPSIS
    Determines if a host has an injected process
    using Get-InjectedProcess.ps1
    #>
    if (($hname -eq "HostNotOnline") -or ($hname -eq "PortNotResponding") -or ($hname -eq "HostnameNotFound")) {
        return "IpWasNotResolved"
    }
    else {
        $result = @()
        $hit = Invoke-Command -Filepath \scripts\Get-InjectedThread.ps1 -ComputerName $hname -ErrorAction SilentlyContinue
        $hit | % {
            $result += $_.ProcessName 
        }
        if (!($result)) {
            return "NoInjectionFound"
        }
        return $result
    }
}

function getInjectionIp ($ip) {
    <#
    .SYNOPSIS
    Determines if an IP has an injected process 
    by obtaining the hostname and using Get-InjectedProcess.ps1
    #>
    $hname = resolveAddress $ip
    $result = checkMemory $hname
    if ($result -eq "NoInjectionFound") {
        Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $ip `t$hname `t`t"No injection found"
    }
    elseif ($result -eq "IpWasNotResolved") {
        Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $ip `t$hname `t`t"IP was not resolved"
    }
    else {
        Write-Host -Fore Green "[+] " -NoNewLine;Write-Host $ip `t$hname `t`t$result
    }
}

function getInjectionHost ($hname) {
    <#
    .SYNOPSIS
    Determines if an IP has an injected process 
    by obtaining the hostname and using Get-InjectedProcess.ps1
    #>
    $result = checkMemory $hname
    if ($result -eq "NoInjectionFound") {
        Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $ip `t$hname `t`t"No injection found"
    }
    elseif ($result -eq "IpWasNotResolved") {
        Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $ip `t$hname `t`t"IP was not resolved"
    }
    else {
        Write-Host -Fore Green "[+] " -NoNewLine;Write-Host $ip `t$hname `t`t$result
    }
}

function getPostExpModules {
    <#
    .SYNOPSIS
    Checks Windows PowerShell logs for 600 Events 
    that contain a specific base64-encoded string
    and lists time and command run
    #>
    $logs = Get-WinEvent -filterhashtable @{logname="Windows PowerShell";id=600} | ?{$_.properties[2].Value -match 'LgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOg'}
    $a = @()
    foreach ($log in $logs) {
        $command = $log.properties[2].Value | sls 'HostApplication=.*\x0D\x0A' | %{$_.Matches} | %{($_.Value -split('='))[1]}
        $base64 = $command.split(' ')[-1]
        $base64 = $base64 -replace '(?:\s|\r|\n)',''
        if (!($base64.length % 4 -eq 0)) {
            $base64 += '=='
        }
        $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
        $timestamp = $log.TimeCreated
        $decoded = $decoded.split(';')[1]

        $a += New-Object -TypeName psobject -Property @{
                    Time=$timestamp;
                    Command=$decoded;
        } 
    }
    $a | sort -Unique Command
}

function Remove-RegPersistence ($sid) {
    <#
    .SYNOPSIS
    Removes the persistence installed by Install-RegPersistence
    by removing the stored script from $RegPath and removing
    the registry autorun key
    #>
    New-PSDrive HKU Registry HKEY_USERS
    $RegPath = "HKU:\$sid\Software\Microsoft\Windows\Debug";
    $parts = $RegPath.split('\');
    $path = $RegPath.split("\")[0..($parts.count -2)] -join '\';
    $name = $parts[-1];
    $null=Remove-ItemProperty -Force -Path $path -Name $name;
    Remove-ItemProperty -Force -Path HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Run\ -Name Debug;
    Write-Host 'Registry Persistence removed.'
}

function Get-RegPersistence ($sid) {
    <#
    .SYNOPSIS
    Checks if persistence installed by Install-RegPersistence
    #>
    New-PSDrive HKU Registry HKEY_USERS
    $RegPath = "HKU:\$sid\Software\Microsoft\Windows\Debug";
    $parts = $RegPath.split('\');
    $path = $RegPath.split("\")[0..($parts.count -2)] -join '\';
    $name = $parts[-1];
    Get-ItemProperty -Path $path -Name $name;
    Get-ItemProperty -Path HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Run\ -Name Debug;
}



function resolveAddress ($ip) {
    <#
    .SYNOPSIS
    Resolves an IP address by checking the web
    page on port 8081 and parsing the results
    #>
    if (!(Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue 2>$null)) {
        return "HostNotOnline"
    }

    if (!((New-Object  System.Net.Sockets.TcpClient -ArgumentList "$_" , '8081').Connected -eq 'True')) {
        return "PortNotResponding"
    }

    try {
        $answer = (Invoke-RestMethod $("http://" + $ip + ":8081/AgentLog.json?t=1522768918409")).AgentHostName | Select-Object -first 1
        return $answer
    }
    catch {
        return "HostnameNotFound"
    }
}



# Export these functions
$funcs =  @('Get-ShodanDomainInfo'
            'Get-HostInfo'
            'getIp'
            'getCert'
            'checkMemory'
            'getInjectionHost'
            'getInjectionIp'
            'getPostExpModules'
            'Remove-RegPersistence'
            'Get-RegPersistence'
            'resolveAddress'
            'Get-LastIp'
            'Get-PassiveTotalWhois'
            'Resolve-NameExt'
            'Get-IpPassiveDns'
            'Get-WHOISData'
            'Get-WHOISDazzle'
            'Get-DomainIpOrg'
            'Get-FinalDestination'
            'Add-ToArray'
            'Get-Headers')

Export-ModuleMember -Function $funcs
