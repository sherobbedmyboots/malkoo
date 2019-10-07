<#
.EXAMPLE
   .\Get-IncSens.ps1 -year 2016 -type 1 -list
   .\Get-IncSens.ps1 -year 2017 -month 02 -type 3 -download
 
.SYNOPSIS
List or download all EOC SENs and INCs for chosen year and category
 
.DESCRIPTION
This logs into EOC Online and uses its search function to list INCs and SENs.
If the -download switch is used, the PDFs for each SEN/INC are downloaded into the current directory.
 
SEN/INC Categories:
 
1   Malicious Logic
2   Misuse
3   Unauthorized Access (Intrusion)
4   Denial of Service (DoS)
5   Probes and Reconnaissance Scans
6   Classified Computer Security Incident
7   Alteration/Compromise of Information
8   Non-Incident
9   Investigation-Unconfirmed
 
Use PowerShell SecureString to store EOC username and password in ~\.user.txt and ~\pass.txt files.
 
To store passwords using SecureString:
 
"<username>" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File -Append "~\.user.txt"
"<password>" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File -Append "~\.pass.txt"
#>
 
param
(
    [string]$year,
    [string]$month,
    [string]$type,
    [switch]$download,
    [switch]$list
)
 
function checkargs{
    if ($month){
        if ((!(($month.ToString()).length -eq 2))){
            Write-Host "`nYou must enter months using two digit format:   January --> 01, February --> 02`n"
            exit
        }
    }
    if (!(($year.ToString()).length -eq 4)){
        Write-Host "`nYou must enter years using four digit format:   2015, 2016, etc.`n"
        exit
    }
    if (!($list -or $download)){
        Write-Host "`nYou must choose to list (-list) or download (-download) the SEN/INCs`n"
        exit
    }
}
 
function getcreds{
    [hashtable]$creds =@{}
    $usernamefile = "~\.user.txt"
    $passwordfile = "~\.pass.txt"
    $u = (gc $usernamefile | ConvertTo-SecureString)
    $p = (gc $passwordfile | ConvertTo-SecureString)
    $creds.username = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($u))
    $creds.password = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($p))
    return $creds
}
 
function Get-IncList
{
    $incsearchbody = "q%24inc_year=" + $year + "&q%24inc_month=" + $month
    $incsearchuri = "https:// "
    $incsearchheaders= @{
        "Host" = ""
        "Origin" = "https:// "
        "Upgrade-Insecure-Requests" = "1"
        "User-Agent" = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36"
        "Content-Type" = "application/x-www-form-urlencoded"
        "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        "Referer" = ""
        "Accept-Encoding" = "gzip, deflate, br"
        "Accept-Language" = "en-US,en;q=0.8"
    }
 
    $x = iwr -uri $incsearchuri -method POST -body $incsearchbody -headers $incsearchheaders -websession $sessiontouse
  
    # Build INC list
    $inclist = @()   
    [array]$regmatches = sls 'href.*[\d]{4}-[\d]{2}-[\d]{3}' -input $x.content -AllMatches  | %{$_.matches.value} | Get-Unique
 
    if ($regmatches){
        $regmatches | foreach{
            $tempf = 'INC' + ($_.split('>'))[1]
            $templ = ($_.split('"'))[1] -replace ("amp;", "")
            $inclist += New-Object -TypeName psobject -Property @{PdfLink=$templ; PdfName=$tempf}
        }
    }
   
    # List or Download
    if ($list){
        Write-Host -Fore Green "`n[+]"$inclist.length"INCs:"
        if ($inclist){
            $inclist | %{$_.PdfLink='https://' + $_.PdfLink}
        }
        else{
            $inclist += New-Object -TypeName psobject -Property @{PdfName="None"; PdfLink="None"}
        }
        $inclist | select PdfName, PdfLink | ft -auto
    }
 
    if ($download){
        $inclist | foreach {
            $fname = $_.PdfName
            $pname = $fname + '.pdf'
            $puri = '' + $_.PdfLink
            iwr -uri $puri -websession $sessiontouse -O $pname
        }
    }
}
 
function Get-SenList
{
    $sensearchbody = "q%24sen_year=" + $year + "&q%24sen_month=" + $month + ""   
    $sensearchuri = "https:// "
    $sensearchheaders = @{
        "Host" = ""
        # "Connection" = "keep-alive"
        "Cache-Control" = "max-age=0"
        "Origin" = "https:// "
        "Upgrade-Insecure-Requests" = "1"
        "User-Agent" = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36"
        "Content-Type" = "application/x-www-form-urlencoded"
        "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        "Referer" = ""
        "Accept-Encoding" = "gzip, deflate, br"
        "Accept-Language" = "en-US,en;q=0.8"
    }  
    $x = iwr -uri $sensearchuri -method POST -body $sensearchbody -headers $sensearchheaders -websession $sessiontouse
    
    # Build SEN list
    [array]$senmatches += sls '[\d]{4}-[\d]{2}-[\d]{3}' -input $x.content -AllMatches  | %{$_.matches.value} | Get-Unique
    [array]$linkmatches += sls 'sen_id=[\d]{5}' -input $x.content -AllMatches | %{$_.matches.value} | Get-Unique | %{$_.split('=')[1]}
 
    $senlist = @()
    for ($i=0; $i -lt $senmatches.length; $i++) {
        $sen = 'SEN' + $senmatches[$i]
        $link = '' + $linkmatches[$i]
        $senlist += New-Object -TypeName psobject -Property @{PdfName=$sen; PdfLink=$link}
    }
    if ($senlist.length -eq 0){
       
    }
 
   # List or Download
    if ($list)
    {
        Write-Host -Fore Green "[+]"$senlist.length"SENs:"
        if ($senlist){
            $senlist | %{$_.PdfLink = 'https://' + $_.PdfLink}
        }
        else{
            $senlist += New-Object -TypeName psobject -Property @{PdfName="None"; PdfLink="None"}
        }  
        $senlist | select PdfName, PdfLink | ft -auto
    }
    if ($download)
    {
        $senlist | foreach {
            $fname = $_.PdfName
            $pname = $fname + '.pdf'
            $puri = 'https://' + $_.PdfLink
            iwr -uri $puri -websession $sessiontouse -O $pname
        }
    }
}
 
function authenticate($creds)
{
    $uri =
    $uri1 =
    $headers1 = @{
        "Host" =
        "User-Agent" = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6)"
        "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        "Accept-Language" = "en-US"
        "Accept-Encoding" = "gzip, deflate, br"
        "Referer" =
    }
    $body = @{
        "username" = $creds.username
        "password" = $creds.password
    }
    # First request to get cookie
    $request = iwr -uri $uri -sessionvariable websession
    $sessiontouse = $websession
    # Authenticate
    $firstpage = iwr  -uri $uri1 -headers $headers1 -body $body -method POST -websession $sessiontouse
    return $sessiontouse    
}
 
function Get-IncSens
{
    checkargs
    [hashtable]$creds = getcreds
    $sessiontouse = authenticate($creds)
    Get-IncList
    Get-SenList
}
Get-IncSens -year $year -month $month -type $type