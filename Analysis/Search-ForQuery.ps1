<#
 
.DESCRIPTION
    Searches Google with site operator to find source of DNS query
 
.EXAMPLE
    .\Search-ForQuery.ps1 -queriedsite www.sans.org -sitefile sites.txt
#>
 
Param
(
    $queriedsite,
    $sitefile
)
 
Function Search-ForQuery ($queriedsite, $sitefile){
    $a = @() 
    gc $sitefile | foreach{
        $googleresults = irm -uri "http://www.google.com/search?source=hp&q=site%3A$_+%22$queriedsite%22" 
        $hit = $googleresults | sls '<cite>.*</cite>' -AllMatches | %{$_.Matches} | %{$_.Value}
        $value = $hit -replace ("<cite>","") -replace ("</cite>","")
        if ($hit){
            $a += New-Object -TypeName psobject -Property @{Domain=$_; WebPage=$value} 
            }    
        }
    if ($a){
        Write-Host "[+]  Found the string `"$queriedsite`" on the following web pages:"  -Fore Green
        $a.WebPage
    }
    else{
        Write-Host "[-]  The string `"$queriedsite`" was not found." -Fore Cyan
    }
}
Search-ForQuery -queriedsite $queriedsite -sitefile $sitefile
