$a = @()
gc sites.txt | foreach{
    $value = irm -uri http://$_ -useragent 'xxxx'| sls "wordpress.{0,10}[`'|`"]" | %{$_.matches} | %{$_.Value}
    $a += New-Object -TypeName psobject -Property @{Site=$_; Version=$value}
    }
$a | select Site,Version
