

$a = @()

gc websites.txt | foreach{
    $value = iwr -uri http://$_ | sls "wordpress.{0,10}[`'|`"]" | %{$_.matches} | %{$_.Value}
    $a += New-Object -TypeName psobject -Property @{Site=$_; Version=$value}
        }
$a | select Site,Value
