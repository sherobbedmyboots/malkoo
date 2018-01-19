Param
(
    [string]$file
)

$json = gc $file | ConvertFrom-Json




$start = '[\s]{16}\"ssl.handshake.certificate_length":'
$finish = '[\s]{16\}\,'



$results = gc .\users\pcuser\test.json -raw | sls '(?smi)(^[\s]{16}\"ssl\.handshake\.certificate_length\"\:.*?\x0D\x0A[\s]{16}\})' -AllMatches | % {$_.Matches} | % {$_.Value}

$results = '[{' + $results + '}}]' 



 
$a = @()
foreach ($line in $log)
{
    $split = $line.split(' ')
    $a += New-Object -TypeName psobject -Property @{
        Date=$split[0];
        Time=$split[1];
        Action=$split[2];
        Protocol=$split[3];
        SrcIp=$split[4];
        DstIp=$split[5];
        SrcPort=$split[6];
        DstPort=$split[7];
        Size=$split[8];
        TcpFlags=$split[9];
        TcpSyn=$split[10];
        TcpAck=$split[11];
        TcpWin=$split[12];
        IcmpType=$split[13];
        IcmpCode=$split[14];
        Info=$split[15];
        Path=$split[16];       
    }
}
    $a | Add-Member -membertype NoteProperty -name Profile -Value $null
    return $a
}
 
$publiclog = gc 'C:\Windows\System32\Logfiles\Firewall\publicfirewall.log' | select -skip 5
$privatelog = gc 'C:\Windows\System32\Logfiles\Firewall\privatefirewall.log' | select -skip 5
$domainlog = gc 'C:\Windows\System32\Logfiles\Firewall\domainfirewall.log'  | select -skip 5
 
$public = parse-Logfile($publiclog)
$public | %{$_.Profile = "Public"}
 
$private = parse-Logfile($privatelog)
$private | %{$_.Profile = "Private"}
 
$domain = parse-Logfile($domainlog)
$domain | %{$_.Profile = "Domain"}
 
$fwlogs = $public + $private + $domain
$fwlogs