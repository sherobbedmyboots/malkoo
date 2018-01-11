<#
.EXAMPLE
   $log = Invoke-Command -ComputerName <remote host> -Filepath .\Get-FirewallLog.ps1
 
.EXAMPLE
   $log | select Date,Time,Action,Protocol,SrcIp,SrcPort,DstIp,DstPort,Size,Path | ft -auto
 
   See all logs
.EXAMPLE
    $log | ? Protocol -eq ICMP | select Date, Time,Action,Protocol,SrcIp,DstIp,Size,Path | ft -auto
 
    Filter on ICMP logs
 
.EXAMPLE
   $log | ? Profile -eq Public | select Date, Time, Profile, Action,Protocol,SrcIp,SrcPort,DstIp,DstPort,Size,Path | ft -auto
 
    Filter on Profile
 
.SYNOPSIS
Get Firewall Log
 
.DESCRIPTION
Get Firewall Log

#>
 
Param
(
    [string]$file,
    [string]$user,
    [string]$event
)
 
function parse-Logfile ($log)
{
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