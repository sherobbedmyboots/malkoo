    

function Get-FirewallLogs {
        param ($filepath)

        $a=@()
        $lines = cat $filepath | Select -Skip 5
        
        $lines | %{
                $s = $_.split(' ')
                $a += New-Object -TypeName psobject -Property @{
                        DateTime=[datetime]($s[0] + ' ' + $s[1]);
                        Action=$s[2];
                        Protocol=$s[3];
                        SrcIp=$s[4];
                        DstIp=$s[5];
                        SrcPort=$s[6];
                        DstPort=$s[7];
                        Size=$s[8];
                        TcpFlags=$s[9];
                        TcpSyn=$s[10];
                        TcpAck=$s[11];
                        TcpWin=$s[12];
                        IcmpType=$s[13];
                        IcmpCode=$s[14];
                        Info=$s[15];
                        Path=$s[16];                       
                }
        }
        $a 
}

function Get-AllowedTraffic {

        if (!($global:allowed)) {
                if (!($global:allowed = Get-FirewallLogs $logs)) {
                        $var = Read-Host "Enter filepath of log file: "
                        $global:logs = Get-FirewallLogs $var
                        $global:allowed = Get-AllowedTraffic $logs
                }
        }
        else {
                Write-Host -Fore Green "[+] " -NoNewLine;Write-Host "Using logs in " -NoNewLine;Write-Host -Fore Yellow "`$allowed" -NoNewLine;Write-Host " variable"
        }
}

function Get-ExposedPorts {

        param($ip)

        Get-AllowedTraffic
        $global:allowed | ? SrcIp -notmatch "^10\." | ? DstIp -eq $ip | Select -Unique DstPort 

}

function Get-ExposedPortTraffic {

        param($port)

        Get-AllowedTraffic
        $global:allowed | ? {($_.SrcPort -eq $port) -or ($_.DstPort -eq $port)} | Select DateTime,SrcIp,DstIp,SrcPort,DstPort,Path,Protocol | Sort -Desc DateTime | ft -auto
}





# Export these functions
$funcs =  @('Get-FirewallLogs'
            'Get-AllowedTraffic'
            'Get-ExposedPorts'
            'Get-ExposedPortTraffic'
            )
Export-ModuleMember -Function $funcs
