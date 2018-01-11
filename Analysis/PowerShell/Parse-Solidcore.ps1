<#
.EXAMPLE
   .\Parse-Solidcore.ps1 .\s3diag.log | Out-GridView
   .\Parse-Solidcore.ps1 .\s3diag.log | select Time,Event,User,PID,ProcName | ft -auto
   .\Parse-Solidcore.ps1 .\s3diag.log -user <domain>\<username> | Out-GridView
   .\Parse-Solidcore.ps1 .\s3diag.log -event FILE_MODIFIED -user <domain>\<username> | Out-GridView
   .\Parse-Solidcore.ps1 .\s3diag.log | Export-CSV logs.csv
 
.SYNOPSIS
Parse Solidcore logs
 
.DESCRIPTION
Parse Solidcore logs
 
#>
 
Param
(
    [string]$file,
    [string]$user,
    [string]$event
)
 
Function Parse-Solidcore ($File)
{
    $a = @()
 
    gc $file | foreach{       
        
        $b = $_ -split ('  ') -replace ('/>','') -replace ('<','')
 
        $eventname = $b[0]
        $c = $b -split '" '
        $eventtime = ([string]($c | sls '^event_time_utc')).substring(16)
        $p = ([string]($c | sls '^pid="')).substring(5)
        $filename = ([string]($c | sls '^file_name')).substring(11)
        $username = ([string]($c | sls '^user_name')).substring(11)
        $procname = ([string]($c | sls '^process_name')).substring(14)
        $pprocname = ([string]($c | sls '^parent')).substring(21)
        $pp = ([string]($c | sls '^ppid="')).substring(6)
        # $wflow = ([string]($c | sls '^workflow')).substring(13)
              
        $a += New-Object -TypeName psobject -Property @{
            Time=$eventtime;
            Event=$eventname;
            PID=$p
            FileName=$filename
            User=$username;
            ProcName=$ProcName;
            ParentProc=$pprocname;
            PPID=$pp;
            # WorkflowID=$wflow;
        }
    }
   
    if (($user) -and !($event)){
        $a = $a | ?{$_.User -eq $user}
    }
    elseif (($user) -and ($event)){
        $a = $a | ?{($_.User -eq $user) -and ($_.Event -eq $event)}
    }
    elseif (($event) -and !($user)){
        $a = $a | ?{$_.Event -eq $event}
    }
    return $a | select Time,Event,FileName,User,ProcName,PID,ParentProc,PPID
}
Parse-Solidcore $File