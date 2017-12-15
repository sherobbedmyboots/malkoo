<#
.EXAMPLE
   .\Parse-EventLog.ps1 .\s3diag.log | Out-GridView
   .\Parse-EventLog.ps1 .\s3diag.log | select Time,Event,User,PID,ProcName | ft -auto
   .\Parse-EventLog.ps1 .\s3diag.log -user <domain>\<username> | Out-GridView
   .\Parse-EventLog.ps1 .\s3diag.log -event FILE_MODIFIED -user <domain>\<username> | Out-GridView
   .\Parse-EventLog.ps1 .\s3diag.log | Export-CSV logs.csv
 
.SYNOPSIS
Parse EventLog logs
 
.DESCRIPTION
Parse EventLog logs
 
#>
Param 
(
    [int]$count,
    [string]$user
)
 
Function Parse-EventLogs ($count)
{
    $a = @()
    $count
    $log = Get-EventLog -logname security -newest "$count" | ? EventID -eq 4688     
    
    foreach ($l in $log)
    {
        $new_process = $l.message | sls 'New Process Name.*exe' | %{$_.Matches} | %{$_.Value} 
        $new_process = ($new_process -split '\t')[1]
        
        $new_process_id = $l.message | sls 'New Process ID.*\d+' | %{$_.Matches} | %{$_.Value}
        $new_process_id = ($new_process_id -split '\t\t')[1]
 
        $creator_process_id = $l.message | sls 'Creator Process ID.*\d+' | %{$_.Matches} | %{$_.Value}
        $creator_process_id = ($creator_process_id -split '\t')[1]
 
        $account_name = $l.message | sls 'Account Name.+' | %{$_.Matches} | %{$_.Value}
        $account_name = ($account_name -split '\t\t')[1]
 
        $a += New-Object -TypeName psobject -Property @{
            Time = $l.TimeGenerated;
            # EventID = $l.EventID;
            AccountName=$account_name;
            NewProcess=$new_process;
            NewProcessID=$new_process_id;
            CreatorProcessID=$creator_process_id;
        }
    }
    return $a
}
 
if ($user){
    $a = Parse-EventLogs -count $count
    $a | ? AccountName -match $user | select Time,AccountName,NewProcess,NewProcessID,CreatorProcessID 
}
else
{
    $a = Parse-EventLogs -count $count
    $a | select Time,AccountName,NewProcess,NewProcessID,CreatorProcessID 
}