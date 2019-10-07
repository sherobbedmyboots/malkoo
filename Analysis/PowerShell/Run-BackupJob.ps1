<#
.EXAMPLE
   .\Run-BackupJob.ps1 –type 1
   .\Run-BackupJob.ps1 -type 2
   .\Run-BackupJob.ps1 -type Test
.SYNOPSIS
    Run Backups as a Job
.DESCRIPTION
    The -type parameter determines which backup job is being run:
        1       Backup to 1
        2    Backup to 2
        TEST    Used for testing
#>
 
param
    (
        [string]$type
    )
 
function checkargs{
    if (!($type))
    {
        Write-Host "`nYou must enter a type of backup:       .\Run-BackupJob.ps1 -type 1 `n"
        Write-Host "                                       .\Run-BackupJob.ps1 -type 2 `n"
        Write-Host "                                       .\Run-BackupJob.ps1 -type Test `n"
        Exit
    }
}
 
function Run-BackupJob1
{
    if (!(Test-Path '1))
    {
        Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "Path to 1 not found... Exiting!`n"
        Exit
    }
 
    $Jname = 'Backup_To_1'
    Start-Job -Name $Jname -ScriptBlock {
        $source = '0’
        $destination = '1’
        $date = (Get-Date -UFormat "%Y-%m-%d").ToString()
        $logfile = “3" + $date + "_Backup_To_1.log"
        robocopy /MIR $source $destination /LOG:$logfile
    }
}
 
 
function Run-BackupJob2
{   
    if (!(Test-Path '2'))
    {
        Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "Path to 2  not found... Exiting!`n"
        Exit
    }
 
    $Jname = 'Backup_To_2'
    Start-Job -Name $Jname -ScriptBlock {
        $source = “0"
        $destination = “2"
        $date = (Get-Date -UFormat "%Y-%m-%d").ToString()
        $logfile = “3" + $date + "_Backup_To_2.log"
        robocopy /MIR $source $destination /LOG:$logfile
    }
}
   
 
function Run-BackupJobTest
{
    if (!(Test-Path '4’))
    {
        Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "Path to 4 not found... Exiting!`n"  
        Exit
    }
   
    $Jname = 'Test_Backup_Job'
    Start-Job -Name $Jname -ScriptBlock {
        $source = “0"
        $destination = "4"
        $date = (Get-Date -UFormat "%Y-%m-%d").ToString()
        $logfile = “3" + $date + "_Test_Backup_Job.log"
        robocopy /MIR $source $destination /LOG:$logfile
    }
}
   
    <# Job Status
    $job = Wait-Job -Name $Jname
    if ($job.State -eq 'Failed')
    {
        Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "Job failed:  " -NoNewLine; Write-Host ($job.ChildJobs[0].JobStateInfo.Reason.Message) -Fore Red
    }#>
 
checkargs
 
if ($type -eq "1"){
    Run-BackupJob1
    Exit
}
 
if ($type -eq "2"){
    Run-BackupJob2
    Exit
}
 
if ($type -eq "TEST"){
    Run-BackupJobTest
    Exit
}
 
else{
    Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "You've entered an invalid type.  Choose 1, 2, or TEST.`n"
    Exit
}