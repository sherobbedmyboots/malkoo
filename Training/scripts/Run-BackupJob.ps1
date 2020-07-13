<#
.EXAMPLE
   .\Run-BackupJob.ps1 -type E 
   .\Run-BackupJob.ps1 -type H
   .\Run-BackupJob.ps1 -type T

.SYNOPSIS
    Run Backups as a Job

.DESCRIPTION
    The -type parameter determines which backup job is being run:

        E       Backup to E:\DATA
        H       Backup to \\server\D:\DATA
        T       Used for testing
#>

param
    (
        [string]$type
    )

function checkargs{
    if (!($type))
    {
        Write-Host "`nYou must enter a type of backup:       .\Run-BackupJob.ps1 -type E `n"
        Write-Host "                                       .\Run-BackupJob.ps1 -type H `n"
        Write-Host "                                       .\Run-BackupJob.ps1 -type T `n"
        Exit
    }
}

function Run-BackupJobE
{
    if (!(Test-Path '\\server\e$\case_data')) 
    {
        Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "Path to E:\DATA not found... Exiting!`n" 
        Exit
    }

    $Jname = 'Backup_To_E'
    Start-Job -Name $Jname -ScriptBlock {
        $source = '\\server\d$\data'
        $destination = '\\server\e$\data'
        $date = (Get-Date -UFormat "%Y-%m-%d").ToString()
        $logfile = "C:\path\Robocopy\" + $date + "_Backup_To_E.log"
        robocopy /MIR $source $destination /LOG:$logfile
    }
}


function Run-BackupJobH
{    
    if (!(Test-Path '\\server\D$\DATA'))
    {
        Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "Path to server\D$\DATA not found... Exiting!`n" 
        Exit
    }

    $Jname = 'Backup_To_H'
    Start-Job -Name $Jname -ScriptBlock {
        $source = "\\server\d$\data"
        $destination = "\\server\d$\data"
        $date = (Get-Date -UFormat "%Y-%m-%d").ToString()
        $logfile = "C:\path\Robocopy\" + $date + "_Backup_To_H.log"
        robocopy /MIR $source $destination /LOG:$logfile
    }
}
    

function Run-BackupJobT
{ 
    if (!(Test-Path '\\server\path\Links'))
    {
        Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "Path to \\server\home$\downloads not found... Exiting!`n"   
        Exit
    }
    
    $Jname = 'Test_Backup_Job'
    Start-Job -Name $Jname -ScriptBlock {
        $source = "\\server\c$\Links\"
        $destination = "\\server\C$\Links\"
        $date = (Get-Date -UFormat "%Y-%m-%d").ToString()
        $logfile = "C:\Robocopy\" + $date + "_Test_Backup_Job.log"
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

if ($type -eq "E"){
    Run-BackupJobE
    Exit
}

if ($type -eq "H"){
    Run-BackupJobH
    Exit
}

if ($type -eq "T"){
    Run-BackupJobT
    Exit
}

else{
    Write-Host -Fore Red "`n[-] " -NoNewLine; Write-Host "You've entered an invalid type.  Choose E, H, or T.`n"
    Exit
}
