<#
.DESCRIPTION
    Run weekly backups

.EXAMPLE
    Run-Backup

.NOTES
    It can take a few hours for both backups to complete
#>

function Run-Backup
{
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Starting Backup to E Drive"
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Setting variables..."

    #################################################################
    # Check for path to E
    #################################################################

    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Checking path to E Drive..."
    if (!(Test-Path '\\filepath-to-share'))
        {
            Write-Host -ForegroundColor Red [+] (get-date -UFormat "%H:%M:%S") "   Path to filepath-to-share not found... Exiting!"
            Exit
        }

    #################################################################
    # Create a file for results
    #################################################################

   Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Creating log file for E Drive Backup..."
    $date = (Get-Date -UFormat "%Y-%m-%d")
    $FileName = '\\path-to-log' + $date + '.log'
    if (!(Test-Path $FileName))
        {
            New-Item -ItemType file $Filename >$null
        }
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Created log file $Filename"
    $log = Get-Content $Filename -raw

    #################################################################
    # Start E Drive Backup
    #################################################################

    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Running E Drive Backup now..."
    $timerun = Measure-Command {$process = Start-Process robocopy -argumentlist "/MIR /LOG:$Filename \\path-to-drive \\path-to-share -wait -NoNewWindow -PassThru"}
    if ($process.ExitCode -eq 0)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 0. No files were copied. No failure was encountered. No files were mismatched. The files already exist in the destination directory; therefore, the copy operation was skipped. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 1)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 1. E Drive Backup completed successfully in $timerun"
        }
    elseif ($process.ExitCode -eq 2)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 2. There are some additional files in the destination directory that are not present in the source directory. No files were copied. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 3)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 3. Some files were copied. Additional files were present. No failure was encountered. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 5)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 5. Some files were copied. Some files were mismatched. No failure was encountered. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 6)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 6. Additional files and mismatched files exist. No files were copied and no failures were encountered. This means that the files already exist in the destination directory. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 7)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 7. Files were copied, a file mismatch was present, and additional files were present. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 8)
        {
            Write-Host -ForegroundColor Yellow [+] (get-date -UFormat "%H:%M:%S") "   Warning. Exit code 8. Several files did not copy. Backup completed in $timerun"
        }
    else
        {
            Write-Host -ForegroundColor Red [+] (get-date -UFormat "%H:%M:%S") "   Error. Backup did not complete successfully." + "`r`n`n" + $log
        }
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Starting backup to path-t0-share2..."

    #################################################################
    # Check for path to share2
    #################################################################

    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Checking path to path-to-share2..."
    if (!(Test-Path '\\path-to-share2'))
        {
            Write-Host -ForegroundColor Red [+] (get-date -UFormat "%H:%M:%S") "   Path to \\path-to-share2 not found... Exiting!"
            Exit
        }

    #################################################################
    # Create a file for results
    #################################################################

    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Creating log file for 2nd Backup..."
    $FileName2 = '\\path-to-log_' + $date + '.log'
    if (!(Test-Path $FileName2))
        {
            New-Item -ItemType file $Filename2 >$null
        }
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Created log file $Filename2"
    $log = Get-Content $Filename2 -raw

    #################################################################
    # Start 2nd Backup
    #################################################################

    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Running 2nd  Backup now..."
    $timerun = Measure-Command{$process = Start-Process robocopy -argumentlist "/MIR /LOG:$Filename2 \\path-to-share2" -wait -NoNewWindow -PassThru}
    if ($process.ExitCode -eq 0)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 0. No files were copied. No failure was encountered. No files were mismatched. The files already exist in the destination directory; therefore, the copy operation was skipped. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 1)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 1. 2nd  Backup completed successfully in $timerun"
        }
    elseif ($process.ExitCode -eq 2)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 2. There are some additional files in the destination directory that are not present in the source directory. No files were copied. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 3)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 3. Some files were copied. Additional files were present. No failure was encountered. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 5)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 5. Some files were copied. Some files were mismatched. No failure was encountered. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 6)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 6. Additional files and mismatched files exist. No files were copied and no failures were encountered. This means that the files already exist in the destination directory. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 7)
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successful. Exit code 7. Files were copied, a file mismatch was present, and additional files were present. Backup completed in $timerun"
        }
    elseif ($process.ExitCode -eq 8)
        {
            Write-Host -ForegroundColor Yellow [+] (get-date -UFormat "%H:%M:%S") "   Warning. Exit code 8. Several files did not copy. Backup completed in $timerun"
        }
    else
        {
            Write-Host -ForegroundColor Red [+] (get-date -UFormat "%H:%M:%S") "   Error. Backup did not complete successfully." + "`r`n`n" + $log
        }
    Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Both backups have completed..."
}
Run-Backup
