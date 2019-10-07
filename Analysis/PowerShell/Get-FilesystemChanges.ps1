<#

Example

$fc = Invoke-Command -ComputerName <hostname> -FilePath .\Get-FilesystemChanges.ps1 -ArgumentList @('<accountname>', '<numberofdays>')


See all files created, accessed, or written in last $days days:

    $fc | select Fullname,CreationTime,LastWriteTime,LastAccessTime | sort -desc CreationTime | ft -auto

    $fc | select FullName,Attributes,Length,LastAccessTime| sort -desc LastAccessTime | ft

#>

param
(
    [string]$account,
    [int]$days
)

$fc = ls -r 2>$null "C:\users\$account" | ? {($_.CreationTime -gt (get-date).adddays(-$days)) -or `
                                            ($_.LastAccessTime -gt (get-date).adddays(-$days)) -or `
                                            ($_.LastWriteTime -gt (get-date).adddays(-$days))} 
$fc

