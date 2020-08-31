<#
.DESCRIPTION
    Simulates pivoting techniques for training

.EXAMPLE
    .\Fake-PivotAttempts.ps1 -Systemlist c:\hts.txt -Interval 3 -TotalTime 30

.NOTES
    Interval time is in seconds
    TotalTime is in minutes
#>

Param
(
    [array] $Systemlist,
    [string] $Interval,
    [string] $TotalTime
)

function Fake-PivotAttempts
{
    $timeout = new-timespan -Minutes $TotalTime
    $sw = [diagnostics.stopwatch]::StartNew()
    while ($sw.elapsed -lt $timeout)
    {
        gc $Systemlist | foreach
        {
        $status = Invoke-Command -Scriptblock {hostname} -computer "$_"
        Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Result: $status"
        start-sleep -seconds $Interval
        }
    }
}
Fake-PivotAttempts -Systemlist $Systemlist -Interval $Interval -TotalTime $TotalTime
