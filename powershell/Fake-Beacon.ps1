<#
.DESCRIPTION
    Simulates beaconing techniques for training

.EXAMPLE
    .\Fake-Beacon.ps1 -Website www.sans.org -Interval 3 -TotalTime 30

.NOTES
    Interval time is in seconds
    TotalTime is in minutes
#>

Param
(
    $Website,
    $Interval,
    $TotalTime
)

Function Fake-Beacon ( $Website )
{
    $timeout = new-timespan -Minutes $TotalTime
    $sw = [diagnostics.stopwatch]::StartNew()
    while ($sw.elapsed -lt $timeout)
    {
        $random = get-random -minimum 100000000000000 -maximum 999999999999999
        $status = (iwr $Website -MaximumRedirection 0 -useragent Mozilla/5.0 (Windows NT 6.1; rv:11.0) TEST-$random).StatusCode
        #$status = (iwr $Website -MaximumRedirection 0 -proxy http://<proxy> -useragent Mozilla/5.0 (Windows NT 6.1; rv:11.0) TEST-$random).StatusCode
        Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   ----  $Website  ----  Status: $status  ----  Beacon still alive!"
        start-sleep -seconds $Interval
    }
    Write-Host -ForegroundColor Red [+] (get-date -UFormat "%H:%M:%S") "   ----  $Website  ----  Status: ---  ----  Beacon is dead."
}
Fake-Beacon -Website $Website -Interval $Interval -TotalTime $TotalTime
