<#
.DESCRIPTION
    Simulates cmd.exe tunneled over DNS for training

.EXAMPLE
    .\Fake-DNSTunnel.ps1 -Website cloudflare.com -Interval 3 -TotalTime 10

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

Function Fake-DNSTunnel ( $Website )
{
    $timeout = new-timespan -Minutes $TotalTime
    $sw = [diagnostics.stopwatch]::StartNew()
    while ($sw.elapsed -lt $timeout)
    {
        $random = "testquery.$(get-random -minimum 100000000000000 -maximum 999999999999999).$Website"
        try
        {
            [Net.DNS]::GetHostByName($random) 2>$null
        }
        catch
        {
            Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "    Sending DNS query for: $random"
        }
        start-sleep -seconds $Interval
    }
    Write-Host -ForegroundColor Red [+] (get-date -UFormat "%H:%M:%S") "    Queries have ended"
}
Fake-DNSTunnel -Website $Website -Interval $Interval -TotalTime $TotalTime
