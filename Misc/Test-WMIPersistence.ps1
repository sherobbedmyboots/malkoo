<#
.EXAMPLE
   .\Test-WMIPersistence.ps1 -set -name Test -hour 09 -minute 15
   .\Test-WMIPersistence.ps1 -remove -name Test
   .\Test-WMIPersistence.ps1 -detect -name Test
 
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
 
param
(
    [string]$Name,
    [string]$Hour,
    [string]$Minute,
    [switch]$detect,
    [switch]$remove,
    [switch]$set
)
 
function checkargs{
    if ($set){
        if (!($Name -and $Hour -and -$Minute)){
        Write-Host -Fore Yellow "`nWhen setting persistence, you must enter a name, hour, and minute:      Test-WMIPersistence -set -name Test -hour 09 -minute 15`n"
        Exit
        }
    }
 
    if ($Hour){
        if ((!(($Hour.ToString()).length -eq 2))){
            Write-Host -Fore Yellow "`nYou must enter hours using two digit format:   09 for 9:00 AM, 14 for 2:00 PM`n"
            exit
        }
    }
    if ($Minute){
        if ((!(($Minute.ToString()).length -eq 2))){
            Write-Host -Fore Yellow "`nYou must enter minutes using two digit format:   55 for 09:55, 15 for 10:15`n"
            exit
        }
    }
    if (!($set -or $detect -or $remove)){
        Write-Host -Fore Yellow "`nYou must choose to either set (-set), detect (-detect), or remove (-remove) persistence`n"
        exit
    }
}
 
function Set-Persistence
{
    $exePath = 'C:\Windows\System32\calc.exe'
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
            ExecutablePath=$exePath;
            CommandLineTemplate=$exePath
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
   
    if ($e){
        Write-Host -Fore Green "`n`nEvent Filter details:"
        $e
    }
    else{
        Write-Host -Fore Yellow "`n`nNo Event Filters found"
    } 
 
    if ($c){
        Write-Host -Fore Green "Event Consumer details:"
        $c
    }
    else{
        Write-Host -Fore Yellow "No Consumer Filters found"
    } 
 
    if ($b){
        Write-Host -Fore Green "Binding details:"
        $b
    }
    else{
        Write-Host -Fore Yellow "No Bindings found`n"
    } 
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