param
(
    [array[]]$dir
)
function Deny-PathExe ($dir)
{
    Foreach ($d in $dir)
    {
        $info = "$d\*.exe" 
                
        # Create policy object
        $p = New-AppLockerPolicy -FileInformation $info -RuleType Path -User Everyone -Optimize
        
        # Set Action to Deny
        $p.RuleCollections.ForEach({ $_.ForEach({ $_.Action = 'Deny'}) })
        
        # Set policy
        Set-AppLockerPolicy -PolicyObject $p -Merge
         
        Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Deny EXE was applied to $d" 
    }
}
Deny-PathExe -dir $dir