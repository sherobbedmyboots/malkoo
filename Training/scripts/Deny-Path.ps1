param
(
    [switch]$exe,
	[switch]$script,
	[switch]$dll,
	[switch]$installer,
	[array[]]$dir
)

function Deny-Path ($dir)
{
    if ($exe){$type = 'exe'}
	if ($script){$type = 'vbs'}
	if ($dll){$type = 'dll'}
	if ($installer){$type = 'msi'}
	
	Foreach ($d in $dir)
    {
        $info = "$d\*.$type" 
        
		# Create policy object
        $p = New-AppLockerPolicy -FileInformation $info -RuleType Path -User Everyone -Optimize
        
        # Set Action to Deny
        $p.RuleCollections.ForEach({ $_.ForEach({ $_.Action = 'Deny'}) })
        
        # Set policy
        Set-AppLockerPolicy -PolicyObject $p -Merge
         
        Write-Host "[+] " -Fore Green -NoNewLine; Write-Host "Deny $type was applied to $d" 
    }
}
Deny-Path -dir $dir