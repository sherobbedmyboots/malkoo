param
(
    [switch]$exe,
	[switch]$script,
	[switch]$dll,
	[switch]$installer
)
function Allow-Signed
{
    if ($exe){$type = 'exe';$file = 'c:\windows\system32\cmd.exe'}
	if ($script){$type = 'script';$file = 'xxxx.vbs'}
	if ($dll){$type = 'dll';$file = 'xxxx.dll'}
	if ($installer){$type = 'installer';$file = 'xxxx.msi'}
	
	#Create rule
	$t = Get-AppLockerFileInformation $file
	$p = $t | New-AppLockerPolicy -RuleType Publisher -User Everyone -Optimize
	
	# Modify rule and add to policy
	$p.RuleCollections.ForEach({ $_.ForEach({ $_.Name = 'Signed by *'}) })
	$p.RuleCollections.PublisherConditions.PublisherName = '*'
	$p.RuleCollections.PublisherConditions.ProductName = '*'
	$p.RuleCollections.PublisherConditions.BinaryName = '*'
	$p.RuleCollections.PublisherConditions.BinaryVersionRange.LowSection.BuildPartNumber = ''
	$p.RuleCollections.PublisherConditions.BinaryVersionRange.LowSection.PrivatePartNumber = ''
	$p.RuleCollections.PublisherConditions.BinaryVersionRange.LowSection.MajorPartNumber = ''
	$p.RuleCollections.PublisherConditions.BinaryVersionRange.LowSection.MinorPartNumber = ''
	$p.RuleCollections.PublisherConditions.BinaryVersionRange.LowSection.VersionNumber = ''
	Set-AppLockerPolicy -PolicyObject $p -Merge
       
    Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Allow only signed $type was applied" 
}
Allow-Signed