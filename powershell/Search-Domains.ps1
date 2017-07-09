<#
.DESCRIPTION
    Gathers information on list of domains

.EXAMPLE
    .\Search-Domains.ps1 -File sites.txt

.NOTES
#>

$a = @()
echo google.com | foreach{$a += $(echo "Site_Name: $_")
                            $a += whois $_ }

Switch -Regex ($a)
{
 '^Site_Name: (.*)' {$obj = [PSCustomObject]@{Site_Name=$Matches[1];Creation_Date=$null;Registrar=$null;Registrant_Name=$null;Registrant_Phone=$null}}
 '^Creation Date: (.+)' {$obj.Creation_Date = $matches[1]}
 '^Registrar: (.+)' {$obj.Registrar = $matches[1]}
 '^Registrant Name: (.+)' {$obj.Registrant_Name = $matches[1]}
 '^Registrant Phone: (.*)' {$obj.Registrant_Phone = $Matches[1];$obj}
 }
$a | select Site_Name,Creation_Date,Registrar,Registrant_Name,Registrant_Phone
