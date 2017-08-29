<#
.DESCRIPTION
    Search a user's home directory for terms/phrases and copy files to a share

.EXAMPLE
    Search-HomeDirectory -User a -Term 'cat in the hat','the quick brown fox','search term'

.NOTES
    Recommend running this script as a separate process since these searches can last up to 24 hours
    to complete.  By using the command below, a new PowerShell process is created and will continue
    to run on your system until finished:

    Start-Process powershell -Win Hidden -Arg {Search-HomeDirectory -User a -Term 'cat in the hat','the quick brown fox','search term'}
#>

Param
(
    [Array[]] $User,
    [string[]] $Term,
    [string] $case,
    [switch] $test,
    [switch] $R,
    [switch] $FO,
    [switch] $Spe,
    [switch] $Li
)

Function Search-HomeDirectory
{
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Determining source and destination folder paths..."
    $src = '\\path to folder'
    if($R)
    {
        $src_path = "$src\path"
    }
    elseif($FO)
    {
        $src_path = "$src\pth "
    }
    elseif($Spe)
    {
        $src_path = "$src\path"
    }
    elseif($Lit)
    {
        $src_path = "$src\pth"
    }
    elseif($test)
    {
        $src_path = "\\path to test"
    }
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Source path is $src_path..."

    #################################################################
    # Loop through users
    #################################################################

    foreach ($u in $User)
    {
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Building variables for $u..."

            #################################################################
            # Create a file for results
            #################################################################

            $FileName = (Get-Date).tostring("dd-MM-yyyy-hh-mm-ss") + '_' + $u
            $OutputFile = New-Item -itemtype File -Path \\path -Name ($FileName + ".log")
            $Homedirectory = $(get-aduser "$u" -pr homedirectory).homedirectory
            if (!(Test-Path "$src_path\path\$u"))
            {
                $OutputDir = New-Item -ItemType Directory "$src_path\path\$u" | Out-Null
            }
            else
            {
                $OutputDir = "$src_path\ path \$u"
            }

            # Create combined pattern argument for search-string

            $Term2 = $Term -join ')|('

            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Output directory is $OutputDir..."
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   home directory is $HomeDirectory..."
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Output file is $OutputFile..."
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Term2 is $Term2 ..."

            #################################################################
            # Write date, user info, homedir, and search terms
            #################################################################

            $(Get-Date) | Out-File $OutputFile
            [string]::join("`t`t`t`t", "User:", $u) | Out-File $OutputFile -Append
            [string]::join("`t`t", "Home Directory:", $HomeDirectory)  | Out-File $OutputFile -Append
            "`nSearch Terms:`n" | Out-File $OutputFile -Append
            [string]::join("`n", ($Term | % {echo "$_"}))  | Out-File $OutputFile -Append
            "`n`nFiles where search terms were found:`n" | Out-File $OutputFile -Append
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Output file was built..."

            #################################################################
            # Recursively list all files and string-search for terms
            #################################################################

            $Results = Start-Process powershell -Win Hidden -Arg {gci -r -fo $Homedirectory 2>$null | select -exp fullname | foreach 2>$null `
                {select-string -path "$_" -pattern "($Term2)" | group path | select name} | ft -wrap -HideTableHeaders}

            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Search was completed..."
            $Uniq_Results = $Results | select -unique name | foreach { $_.Name } | ft -wrap -HideTableHeaders
            $Uniq_Results | Out-File $OutputFile -Append
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Unique results for $u are: `n`t$Uniq_Results..."
            $Uniq_Results | foreach
            {
                Copy-Item "$_" "$OutputDir"
            }
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Unique results were copied to: `n`t$OutputDir..."
    }
}
Search-HomeDirectory -User $User -Term $Term
