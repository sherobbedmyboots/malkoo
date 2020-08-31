<# 

.DESCRIPTION
    Search a user's home directory for terms/phrases and copy files to case folder

.EXAMPLE
    Search-HomeDirectory -User bob -Term 'cat in the hat','the quick brown fox','search term'

.NOTES
    Recommend running this script as a separate process since these searches can last up to 24 hours 
    to complete.  By using the command below, a new PowerShell process is created and will continue 
    to run on your system until finished:
    
    Start-Process powershell -Win Hidden -Arg {Search-HomeDirectory -User bob,alice -TEST -case 0000 -Term 'cat in the hat','the quick brown fox','search term'}
    
#>

Param 
( 
    [Array[]] $User,
    [string[]] $Term,
    [string] $case,
    [switch]$R,
    [switch]$F,
    [switch]$L,
    [switch] $TEST
)

Function Search-HomeDirectory 
{
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Determining source and destination folder paths..." 
    $src = '\\path-to-host\folder'
    if($R)
        {
            $src_path = "$src\R"
        }
    elseif($F)
        {
            $src_path = "$src\F"
        }
    elseif($S)
        {
            $src_path = "$src\S"
        }
    elseif($L)
        {
            $src_path = "$src\L"
        }
    elseif($test)
        {
            $src_path = "\\path-to-host\folder"
        } 
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Source path is $src_path"
    
    # Check for Get-AdUser

    try { 
        Get-Help Get-AdUser -Examples | Out-Null
    }
    catch {
        Write-Host -ForegroundColor Yellow [-] (get-date -UFormat "%H:%M:%S") "   Get-AdUser not installed. Exiting."
        Exit
    }


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
            $OutputFile = New-Item -itemtype File -Path \\path-to-host\folder -Name ($FileName + ".log")
            
            # Check if user has share 
            try {
                $Homedirectory = $(get-aduser "$u" -pr homedirectory).homedirectory 
            }
            catch {
                Write-Host -ForegroundColor Yellow [-] (get-date -UFormat "%H:%M:%S") "   Could not find home directory for $u."
                Break
            }
            

            $numDir = ls -Directory $Homedirectory | measure | select -exp count
            $numFil = ls -File $Homedirectory | measure | select -exp count

            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Will be searching through $numDir directories and $numFil files..." 

            if (!(Test-Path "$src_path\Host Artifacts\Server\User Profile\$u"))
                {         
                    $OutputDir = New-Item -ItemType Directory "$src_path\Host Artifacts\Server\User Profile\$u"
                }
            else
                {
                    $OutputDir = "$src_path\Host Artifacts\Server\User Profile\$u"
                }

            # Create combined pattern argument for search-string

            $Term2 = $Term -join ')|(' 

            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Output directory is $OutputDir"        
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Home directory is $HomeDirectory"
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Output file is $OutputFile"       
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Pattern variable is $Term2"

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
            
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Starting search..."

            $Results = $(gci -r -fo -exclude *.pst,*.ost,*.bak $Homedirectory 2>$null | select -exp fullname | foreach 2>$null {select-string -path "$_" -pattern "($Term2)" | group path | select name}).name
            
                                
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Removing duplicates..."

            $Uniq_Results = $Results | Get-Unique 

            $2_Uniq_Results = $Uniq_Results -join "`r`n"

            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Unique files containing one or more strings:`n`n$2_Uniq_Results"
            
            Write-Host -ForegroundColor Cyan `n[+] (get-date -UFormat "%H:%M:%S") "   Writing unique filenames to Logfile..."      

            $2_Uniq_Results | Out-File $OutputFile -Append
                    
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Copying unique files to FDCS server..."      
                        
           
            $Uniq_Results | foreach {Copy-Item -Path "$_" -Destination $OutputDir}
                        
            Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Unique files were copied to: `n`n$($OutputDir | Out-String -Width 2000)"  
        }    
}
Search-HomeDirectory -User $User -Term $Term
