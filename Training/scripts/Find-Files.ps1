
$ErrorActionPreference = 'SilentlyContinue'

# Read location file
[array]$locations = Get-Content location_list.txt

# Read list of keywords
[array]$wordlist = Get-Content keywords.txt 


function Get-MatchingFiles ($filePath) {
    $scriptblock = [scriptblock]::create(@"
param([array]`$wordlist, [string]`$filePath )
`$filelist = Get-ChildItem -Recurse -Force -Exclude *.pst,*.ost,*.bak $filePath 2>`$null | where { ! `$_.PSIsContainer } | select -exp fullname
Foreach (`$file in `$filelist) {
    Foreach (`$word in `$wordlist) {
            (Select-String -Path `$file -Pattern `$word 2>`$null | group path | select name).name
    }
}
"@)
    Invoke-Command -ScriptBlock $scriptblock -Session $s -AsJob -ArgumentList $wordlist,$filePath | Wait-Job | Receive-Job
}

function Get-MatchingFilesFromMappedDrive ($filePath) {
    $filelist = Get-ChildItem -Recurse -Force -Exclude *.pst,*.ost,*.bak $filePath 2>$null | where { ! $_.PSIsContainer } | select -exp fullname
    Foreach ($file in $filelist) {
        Foreach ($word in $wordlist) {
            (Select-String -Path $file -Pattern $word 2>$null | group path | select name).name
        }
    }
}


Foreach ($location in $locations) {

    Write-Host -Fore Cyan "[>] " -NoNewLine;Write-Host $location


    # Check if host online
    $shareHostname = $location.split('\')[2]
    $shareName = $location.split('\')[3]

    If (!(Test-Connection $shareHostname -Count 1 -Quiet)){
        Write-Host -Fore Red `t"[-] " -NoNewLine;Write-Host $shareHostname "doesn't appear to be online"
        Continue
    }

    # Create session with host
    if (!($s = New-PSSession -ComputerName $shareHostname)){
        Write-Host -Fore Yellow `t"[-] " -NoNewLine;Write-Host "Problems creating PS session with"$shareHostname", Attempting to map drive.."
        
        # Map share as drive
        $mappedDrive = New-PSDrive -Name $shareHostname -PSProvider FileSystem -Root $location 
        if (!($mappedDrive)){
            Write-Host -Fore Red `t"[-] " -NoNewLine;Write-Host "Could not map $location to a drive"
            Continue
        }
        else {
            Write-Host -Fore Green `t"[+] " -NoNewLine;Write-Host "Successfully mapped"$location" to drive "$shareHostname":\"
        }
    }

    # Search for files that contain words in wordlist    
    Write-Host -Fore Green `t"[+] " -NoNewLine;Write-Host "Searching files..."
    if ($mappedDrive) {
        $filePath = $mappedDrive.Name + ':\'
        [array]$matchlist = Get-MatchingFilesFromMappedDrive $filePath
    }
    else {
        $localPath = Invoke-Command -Session $s -ScriptBlock {param($shareName)(Get-SmbShare $shareName).Path} -ArgumentList $shareName
        $filePath = $localPath + $location.split('$')[1]
        [array]$matchlist = Get-MatchingFiles $filePath
    }

    
    $totalcount = $matchlist.length
    $matchlist = $matchlist | ? {$_}
    $matchlist - $matchlist | Select -uniq
    $filecount = $matchlist.length
     
    # Make directory for matching files
    $newDir = (New-Item -Name $location -Type Directory).FullName

    # Report duration of Search
    $job = Get-Job -Newest 1
    $minutes = ($job.PSEndTime - $job.PSBeginTime).Minutes
    if ($mappedDrive) {
        Write-Host -Fore Green `t"[+] " -NoNewLine;Write-Host "Completed searching $totalcount files in $location with $filecount matching files found"
    }
    else {
        Write-Host -Fore Green `t"[+] " -NoNewLine;Write-Host "Completed searching $totalcount files in $location in $minutes minutes with $filecount matching files found"
    }
    

    # Copy matching files to new directory
    Foreach ($file in $matchlist) {
        if ($file) {
            if ($mappedDrive) {
                Copy-Item -Path "$file" -Destination $newDir
            }
            else {
                Copy-Item -FromSession $s -Path "$file" -Destination "$newDir" 
            }            
        }
    }
}
