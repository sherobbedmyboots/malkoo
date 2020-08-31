function PerformBackup() {
    Write-Host "`nTesting path to share..."
    if (!(Test-Path \\192.168.2.147\Backup\container)){
        Write-Host "Share not found... exiting"
        Read-Host
        Exit
    }
    
    Write-Host "Attempting to mount container..."
    if (!(Get-Command veracrypt -ErrorAction SilentlyContinue)){
        $env:PATH += ';C:\Program Files\VeraCrypt'
    }
    veracrypt /q /v \\192.168.2.147\Backup\container /l x /a /b | Out-Null
        
    Write-Host "Copying files..."
    robocopy /MIR /NFL /NJH C:\Users\kbota\Desktop x:\ /Z /W:5
    
    Write-Host "`nDismounting container..."
    veracrypt /q /d x
    Write-Host "Backup complete... `nExiting!`n"
}

$filegone = $False
$hashchanged = $False

if ((Test-Path C:\Users\kbota\Desktop\HoneyToken.txt) -eq $False){
    $filegone = $true
}

$hash = (Get-FileHash C:\Users\kbota\Desktop\HoneyToken.txt -Algorithm sha256).hash
if ($hash -ne 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'){
    $hashchanged = $true
}

if (($filegone -eq $true) -or ($hashchanged -eq $true)){
    $answer = Read-Host "`n**** Honeytoken has changed! *****`n`nWould you still like to backup [y/N]?"
    if ($answer -eq "y"){
        PerformBackup        
    }
    else {
        Write-Host "`nExiting...`n"
        Read-Host
        Exit
    }
}
else {
    PerformBackup
}

Read-Host