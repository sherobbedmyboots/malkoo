function Convert-EncodedFile ($encodedstring) {

    $ByteArray = [System.Convert]::FromBase64String($encodedstring)
    [System.IO.File]::WriteAllBytes("$(pwd)\decoded", $ByteArray)
    Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Wrote to file '.\decoded'"
}


function Convert-CompressedFile ($compressedstring) {

    $ms = New-Object System.IO.MemoryStream
    $ms.Write($compressedstring, 0, $compressedstring.Length)
    $ms.Seek(0,0) | Out-Null
    $sr = New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))
    # $sr.ReadToEnd() | set-clipboard
    $sr.ReadToEnd() | Set-Content -Path "$(pwd)\decompressed"
    Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Wrote to file '.\decompressed'"
}



function getTasks {

    $schedule = New-Object -ComObject "Schedule.Service"
    $schedule.Connect() 
    $out = @()

    # Get root tasks
    $schedule.GetFolder($path).GetTasks(0) | % {
        $xml = [xml]$_.xml
        $out += New-Object psobject -Property @{
            "Name" = $_.Name
            "Path" = $_.Path
            "LastRunTime" = $_.LastRunTime
            "NextRunTime" = $_.NextRunTime
            "Actions" = ($xml.Task.Actions.Exec | % { "$($_.Command) $($_.Arguments)" }) -join "`n"
        }
    }

    # Close com
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($schedule) | Out-Null
    Remove-Variable schedule

    # Output all tasks
    $out
}



function gTasks {
    $ErrorActionPreference = "SilentlyContinue"
    $Report = @()

    $path = "C:\Windows\System32\Tasks"
    $tasks = Get-ChildItem -recurse -Path $path -File
    foreach ($task in $tasks)
    {
        $Details = "" | select ComputerName, Task, User, Enabled, Application
        $AbsolutePath = $task.directory.fullname + "\" + $task.Name
        $TaskInfo = [xml](Get-Content $AbsolutePath)
        $Details.ComputerName = $Computer
        $Details.Task = $task.name
        $Details.User = $TaskInfo.task.principals.principal.userid
        $Details.Enabled = $TaskInfo.task.settings.enabled
        $Details.Application = $TaskInfo.task.actions.exec.command
        $Details
        $Report += $Details
    }
    $Report | ft
}










