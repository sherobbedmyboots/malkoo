function Strip-ForCuckoo
{
    Param($Path)
        
    # Load application
    Write-Host -Fore Green "Creating Outlook object..."
    $outlook1 = New-Object -ComObject Outlook.Application
    if (Test-Path Out) {
        Remove-Item -Recurse -Force Out | Out-Null
    }
    New-Item -ItemType 'Directory' -Path Out -Force | Out-Null
        
    # Extract attachments
    Write-Host -Fore Green "Extracting attachments..."
    $files = Get-ChildItem $Path *.msg | select FullName
    $files | % {
        $msgFn = $_.FullName
        $msg = $outlook1.CreateItemFromTemplate($msgFn)
        $msg.Attachments | % {
                
            # Give attachment filename
            $attFn = $msgFn -replace '\.msg$', " - Attachment - $($_.FileName)"

            # Save attachment and move to Out directory
            $_.SaveAsFile($attFn)
            mv $attFn 'Out\'
        }
    }
    
    # Extract Links From Attachments
    Write-Host -Fore Green "Extracting Links from Attachments..."
    $links = @()
    $outlook2 = New-Object -ComObject Outlook.Application
    $attachments = Get-ChildItem -Path '.\Out' *.msg | select FullName
    $attachments | % {
        $msgFn = $_.FullName
        $msg = $outlook2.CreateItemFromTemplate($msgFn)
        $rlink = $msg.Body | select-string -pattern '(ht|f)tp(s?)\:\/\/[\p{N}\p{L}]([-.\w]*[\p{N}\p{N1}\p{No}\p{L}])*(:(0-9)*)*(\/?)([\p{L}\p{N}\p{N1}\p{No}\-\.\?\,\/\\\+&amp;%\$#_]*)' | % {$_.Matches} | %{$_.Value}
        if ($rlink) { $links += $rlink.trim('<>') }
    }
    if ($links) {
        Set-Content -Path 'Out\Links.txt' -Value $links
    }
}
Strip-ForCuckoo -Path ($Path)
