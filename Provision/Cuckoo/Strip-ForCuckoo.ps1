function Main
{
    Param($Path)

    # Extract attachments and save in .\Out
    createOutDir
    $outlook1 = New-Object -ComObject Outlook.Application
    $files = Get-ChildItem $Path *.msg | select -exp FullName
    $files | %{
        extractAttAndWrite($_)
    }

    # Extract links from attachments
    $outlook2 = New-Object -ComObject Outlook.Application
    $atts = Get-ChildItem Out *.msg | select -exp FullName
    $results = @()
    $atts | %{
        $links = extractLinks($_)
        $results += New-Object -TypeName psobject -Property @{EmailName=$_.split('\')[-1]; Links=$links; LinkCount=$links.count}
    }

    # Write results to Links.txt
    writeLinksFile($results)
}

function createOutDir(){
    if (Test-Path Out) {
        Remove-Item -Recurse -Force Out | Out-Null
    }
    New-Item -ItemType 'Directory' -Path Out -Force | Out-Null
}

function extractAttAndWrite($msgFile) {
    
    Write-Host -Fore Green "[+] " -NoNewLine; Write-Host Reading: $msgFile
    $msg = $outlook1.CreateItemFromTemplate($msgFile)
    $msg.Attachments | % {
        
        # Give attachment filename
        $attFn = $(pwd).path + '\Out\' + $_.FileName

        # Save attachment in Out directory
        $_.SaveAsFile($attFn)
    }
}

function extractLinks($msgFile) {

    $msg = $outlook2.CreateItemFromTemplate($msgFile)
    $links = searchForUrl($msg.body)
    $links = $links | select -Unique
    $links | %{
        $sanUrl = desensitizeUrl($_)
        $_ = $sanUrl
    }
    return $links
}

function searchForUrl($body) {
    $regex = '\b(?:(?:https?|ftp|file)://|www\.|ftp\.)(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[A-Z0-9+&@#/%=~_|$])'
    $hits = $body | select-string -AllMatches -pattern $regex  | % {$_.Matches} | %{$_.Value}
    return $hits
}

function desensitizeUrl($url) {
    $regex = '(\w+\.){1,}\w+@(\w+\.){0,}dhs\.gov'
    $hits = $url | select-string -AllMatches -pattern $regex | %{$_.Matches} |%{$_.Value}
    if ($hits) {
        foreach ($hit in $hits){
            if ($hit.contains('@')){
                $url = $url.replace($hit, 'bubba.t.merica@freedom.com')
            }
            else {
                $url = $url.replace($hit, 'mail.example.com')
            }
        }
    }
    return $url
}

function writeLinksFile($results) {
    
    $outpath = $(pwd).path + '\Out\Links.txt'
    
    Add-Content -path $outpath -value "###########################################`r`n"
    Add-Content -path $outpath -value "##     Number of Links in Each Email     ##`r`n"
    Add-Content -path $outpath -value "###########################################`r`n"
    $results | select LinkCount, EmailName | sort -desc LinkCount | Out-File -Append $outpath -Encoding ASCII

    Add-Content -path $outpath -value "`r`n###########################################`r`n"
    Add-Content -path $outpath -value "##     List of Links Sorted By Email     ##`r`n"
    Add-Content -path $outpath -value "###########################################`r`n`r`n"
    $results | ? LinkCount -gt '0' | sort LinkCount | %{
        Add-Content -path $outpath -value ("<<<<<  " + $_.EmailName + "  >>>>>")
        Add-Content -path $outpath -value "`r`n-------------------------------------------------------------------------------------------------------`r`n"
        Add-Content -path $outpath -value $_.Links
        Add-Content -path $outpath -value "`r`n`r`n`r`n"  
    }

    Add-Content -path $outpath -value "`r`n############################################`r`n"
    Add-Content -path $outpath -value "##  List of Unique Links in All Emails    ##`r`n"
    Add-Content -path $outpath -value "############################################`r`n"
    Add-Content -path $outpath -value $results.Links 
}

Main -Path ($Path)
