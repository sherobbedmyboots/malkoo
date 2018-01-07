Param ($File)
 
Function Convert-ToMarkdown ( $File )
{
    $content = (gc $File -encoding UTF8) -replace "(^\d\.)(\s+)",'$1 '
    $content = $content -replace "(^\-)(\s+)",'$1 '
    $content = $content -replace "(^o)(\s+)",'    - '
    $content = $content -replace "(cid:\w+\d+\.\w{3}\@.*)","![](images/$File/image001.png)"
    $content = $content -replace "\n",""

    $content | Out-File ".\New-File.md"
        
}
Convert-ToMarkdown -File $File