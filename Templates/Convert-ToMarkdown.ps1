<# 

Compromised Site    colddistance.com       -->
C2 Staging          concretebeard.com      -->   redirector #1         -->     C2 Server
C2 Operations       d0.awsstatic.com       -->   rogerdodgerroger.xyz  -->     C2 Server
C2 Persistence      puttysystemsinc.com    -->   redirector #2         -->     C2 Server


#>

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