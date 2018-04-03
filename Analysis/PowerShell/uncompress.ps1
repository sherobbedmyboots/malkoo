function Convert-EncodedFile ($encodedstring) {

    $encodedstring = $(cat compressed.txt)
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





