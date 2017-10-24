param(
    [string] $bup
)

function Unxor-Bup{
    $key = "0x6a"
    
    write-host "[+] " -fore yellow -nonewline; Write-host "Unzipping bup file..."
    7z e $bup | Out-Null
    $files = @(".\File_0", ".\Details")

    write-host "[+] " -fore yellow -nonewline; Write-host "Unxoring files..."
    foreach ($file in $files){
        $output = $file + ".bin"
        $bytes = [System.IO.File]::ReadAllBytes($file)
        for($i=0; $i -lt $bytes.count ; $i++){
            $bytes[$i] = $bytes[$i] -bxor $key
        }
        [System.IO.File]::WriteAllBytes("$output", $bytes)
    }

    $p = Select-String -path ".\Details.bin" -pattern 'OriginalName'
    $o = ($p | %{$_ -split("\\")})[-1]
    mv ".\File_0.bin" ".\$o"
    mv ".\Details.bin" ".\Details.txt"
    foreach ($file in $files){
        rm -fo $file
    }
    write-host "[+] " -fore green -nonewline; Write-host "File extracted: " -nonewline; Write-host -fore green "    $o"
    write-host "[+] " -fore green -nonewline; Write-host "File information: " -nonewline; Write-host -fore green "  Details.txt"
}
Unxor-Bup -bup $bup 