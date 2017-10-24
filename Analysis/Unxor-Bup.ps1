param(
    [string] $bup
)

function Unxor-Bup{
    $key = "0x6a"
    $output = $bup + ".out"
    $bytes = [System.IO.File]::ReadAllBytes("$bup")
    for($i=0; $i -lt $bytes.count ; $i++){
        $bytes[$i] = $bytes[$i] -bxor $key
    }
    [System.IO.File]::WriteAllBytes("$output", $bytes)
    write-host "[+] " -fore green -nonewline; Write-host "File: " -nonewline; Write-host "$bup unxor'd and saved to $output"
}
Unxor-Bup -bup $bup 