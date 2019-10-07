param
(
    [Parameter(Mandatory = $True)]
    [string]$ipaddress
)



function Get-Hostsname
{        
    param
    (
        [Parameter(Mandatory = $True)]
        [string]$ipaddress
    )

    $firsttry = (Resolve-DnsName $ipaddress).NameHost
    if ($firsttry)
    {
        Write-Host "[+]" -Fore Green -NoNewLine; Write-Host "The IP belongs to $firsttry"
        return $firsttry
    }
    else{
        Write-Host "[+]" -Fore Yellow -NoNewLine; Write-Host "No reverse record found... trying ping..."
        $secondtry = (Test-Connection -Count 1 $ipaddress).PSComputerName
        if ($secondtry){
            Write-Host "[+]" -Fore Green -NoNewLine; Write-Host "The IP belongs to $secondtry"
            return $secondtry
        }
        else{
            Write-Host "[+]" -Fore Yellow -NoNewLine; Write-Host "Can't find using ping... trying port 8081..."
            $thirdtry = wget $ipaddress | sls hostsname
            if ($thirdtry){
                Write-Host "[+]" -Fore Green -NoNewLine; Write-Host "The IP belongs to $thirdtry"
                return $thirdtry
            }
            else{
                Write-Host "[+]" -Fore Yellow -NoNewLine; $tellme = Read-Host "Can't find using port 8081... Enter the hostname:"
                Write-Host "[+]" -Fore Green -NoNewLine; Write-Host "You entered: $tellme"
                return $tellme
            }
        }
    }
}


$GetScreenshot2 = {
    Add-Type -Assembly System.Windows.Forms;
    $ScreenBounds = [Windows.Forms.SystemInformation]::VirtualScreen;
    $ScreenshotObject = New-Object Drawing.Bitmap $ScreenBounds.Width, $ScreenBounds.Height;
    $DrawingGraphics = [Drawing.Graphics]::FromImage($ScreenshotObject);
    $DrawingGraphics.CopyFromScreen( $ScreenBounds.Location, [Drawing.Point]::Empty, $ScreenBounds.Size);
    $DrawingGraphics.Dispose();
    $ms = New-Object System.IO.MemoryStream;
    $Time = (Get-Date);
    [String] $FileName = "$($Time.Month)";
    $FileName += '-';
    $FileName += "$($Time.Day)"; 
    $FileName += '-';
    $FileName += "$($Time.Year)";
    $FileName += '-';
    $FileName += "$($Time.Hour)";
    $FileName += '-';
    $FileName += "$($Time.Minute)";
    $FileName += '-';
    $FileName += "$($Time.Second)";
    $FileName += '.png';
    $Path = "C:\";
    [String] $FilePath = (Join-Path $Path $FileName);
    $ScreenshotObject.Save($FilePath);
    $ScreenshotObject.Dispose();
}


function Connect-AndStart
{
    param
    (
        [Parameter(Mandatory = $True)]
        [string]$hostsname
    )
    $cred = Get-Credential "host\name"
    Invoke-Command -ComputerName $hostsname -ScriptBlock $GetScreenShot2 -Credential $cred

}

$hostsname = Get-Hostsname $ipaddress
Connect-AndStart $hostsname
