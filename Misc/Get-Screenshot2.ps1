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
        Write-Host "The IP belongs to $firsttry"
        return $firsttry
    }
    else{
        Write-Host "The IP could not be resolved."
        Exit
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
