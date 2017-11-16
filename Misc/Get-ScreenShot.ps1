# https://github.com/mikepruett3/psfetch/blob/master/psfetch.ps1
 
Function Take-Screenshot
{
    [CmdletBinding()]Param
    (
        [string]$Width,
        [string]$Height,
        [string]$Path
    )
 
    PROCESS
    {
        [Reflection.Assembly]::LoadWithPartialName("System.Drawing") > $Null
        $bounds = [Windows.Forms.SystemInformation]::VirtualScreen
        if ( $Path.EndsWith("\") ) {
            $Path = $Path.Substring(0,$Path.Length-1)
        }
 
        $stamp = get-date -f MM-dd-yyyy_HH_mm_ss
        $target = "$Path\screenshot-$stamp.png"
        $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height
        $graphics = [Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
        $bmp.Save($target)
        $graphics.Dispose()
        $bmp.Dispose()
    }
}
 
[void] [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")           
[void] [Reflection.Assembly]::LoadWithPartialName("System.Drawing")           
 
$ScreenWidth = 0
$ScreenHeight = 0
Add-Type -AssemblyName System.Windows.Forms
$DisplayCount = [System.Windows.Forms.Screen]::AllScreens.Bounds.Count
$Bounds = [System.Windows.Forms.Screen]::AllScreens | Select-Object -ExpandProperty Bounds
$ScreenWidth = $Bounds | Measure-Object -Property Width -Sum | Select-Object -ExpandProperty Sum
$ScreenHeight = $Bounds | Measure-Object -Property Height -Maximum | Select-Object -ExpandProperty Maximum
# $filepath = "\\\ScreenShots\"
$filepath = "C:\Users\pcuser\malkoo\misc\"
 
Take-Screenshot -Width $screenwidth -Height $screenheight -Path $filepath
 