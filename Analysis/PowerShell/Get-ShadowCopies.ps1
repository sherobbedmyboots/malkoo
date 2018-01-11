$shadowCopies = gwmi win32_ShadowCopy | select ID,InstallDate

$shadowCopies | foreach {
    $strtime = ($_.InstallDate).substring(0,8)
    $Copy_Date = ([datetime]::ParseExact($strtime,"yyyyMMdd",$null)).toshortdatestring() 
    $_.InstallDate = $Copy_Date
}

$shadowCopies | ft -auto