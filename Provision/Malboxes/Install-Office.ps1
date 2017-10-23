$ToolsDir = "C:\Tools"
if ([Environment]::osversion.Version.Major -eq 10){
    try {
        Mount-DiskImage -imagepath $ToolsDir\OfficeProfessionalPlus_x64_en-us.img 
        $drive = (get-PSDrive | ? Description -eq "15.0.4420.1017").Root
        cd $drive
        .\setup.exe /config $ToolsDir\extra\config.xml
    }
    catch {
        7z e $ToolsDir\OfficeProfessionalPlus_x64_en-us.img -o"$ToolsDir"\Office -aoa
        $ToolsDir\Office\setup.exe  /config $ToolsDir\extra\config.xml
    }
}

if ([Environment]::osversion.Version.Major -eq 6){
    cd C:\Tools\OfficeProfessionalPlus_x64_en-us
    .\setup.exe /config C:\Tools\extra\config.xml
}




