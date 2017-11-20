$ToolsDir = "C:\Tools"

if (Test-Path 'C:\Program Files\Microsoft Office'){
    
    # If image is already mounted, uninstall

    $drive = (get-PSDrive | ? Description -eq "15.0.4420.1017").Root
    if ($drive) {    
        cd "$drive"
        .\setup.exe /uninstall ProPlus
    }

    # If not, mount image and uninstall

    else{
        try {
			Mount-DiskImage -imagepath $ToolsDir\OfficeProfessionalPlus_x64_en-us.img 
		    $newdrive = (get-PSDrive | ? Description -eq "15.0.4420.1017").Root
			cd $newdrive
			.\setup.exe /uninstall ProPlus
		}
		catch {
			7z e $ToolsDir\OfficeProfessionalPlus_x64_en-us.img -o"$ToolsDir"\Office -aoa
			$ToolsDir\Office\setup.exe /uninstall ProPlus
        }
    }
}

# Install Office Professional Plus


# If image is not already mounted, mount it

$drive = (get-PSDrive | ? Description -eq "15.0.4420.1017").Root

if(!($drive)) {    
    try {
			Mount-DiskImage -imagepath $ToolsDir\OfficeProfessionalPlus_x64_en-us.img 
		    $newdrive = (get-PSDrive | ? Description -eq "15.0.4420.1017").Root
			cd $newdrive
			.\setup.exe /config $ToolsDir\extra\config.xml
	}
	catch {
	    7z e $ToolsDir\OfficeProfessionalPlus_x64_en-us.img -o"$ToolsDir"\Office -aoa
		$ToolsDir\Office\setup.exe	/config $ToolsDir\extra\config.xml
    }
}

# If image already mounted, install

else{
    cd "$drive"
    .\setup.exe /config $ToolsDir\extra\config.xml
}

