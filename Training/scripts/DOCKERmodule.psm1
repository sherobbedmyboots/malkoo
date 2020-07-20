

function Get-AuthorizationHeader {
	[Cmdletbinding()]
    [OutputType([hashtable])]
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$repoimage,

        [Parameter(Position=1,Mandatory=$true)]
        [string]$endpoint
    )

    if ($endpoint -eq "index.docker.io") {
        $endpoint = "auth.docker.io"
        $reg_endpoint = "registry.docker.io"
    }

    $uri = ("https://$endpoint/token?service=$reg_endpoint&scope=repository:{0}:pull" -f $repoimage)
    $AuthResponse = Invoke-RestMethod -Method GET -Uri $uri -UserAgent "xxxxxxx"

    Write-Output  @{"Authorization" = "Bearer $($AuthResponse.access_token)"}
}

function Get-RepoImages {
    [Cmdletbinding()]
    [OutputType([string[]])]
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$endpoint
    )

    [hashtable]$headers = @{}
    $headers.Add("Accept","application/vnd.docker.distribution.manifest.v2+json")
    $uri = "https://$endpoint/v2/_catalog"
    $res = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -UserAgent "Go-xxxxxxx"
    $res.repositories | ForEach-Object{
        Write-Output "$_"
    }
}

function Get-ImageTags {
    [Cmdletbinding()]
    [OutputType([string[]])]
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$repoimage,

        [Parameter(Position=1,Mandatory=$true)]
        [string]$endpoint
    )

    try {$headers = (Get-AuthorizationHeader -repoimage $repoimage -endpoint $endpoint)}
    catch {[hashtable]$headers = @{}}

    $headers.Add("Accept","application/vnd.docker.distribution.manifest.v2+json")
    $uri = "https://$endpoint/v2/$repoimage/tags/list"
    $res = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -UserAgent "Go-xxxxxxx"
    $res.tags | ForEach-Object{
        Write-Output "$($repoimage):$_"
    }
}

function Get-ImageManifest {
    [Cmdletbinding()]
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$repoimagetag,

        [Parameter(Position=1,Mandatory=$true)]
        [string]$endpoint
    )

    $repoimage = $repoimagetag.split(':')[0]
    $imagetag = $repoimagetag.split('/')[1]
    $tag = $repoimagetag.split(':')[1]
    $repo = $repoimage.split('/')[0]
    $image = $repoimage.split('/')[1]
    
    try {$headers = (Get-AuthorizationHeader -repoimage $repoimage -endpoint $endpoint)}
    catch {[hashtable]$headers = @{}}

    $headers.Add("Accept","application/vnd.docker.distribution.manifest.v2+json")

    $uri = "https://$endpoint/v2/$repoimage/manifests/$tag"
    Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -UserAgent "Go-xxxxxxx"
}

function Get-ImageLayers {
    [Cmdletbinding()]
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$repoimagetag,

        [Parameter(Position=1,Mandatory=$true)]
        [string]$endpoint
    )

    $repoimage = $repoimagetag.split(':')[0]
    $imagetag = $repoimagetag.split('/')[1]
    $tag = $repoimagetag.split(':')[1]
    $repo = $repoimage.split('/')[0]
    $image = $repoimage.split('/')[1]

    $manifest = Get-ImageManifest -repoimagetag $repoimagetag -endpoint $endpoint

    if ($manifest.schemaVersion -eq 1){
        $layers = $manifest.fsLayers.blobSum | Select -Unique
    }
    elseif ($manifest.schemaVersion -eq 2){
        $layers = $manifest.layers.digest
    }
    else {
        Write-Host -Fore Red "EXITING: " -NoNewLine; Write-Host "Could not read schemaVersion"
        Break
    }
    
    [array]$all_layers = @()
    
    Foreach ($layer in $layers) {
        try {$headers = (Get-AuthorizationHeader -repoimage $repoimage -endpoint $endpoint)}
        catch {[hashtable]$headers = @{}}

        $headers.Add("Accept","application/vnd.docker.distribution.manifest.v2+json")
        $uri = "https://$endpoint/v2/$repoimage/blobs/$layer"
        
        
        $blob = Invoke-WebRequest -Method GET -MaximumRedirection 0 -ErrorAction Ignore -Uri $uri -Headers $headers -UserAgent "xxxxxxx" 

        if ($blob.StatusDescription -Match "Redirect") {
            $uri = $blob.Headers.Location
            $blob = Invoke-WebRequest -Method GET -MaximumRedirection 0 -ErrorAction Ignore -Uri $uri -Headers $headers -UserAgent "xxxxxxx"
        }

        $size = ($blob.Content).Length

        $all_layers += New-Object -TypeName psobject -Property @{
            Name    = $layer.split(':')[1]
            Size    = $size
            Data    = $blob.Content
        }
      
        $num = $layers.IndexOf("$layer")
        Write-Host -Fore DarkRed "    => " -NoNewLine; Write-Host "Layer ($num): " -NoNewLine; Write-Host -Fore DarkGreen $layer -NoNewLine; Write-Host " Size: $size"
    }
    return $all_layers
}

function Get-ImageConfig {
    [Cmdletbinding()]
    [OutputType([string[]])]
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$repoimage,

        [Parameter(Position=1,Mandatory=$true)]
        [string]$endpoint,

        [Parameter(Position=2,Mandatory=$true)]
        [string]$config_name
    )

    try {$headers = (Get-AuthorizationHeader -repoimage $repoimage -endpoint $endpoint)}
    catch {[hashtable]$headers = @{}}

    $headers.Add("Accept","application/vnd.docker.distribution.manifest.v2+json")
    $uri = "https://$endpoint/v2/$repoimage/blobs/$config_name"
    $res = Invoke-WebRequest -Method GET -MaximumRedirection 0 -ErrorAction Ignore -Uri $uri -Headers $headers -UserAgent "xxxxxxx"
        
    if ($res.StatusDescription -Match "Redirect") {
        $uri = $res.Headers.Location
        $res = Invoke-WebRequest -Method GET -MaximumRedirection 0 -ErrorAction Ignore -Uri $uri -Headers $headers -UserAgent "xxxxxxx"
    }

    $config_name = ($config_name.split(':')[1]) + ".json"
    $props = @{
        Name    = $config_name
        Data    = $res.Content
    }
    $config = New-Object -TypeName psobject -Property $props
    $config 
}

function Get-DockerImage {
    [Cmdletbinding()]
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$repoimagetag,
        
        [Parameter(Position=1)]
        [string]$endpoint,

        [switch]$tar
    )
    
    if (!($endpoint)) {
        $endpoint = "index.docker.io"
    }

    if (!($repoimagetag.contains('/'))){
        $repoimagetag = "library/" + $repoimagetag
    }

    if (!($repoimagetag.contains(':'))) {
        $repoimagetag = $repoimagetag + ":latest"
    }

    $repo = $repoimagetag.split('/')[0]
    $imagetag = $repoimagetag.split('/')[1]
    $repoimage = $repoimagetag.split(':')[0]
    $image = $imagetag.split(':')[0]
    $tag = $imagetag.split(':')[1]

   
    $origpath = $pwd.Path
    $image_dir = $origpath + '\' + $repo + '\' + $image
    New-Item -Type Directory -Name $repo -Force | Out-Null
    New-Item -Type Directory -Name "$repo\$image" -Force | Out-Null

    # Get sha256 hash of string
    Function Get-StringHash([String] $String) { 
        $StringBuilder = New-Object System.Text.StringBuilder 
        [System.Security.Cryptography.HashAlgorithm]::Create("SHA256").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
            [Void]$StringBuilder.Append($_.ToString("x2")) 
        } 
        $StringBuilder.ToString() 
    }

    # Get manifest
    $manifest = Get-ImageManifest -repoimagetag $repoimagetag -endpoint $endpoint

    # Get config
    switch ($manifest.schemaVersion) {
        1 {
            $lcount = ($manifest.fslayers.blobSum | Select -Uniq).Count
            
            $last_config = $manifest.history.V1Compatibility | ConvertFrom-Json | sort created | select -last 1

            $history = $manifest.history.V1Compatibility | ConvertFrom-Json | select created,container_config

            $rootfs = New-Object -TypeName psobject -Property @{
                "type"                  = "layers";
                "diff_ids"              = ($manifest.fslayers.blobSum | Select -Uniq);
            }

            $hist_objs = @()
            $history | %{
                $cmds = $_.container_config | Select Cmd
                $joined_cmds = $cmds | %{$_.cmd -join(' ')}

                $hist_objs += New-Object -TypeName psobject -Property @{
                    "created"           = $_.created;
                    "created_by"        = $joined_cmds;
                }
            }

            $config_obj = New-Object -TypeName psobject -Property @{
                "architecture"          = $manifest.architecture;
                "config"                = $last_config.config;
                "container"             = $last_config.container;
                "container_config"      = $last_config.container_config;
                "created"               = $last_config.created;
                "docker_version"        = $last_config.docker_version;
                "history"               = $hist_objs;
                "os"                    = $last_config.os;
                "rootfs"                = $rootfs;
            }

            $config_data = $config_obj | ConvertTo-Json
            $config_name = Get-StringHash($config_data)
            $config_name += ".json"
            $config_path = "$image_dir\$config_name"
            Set-Content -Value $config_data -Path $config_path
        }
        
        2 { 
            $lcount = ($manifest.layers.digest).Count
            $config_name = $manifest.config.digest
            try {
                $config = Get-ImageConfig -repoimage $repoimage -endpoint $endpoint -config_name $config_name
            }
            catch {
                Write-Host -Fore Red "EXITING: " -NoNewLine; Write-Host "Could not download config file"
                Break
            }
            $config_name = $config.Name
            $config_data = $config.Data
            $config_path = "$image_dir\$config_name"
            [System.IO.File]::WriteAllBytes($config_path,$config_data)
        }
        
        default {
            Write-Host -Fore Red "EXITING: " -NoNewLine; Write-Host "Could not read schemaVersion"
            Break
        } 
    }

    # Write-Host -Fore DarkRed "=> " -NoNewLine; Write-Host "Obtained manifest for " -NoNewLine; Write-Host -Fore DarkGreen $repoimagetag
    Write-Host -Fore DarkRed "=> " -NoNewLine; Write-Host "Fetching $lcount layers"
    
    # Get layers
    [array]$layers = Get-ImageLayers -repoimagetag $repoimagetag -endpoint $endpoint
    # $l2count = $layers.Count
    # if ($lcount -ne $l2count) {
    #     Write-Host -Fore Red "EXITING: " -NoNewLine; Write-Host "Could not download all layers"
    #     Break
    # }

    # Decompress layers
    [array]$combined_layers = @()
    Foreach ($layer in $layers) {
        
        $layer_name = $layer.Name
        $layer_data = $layer.Data
        $layer_dir ="$repo\$image\$layer_name"

        New-Item -Type Directory -Name $layer_dir -Force | Out-Null
        $zipped = $layer_dir + "\layer.tar.gz"
        
        [System.IO.File]::WriteAllBytes($zipped,$layer_data)
       
        if (!(Get-Command gunzip 2>$null)) {
            Write-Host -Fore Red "EXITING: " -NoNewLine; Write-Host "Required program not installed or not in path: " -NoNewLine; Write-Host -Fore Yellow "gunzip"
            Break
        }
        if (!(Get-Command bash 2>$null)) {
            Write-Host -Fore Red "EXITING: " -NoNewLine; Write-Host "Required program not installed or not in path: " -NoNewLine; Write-Host -Fore Yellow "bash"
            Break
        }

        $layerpath = "$image_dir\$layer_name"
        $gzpath = $layerpath -replace '\\','/' -replace ':',''
        Start-Process -WindowStyle Hidden "C:\Program Files\Git\bin\bash.exe" -ArgumentList "gunzip /$gzpath/layer.tar.gz"
        $combined_layers += "$layer_name/layer.tar"
    }

    # Build manifest file
    # Write-Host -Fore DarkRed "=> " -NoNewLine; Write-Host "Creating manifest file " -NoNewLine; Write-Host -Fore DarkGreen "manifest.json"
    $combined_tars = $combined_layers -join "`", `""
    Set-Content -Path "$image_dir\manifest.json" -Value "[{" 
    Add-Content -Path "$image_dir\manifest.json" -Value "    `"Config`": `"$config_name`","
    Add-Content -Path "$image_dir\manifest.json" -Value "    `"RepoTags`" : [`"$imagetag`"],"
    Add-Content -Path "$image_dir\manifest.json" -Value "    `"Layers`" : [`"$combined_tars`"]"
    Add-Content -Path "$image_dir\manifest.json" -Value "}]"
    
    # Create tar file
    $tarname = $image + ".tar"

    if (!(Get-Command tar 2>$null)) {
            Write-Host -Fore Red "EXITING: " -NoNewLine; Write-Host "Required program not installed or not in path: " -NoNewLine; Write-Host -Fore Yellow "tar"
            Break
    }
    
    # Write-Host -Fore DarkRed "=> " -NoNewLine; Write-Host "Creating tar file " -NoNewLine; Write-Host -Fore DarkGreen $tarname

    $arguments = @("$image_dir","$tarname")
    $scriptblock = {cd $($args[0]); tar -cvf $($args[1]) $(Get-ChildItem . -Exclude *.tar).Name}
    $j = Start-Job -ScriptBlock $scriptblock -ArgumentList $arguments | Wait-Job
    if ($j.State -eq "Completed") {
        # Write-Host -Fore DarkRed "=> " -NoNewLine; `
        # Write-Host "Docker image " -NoNewLine; `
        # Write-Host -Fore DarkGreen $repoimagetag -NoNewLine;  `
        # Write-Host " saved to " -NoNewLine; `
        # Write-Host -Fore DarkGreen "$image_dir\$tarname"
    }
    else {
        Write-Host -Fore Red "=> " -NoNewLine; Write-Host "Job to create tar file failed. Exiting"
        Break
    }

    # Loading into Docker
    if (!($tar)) {
        if (!(Get-Command docker 2>$null)) {
            Write-Host -Fore Red "EXITING: " -NoNewLine; Write-Host "Required program not installed or not in path: " -NoNewLine; Write-Host -Fore Yellow "docker"
            Break
        }
        
        # Write-Host -Fore DarkRed "=> " -NoNewLine; `
        # Write-Host "Loading " -NoNewLine; `
        # Write-Host -Fore DarkGreen "$image_dir\$tarname" -NoNewLine; `
        # Write-Host " into Docker" 
        
        $arguments = @("$image_dir","$tarname")
        $scriptblock = {cd $($args[0]); docker load -i $($args[1])}
        $k = Start-Job -ScriptBlock $scriptblock -ArgumentList $arguments | Wait-Job
        if ($k.State -eq "Completed") {
            Write-Host -Fore DarkRed "=> " -NoNewLine; `
            Write-Host "Docker image " -NoNewLine; `
            Write-Host -Fore DarkGreen $repoimagetag -NoNewLine;  `
            Write-Host " successfully loaded" -NoNewLine; 
        }
        else {
            Write-Host -Fore Red "=> " -NoNewLine; Write-Host "Job to create tar file failed. Exiting"
            Break
        }
    }
}

function Get-InspectContainersInfo {

    $containerinfo = &{docker ps -a} | select -skip 1
    $ids = foreach ($line in $containerinfo) {(-split $line)[0]}  

    [array]$global:inspectContainers = @()

    Foreach ($id in $ids) {

        [array]$cinspect = docker inspect $id | ConvertFrom-Json
        
        function ToTime ($tim) {
            return [datetime]$tim.ToString()
        }

        [array]$diffs = docker diff $id 
        [array]$logs = docker logs $id
        [array]$ports = docker port $id 
        [array]$procs = docker top $id 2>$null

        $cobj = New-Object -Type psobject -Property @{
            Name            = $cinspect.Name;
            Id              = $cinspect.Id;
            Hostname        = $cinspect.Config.Hostname;
            State           = $cinspect.State.Status;
            Command         = $cinspect.Config.Cmd;
            CreatedAt       = (ToTime $cinspect.Created);
            StartedAt       = ToTime $cinspect.State.StartedAt;
            FinishedAt      = ToTime $cinspect.State.FinishedAt;
            RestartCount    = $cinspect.RestartCount;
            ChangedFiles    = $diffs;
            Logs            = $logs;
            Mounts          = $cinspect.Mounts;
            MountLabel      = $cinspect.MountLabel;
            Ports           = ($ports -join ', ');
            Processes       = $procs;
            Platform        = $cinspect.Platform;
            IPv4Gateway     = $cinspect.NetworkSettings.Gateway;
            IPv4Address     = $cinspect.NetworkSettings.IPAddress;
            IPv6Gateway     = $cinspect.NetworkSettings.IPv6Gateway;
            IPv6Address     = $cinspect.NetworkSettings.ClobalIPv6Address;
            MACAddress      = $cinspect.NetworkSettings.MacAddress;
            LogPath         = $cinspect.Logpath;
            HostsPath       = $cinspect.HostsPath;
            HostnamePath    = $cinspect.HostnamePath;
            ImageDigest     = $cinspect.Image;
            ImageName       = $cinspect.Config.Image;
        }
        $global:inspectContainers += $cobj
    }

    $global:inspectContainers | Select ImageName,Platform,IPv4Address,Command,CreatedAt,StartedAt,State | ft -auto

    Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Full container data available in global `$inspectContainers variable"`n
}


function Get-InspectImagesInfo {

    $imagesinfo = &{docker images} | select -skip 1
    $ids = foreach ($line in $imagesinfo) {(-split $line)[2]}  

    [array]$global:inspectImages = @()

    Foreach ($id in $ids) {

        [array]$iinspect = docker inspect $id | ConvertFrom-Json

        $sizeMB = "$([math]::round($iinspect.Size / 1Mb, 1)) MB"
        $newdt = [datetime]$iinspect.Created.ToString()

        $iobj = New-Object -Type psobject -Property  @{
            ImageId             = $iinspect.Id;
            Author              = $iinspect.Author;
            ImageSize           = $sizeMB;
            VirtualSize         = $iinspect.VirtualSize;
            LayerCount          = $iinspect.Rootfs.Layers.Count;
            Layers              = $iinspect.Rootfs.Layers;
            ParentImageId       = $iinspect.Parent;
            Arch                = $iinspect.architecture;
            OS                  = $iinspect.Os;
            RepoTags            = $iinspect.RepoTags;
            Comment             = $iinspect.Comment;
            CreatedAt           = "$newdt";
            Container           = $iinspect.Container;
            ContainerHostname   = $iinspect.ContainerConfig.hostname;
            ContainerCmd        = ($iinspect.ContainerConfig.Cmd -join (', '));
            ContainerImage      = $iinspect.ContainerConfig.Image;
            DockerVersion        = $iinspect.DockerVersion;
        }

        $global:inspectImages += $iobj
    }
    
    $inspectImages  | Select RepoTags,ContainerHostname,OS,Arch,CreatedAt,LayerCount,ImageSize,Author| ft -auto
    
    Write-Host -Fore Green "[+] " -NoNewLine;Write-Host "Full images data available in global `$inspectImages variable"`n
}


function Get-ContainerChangedFiles {

    param (
        [string]$cid
    )
    if (Test-Path $ENV:TEMP\artifacts) {
        Remove-Item -Force -Recurse $ENV:TEMP\artifacts
    }
    $files = docker diff $cid
    $files = $files | ? {$_ -Match '^A'} | %{$_.split(' ')[1]}
    $d = mkdir $ENV:TEMP\artifacts
    

    $source = $cid + ":"
    $dest = $d.FullName + "\"
    $files | %{
        docker cp $source$_ $dest
    }

    $filenames = (Get-ChildItem $d.FullName).Fullname 
    [array]$artifacts = @()
    $filenames | % { 
        $artifacts += New-Object psobject -Property @{
                "Name" = $_.split('\')[-1];
                "Data" = $(Get-Content -Raw $_);
        }
    }
    Remove-Item -Force -Recurse $d
    return $artifacts
}

function Get-EnvironmentInfo {

}

function Get-DockerArtifacts {


    $changed_files = Get-ContainerChangedFiles
}




function tryHttps {
    param ([string]$h)

    $uri = "tcp://" + $h + ":2376"
    $res = docker -H $uri --tls info 2>&1
    if ($res.Exception){
        if ($res.Exception -match "did not properly respond"){
            Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $h ": No SYN/ACK received from 2376"
        }
        elseif ($res.Exception -match "no such host"){
            Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $h ": did not resolve to an IP"
        }
        elseif ($res.Exception -match "actively refused it"){
            Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $h ": refused the connection"
        }
        elseif ($res.Exception -match "forcibly closed"){
            Write-Host -Fore Green "[-] " -NoNewLine;Write-Host $h ": Port 2376 open, but connection was closed"
        }
        elseif (($res.Exception -match "Forbidden") -or ($res.Exception -match "logo.gif")){
            Write-Host "You're hitting the proxy... turn off with: "`n
            Write-Host `t"Remove-Item env:\HTTP_PROXY;Remove-Item env:\HTTPS_PROXY"
            Break
        }
        else {
            Write-Host $h ": " $res.Exception
        }
    }
    else {
        Write-Host $h ": " $res
    }
}

function tryHttp {
    param ([string]$h)

    $uri = "tcp://" + $h + ":2375"
    $res = docker -H $uri info 2>&1
    if ($res.Exception){
        if ($res.Exception -match "did not properly respond"){
            Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $h ": No SYN/ACK received from 2375"
        }
        elseif ($res.Exception -match "no such host"){
            Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $h ": did not resolve to an IP"
        }
        elseif ($res.Exception -match "actively refused it"){
            Write-Host -Fore Red "[-] " -NoNewLine;Write-Host $h ": refused the connection"
        }
        elseif ($res.Exception -match "forcibly closed"){
            Write-Host -Fore Green "[-] " -NoNewLine;Write-Host $h ": Port 2375 open, but connection was closed"
        }
        elseif (($res.Exception -match "Forbidden") -or ($res.Exception -match "logo.gif")){
            Write-Host "You're hitting the proxy... turn off with: "`n
            Write-Host `t"Remove-Item env:\HTTP_PROXY;Remove-Item env:\HTTPS_PROXY"
            Break
        }
        else {
            Write-Host $h ": " $res.Exception
        }
    }
    else {
        Write-Host $h ": " $res
    }
}


function Find-DockerHostsOnline {
    [array]$dhosts=@('host','host2')

    foreach ($h in $dhosts){
        tryHttp $h
        tryHttps $h
    }
}




# Export these functions
$funcs =  @('Get-AuthorizationHeader'
            'Get-RepoImages'
            'Get-ImageTags'
            'Get-ImageManifest'
            'Get-ImageLayers'
            'Get-ImageConfig'
            'Get-DockerImage'
            'Get-InspectImagesInfo'
            'Get-InspectContainersInfo'
            'Get-ContainerChangedFiles'
            'tryHttp'
            'tryHttps'
            'Find-DockerHostsOnline')

Export-ModuleMember -Function $funcs
