function New-AWApiPassword {
    Read-Host "Enter password" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "~\.airwatch.txt"
}

function Get-AWApi {

    <#
    .EXAMPLE
        PS C:\> New-AWApiPassword 
        Enter Password: ***********

        PS C:\> Get-AWApi mdm/devices/serialnumber/xxxxxxx

        Udid                             : xxxxxxxxxxxxxx
        SerialNumber                     : xxxxxxxxx
        MacAddress                       : xxxxxxxx
        Imei                             : xxxxxxx
        EasId                            :
        AssetNumber                      : xxxxxxx
        DeviceFriendlyName               : xxxxxxxx
        LocationGroupId                  : @{Id=; Uuid=xxxxxxx; Name=MD}
        LocationGroupName                : MacBook
        ...
        
    .EXAMPLE
        PS C:\> Get-AWApi system/info

    .SYNOPSIS
        Make API calls to AirWatch API

    .DESCRIPTION
        This script takes encrypted API keys and password and uses them to make API calls with AirWatch

        To store API key using SecureString:

        PS C:\> Read-Host "Enter API key" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "~\.airwatch_api.txt"

    .LINK
        https://

    .NOTES
        To see the examples, type: "Get-Help Get-AWApi -examples".
        For more information, type: "Get-Help Get-AWApi -detailed".
        For technical information, type: "Get-Help Get-AWApi -full".
    #>
    param
    (
        [Parameter(Mandatory = $true )]
        [string]$api,
        [switch]$post
    )

    # Check password
    $today = (Get-Date).ToShortDateString()
    $lastwrite = (Get-ChildItem "$env:USERPROFILE\.airwatch.txt").LastWriteTime.ToShortDateString()
    if ($lastwrite -lt $today) {
        Write-Host -Fore Red "[-] " -NoNewline;Write-Host "You need to enter a new password using New-AWApiPassword"
        Break
    }


    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://uscisprodconsole.awfed.com/api/' + $api
    $t = Get-Content "$env:USERPROFILE\.airwatch.txt"
    $u = Get-Content "$env:USERPROFILE\.airwatch_api.txt"
    $pw = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($($t | ConvertTo-SecureString)))
    $key = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($($u | ConvertTo-SecureString)))
    $pwstring = 'username:' + $pw
    try {
        $base64 = ConvertTo-Base64 -String $pwstring
    }
    catch {Write-Host "You need to import ConvertTo-Base64 function"}

    $headers = @{   'Authorization'="Basic $base64";
                    'aw-tenant-code'="$key";
                    'Accept'='application/json';
                    'version'='1'
                }
    if ($post) {
        try{
            Invoke-RestMethod -Uri $uri -Headers $headers -Method POST
        }
        catch {
            Write-Host -Fore Red "[-] " -NoNewline;Write-Host "Bad Request"
            Break
        }
    }
    else {
        try {
            Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
        }
        catch {
            Write-Host -Fore Red "[-] " -NoNewline;Write-Host "Bad Request"
            Break
        }
    }

}

function Get-AWGroupInfo {
    param(
        [string]$groupname,        
        [string]$groupid,        
        [string]$type
    )

    if (!($groupname -or $groupid -or $type)) {
        $output = (Get-AWApi system/groups/search).LocationGroups
        $output | %{
            Add-Member -InputObject $_ -NotePropertyName _Id -NotePropertyValue $_.Id.Value
        }
        $output | Select _Id,GroupId,Name,Users,Devices,LocationGroupType,CreatedOn | Sort GroupId | ft -auto
    }
    else {
        $base = "system/groups/search?"
        [array]$given=@()

        if ($groupname){$given += "name=$groupname"}
        if ($groupid){$given += "groupid=$groupid"}
        if ($type){$given += "type=$type"}
        if ($username){$given += "username=$username"}
        $sum = $given -join ('"&"')
        [string]$uri = $base + $sum
        $output = (Get-AWApi $uri).LocationGroups

        if ($output) {
            $output | %{
                Add-Member -InputObject $_ -NotePropertyName _Id -NotePropertyValue $_.Id.Value
            }

            $output | %{
                $children = Get-AWApi system/groups/$($_._Id)/children
                Add-Member -InputObject $_ -NotePropertyName Children -NotePropertyValue $children

                $tags = (Get-AWApi system/groups/$($_._Id)/tags).Tags
                Add-Member -InputObject $_ -NotePropertyName Tags -NotePropertyValue $tags
                
                $roles = Get-AWApi system/groups/$($_._Id)/roles
                Add-Member -InputObject $_ -NotePropertyName Roles -NotePropertyValue $roles

                $usercount = $($_.Users)
                Add-Member -InputObject $_ -NotePropertyName UserCount -NotePropertyValue $usercount

                $admincount = $($_.Admins)
                Add-Member -InputObject $_ -NotePropertyName AdminCount -NotePropertyValue $admincount

                $devicecount = $($_.Devices)
                Add-Member -InputObject $_ -NotePropertyName DeviceCount -NotePropertyValue $devicecount

                $_.PSObject.Properties.Remove('Users')
                $_.PSObject.Properties.Remove('Admins')
                $_.PSObject.Properties.Remove('Devices')

                $users = Get-AWApi system/groups/$($_._Id)/users
                $users = $users | ? LocationGroupId -eq "$($_._Id)"
                Add-Member -InputObject $_ -NotePropertyName Users -NotePropertyValue $users
                
                $admins = Get-AWApi system/groups/$($_._Id)/admins
                $admins = $admins | ? LocationGroupId -eq "$($_._Id)"
                Add-Member -InputObject $_ -NotePropertyName Admins -NotePropertyValue $admins
                
                $custom = (Get-AWApi system/groups/$($_._Id)/CustomAttributes).CustomAttribute
                Add-Member -InputObject $_ -NotePropertyName CustomAttribute -NotePropertyValue $custom
            }

            $output
        }
        else {
           Write-Host -Fore Red "[-] " -NoNewline;Write-Host "Bad Request" 
        }
    }
}

function Get-AWUserInfo {
    param(
        [string]$firstname,
        [string]$lastname,
        [string]$email,
        [string]$username
    )

    $base = "system/users/search?"
    [array]$given=@()
    if ($firstname){$given += "firstname=$firstname"}
    if ($lastname){$given += "lastname=$lastname"}
    if ($email){$given += "email=$email"}
    if ($username){$given += "username=$username"}
    $sum = $given -join ('"&"')
    [string]$uri = $base + $sum
    $output = (Get-AWApi $uri).Users

    $output | % {
        try {
            $security = (Get-AWApi mdm/devices/securityinfosearch?user=$($output.UserName)).SecurityInfo
            Add-Member -InputObject $_ -NotePropertyName Security -NotePropertyValue $security

            $devices = (Get-AWApi mdm/devices/search?user=$($output.UserName)).Devices
            Add-Member -InputObject $_ -NotePropertyName Devices -NotePropertyValue $devices

            $admininfo = (Get-AWApi system/admins/search?username=$($output.UserName)).Admins

            $lastlogon = $admininfo.LastLoginTimestamp
            Add-Member -InputObject $_ -NotePropertyName LastLogin -NotePropertyValue $lastlogon

            $roles = $admininfo.Roles
            Add-Member -InputObject $_ -NotePropertyName Roles -NotePropertyValue $roles

            $landingpage = $admininfo.InitialLandingPage
            Add-Member -InputObject $_ -NotePropertyName LandingPage -NotePropertyValue $landingpage
        }catch{}
    }
    $output
}

function Get-AWDeviceInfo {
    param(
        [string]$organizationgroupid,
        [string]$platform,
        [string]$deviceid
    )

    $base = "mdm/devices/extensivesearch?"
    [array]$given=@()
    if ($organizationgroupid){$given += "organizationgroupid=$organizationgroupid"}
    if ($platform){$given += "platform=$platform"}
    if ($deviceid){$given += "deviceid=$deviceid"}
    $sum = $given -join ('"&"')
    [string]$uri = $base + $sum
    $output = (Get-AWApi $uri).Devices

    
    $output | % {
        $certs = (Get-AWApi mdm/devices/$($output.DeviceId)/certificates).DeviceCertificates
        Add-Member -InputObject $_ -NotePropertyName Certificates -NotePropertyValue $certs

        $user = (Get-AWApi mdm/devices/$($output.DeviceId)/user).DeviceUser
        Add-Member -InputObject $_ -NotePropertyName UserInfo -NotePropertyValue $user

        $security = (Get-AWApi mdm/devices/security?searchby=deviceid"&"id=$($output.DeviceId))
        Add-Member -InputObject $_ -NotePropertyName Security -NotePropertyValue $security

        $apps = (Get-AWApi mdm/devices/$($output.DeviceId)/apps).DeviceApps
        Add-Member -InputObject $_ -NotePropertyName DeviceApps -NotePropertyValue $apps

        $profiles = (Get-AWApi mdm/devices/$($output.DeviceId)/profiles).DeviceProfiles
        Add-Member -InputObject $_ -NotePropertyName DeviceProfiles -NotePropertyValue $profiles

        $notes = (Get-AWApi mdm/devices/$($output.DeviceId)/notes).DeviceNotes
        Add-Member -InputObject $_ -NotePropertyName DeviceNotes -NotePropertyValue $notes
    }
    $output
}

function Get-AWApplicationInfo {
    param(
        [string]$appname
    )

    if (!($appname)) {
        $output = (Get-AWApi  mam/apps/search).Application
        $output | %{
            Add-Member -InputObject $_ -NotePropertyName _Id -NotePropertyValue $_.Id.Value
        }
        $output | Select _Id,AppType,Status,ApplicationSize,ApplicationName | Sort _Id | ft -auto
    }
    else {
        $base = "mam/apps/search?applicationname="
        [string]$uri = $base + $appname
        $appinfo = (Get-AWApi $uri).Application

        $appinfo | %{
            Add-Member -InputObject $_ -NotePropertyName _Id -NotePropertyValue $_.Id.Value
        }
        $appinfo
    }
}

# Export these functions
$funcs =  @('New-AWApiPassword'
            'Get-AWApi'
            'Get-AWGroupInfo'
            'Get-AWUserInfo'
            'Get-AWDeviceInfo'
            'Get-AWApplicationInfo')

Export-ModuleMember -Function $funcs
