
$regions = @('us-east-2'
'us-east-1'
'us-west-1'
'us-west-2'
'ap-south-1'
'ap-northeast-3'
'ap-northeast-2'
'ap-southeast-1'
'ap-southeast-2'
'ap-northeast-1'
'ca-central-1'
'cn-north-1'
'cn-northwest-1'
'eu-central-1'
'eu-west-1'
'eu-west-2'
'eu-west-3'
'sa-east-1'
)

[hashtable]$accounts = [Ordered]@{
        "xxxxxxxxx"  = @('prod','nonprod','[poc')
}

$ErrorActionPreference = "SilentlyContinue"

function Get-AwsId {
    param 
    (
        [ValidateLength(12,12)][String]$accountid    
    )
    $accounts.Item($accountid)[0]
}


function Test-AwsPowerShell {
    if (!($(Get-Module AWSPowerShell))) {
        Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "AWSPowerShell module not installed... Exiting!"
        Break
    }
}

function Test-CredentialFile {
    if (!(Test-Path $env:USERPROFILE\.aws\credentials)) {
        Write-Host -Foreground Gray "[-] " -NoNewLine; Write-Host "$env:USERPROFILE\.aws\credentials file not found... creating."
        New-Item -Type File -Value '' -Path "$env:USERPROFILE\.aws\credentials" -Force | Out-Null 
    }
}

function Expand-Zip {
    param (
        [parameter(Mandatory = $true,ValueFromPipelineByPropertyName,ValueFromPipeline)]
        $zip
    )

    $TempFile1 = Set-Content -Value $zip -Path "${Env:\TEMP}\$(Get-Random).zip" -PassThru
    $TempFile2 = (Expand-Archive -Path $TempFile1.PSPath -Destination "${Env:\TEMP}" -Verbose 4>&1 | sls "'.*'").Matches.Value.Trim("'")
    Remove-Item -Force $TempFile1.PSPath 
    return $TempFile2
}

function ConvertTo-Base64
{
    param (
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$String,
        
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [switch]$unicode
    )

    if ($unicode) {
        Write-Output ([System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($String)))
    }
    else {
        Write-Output ([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($String)))
    }
    
}

function ConvertFrom-Base64
{
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Base64String,
        
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [switch]$unicode
    )

    if ($unicode){
       $stringBytes = [System.Convert]::FromBase64String($Base64String)
       Write-Output ([System.Text.Encoding]::Unicode.GetString($stringBytes))
    }
    else {
        $stringBytes = [System.Convert]::FromBase64String($Base64String)
        Write-Output ([System.Text.Encoding]::ASCII.GetString($stringBytes))
    }
}


function Expand-Gz {
    param
    (
    [string]$gz
    )

    $t = New-Object System.IO.FileStream "$gz", ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $Stream = New-Object -TypeName System.IO.MemoryStream
    $GZipStream = New-Object -TypeName System.IO.Compression.GZipStream -ArgumentList $t, ([System.IO.Compression.CompressionMode]::Decompress)
    $buffer = New-Object byte[](1024)
    $count = 0
    do {
        $count = $gzipstream.Read($buffer, 0, 1024)
        if ($count -gt 0) {
            $Stream.Write($buffer, 0, $count)
        }
    }
    While ($count -gt 0)
    $array = $stream.ToArray()
    $GZipStream.Close()
    $stream.Close()
    $t.Close()
    $unzipped = [System.Text.Encoding]::ASCII.GetString($array)
    return $unzipped
}

function Get-AWSPOCUpdate {
    <#
    save as a CSV
    #>
    param
    (
        [Parameter(Mandatory = $true )]
        [string]$csvfile
    )

    $csv = Get-Content $csvfile | ConvertFrom-Csv | sort AccountId;

    Write-Host "[hashtable]`$accounts = [Ordered]@{";
    foreach ($x in ($csv | sort AccountId)) {
        Write-Host "`t`"$($x.AccountId)`"`t= @(`'$($x.AccountName)`',`'$($x.RootAccountEmailAddress)`',`'$($x.Poc)`')"
    };
    Write-Host "}"
}

function Get-SamlResponse {

    Write-Host -NoNewline [-] -ForegroundColor Gray ; Write-Host " Attempting to obtain SAML response"

    $r = iwr $first_url -UseBasicParsing -UseDefaultCredentials -SessionVariable t

    $r2 = iwr $second_url -UseBasicParsing -UseDefaultCredentials -WebSession $t -Method POST -Body @{'SAMLRequest'=$r.InputFields[0].VALUE}

    $r3 = iwr $third_url -UseBasicParsing -UseDefaultCredentials -WebSession $t -Method POST -Body @{'_eventId'="proceed";'SAMLRequest'=$r2.InputFields[0].VALUE;'e
    xecution'=$r2.InputFields[1].VALUE}

    $r4 = iwr $fourth_url -UseBasicParsing -UseDefaultCredentials -WebSession $t -Method POST -Body @{'_eventId_proceed'=''}
    
    $aa2 = iwr $second_url -UseBasicParsing -UseDefaultCredentials -WebSession $u -Method POST -Body @{'SAMLRequest'=$aa.InputFields[0].VALUE}

    $aa3 = iwr $third_url -UseBasicParsing -UseDefaultCredentials -WebSession $u -Method POST -Body @{'_eventId'="proceed";'SAMLRequest'=$aa2.InputFields[0].VALUE;'e
    xecution'=$r2.InputFields[1].VALUE}

    
    # select agency
    $aa4 = iwr $fourth_url -UseBasicParsing -UseDefaultCredentials -WebSession $u -Method POST -Body @{'_eventId_proceed'=''}

    # submit saml 
    # request api key 




    if($r4.content -match 'name="SAMLResponse" value="(?<SAMLResponse>[a-zA-Z0-9\+\=]+)"') {
        $SAMLResponse = $Matches.SAMLResponse  
    }
    else {
        write-Host -NoNewline [+] -ForegroundColor Red ; Write-Host " Didn't get the SAML response..."
        Break
    }

    $converted = ConvertFrom-Base64 $SAMLResponse
    $auths = $converted | sls 'arn:aws:iam::(?<abc>\d{12}):role' -AllMatches | %{$_.Matches} | %{$_.Groups[1].Value}
    $numAuths = $auths.length
    Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "This account authorized for " -NoNewLine; Write-Host -Fore Green $numAuths -NoNewLine;Write-Host " roles"

    [hashtable]$h = @{
        "saml"  = $SAMLResponse;
        "auths" = $auths;
    }
    return $h
}

function Get-AWSCreds ($account, $saml) {

    $role_arn = "arn:aws:iam::" + $account + ":role/ReadOnlyAccess"
    $prin_arn = "arn:aws:iam::" + $account + ":saml-provider/xxxx"
    
    try {
        $o = Use-STSRoleWithSAML -RoleArn $role_arn -PrincipalArn $prin_arn -SAMLAssertion $saml
    }
    catch {
        try {
            $prin_arn = "arn:aws:iam::" + $account + ":saml-provider/cccccc"
            $o = Use-STSRoleWithSAML -RoleArn $role_arn -PrincipalArn $prin_arn -SAMLAssertion $saml
        }
        catch {
            $prin_arn = "arn:aws:iam::" + $account + ":saml-provider/dddddddd"
            $o = Use-STSRoleWithSAML -RoleArn $role_arn -PrincipalArn $prin_arn -SAMLAssertion $saml
        }
    }

    $key = $($o.credentials.AccessKeyId)
    $secret = $($o.credentials.SecretAccessKey)
    $token = $($o.credentials.SessionToken)

    if (($key) -and ($secret) -and ($token)) {
        AddBlock $account $filename $key $secret $token
        return 1
    }
    else {
        return 0
    }
}


function Get-TempAWSCreds {
    <#
    .EXAMPLE
        C\:> Get-TempAWSCreds 09999999999

        [-] Requesting SAML assertion...
        [+] This account authorized for 39 roles
        [-] You do not have access for the requested account:

                Account Id:             0999999999999
                Account Name:           zzzzzzz
                Root Account Email:     zzzzzzzzzzz
                Point of Contact:       zzzzzzzzzzzzz

    .EXAMPLE
        C\:> Get-TempAWSCreds xxxxxxx -showUnauthAccounts

        [-] Requesting SAML assertion...
        [+] This account authorized for 39 roles
        [-] Requesting Temp AWS Creds for the xxxxxxx account...
        [+] You have been issued temporary credentials for the ReadOnlyAccess role in dddddddd

                To make an API call with this role, use the Account ID:


                C:\> Get-IAMAccountAlias -ProfileName xxxxxxx

        [-] You do not have access to the following 29 accounts:


        AccountId    AccountName
        ---------    -----------
        ...

    .EXAMPLE
        PS C:\> Get-TempAWSCreds -ALL
        [-] Requesting SAML assertion...
        [+] This account authorized for 56 roles
        [-] Requesting Temp AWS Creds for ReadOnlyAccess role in 56 authorized accounts...
        [-] Creds obtained for the following 55 authorized accounts:


         To make an API call with a role, use the Account ID:

                C:\> Get-IAMAccountAlias -ProfileName xxxxxxx


        [-] Creds could not be obtained for the following authorized accounts:


        AccountId    AccountName               RootAccountEmailAddress                 POC
        ---------    -----------               -----------------------                 ---
        xxxxxxx 
  
    .EXAMPLE
        PS C:\> Get-TempAWSCreds -listAccounts

        AccountId    AccountName                      POC
        ---------    -----------                      ---
        ...

    .SYNOPSIS
        Obtain temporary AWS credentials for API access using AssumeRoleWithSaml 

    .DESCRIPTION
        This script authenticates the user via SSO, requests a SAML assertion for https://signin.aws.amazon.com/saml, and obtains temporary AWS credentials for API access using AssumeRoleWithSaml

    .LINK
        https://docs/AWS%20IAM%20Best%20Practices.md

    .NOTES

        To see the examples, type: "Get-Help Get-TempAWSCreds -examples".
        For more information, type: "Get-Help Get-TempAWSCreds -detailed".
        For technical information, type: "Get-Help Get-TempAWSCreds -full".
    #>

    param
    (
        [ValidateLength(12,12)][String]$account,
        [Switch]$showUnauthAccounts,
        [Switch]$listAccounts,
        [Switch]$ALL
    )


    if ($listAccounts -eq $True){
        $a = @()
        $accounts.keys | % {
            $a += New-Object -TypeName psobject -Property @{
                AccountId=$_;
                AccountName=$accounts.Item($_)[0];
                RootAccountEmailAddress=$accounts.Item($_)[1];
                POC=$accounts.Item($_)[2];
            } 
        }
        $a | select AccountId,AccountName,POC | sort AccountId | ft -auto
        Write-Host `n
        Break
    }

    if (!($account) -and ($ALL -ne $True)) {
        Write-Host -Fore Red "`n[-] " -NoNewLine;Write-Host "You must provide an AccountID or use `"-ALL`" for all authorized accounts:`n`n"
        Write-Host `t"C:\> " -NoNewLine;Write-Host -Foreground Yellow "Get-TempAWSCreds " -NoNewLine;Write-Host "xxxxxxx" `n
        Write-Host `t"-- OR --" `n
        Write-Host `t"C:\> " -NoNewLine;Write-Host -Foreground Yellow "Get-TempAWSCreds " -NoNewLine;Write-Host -Fore Gray "-ALL" `n
        Break
    }

    function AddBlock ($blockname, $filename, $key, $secret, $token) {
    $line = (sls $blockname $filename).linenumber
$block = @"
aws_access_key_id=$key
aws_secret_access_key=$secret
aws_session_token=$token
"@

    if ($line) {
        $content = gc $filename 
        Set-Content -Path $filename -Value "[default]"
        Add-Content -Path $filename -Value "region=us-east-1"
        Add-Content -Path $filename -Value $null
        [array]$lines = ($line -1)..($line + 3) 
        [array]$newlines = @()
        0..($content.length - 1) | %{if ($_ -notin $lines){[array]$newlines += $_}}
        $newlines | %{Add-Content -Value $content[$_] -Path $filename}
    }

    Add-Content -Path $filename -Value ""
    Add-Content -Path $filename -Value "[$blockname]"
    Add-Content -Path $filename -Value $block
    }
   

    function Get-Success {
        
        Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "You have been issued temporary credentials for the " -NoNewLine; Write-Host -Fore Green "ReadOnlyAccess" -NoNewLine;Write-Host " role in " -NoNewLine;Write-Host -Fore Green $($accounts.Item($account)[0])`n
        Write-Host " To make an API call with this role, use the Account ID:`n"
        Write-Host `t"C:\> " -NoNewLine;Write-Host -Foreground Yellow "Get-IAMAccountAlias" -NoNewLine;Write-Host " -ProfileName $account "`n
    }

    function Get-One ($saml, $account) {

        Write-Host -Fore Gray "[-] " -NoNewLine; Write-Host "Requesting Temp AWS Creds for the ReadOnlyAccess role in the " -NoNewLine; Write-Host -Foreground Gray $account -NoNewLine;Write-Host " account..." 
        $successful = Get-AWSCreds $account $saml
        if ($successful -eq 0) {
            Write-Host -Fore Red "[-] " -NoNewLine;Write-Host "There was a problem obtaining access to this role:`n"
            Write-Host `tAccount Id:`t`t$account
            Write-Host `tAccount Name:`t`t$($accounts.Item($account)[0])
            Write-Host `tRoot Account Email:`t$($accounts.Item($account)[1])
            Write-Host `tPoint of Contact:`t$($accounts.Item($account)[2])`n
        }
        else{
            Get-Success
        }
    }


    function Get-All ($saml, $auths) {

        $numAccts = $auths.length
        Write-Host -Foreground Gray "[-] " -NoNewLine; Write-Host "Requesting Temp AWS Creds for ReadOnlyAccess role in $numAccts authorized accounts..."
        $t = @{}
        $u = @{}
        $auths | % {
            $success = Get-AWSCreds $_ $saml
            if ($success -eq 1){
                $t.add($_,$success)
            }
            else {
                $u.add($_,$success)
            }
        }
        
        $numAuths=$t.count
        Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "Obtained creds for " -NoNewLine;Write-Host -Fore Green $numAuths -NoNewline;Write-Host " authorized accounts. Account info saved to " -NoNewLine;Write-Host -Fore Cyan '$success' -NoNewLine; Write-Host " variable"

        $global:success = @()
        $t.keys | % {
            $global:success += New-Object -TypeName psobject -Property @{
                AccountId=$_;
                AccountName=$accounts.Item($_)[0];
                RootAccountEmailAddress=$accounts.Item($_)[1];
                POC=$accounts.Item($_)[2];
            } 
        }
        
        Write-Host `n" To make an API call with a role, use the Account ID:`n"
        Write-Host `t"C:\> " -NoNewLine;Write-Host -Foreground Yellow "Get-IAMAccountAlias" -NoNewLine;Write-Host " -ProfileName xxxxxxx"`n`n

        if ($u.count -gt 0) {
            Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Creds could not be obtained for the following authorized accounts:"`n

            $a = @()
            $u.keys | % {
                $a += New-Object -TypeName psobject -Property @{
                    AccountId=$_;
                    AccountName=$accounts.Item($_)[0];
                    RootAccountEmailAddress=$accounts.Item($_)[1];
                    POC=$accounts.Item($_)[2];
                } 
            }
            $a | select AccountId,AccountName,RootAccountEmailAddress,POC | ft -auto
            Write-Host `n
        }
    }

    function Get-Unauth ($account) {

        Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "You do not have access for the requested account:"`n
        Write-Host `tAccount Id:`t`t$account
        Write-Host `tAccount Name:`t`t$($accounts.Item($account)[0])
        Write-Host `tRoot Account Email:`t$($accounts.Item($account)[1])
        Write-Host `tPoint of Contact:`t$($accounts.Item($account)[2])`n
    }

    function main {

        # Ensure AWSCLI and Credentials file are present
        $filename = "$env:USERPROFILE\.aws\credentials"
        Test-AwsPowerShell
        Test-CredentialFile
        $env:HTTPS_PROXY = "http://110.10.10.10:80"
        
        # Obtain SAML response and authorized accounts
        $response = Get-SamlResponse
        $saml = $response.Item('saml')
        $auths = $response.Item('auths')


        # If all accounts
        if ($ALL -eq $True) { 
            Remove-Item -Force $filename
            Set-Content -Path $filename -Value "[default]"
            Add-Content -Path $filename -Value "region=us-east-1"
            Add-Content -Path $filename -Value $null
            Get-All $saml $auths
            $global:ids = Get-Content $env:USERPROFILE\.aws\credentials | sls '\d{12}' | %{$_.Matches} | %{$_.Value}
        }

        # If one, is account authorized
        elseif ($auths.Contains($account)){
            Get-One $saml $account
        }
        
        else {        
            Get-Unauth $account
        }

        # Report unauthorized accounts
        if ($showUnauthAccounts -eq $True) {
            $unauths = $accounts.keys | ? {$auths -NotContains $_}
            Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "You do not have access to the following " -NoNewLine; Write-Host -Fore Green $unauths.Count -NoNewLine; Write-Host " accounts:"`n

            $c=@()
            ForEach ($unauth in $unauths) {
                $c += New-Object -TypeName psobject -Property @{
                    AccountId=$unauth;
                    AccountName=$accounts.Item($unauth)[0];
                }
            }
            $c | select AccountId,AccountName | sort AccountName
        }
    }
    main

}


function Get-ExtTempAWSCreds {
    <#
    .EXAMPLE
        PS C:\> Get-ExtTempAWSCreds -accountid 12345678 -user cwaite -role ops -credfile $env:USERPROFILE\creds.txt -token 123456
        [+] Obtained new temp creds for operations role at 12:40 PM

    .EXAMPLE
        PS C:\> Get-ExtTempAWSCreds

        [-] You must provide a token:


                C:\> Get-ExtTempAWSCreds -accountid 12345678 -user cwaite -role ops -credfile $env:USERPROFILE\creds.txt -token 123456

    .SYNOPSIS
        Obtain temporary AWS credentials for a personal account for API access using AssumeRole 

    .DESCRIPTION
        This script takes encrypted API keys and a token from a virtual MFA device and uses 
        them to request temporary AWS credentials for a role using the AssumeRole API

        To store AWS Access ID and Access Secret Key using SecureString:
        
        # Access ID
        Read-Host | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File -Append "$env:USERPROFILE\.cwaite.txt"
        
        # Access Secret Key
        Read-Host | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File -Append "$env:USERPROFILE\.cwaite.txt"

    .LINK
        https://docs/Hardening%20AWS%20Environments%20Using%20External%20Accounts.md

    .NOTES

        To see the examples, type: "Get-Help Get-ExtTempAWSCreds -examples".
        For more information, type: "Get-Help Get-ExtTempAWSCreds -detailed".
        For technical information, type: "Get-Help Get-ExtTempAWSCreds -full".
    #>

    param
    (
        [Parameter(Mandatory = $true )]
        [ValidateLength(12,12)][string]$accountid,

        [Parameter(Mandatory = $true )]
        [string]$user,
        
        [Parameter(Mandatory = $true )]
        [string]$role,
        
        [Parameter(Mandatory = $true )]
        [string]$credfile,

        [Parameter(Mandatory = $true )]
        [ValidateLength(6,6)][string]$token
    )

    function main {
    # Pull the encrypted credentials from file to memory
    [array]$t = Get-Content $env:USERPROFILE\.cwaite.txt

    # Decrypt into original access id and secret key values
    $id = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($($t[0] | ConvertTo-SecureString)))
    $key = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($($t[1] | ConvertTo-SecureString)))

    # Request and capture temporary credentials for role using MFA
    $sn = "arn:aws:iam::" + $accountid + ":mfa/" + $user
    $ra = "arn:aws:iam::" + $accountid + ":role/" + $role

    $r = Use-STSRole -AccessKey $id -SecretKey $key -RoleArn $ra -Region "us-east-1" -RoleSessionName $user -SerialNumber $sn -TokenCode $token -DurationInSeconds 43200
    $expire = $r.Credentials.Expiration

    # Clear out old temp credentials
    [array]$creds = (Select-String -Path $env:USERPROFILE\.aws\credentials -Pattern '\[temp\]').LineNumber
    [array]$linenumbers = @()
    $creds|%{$linenumbers += ($_-1),$_,($_+1),($_+2),($_+3),($_+4)} | Out-File $env:USERPROFILE\.aws\credentials

    # Add credentials to $env:USERPROFILE\.aws\credentials file
$content = @"

[temp]
aws_access_key_id=$($r.Credentials.AccessKeyId)
aws_secret_access_key=$($r.Credentials.SecretAccessKey)
aws_session_token=$($r.Credentials.SessionToken)

"@
    Add-Content -Value $content -Path $env:USERPROFILE\.aws\credentials

    if ($r){
        Write-Host -Fore Green "[+] " -NoNewLine; Write-Host $(Get-Date).ToShortTimeString()": Temp creds for"$role" role valid until " -NoNewLine;Write-Host -Fore Green $expire `n
    }
    }

    Test-AwsPowerShell
    Test-CredentialFile
    main
}

function Get-AWSCloudTrailLogs {
    <#
    .EXAMPLE
        PS C:\> $logs = Get-AWSCloudTrailLogs -accountid xxxxxxxx -month 10 -day 18 -year 2016
        PS C:\> $logs | select -First 1


        eventVersion       : 1.04
        userIdentity       : @{type=AssumedRole; principalId=...
        eventTime          : 2016-10-17T23:54:03Z
        eventSource        : elasticloadbalancing.amazonaws.com
        eventName          : DescribeInstanceHealth
        awsRegion          : us-east-1
        sourceIPAddress    : ecs.amazonaws.com
        userAgent          : ecs.amazonaws.com
        requestParameters  : @{loadBalancerName=el2-pr-vpmts1}
        responseElements   :
        requestID          : fb32a567-94c4-11e6-b425-09bc88b13e72
        eventID            : 173ca32e-dbde-4599-bc37-dda4f9297e2d
        eventType          : AwsApiCall
        apiVersion         : 2012-06-01
        recipientAccountId : xxxxxxxx


        PS C:\> $logs | ? eventName -match queue | select eventTime,eventName,userIdentity

        eventTime            eventName          userIdentity
        ---------            ---------          ------------
        2016-10-18T14:31:14Z CreateQueue        @{type=AssumedRole; principalId=...
        2016-10-18T14:33:44Z SetQueueAttributes @{type=AssumedRole; principalId=...
        2016-10-18T14:34:03Z SetQueueAttributes @{type=AssumedRole; principalId=...


    .EXAMPLE
        PS C:\> $logs = Get-AWSCloudTrailLogs -accountid xxxxxxx -month 10 -day 18 -year 2016
        [-] You must provide a stream of bytes... Breaking!

    .SYNOPSIS
        Obtain AWS CloudTrail logs for an account on a specific day as PowerShell objects

    .DESCRIPTION
        This function downloads every CloudTrail log created for a specific day, unzips each one, and compiles all logs into PowerShell objects
    
    .LINK
        https://docs/Postmortem%20Forensics%20in%20the%20Cloud.md

    .NOTES
        To see the examples, type: "Get-Help Get-AWSCloudTrailLogs -examples".
        For more information, type: "Get-Help Get-AWSCloudTrailLogs -detailed".
        For technical information, type: "Get-Help Get-AWSCloudTrailLogs -full".

    #>

    param (
        [Parameter(Mandatory = $true )]
        [ValidateLength(12,12)][string]$accountid,
        
        [Parameter(Mandatory = $true )]
        [ValidateLength(2,2)][string]$month,
        
        [Parameter(Mandatory = $true )]
        [ValidateLength(2,2)][string]$day,
        
        [Parameter(Mandatory = $true )]
        [ValidateLength(4,4)][string]$year,

        [Parameter(Mandatory = $true )]
        [string]$region
    )

    $bucketName = (Get-CTTrail -ProfileName $accountid -Region $region).S3BucketName
    
    if ($Error[0].Message -Match "No credentials specified") {
        Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "No credentials provided for this account... Exiting"
        Break
    }

    $prefix = "AWSLogs/$accountid/CloudTrail/$region/$year/$month/$day"
    
    if (!($bucketName)) {
        Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Bucket containing CloudTrail logs not found... Breaking!"
        Break
    }

    $logs=@()
    $bucketName | %{

        $keys = (Get-S3Object -ProfileName $accountid -Region $region -BucketName $_ -Prefix $prefix).Key
        
        foreach ($key in $keys){
            Read-S3Object -ProfileName $accountid -Region $region -BucketName $_ -Key $key -File "${Env:\TEMP}\logs.gz" | Out-Null
            $json = Expand-Gz "${Env:\TEMP}\logs.gz"
            $logs += ($json | ConvertFrom-Json).Records
            Remove-Item -Force "${Env:\TEMP}\logs.gz"
        }
    }
    $logs
}


function Get-AWSFlowLogs {

    <#
    .EXAMPLE
        PS C:\> $logs = Get-AWSFlowLogs -accountid xxxxxxxxx -eni eni-xxxxxxxxx
        PS C:\> $logs | ? SrcIp -eq '110.10.10.11' | Group DstIp,DstPort -NoElement | sort -Descending count

        Count Name
        ----- ----
           91 10.10.10.11, 53
           54 110.10.10.10, 58890
           48 10.79.171.18, 443
           41 10.79.171.16, 443
           41 110.10.10.10, 80
           21 10.79.171.17, 443
           15 10.103.136.34, 49018
            6 110.10.10.10, 44856
            2 192.99.45.140, 443
            1 10.60.50.206, 0
            1 10.79.249.232, 0
            1 10.79.249.218, 0

    .EXAMPLE
        PS C:\> $logs = Get-AWSFlowLogs -accountid xxxxxxxxx -eni eni-xxxxxxxxx
        PS C:\> $logs | ? DstIp -eq '10.10.10.10' | select Date,Time,SrcIp,SrcPort,DstIp,DstPort,Bytes | ft -auto

        Date      Time        SrcIp         SrcPort DstIp          DstPort Bytes
        ----      ----        -----         ------- -----          ------- -----
        11/7/2018 5:19:42 PM  110.10.10.11 22      110.10.10.10 58890   138332
        11/7/2018 5:27:30 PM  110.10.10.11 22      110.10.10.10 58890   85208
        11/7/2018 5:38:58 PM  110.10.10.11 22      110.10.10.10 58890   616292
        11/7/2018 5:47:31 PM  110.10.10.11 22      110.10.10.10 58890   710536
        11/7/2018 5:57:31 PM  110.10.10.11 22      110.10.10.10 58890   540504
        11/7/2018 6:07:32 PM  110.10.10.11 22      110.10.10.10 58890   477828
        11/7/2018 6:17:33 PM  110.10.10.11 22      110.10.10.10 58890   479716
        11/7/2018 6:27:33 PM  110.10.10.11 22      110.10.10.10 58890   387928
        11/7/2018 6:37:34 PM  110.10.10.11 22      110.10.10.10 58890   351196
        11/7/2018 6:47:34 PM  110.10.10.11 22      110.10.10.10 58890   463040
        11/7/2018 6:57:34 PM  110.10.10.11 22      110.10.10.10 58890   464740

    .EXAMPLE
        PS C:\> $logs = Get-AWSFlowLogs -accountid xxxxxxxxx -eni eni-xxxxxxxxx
        PS C:\> $logs | ? SrcIp -eq '110.10.10.11' | select Date,Time,DstIp,DstPort,Bytes,Protocol,Action | ft -auto

        Date      Time        DstIp          DstPort Bytes   Protocol Action
        ----      ----        -----          ------- -----   -------- ------
        11/4/2018 6:26:51 AM  10.10.10.11   53      74      17       ACCEPT
        11/4/2018 6:26:51 AM  10.10.10.11   53      50      17       ACCEPT
        11/5/2018 6:26:53 AM  10.10.10.11   53      50      17       ACCEPT
        11/5/2018 6:26:53 AM  10.10.10.11   53      74      17       ACCEPT
        11/6/2018 6:26:53 AM  10.10.10.11   53      50      17       ACCEPT
        11/6/2018 6:26:53 AM  10.10.10.11   53      74      17       ACCEPT
        11/7/2018 6:26:14 AM  10.10.10.11   53      74      17       ACCEPT
        11/7/2018 6:26:14 AM  10.10.10.11   53      50      17       ACCEPT
        11/7/2018 5:19:42 PM  110.10.10.10 58890   138332  6        ACCEPT
        11/7/2018 5:23:30 PM  10.10.10.11   53      69      17       ACCEPT
        11/7/2018 5:23:30 PM  110.10.10.10   80      545     6        ACCEPT
        11/7/2018 5:23:30 PM  110.10.10.10   80      1585    6        ACCEPT
        11/7/2018 5:23:30 PM  10.10.10.11   53      69      17       ACCEPT


    .SYNOPSIS
        Obtain flow logs for an Elastic Network Interface (ENI) using temporary AWS credentials and AWSPowerShell module 

    .DESCRIPTION
        This script uses the AWSPowerShell module to pull flow logs for an Elastic Network Interface (ENI) and store them in objects for easier filtering and searching.
    
    .LINK
        https://docs/Investigating%20AWS%20Internet%20Gateways.md

    .NOTES

        To see the examples, type: "Get-Help Get-AWSFlowLogs -examples".
        For more information, type: "Get-Help Get-AWSFlowLogs -detailed".
        For technical information, type: "Get-Help Get-AWSFlowLogs -full".
    #>

    param
    (
        [Parameter(Mandatory = $true )]
        [ValidateLength(12,12)][string]$accountid,

        [Parameter(Mandatory = $true )]
        [string]$eni,

        [Parameter(Mandatory = $true )]
        [string]$region
    )

    function Get-Logs {
        $fulleni = $eni + "-all"
        $fulleni
        $raw = (Get-CWLLogEvents -ProfileName $accountid -Region $region -LogGroupName "security-flowlogs" -LogStreamName $fulleni).Events

        if ($Error[0].Message -Match "No credentials specified") {
            Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "No credentials provided for this account... Exiting"
            Break
        }

        if (!($raw)){
            Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Nothing received, verify you have session token for this account and it's not expired... Breaking!"
            Break
        }

        $a=@()
        $raw | % {if (($_.message -notmatch 'NODATA') -and ($_.message -notmatch 'SKIPDATA')) {
            $a += New-Object -TypeName psobject -Property @{
                        Date=$_.Timestamp.ToShortDateString();
                        Time=$_.Timestamp.ToLongTimeString();
                        SrcIp=$_.message.split(' ')[3];
                        DstIp=$_.message.split(' ')[4];
                        SrcPort=$_.message.split(' ')[5];
                        DstPort=$_.message.split(' ')[6];
                        Protocol=$_.message.split(' ')[7];
                        Packets=$_.message.split(' ')[8];
                        Bytes=$_.message.split(' ')[9];
                        Start=$_.message.split(' ')[10];
                        End=$_.message.split(' ')[11];
                        Action=$_.message.split(' ')[12];
                        Status=$_.message.split(' ')[13];
                }
            }
        }
        $a
    }

    function main {
        Test-AwsPowerShell
        Test-CredentialFile
        Get-Logs
    }
    main
}


function Get-AWSLambdaCode {
    <#
    .EXAMPLE
        PS C:\> Get-LMFunction -ProfileName xxxxxxx -Region us-east-1 -FunctionName testAssumeRole | Get-AWSLambdaCode
        import boto3
        import time
        import sys

        def create_session(account=None, role=None, region='us-east-1'):

            session = None

            if account:
        ...

    .EXAMPLE
        PS C:\> Get-LMFunction -ProfileName xxxxxxx -Region us-east-1 -FunctionName testAssumeRole | Get-AWSLambdaCode -save
        [+] File saved as :  C:\lambda_function.py

    .EXAMPLE
        PS C:\> Get-AWSLambdaCode
        [-] You must provide an AWS Lambda Function PowerShell object!

    .SYNOPSIS
        Obtain AWS Lambda code by providing an AWS Lambda Function PowerShell object

    .DESCRIPTION
        This function gets the location of the Lambda code, downloads it, unzips it and either saves it (-save) or prints to the console (default)
    
    .LINK
        https://docs/Postmortem%20Forensics%20in%20the%20Cloud.md

    .NOTES

        To see the examples, type: "Get-Help Get-AWSLambdaCode -examples".
        For more information, type: "Get-Help Get-AWSLambdaCode -detailed".
        For technical information, type: "Get-Help Get-AWSLambdaCode -full".    
    #>

    param
    (
        [parameter(Mandatory = $true,ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [psobject]$lambda,
        
        [switch]$save
    )

    function GrabCode {
        $location = $lambda.Code.Location
        [byte[]]$Content = (Invoke-WebRequest $location).Content
        return $Content
    }

    function main {
        $Content = GrabCode
        $TempFile2 = Expand-Zip $Content
        if ($save -eq $False) {
            Get-Content $TempFile2
            Remove-Item -Force $TempFile2
        }
        else {
            Write-Host -Fore Green "[+] " -NoNewLine; Write-Host "File saved as: $TempFile2"
        }
    }
    main
}

function Find-AWSPublicResources {
    <#
    .EXAMPLE
        PS C:\> Find-AWSPublicResources
        [-] Looking for public snapshots...
        [-] Looking for public AMIs...

    .SYNOPSIS
        Use an external account to check for public snapshots and AMIs

    .DESCRIPTION
        This is a function in progress that currently only checks for public snapshots and public AMIs.  To run it you must first obtain external credentials with Get-ExtTempAWSCreds
    
    .LINK
        https://docs/Hardening%20AWS%20Environments%20Using%20External%20Accounts.md

    .NOTES

        To see the examples, type: "Get-Help Find-AWSPublicResources -examples".
        For more information, type: "Get-Help Find-AWSPublicResources -detailed".
        For technical information, type: "Get-Help Find-AWSPublicResources -full".   
    #>

    $erroractionpreference = "SilentlyContinue"
    $x = Get-IAMUsers -ProfileName temp
    if (!($x)) {
        Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Creds not valid. Request new creds using Get-ExtTempAWSCreds..."
        Break
    }

    Write-Host -Foreground Gray "[-] " -NoNewLine; Write-Host "Looking for public snapshots..."
    $snap = $regions | %{$r=$_; $accounts.keys | %{Get-EC2Snapshot -ProfileName temp -Region $r -Owner $_}}

    if ($snap) {
        Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Public snapshot discovered:"
        $snap
    }
    
    Write-Host -Foreground Gray "[-] " -NoNewLine; Write-Host "Looking for public AMIs..."
    $ami = $regions | %{$r=$_; $accounts.keys | %{Get-EC2Image -ProfileName temp -Region $r -Owner $_}}

    if ($ami) {
        Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "Public AMI discovered:"
        $ami | Select ImageId,Description,OwnerId,CreationDate | ft -auto
    }
}

function Get-SGRules {
    <#
    .EXAMPLE
        PS C:\> Get-EC2SecurityGroup -ProfileName xxxxxxxxx -Region us-east-1 -GroupId sg-xxxxx | Get-SGRules

        Type    Protocol Port IpRange
        ----    -------- ---- -------
        Ingress tcp        22 {10.10.10.10/32, 10.10.10.11/32}
        Ingress tcp      3389
        Egress  -1          0 0.0.0.0/0

    .SYNOPSIS
        Show ingress and egress rules for an AWS Security Group object

    .DESCRIPTION
        This function parses the properties of a security group object and shows the actual traffic rules it contains
    
    .LINK
        https://docs/Investigating%20AWS%20Internet%20Gateways.md

    .NOTES

        To see the examples, type: "Get-Help Get-SGRules -examples".
        For more information, type: "Get-Help Get-SGRules -detailed".
        For technical information, type: "Get-Help Get-SGRules -full".   

    #>    
    param
    (
        [cmdletbinding()]
        [parameter(ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [psobject]$sg
    )

    foreach ($rule in $sg.IpPermissions) {
        [array]$a += New-Object -TypeName psobject -Property @{
            Protocol  = $rule.IpProtocol;
            Port      = $rule.ToPort;
            IpRange   = $rule.Ipv4Ranges.CidrIp;
            Type      = 'Ingress';
        }
    }
    foreach ($rule in $sg.IpPermissionsEgress) {
        [array]$a += New-Object -TypeName psobject -Property @{
            Protocol  = $rule.IpProtocol;
            Port      = $rule.ToPort;
            IpRange   = $rule.Ipv4Ranges.CidrIp;
            Type      = 'Egress';
        }
    }
    return $a | select Type,Protocol,Port,IpRange
}

function Get-IGWInfo {
    <#
    .EXAMPLE
        PS C:\> Get-IGWInfo -accountid xxxxxxxxxxx -VpcId vpc-xxxxxxxxxxx -GatewayId igw-xxxxxxxxxxx

    .SYNOPSIS
        Shows various information about IGW, attached VPCs, instances on VPC, SG for instances, and NACLs for VPCs.

    .DESCRIPTION
        This function displays information relevant to an Internet Gateway in the AWS environment
    
    .LINK
        https://docs/Investigating%20AWS%20Internet%20Gateways.md

    .NOTES
        To see the examples, type: "Get-Help Get-IGWInfo -examples".
        For more information, type: "Get-Help Get-IGWInfo -detailed".
        For technical information, type: "Get-Help Get-IGWInfo -full".   
    #>    
    param
    (
        [Parameter(Mandatory = $true )]
        [ValidateLength(12,12)][string]$Accountid,

        [Parameter(Mandatory = $true )]
        [array]$GatewayIds,

        [Parameter(Mandatory = $true )]
        [string]$Region,

        [Parameter(Mandatory = $true )]
        [array]$Vpcs
    )

    
    Write-Host -Fore Gray "[>] " -NoNewLine; Write-Host "Inspecting gateways..."
    
    foreach ($GatewayId in $GatewayIds){

        $IGW = Get-EC2InternetGateway -ProfileName $accountid -Region $region -InternetGatewayId $GatewayId
        
        <#if ($Error[0].Exception -Match "No credentials specified") {
            Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "No credentials provided for this account... Exiting"
            Break
        }
        #>
        if (!($IGW)) {
            Write-Host -Fore Red "   [-] " -NoNewLine; Write-Host $GatewayId" no longer exists"
            # Break
        }
        else {
            # Are VPCS attached to IGW
            [array]$attached_vpcs = ($IGW.Attachments | ? State -eq 'available').VpcId
            $num_of_vpcs = $attached_vpcs.Count
            
            if ($num_of_vpcs -gt 0){
                Write-Host -Fore Green "   [-] " -NoNewLine; Write-Host "IGW $($IGW.InternetGatewayId) is currently attached to $num_of_vpcs VPC(s)"
            }
            else {
                Write-Host -Foreground Gray "   [-] " -NoNewLine; Write-Host "IGW $($IGW.InternetGatewayId) is currently attached to $num_of_vpcs VPC(s)"
            }
        }
    }

    Write-Host -Fore Gray "[>] " -NoNewLine; Write-Host "Inspecting VPCs..."

    $attached_vpcs += $vpcs
        
    Foreach ($vpc in $attached_vpcs){

        if ($r = Get-EC2Vpc -ProfileName $AccountId -Region $Region -VpcId $vpc ){
            Write-Host -Fore Green "   [>] " -NoNewLine; Write-Host "Inspecting " -NoNewLine;Write-Host -Foreground Gray $vpc -NoNewLine;Write-Host " IsDefault =" -NoNewLine;Write-Host -Foreground Gray $r.IsDefault
        }
        else {
            Write-Host -Fore Red "   [-] " -NoNewLine; Write-Host "VPC does not exist"
        }
        
        # 1. Is there a route table for VPC
        $table = Get-EC2RouteTable -ProfileName $accountid -Region $region | ? VpcId -eq $vpc 
        $igw_routes = $table.Routes | ? GatewayId -eq $GatewayId
        if ($igw_routes){
            Write-Host -Fore Green "`t[>] " -NoNewLine; Write-Host "VPC has route table"
            Write-Host "`t   RouteTableId   = "$table.RouteTableId
            Write-Host "`t   RoutesToIgw    = "$igw_routes.DestinationCidrBlock
        }
        else{
            Write-Host -Fore Red "`t[-] " -NoNewLine; Write-Host "VPC has no routes"
        }


        # 2. Does VPC have NACL allowing traffic
        $nacl = Get-EC2NetworkAcl -ProfileName $accountid -Region $region | ? VpcId -eq $vpc
        $nacl_rules = $nacl.Entries

        $ingress = $nacl_rules | ? Egress -eq $False | ? RuleAction -eq allow
        $ing_proto = $ingress.Protocol
        if (!($ingress.PortRange)){$ingressPortRange = "ANY"}
        else {$ingressPortRange = $ingress.PortRange}
        $ing_ip_port = $ingress.CidrBlock + ":" + $ingressPortRange
                
        $egress = $nacl_rules | ? Egress -eq $True | ? RuleAction -eq allow
        $egr_proto = $egress.Protocol
        if (!($egress.PortRange)){$egressPortRange = "ANY"}
        else {$egressPortRange = $egress.PortRange}
        $egr_ip_port = $egress.CidrBlock + ":" + $egressPortRange

        if (($ingress) -or ($egress)){
            $nacl_allows = $True
        }
        if ($ing_proto -eq '-1') {
            $ing_proto = 'ANY'
        }
        if ($egr_proto -eq '-1') {
            $egr_proto = 'ANY'
        }

        # Eligible VPCs

        $vpc_info += New-Object -TypeName psobject -Property @{
            VpcId          = $vpc;
            RouteTableId   = $table.RouteTableId;
            RoutesToIgw    = $igw_routes.DestinationCidrBlock;
            NaclId         = $nacl.NetworkAclId;
            NaclEgrProto   = $egr_proto;
            NaclEgrDest    = $egr_ip_port;
            NaclIngProto   = $ing_proto;
            NaclIngDest    = $ing_ip_port;
        }

        if ($nacl_allows){
            Write-Host -Fore Green "`t[>] " -NoNewLine; Write-Host "NACL has rules that allow traffic"
            Write-Host "`t   NaclId         = "$vpc_info.NaclId
            Write-Host "`t   NaclEgrProto   = "$vpc_info.NaclEgrProto
            Write-Host "`t   NaclEgrDest    = "$vpc_info.NaclEgrDest
            Write-Host "`t   NaclIngProto   = "$vpc_info.NaclIngProto
            Write-Host "`t   NaclIngDest    = "$vpc_info.NaclIngDest            
        }
        else{
            Write-Host -Fore Red "`t[-] " -NoNewLine; Write-Host "NACL has no rules allowing traffic"
        }

        # 3. Are there instances using the VPC
        $insts = (Get-EC2Instance -ProfileName $accountid -Region $region).Instances | ? VpcId -eq $vpc
        $num_insts = $insts.count

        if (!($insts)){
            Write-Host -Fore Red "`t[-] " -NoNewLine; Write-Host "VPC has no instances"
        }
        else{
            Write-Host -Fore Green "`t[>] " -NoNewLine; Write-Host "VPC has " $num_insts " instances"
        }
    }
    
    Write-Host -Fore Gray "[>] " -NoNewLine; Write-Host "Inspecting instances..."

    if ($insts.count -eq 0){
        Write-Host -Fore Red "   [-] " -NoNewLine; Write-Host "No instances on any of the VPCs"
    }
    else {
        Foreach ($inst in $insts){
            
            Write-Host -Fore Gray "`t   [>] " -NoNewLine; Write-Host $inst.InstanceId

            # 4. Does it have Security Groups that allow traffic
            $sg_ids = $inst.SecurityGroups.GroupId
            $sg_rules = $sg_ids | % {Get-EC2SecurityGroup -ProfileName $accountid -Region $region -GroupId $_ | Get-SGRules}
            
            $ingress = $sg_rules | ? Type -eq Ingress
            $ing_proto = $ingress.Protocol
            $ing_ip_port = $ingress.IpRange + ":" + $ingress.Port
            
            $egress = $sg_rules | ? Type -eq Egress
            $egr_proto = $egress.Protocol
            $egr_ip_port = $egress.IpRange + ":" + $egress.Port

            if ($ing_proto -eq '-1') {
                $ing_proto = 'ANY'
            }
            if ($egr_proto -eq '-1') {
                $egr_proto = 'ANY'
            }

            if ($sg_rules){
                Write-Host -Fore Green "`t`t[>] " -NoNewLine; Write-Host "Instance has SGs allowing traffic"
                #Write-Host "`t   SgEgressProto   = "$egr_proto
                #Write-Host "`t   SgEgressDest    = "$egr_ip_port
                #Write-Host "`t   SgIngressProto  = "$ing_proto
                #Write-Host "`t   SgIngressDest   = "$ing_ip_port                   
            }
            else{
                Write-Host -Fore Red "`t`t[-] " -NoNewLine; Write-Host "Instance has no SGs allowing traffic"
            }

            # 5. Does it have an ENI with public IP address or elastic IP 
            if ($inst.PublicIpAddress) {
                Write-Host -Fore Green "`t`t[>] " -NoNewLine; Write-Host "Instance has a public IP: " $inst.PublicIpAddress
            }
            else {
                Write-Host -Fore Red "`t`t[-] " -NoNewLine; Write-Host "Instance does not have a public IP address"
            }
        }
    }

    if ($elig_vpcs) {
        Write-Host -Foreground Gray `n"[-] " -NoNewLine; Write-Host "The following VPCs have the IGW attached and Routing/NACLs in place for IGW use:"
        $elig_vpcs | Select VpcId,RouteTableId,RoutesToIgw,NaclId,NaclEgrProto,NaclEgrDest,NaclIngProto,NaclIngDest 
    }
    if ($elig_insts) {
        Write-Host -Foreground Gray `n"[-] " -NoNewLine; Write-Host "The following instances can use the IGW:"`n
        $elig_insts | Select InstanceId,VpcId,SubnetId,PrivateIpAddress,PublicIpAddress,SgEgressProto,SgEgressDest,SgIngressProto,SgIngressDest
    }
}

function Get-S3ElbLogs {
    <#
    .EXAMPLE
        PS C:\> Get-S3ElbLogs -accountid xxxxxxxxxxx -bucketName someelb -prefix AWSLogs/xxxxxxxxxxx/elasticloadbalancing/us-east-1/2019/01/28

        response_processing_time : 0.000016
        Time                     : 6:00:26 PM
        Date                     : 1/28/2019
        elb                      : someELB
        s_ip                     : 10.10.10.10
        ssl_cipher               : -
        backend_status_code      : -
        request                  : "-
        s_port                   : 443
        c_port                   : 61947
        received_bytes           : 2342146
        c_ip                     : 10.10.10.10
        elb_status_code          : -
        ssl_protocol             : "
        user_agent               : -
        sent_bytes               : 3805357
        backend_processing_time  : 0.000009
        request_processing_time  : 0.001157

    .EXAMPLE
        PS C:\> $lb = Get-S3ElbLogs -accountid xxxxxxxxxxx -bucketName someelb -prefix AWSLogs/xxxxxxxxxxx/elasticloadbalancing/us-east-1/2019/01/28

        PS C:\> $lb | Group c_ip,s_ip -NoElement | Sort -Desc Count | Format-Table -auto

        Count Name
        ----- ----

    .SYNOPSIS
        Captures and parses fields from ELB logs stored in S3 buckets

    .DESCRIPTION
        To download ELB log files stored in S3 buckets, parse, and capture as objects
    
    .NOTES
        To see the examples, type: "Get-Help Get-S3ElbLogs -examples".
        For more information, type: "Get-Help Get-S3ElbLogs -detailed".
        For technical information, type: "Get-Help Get-S3ElbLogs -full".   
    #>     
    param (
        [string]$accountid,
        [string]$bucketName,
        [string]$prefix
    )   
    # $prefix = "AWSLogs/xxxxxxxxxxx/elasticloadbalancing/us-east-1/2019/01/28"
    $logs=@()
    $keys = (Get-S3Object -ProfileName $accountid -Region us-east-1 -BucketName $bucketName -Prefix $prefix).Key

    if ($Error[0].Message -Match "No credentials specified") {
        Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "No credentials provided for this account... Exiting"
        Break
    }

    foreach ($key in $keys){
        Read-S3Object -ProfileName $accountid -Region us-east-1 -BucketName $bucketName -Key $key -File "${Env:\TEMP}\logs.log" | Out-Null
        $logs += Get-Content "${Env:\TEMP}\logs.log"
        # $logs += ($json | ConvertFrom-Json).Records
        Remove-Item -Force "${Env:\TEMP}\logs.log"
    }

    $a = @()
    foreach ($line in $logs) {
        $split = $line.split(' ')
        
        $timestamp = $split[0]  
        [datetime]$date = $timestamp.split('T')[0]
        [datetime]$time = $timestamp.split('T')[1]
       
        $client_port = $split[2]
        $c_ip = $client_port.split(':')[0]
        $c_port = $client_port.split(':')[1]

        $backend_port = $split[3]
        $s_ip = $backend_port.split(':')[0]
        $s_port = $backend_port.split(':')[1]

        $a += New-Object -TypeName psobject -Property @{
            Date                        =   $date.ToShortDateString();
            Time                        =   $time.ToLongTimeString();
            elb                         =   $split[1];
            c_ip                        =   $c_ip;
            c_port                      =   $c_port;
            s_ip                        =   $s_ip;
            s_port                      =   $s_port;
            request_processing_time     =   $split[4];
            backend_processing_time     =   $split[5];
            response_processing_time    =   $split[6];
            elb_status_code             =   $split[7];
            backend_status_code         =   $split[8];
            received_bytes              =   $split[9];
            sent_bytes                  =   $split[10];
            request                     =   $split[11];
            user_agent                  =   $split[12];
            ssl_cipher                  =   $split[13];
            ssl_protocol                =   $split[14];
        } 
    }
    $a
}

# Export these functions
$funcs =  @('Get-TempAWSCreds'
            'Get-ExtTempAWSCreds'
            'Get-AWSCloudTrailLogs'
            'Get-AWSFlowLogs'
            'Get-AWSLambdaCode'
            'Find-AWSPublicResources'
            'Get-SGRules'
            'Expand-Zip'
            'Expand-Gz'
            'Get-AwsId'
            'Get-IGWInfo'
            'ConvertFrom-Base64'
            'ConvertTo-Base64'
            'Get-AWSPOCUpdate'
            'Get-S3ElbLogs'
            'Get-SamlResponse'
            'Get-AWSCreds'
            )
Export-ModuleMember -Function $funcs
