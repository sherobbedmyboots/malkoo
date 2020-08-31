# AWS IAM Best Practices

AWS secures the cloud, we the customer are responsible for configuring our security in the cloud.  We must use all the tools at our disposal... [CloudCheckr](), [Splunk](), [AWS]()---console access as well as API calls.

This document will walk through how we can obtain temporary API credentials, how we can use them for API access, and some basic best practices to look for regarding AWS Identity and Access Management (IAM):

- [Obtaining Temporary Credentials](#obtaining-temporary-credentials)
- [API Calls with AWSPowerShell](#api-calls-with-awspowershell)
- [IAM Best Practices](#iam-best-practices)
	- [Restrict Root Account Use](#restrict-root-account-use)
	- [Prohibit Root Access Keys](#prohibit-root-access-keys)
	- [Require MFA for Console Access](#require-mfa-for-console-access)
	- [Use Roles for API Access](#use-roles-for-api-access)
	- [Rotate Credentials Regularly](#rotate-credentials-regularly)
	- [Attach Policies to Groups not Users](#attach-policies-to-groups-not-users)
	- [Use AWS Managed Policies to Assign Permissions](#use-aws-managed-policies-to-assign-permissions)

<br>

## Obtaining Temporary Credentials

When we log on to a role in an AWS account using the [SSO Portal](), our browser authenticates us with our PIV and obtains temporary API keys for the account we select.  This is fine when we want to use the browser to access an account, but sometimes we may want to script API calls and ask the same questions across multiple accounts.  In this case, we can use the [Get-TempAWSCreds.ps1](scripts/Get-TempAWSCreds.ps1) script to obtain and store the temporary credentials for us.

I've modified the [Get-TempAWSCreds.ps1](scripts/Get-TempAWSCreds.ps1) script to contain a current list of AWS accounts, their aliases, and their points of contact.  The list of accounts is shown when you run the script with the `list-accounts` argument:

```powershell
Get-TempAWSCreds list-accounts
```

To get keys for a single account, provide the Account ID:

```powershell
Get-TempAWSCreds 123456789012
```

To get keys for all accounts you have access to, provide the `ALL` argument:

```powershell
Get-TempAWSCreds -ALL
```

If credentials cannot be obtained for any of the accounts, they are listed:

![](images/AWS%20IAM%20Best%20Practices/image007.png)<br><br>

All credentials obtained are stored in the `.aws\credentials` file under account profiles:

![](images/AWS%20IAM%20Best%20Practices/image008.png)<br><br>

You can make API calls with any of the profiles using the [AWS Command Line Interface](https://aws.amazon.com/cli/) tool:

![](images/AWS%20IAM%20Best%20Practices/image009.png)<br><br>

But these results are returned in a JSON object.  To get results in the form of PowerShell objects, we can use [AWS Tools for PowerShell](https://aws.amazon.com/powershell/).


## API Calls with AWSPowerShell

First, download the [AWSPowerShell module](https://www.powershellgallery.com/packages/AWSPowerShell/3.3.365.0) raw nupkg file, unzip it, and place the `awspowershell.3.3.365` folder in your Modules directory (`~\Work Folders\Documents\WindowsPowerShell\Modules`).

![](images/AWS%20IAM%20Best%20Practices/image001.png)<br><br>

Then, import the module with `Import-Module` and ensure it was successfully imported with `Get-Module`:

![](images/AWS%20IAM%20Best%20Practices/image002.png)<br><br>

You can list all module cmdlets with `Get-Command` and use `Select-String` to search for patterns:

![](images/AWS%20IAM%20Best%20Practices/image003.png)<br><br>

Include the name of the profile (`AccountID`) when using an API call, and select the properties you want:

![](images/AWS%20IAM%20Best%20Practices/image010.png)<br><br>

To get a quick list of Account IDs in your `.aws\credentials` file, capture them in a variable:

![](images/AWS%20IAM%20Best%20Practices/image011.png)<br><br>

To run the same API call on multiple accounts:

![](images/AWS%20IAM%20Best%20Practices/image014.png)<br><br>


## IAM Best Practices

- [Restrict Root Account Use](#restrict-root-account-use)
- [Prohibit Root Access Keys](#prohibit-root-access-keys)
- [Require MFA for Console Access](#require-mfa-for-console-access)
- [Use Roles for API Access](#use-roles-for-api-access)
- [Rotate Credentials Regularly](#rotate-credentials-regularly)
- [Attach Policies to Groups not Users](#attach-policies-to-groups-not-users)
- [Use AWS Managed Policies to Assign Permissions](#use-aws-managed-policies-to-assign-permissions)


### Restrict Root Account Use

Each AWS account has a root user account with access to all services and resources in the account.  This root account **should not** be used for normal, everyday activity.  

The root account should be used to create one or more of the following accounts for conducting normal operations:

|Account|Description|
|-|-|
|[IAM User](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html)|User accounts with console and/or API access|
|[IAM Role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)|A role that can be assumed with console and/or API access|
|[Instance Profile](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html)|A role that an application can assume for API access|

<br>

**INCORRECT** 

Over the last 30 days, the root users from these accounts are being used to perform normal operations like running instances:

![](images/AWS%20IAM%20Best%20Practices/image015.png)<br><br>

**CORRECT**

These accounts have delegated running instances to users and roles:

![](images/AWS%20IAM%20Best%20Practices/image016.png)<br><br>


### Prohibit Root Access Keys

Long term access keys provide account access using single factor authentication.  That means if someone obtains the root user's secret key, they have complete control over everything in the account.   For this reason, the root account **should not** have any access keys.

**INCORRECT**

This account's root user has access keys:

![](images/AWS%20IAM%20Best%20Practices/image017.png)<br><br>

**CORRECT**

CloudCheckr reports that the root users for all non-production accounts do not have access keys:

![](images/AWS%20IAM%20Best%20Practices/image018.png)<br><br>


### Require MFA for Console Access

For console access, an account must have a password.  When this password is set, all that's needed to log on as that user is the account name and password.  Enabling MFA on the account will require the use of a second form of authentication before providing account access.


**INCORRECT**

The `Get-IAMLoginProfile` cmdlet can be used to find accounts with console passwords.  This account has two users with their console password set:

```powershell
(Get-IAMUsers -ProfileName 123456789012).UserName | %{Get-IAMLoginProfile -ProfileName 123456789012 -UserName $_}
```

Neither of them have MFA devices assigned:

```powershell
Get-IAMMFADevice -ProfileName 123456789012 -UserName x
```

We can log in using the console confirm that the account password is enabled and that no MFA device being used in the AWS console:

![](images/AWS%20IAM%20Best%20Practices/image021.png)<br><br>


**CORRECT**

This user assigned a MFA device minutes after his password was created:

```powershell
Get-IAMLoginProfile -ProfileName 123456789012 -UserName y

Get-IAMMFADevice -ProfileName 123456789012 -UserName y
```





### Use Roles for API Access

Storing static API keys on an instance makes it more difficult to perform credential management functions such as safe key distribution, rotating and revoking keys, and protecting keys from unauthorized use.  

Roles use temporary credentials which do not require an AWS identity, have a limited lifetime, are generated dynamically and provided to the instance when requested.  

**INCORRECT**

CloudCheckr reports 23 different accounts are running instances with embedded credentials:

![](images/AWS%20IAM%20Best%20Practices/image030.png)<br><br>

This access key (`AKIAABCDEFGHIJKLMNOP`) is being used to make API calls from 32 different IP addresses and is most likely embedded in an application running on 32 different instances:

![](images/AWS%20IAM%20Best%20Practices/image027.png)<br><br>

The `userIdentity` object shows this is a key belonging to IAM User `z`:

![](images/AWS%20IAM%20Best%20Practices/image028.png)<br><br>

It appears this access key has been in use for almost 4 years:

```powershell
Get-IAMAccessKey -ProfileName 123456789012 -UserName z
```

**CORRECT**

Let's look at an instance profile (`i-0abcdefghijklmnop`) assuming a role (`databricks-prod-worker-role`) and obtaining a temporary access key (`AKIAABCDEFGHIJKLMNOP`).  If we find the earliest event for this key, we see it was requested by the `j` role at 7:58:15 and is set to expire 12 hours later:

![](images/AWS%20IAM%20Best%20Practices/image024.png)<br><br>

The session is named after the instance requesting it (`i-0abcdefghijklmnop`) and is used to distinguish it from other instances that might assume that same role.  A session token is provided to be used with all further API calls in that session.

After receiving the access key, secret key, and session token, the instance begins making API calls with the credentials.

![](images/AWS%20IAM%20Best%20Practices/image025.png)<br><br>

In each cloudtrail log, the userIdentity json object contains information identifying the entity using the credentials, the role that issued them, and other details:

![](images/AWS%20IAM%20Best%20Practices/image026.png)<br><br>

|Object|Description|
|-|-|
|`principalId`|Role Id + Session Name|
|`sessionContext.attributes.creationDate`|Date this session was created|
|`sessionContext.attributes.mfaAuthenticated`|Multifactor Authenticated used|
|`sessionIssuer.principalId`|Role Id|
|`sessionIssuer.userName`|Role Name|

Before the key expires, the instance will request another set of temporary credentials to maintain API access.

### Rotate Credentials Regularly

All long-term credentials should be rotated regularly---that includes both passwords and access keys. Password policies should be enabled to enforce this as well as provide complexity requirements.

**INCORRECT**

CloudCheckr shows hundreds of access keys in our environment that are older than 90 days:

![](images/AWS%20IAM%20Best%20Practices/image031.png)<br><br>

Both this user's console password and access key have not been rotated in almost 2 years:

```powershell
Get-IAMCredentialReport -ProfileName 123456789012 -AsTextArray | ConvertFrom-CSV | ? user -eq 'z' | select user,password_last_changed

Get-IAMAccessKey -ProfileName 123456789012 -UserName z
```

**CORRECT**

This user's password was changed less than 90 days ago:

![](images/AWS%20IAM%20Best%20Practices/image033.png)<br><br>

This user's access key was rotated.  The old credentials were made inactive and the new credentials which were created less than 90 days ago are now being used:

![](images/AWS%20IAM%20Best%20Practices/image034.png)<br><br>


### Attach Policies to Groups not Users

Attaching policies to a group and then assigning the user to that group is the proper way to assign permissions.  This way, users can be added to or removed from different groups according to the permissions required by their job functions.

**INCORRECT**

These two policies are attached directly to the user:

```powershell
Get-IAMAttachedUserPolicies -ProfileName 123456789012 -UserName z
```
![](images/AWS%20IAM%20Best%20Practices/image012.png)<br><br>

There is already an `Administrators` group in the account with the `AdministratorAccess` policy attached that the user could have been granted membership to:

```powershell
Get-IAMAttachedGroupPolicyList -ProfileName 123456789012 -GroupName Administrators
```

![](images/AWS%20IAM%20Best%20Practices/image035.png)<br><br>

**CORRECT**

The user `o` has no attached policies.  But because it is a member of the `S3Bucket` group, the `AmazonS3FullAccess` policy will be applied:

```powershell
Get-IAMAttachedUserPolicies -ProfileName 123456789012 -UserName o
Get-IAMGroupForUser -ProfileName 123456789012 -UserName o
```

![](images/AWS%20IAM%20Best%20Practices/image013.png)<br><br>


### Use AWS Managed Policies to Assign Permissions

Use the following types of policies to grant permissions that only allow a user to perform their job:

|Policy|Description|
|-|-|
|AWS Managed|Created by AWS and attached to an entity|
|Customer Managed|Created by customer and attached to an entity|
|Inline|Embedded into and an inherent part of an entity|

<br>

AWS Managed policies should be utilized before making custom managed policies in order to avoid unintentionally assigning unnecessary permissions to entities.  If an AWS managed policy can't be found that is exactly right, find one that's close, copy it, and then modify it to fit your requirements.

**INCORRECT**

Here is a list of policies for an account that are not managed by AWS:

```powershell
Get-IAMPolicyList -ProfileName 123456789012 | ? Arn -NotMatch 'aws:policy' | select PolicyName,Arn 
```


![](images/AWS%20IAM%20Best%20Practices/image037.png)<br><br>

To see the policy's metadata, use the `Get-IAMPolicy` cmdlet:

```powershell
Get-IAMPolicy -ProfileName 123456789012 -PolicyArn arn:aws:iam::123456789012:policy/PolicyZ 
```


![](images/AWS%20IAM%20Best%20Practices/image038.png)<br><br>

To see the actual policy, use the `Get-IAMPolicyVersion` cmdlet and decode the URL-encoded `document` property:

```powershell
$url = (Get-IAMPolicyVersion -ProfileName 123456789012 -PolicyArn arn:aws:iam::123456789012:policy/PolicyZ -VersionId v1).Document
[System.Web.HttpUtility]::UrlDecode($url)
```

![](images/AWS%20IAM%20Best%20Practices/image039.png)<br><br>

This policy grants access to all services and actions in AWS except for IAM.  This is a very broad policy and almost certainly grants entities more permissions that needed to perform their jobs.

**CORRECT**

This customer managed policy lists only the actions allowed for the `VisualEditor0` Sid:

![](images/AWS%20IAM%20Best%20Practices/image040.png)<br><br>

Inline policies are good for when permissions will only apply to one user and will not be attached to other entities.  Policy conditions can also be used to ensure permissions are assigned with least privilege in mind.

## Summary

Splunk is great, CloudCheckr is great, logging in via the console is better for some things and API calls are better for others.  No method does it all well so get familiar with different ways we can obtain information about our AWS users, resources, and environment.

Try using short scripts like the one below to obtain information about users and groups in different accounts.  This is a short script to find accounts with users that have a console password set but no assigned MFA device:

```powershell
$ids | %{
	$users = (Get-IAMUsers -ProfileName $_).UserName
	$profile = $_
	$users | %{
		if (Get-IAMLoginProfile -ProfileName $profile -UserName $_) {
			if (!(Get-IAMMFADevice -ProfileName $profile -UserName $_)) {
				Write-Host $profile ":" User $_ console password set with MFA disabled
			}
		}
	}
}
```
![](images/AWS%20IAM%20Best%20Practices/image022.png)<br><br>
