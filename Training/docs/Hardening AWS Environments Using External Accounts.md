# Hardening AWS Environments Using External Accounts

AWS secures the cloud, we the customer are responsible for configuring our security in the cloud.  We must use all the tools at our disposal... [CloudCheckr](), [Splunk](), and [AWS]()---console access as well as API calls.

This document will walk through how to use external AWS accounts to help identify and gather information about AWS resources that may not be utilizing best practices.  Using an external account is a great way to gain deeper knowledge of AWS features and capabilities as well as demonstrate the various security issues we find while monitoring the environment.


- [Using External AWS Accounts](#using-external-aws-accounts)
	- [Create a Role with Admin Privileges](#create-a-role-with-admin-privileges)
	- [Create A Limited User](#create-a-limited-user)
	- [Configure User for MFA](#configure-user-for-mfa)
	- [Store Credentials Safely](#store-credentials-safely)
	- [Use API to Assume the Role](#use-api-to-assume-the-role)
- [AWS EC2 Instance Fundamentals](#aws-ec2-instance-fundamentals)
	- [Image](#image)
	- [Instance Settings](#instance-settings)
	- [Storage](#storage)
	- [Networking](#networking)
	- [SG and NACL Rules](#sg-and-nacl-rules)
- [Publicly Accessible Resources](#publicly-accessible-resources)
	- [SNS Topics](#sns-topics)
	- [SQS Queues](#sqs-queues)
	- [EBS Snapshots](#ebs-snapshots)
	- [AMIs](#amis)

<br>

## Using External AWS Accounts

An external account is helpful for finding, testing, and confirming potential security issues in our AWS environment.  Register for a free account [here](https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free_np/):

- Enter an account name, password, choose personal, enter payment info (for if you exceed free tier limits), complete the phone verification, and choose the free, basic plan 
- Sign in to the AWS console at https://console.aws.amazon.com/
- On the next page, click on **Sign In as Root User**
- Log in with your email address and password 


You're now at the AWS Console Dashboard logged in as the root user of your account.  To harden this account for future use, do the following:

- [Create a Role with Admin Privileges](#create-a-role-with-admin-privileges)
- [Create A Limited User](#create-a-limited-user)
- [Configure User for MFA](#configure-user-for-mfa)
- [Store Credentials Safely](#store-credentials-safely)
- [Use API to Assume the Role](#use-api-to-assume-the-role)

#### Create A Role with Admin Privileges

First you need to create a Role that will be used for normal operations within the AWS environment:

- Go to **IAM** -> **Roles** -> **Create Role**
- Select **Another AWS Account** and enter your 12-digit account number
- Select **Administrator Access** and **Next**
- Click **Next** without adding tags
- Give the role and name and select **Create Role**
- Save your Access Key ID and Secret Access Key into variables

Now we need to create a limited user that will be assuming this role.

### Create A Limited User

First create a policy with permissions to only use the `AssumeRole` API call:

- Go to **IAM** -> **Policies** -> **Create Policy**
- Select the `JSON` tab and change to match this:

```javascript
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
    ]
}
```

- Continue to next page, give the policy a name (`mfa_policy` for example), and select `Create Policy`

Now we'll create a user

- Go to **IAM** -> **Users** -> **Add User**
- Pick a name, select `Console and Programmatic Access` for the Access Type field
- Select `Attach Existing Policies Directly` then search for and select `mfa_policy` and click **Next**
- Click **Next** without adding tags, then **Create User** to complete

You now are provided an Access Key ID and a Secret Access Key which you can only retrieve this one time.  Copy the secret key to your clipboard. 


#### Configure User for MFA

Now we need to require Multifactor Authentication for this user.

- Go to **IAM** -> **Users** and select the new user you created
- Select the **Security Credentials** tab and click on the **Manage** Link next to `Assigned MFA device`
- Select **Virtual MFA Device** and select **Continue**
- Capture the QR code with an MFA application such as Google Authenticator or Authy
- Type in two consecutive codes and select **Assign MFA**

The user now has a virtual MFA device assigned:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image048.png)<br><br>


### Store Credentials Safely

The AWS credentials (Access Key ID and Access Secret Key) need to be stored safely and we can do this using [SecureString](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring?view=netframework-4.7.2).

- Use `Read-Host` to read the Access Key ID into memory and convert it to a SecureString which is placed in a file:

```powershell
Read-Host | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File -Append "~
\.cwaite.txt"
```

- Do the same thing with the Access Secret Key:

```powershell
Read-Host | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File -Append "~
\.cwaite.txt"
```

Now you have the Key ID and Secret Key stored as SecureStrings:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image044.png)<br><br>


When you capture the file's content in an array using `Get-Content`, the first value (`t[0]`) contains the Key ID and the second (`t[1]`) contains the Secret Key.  We then use the `SecureStringToBSTR` function to convert the SecureStrings into their original values:

```powershell
$t = Get-Content ~\.cwaite.txt

$id = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR(($t[0]|ConvertTo-SecureString)))

$key = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR(($t[1]|ConvertTo-SecureString)))
```

<br>

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image045.png)<br><br>

Now you have the credentials saved in memory and can use them to make API calls---but remember the user is only allowed to use the `AssumeRole` API:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image046.png)<br><br>


### Use API to Assume the Role

With the user's API keys, you can assume the role you created with administrative privileges using:

```powershell
$r = Use-STSRole -AccessKey $id -SecretKey $key -RoleArn arn:aws:iam::314615191983:role/operations -Reg
ion us-east-1 -RoleSessionName cwaite -SerialNumber arn:aws:iam::314615191983:mfa/cwaite -TokenCode 520152

$r.Credentials

```

This will return temporary credentials good for one hour.  To use these with every API call you make, you need to get them into variables:

```powershell
$tid = $r.Credentials.AccessKeyId
$tkey = $r.Credentials.SecretAccessKey
$tok = $r.Credentials.SessionToken
```

The credentials can now be used like this to make API calls:

```powershell
Get-IAMUsers -AccessKey $tid -SecretKey $tkey -SessionToken $tok
```

To make things easier, you can add the credentials to your `~\.aws\credentials` file:

```powershell
$content = @"

[temp]
aws_access_key_id=$tid
aws_secret_access_key=$tkey
aws_session_token=$tok

"@

Add-Content -Value $content -Path ~\.aws\credentials
```

And just use the `-ProfileName` parameter to specify that set of credentials:

```powershell
Get-IAMUsers -ProfileName temp
```

When the temporary credentials expire, I can either repeat all these steps individually or use the following [Get-ExtTempAWSCreds.ps1](scripts/Get-ExtTempAWSCreds.ps1) script:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image047.png)<br><br>



## AWS EC2 Instance Fundamentals

Understanding how EC2 instances are created, used, and terminated is critical for conducting accurate and timely incident response actions and postmortem investigations.  Use an external AWS account to get familiar with EC2 processes and how to obtain the information that is most valuable during analysis.

When an EC2 instance is created, the following determine its capabilities and how it can be accessed:
 
|Name|Description|
|-|-|
|[Image](#image)|OS and applications running on an instance|
|[Instance Settings](#instance-settings)|CPU, memory, IAM roles assigned to an instance|
|[Storage](#storage)|Volumes and snapshots used by the instance for storing data|
|[Networking](#networking)|VPCs, subnets, and ENIs associated with an instance|
|[SG and NACL Rules](#sg-and-nacl-rules)|Rules to control inbound and outbound traffic|


### Image

The image is the software configuration of the instance----its OS and applications.  This is provided in the form of a template called an Amazon Machine Image (AMI).  An AMI can be created by an account owner or can be obtained from Amazon, the AWS Marketplace, or the user community.

To see details of an AMI, use the `Get-EC2Image` cmdlet:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image001.png)<br><br>

### Instance Settings

These are the individual characteristics of the instance including [type and size](https://aws.amazon.com/ec2/instance-types/), platform, CPU options, architecture, assigned IP addresses, assigned IAM role, assigned tags, etc.

To see details of an Instance, use the `Get-EC2Instance` cmdlet:

```powershell
$a=Get-EC2Instance -ProfileName 123456789012 -Region <region> -InstanceId i-123456789
$a.Instances
```

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image002.png)<br><br>

Use `$a.Instances | select *` to see all properties:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image014.png)<br><br>


### Storage

An instance boots from a root device volume and may mount additional volumes using [block device mapping](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-device-mapping-concepts.html).

Instances can utilize the following types of storage devices:

|Type|Description|
|-|-|
|[EBS Volume](https://aws.amazon.com/ebs/)|Persistent independently from life of instance|
|[Instance Store](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html)|Persists only during the life of the instance|
|[EFS File System](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEFS.html)|Can be accessed by multiple instances at the same time|
|[S3 Object](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonS3.html)|Used to store snapshots of volumes|

<br>

To see the volumes for an instance:

```powershell
$a.Instances | select -exp BlockDeviceMappings | select -exp Ebs
```

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image015.png)<br><br>

To see details of an EC2 Volume, use the `Get-EC2Volume` cmdlet:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image003.png)<br><br>

To see details of an EC2 Snapshot, use the `Get-EC2Snapshot` cmdlet:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image004.png)<br><br>


### Networking

An instance operates on a Virtual Private Cloud (VPC) which can contain one or more subnets.  It can be provided one or more Elastic Network Interfaces (ENI) which are virtual network cards that send and receive traffic across the VPCs and subnets they're associated with.

To see the VPC, Subnet, and ENIs associated with an instance:

```powershell
$a.Instances.NetworkInterfaces | select VpcId,SubnetId,NetworkInterfaceId
```

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image016.png)<br><br>

You can look at individual VPCs:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image017.png)<br><br>

As well as subnets:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image018.png)<br><br>

And ENIs:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image019.png)<br><br>


### SG and NACL Rules

A Security Group (SG) is a virtual firewall applied to an instance to control inbound and outbound traffic.  

To see information about a security group, use `Get-EC2SecurityGroup`:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image020.png)<br><br>

To see the rules of a security group, use the [Get-Rules](scripts/Get-Rules.ps1) function:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image021.png)<br><br>

Network ACLs (NACL) apply to all instances in a subnet. Use `Get-EC2NetworkAcl` to see rules in a Network ACL:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image022.png)<br><br>


### Creating an Instance

For our purposes, you'll need to provide the following when creating an instance:
	- imageid (AMI)
	- instancetype (t1.micro)
	- keypair (keypair1)

This command creates a new keypair and stores the private key in a file named `keypair.pem`:

```powershell
(New-EC2KeyPair -ProfileName temp -Region us-east-1 -KeyName "keypair1").KeyMaterial | Out-File ~\keypair1.pem
```

This command starts a new instance using that keypair:

```powershell
New-EC2Instance -ProfileName temp -Region us-east-1 -ImageId ami-0ac019f4fcb7cb7e6 -InstanceType t1.micro -KeyName keypair1
```

Use these two together to create a keypair and start a new instance running Ubuntu Server 18.04 LTS:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image051.png)<br><br>

Once it comes up, we can see all information:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image052.png)<br><br>


This command starts a Windows Server 2016 instance:

```powershell
New-EC2Instance -ProfileName temp -Region us-east-1 -ImageId ami-050202fb72f001b47 -InstanceType t1.micro -KeyName keypair1
```

We can use the same keypair to start a new instance running Windows Server 2016:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image053.png)<br><br>

Use `Get-EC2Instance` to confirm both instances are running:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image054.png)<br><br>

For a Windows instance, you'll need to open up port 3389 and use the `keypair1.pem` file to obtain the Administrator password.

Use the following to open up port 3389 on the instance's Security Group:

```powershell
# Find Security Group ID
(Get-EC2Instance -ProfileName temp -Region us-east-1 -InstanceId i-082fdb04843d3f224).Instances.S
ecurityGroups.GroupId

# Create rule
$rule = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="128.80.22.0/24" }

# Append rule to SG
Grant-EC2SecurityGroupIngress -ProfileName temp -Region us-east-1 -GroupId sg-11124875 -IpPermission $rule
```
<br>

Once the rule is added to the security group, check it with [Get-Rules](scripts/Get-Rules.ps1):

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image055.png)<br><br>


Use `Get-EC2PasswordData` to obtain and decrypt the Administrator password:

```powershell
Get-EC2PasswordData -ProfileName temp -Region us-east-1 -InstanceId i-082fdb04843d3f224 -Pemfile ~\keypair1.pem
```

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image056.png)<br><br>

Now you can create an instance using an AMI and connect to it using the keyfile.


## Publicly Accessible Resources

Let's use our external AWS account to look at some common misconfigurations that may be present in our environment:

- [SNS Topics](#sns-topics)
- [SQS Queues](#sqs-queues)
- [EBS Snapshots](#ebs-snapshots)
- [AMIs](#amis)


<br>

### SNS Topics

The AWS Simple Notification Service (SNS) allows clients to publish and receive messages using an SNS Topic.  These messages can be alerts, emails, texts, or other notifications. A client who publishes a message to an SNS topic is called a publisher. An application, device, or user configured to recieve messages from an SNS topic is called a subscriber.  

Create a topic and subscriber to see how messages are published and received with:

```powershell
New-SNSTopic -ProfileName temp -Region us-east-1 -Name TestTopic
Connect-SNSNotification -ProfileName temp -Region us-east-1 -TopicArn arn:aws:sns:us-east-1:123456789012:TestTopic -Protocol email -Endpoint a@gmail.com
```
<br>

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image025.png)<br><br>

This sends a confirmation email to the subscriber:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image023.png)<br><br>


After confirming we get verification of the subscription:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image024.png)<br><br>

We can also add a phone number for SMS texts:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image028.png)<br><br>


Now we can publish something to the topic with:

```powershell
Publish-SNSMessage -ProfileName temp -Region us-east-1 -TopicArn arn:aws:sns:us-east-1:123456789012:TestTopic -Message 'This is a test SNS message' -Subject 'TEST MSG'
```
<br>

We receive the message via email and SMS text:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image026.png)<br><br>

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image027.png)<br><br>

Owners create SNS topics and control all access to the topic.

See topics for an account using `Get-SNSTopic`:

```powershell
Get-SNSTopic -ProfileName temp -Region us-east-1
```

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image029.png)<br><br>


See subscriptions for a topic with `Get-SNSSubscriptionByTopic`:

```powershell
Get-SNSSubscriptionByTopic -ProfileName temp -Region us-east-1 -TopicArn 'arn:aws:sns:us-east-1:123456789012:Test2'
```

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image030.png)<br><br>


See subscriptions for an endpoint using `Get-SNSSubscription`:

```powershell
Get-SNSSubscription -ProfileName temp -Region us-east-1 | ? Endpoint -eq 'w@gmail.com'
```

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image031.png)<br><br>


See an SNS Topic's policy:

```powershell
(Get-SNSTopicAttribute -ProfileName temp -Region us-east-1 -TopicArn arn:aws:sns:us-east-1:123456789012:Test2').Item('Policy') | ConvertFrom-Json | Select -exp Statement
```

<br>

This shows anyone can publish to this topic.

I can use an external AWS account to publish messages to the `Test2` Topic which will be received by all clients that are subscribed to that topic:

```powershell
PS C:\> Publish-SNSMessage -ProfileName temp -Region us-east-1 -TopicArn arn:aws:sns:us-east-1:123456789012:Test2 -Message 'This is a test SNS message' -Subject 'TEST MSG'
f80e472b-3450-52f8-872e-1346305038f8
```

<br>

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image032.png)<br><br>


Here is one SNS Topic that allows any AWS account to subscribe:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image036.png)<br><br>

We can subscribe to this topic with an external AWS account using:

```powershell
Connect-SNSNotification -ProfileName temp -Region us-east-1 -TopicArn arn:aws:sns:us-east-1:123456789012:Test3 -Protocol email -Endpoint a@gmail.com
```

The request goes through and is pending confirmation:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image033.png)<br><br>

After confirming the subscription, the email address starts recieving messages:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image035.png)<br><br>


### SQS Queues

Amazon Simple Queue Service (Amazon SQS) stores messages so that different applications can send and receive data to each other without being available at the same time.  Queue permissions determine what accounts can read and upload messages and should be configured for least privilege.


CloudCheckr shows 8 queues have one or more permissions set to Everyone:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image043.png)<br><br>


Here I am able to receive a message from the queue using an external AWS account:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image039.png)<br><br>

These seven queues allow everyone to receive messages:

```powershell

```

To make them easier to work with, put them all into an array:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image040.png)<br><br>

Then try to receive a message from each one.  This time one of the queues returns a message:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image041.png)<br><br>


This queue allows everyone to send messages:

```powershell

```

<br>

Use `Send-SQSMessage` to send a message to an SQS queue from an external account:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image042.png)<br><br>


### EBS Snapshots

Snapshots are captures of EBS Volumes made at a specific point in time.  By default they are not shared but changing a snapshot's permissions can make it available to any AWS account.

To check our accounts for any public snapshots, first capture the account numbers in an array (`$a`).  Then for each account number, search for any snapshots owned by that account.

This snapshot owned by the GSS account is visible to any AWS account:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image049.png)<br><br>

This is due to the `CreateVolumePermissions` being set to **ALL**:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image063.png)<br><br>

We can use the EC2 instance we created earlier to create a volume with this snapshot, mount it, and inspect it.  First create a volume using the snapshot:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image058.png)<br><br>

Then attach the volume to the Ubuntu instance we created earlier:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image059.png)<br><br>

After we SSH to the Ubuntu instance, we see the new volume as a block device:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image060.png)<br><br>

And can mount it and browse the files it contains:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image061.png)<br><br>

A quick search reveals the image contains sensitive data:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image062.png)<br><br>


### AMIs

Similar to how EBS snapshots have a `CreateVolumePermission` attribute which controls which account can access it, Amazon Machine Images (AMI) have a `LaunchPermission` attribute.

You can use credentials for an account to find all AMIs that account owns using the following:

```powershell
Get-EC2Image -ProfileName 123456789012 -Region us-east-1 -Owner 123456789012 | measure
```

This returns thousands of AMIs:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image065.png)<br><br>

To see which of these AMIs are public we can search for the same owner but using credentials from an external account with:


```powershell
Get-EC2Image -ProfileName temp -Region us-east-1 -Owner 123456789012 | measure
```

This time there are no results. None of the AMIs owned by the `123456789012` account are visible to the `temp` account:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image066.png)<br><br>


To search all accounts and all regions, you can use a nested For loop.  To do this, first create an array containing all the regions:

```powershell
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
```

Then create an array (or hashtable) containing all account numbers.  An easy way to do this is copy the `accounts` hashtable from the [Get-TempAWSCreds.ps1](scripts/Get-TempAWSCreds.ps1) script and paste it into your PowerShell terminal:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image067.png)<br><br>

This will allow you to retrieve all the account numbers by calling its `keys` property:

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image068.png)<br><br>

Now we can call the `Get-EC2Image` API on every combination of region and account with the following:

```powershell
$regions | %{$reg=$_;$accounts.keys | %{Get-EC2Image -ProfileName temp -Region $reg -Owner $_}}
```
The command returns zero results which is good: 

![](images/Hardening%20AWS%20Environments%20Using%20External%20Accounts/image069.PNG)<br><br>


## Summary

- Create an external AWS account to help identify potential security issues in our AWS environment
- Become familiar with how EC2 instances are created and the different characteristics that will aid an investigation such as the AMI used, attached storage devices, and networking configurations
- Misconfigured SNS Topics and SQS Queues can allow any AWS account to send and receive messages to and from clients 
- EBS Snapshots and AMIs have attributes that can provide public access to AWS resources