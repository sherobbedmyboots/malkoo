# Assessing Impact Of Exposed Resources

When sensitive information is exposed to the public, an important part of our job is identifying data that can be extracted by someone who discovers it and searches through it with bad intentions.  This training document will walk through various options to consider using two examples where sensitive data could have been exposed to unauthorized parties.

- [Filesystems](#filesystems)
- [Images](#images)


## Filesystems

A Github repository was recently discovered to contain sensitive information.  The first task was to obtain the current state of the repo and identify the data it contained:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image011.png)<br><br>

And a timeline of activity:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image005.png)<br><br>

First, the `file1.zip` file is added:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image006.png)<br><br>

Then it's deleted:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image007.png)<br><br>

`README.md` is changed:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image008.png)<br><br>

`Test.txt` is changed:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image009.png)<br><br>

`file2.zip` file is added:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image010.png)<br><br>

We need to download `file1.zip` and `file2.ip` to inspect for sensitive information they may contain.  Once we have copies, we can unzip them and search all files recursively using [BulkExtractor](https://github.com/simsong/bulk_extractor):

```powershell
.\bulk_extractor64.exe -o BE -R <reponame>
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image012.png)<br><br>

Show files and directories that contain results using:

```powershell
ls BE | ? length -ne 0 
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image013.png)<br><br>

Identify hostnames discovered:

```powershell
Get-Content .\BE\domain_historgram.txt | sls '<regex>'
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image014.png)<br><br>

Urls:

```powershell
Get-Content .\BE\url_historgram.txt | sls '<regex>'
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image015.png)<br><br>

Services:

```powershell
Get-Content .\BE\url_services.txt | sls '<regex>'
```


![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image016.png)<br><br>

Email addresses:

```powershell
Get-Content .\BE\email_historgram.txt | sls '<regex>'
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image017.png)<br><br>

Phone numbers:

```powershell
Get-Content .\BE\telephone_historgram.txt | sls '<regex>'
```


![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image018.png)<br><br>

PII:

```powershell
Get-Content .\BE\pii.txt 
```


![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image019.png)<br><br>

Also, visually inspect all data in images that may contain sensitive data:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image020.png)<br><br>

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image021.png)<br><br>

[BulkExtractor](https://github.com/simsong/bulk_extractor) also reports metadata about binary files discovered:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image022.png)<br><br>

Header, section, and other file information:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image023.png)<br><br>

Further inspection of binary files can be performed using static analysis, dynamic analysis, etc.


## Images

Sometimes it is an image that's exposed.  If AWS, it may be an AMI:

```powershell
Find-AWSPublicResources
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image024.png)<br><br>

Or as in a recent case, a snapshot:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image001.png)<br><br>

First, find the account's alias using `Get-AwsId`:

```powershell
Get-AwsId <id>
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image003.png)<br><br>

Check to see if you can use the API to gather additional information---in this case we do not have access to the account:

```powershell
Get-TempAWSCreds <id>
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image004.png)<br><br>

But since it is public, any AWS account can copy the snapshot using:

```powershell
New-EC2Volume -ProfileName temp -Region us-east-1 -AvailabilityZone us-east-1c -SnapshotId <id>
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image002.png)<br><br>

For other AWS storage types use the following copy methods:

|Type|Description|Copy Method|
|-|-|-|
|[EBS Snapshot](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html)|Point in time backup copy of a volume|Create a volume with `New-EC2Volume`|
|[EBS Volume](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEBS.html)|Detachable storage device|Create a snapshot using `New-EC2Snapshot`|
|[AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)|Machine image|Make a copy with `Copy-EC2Image`|
|[Instance Store Volume](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html)|Attached to instance|Log on instance and copy|

<br>

With a copy obtained, start an instance:

```powershell
New-EC2Instance -ProfileName temp -Region us-east-1 -ImageId <id> -InstanceType t2.micro -KeyName demo
(Get-EC2Instance -ProfileName temp -Region us-east-1).Instances
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image025.png)<br><br>

Attach the volume to the instance using `Add-EC2Volume` :

```powershell
Add-EC2Volume -ProfileName temp -Region us-east-1 -InstanceId <id> -VolumeId <id> -Device xvdb
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image026.png)<br><br>

Now log on to the instance and verify the volume is mounted as device `xvdb1`:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image027.png)<br><br>

Mount the filesystem and list the root directory:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image028.png)<br><br>

You may wish to use these mounting options depending on the scenario:

|Option|Command|
|-|-|
|Read Only|`mount -o ro /dev/xvdb demo`|
|Windows|`mount -ro loop,ro,show_sys_files,streams_interface=windows /dev/xvdb`|

<br>

A quick way to scan for sensitive information is to use [BulkExtractor](https://github.com/simsong/bulk_extractor) like we did in the previous example.

Download and install with:

```
yum install git -y
git clone https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
sudo sh etc/CONFIGURE
sudo make
sudo make install
```

Then run against the volume using `bulk_extractor -o be -R demo`:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image029.png)<br><br>

When it completes, sort through all the files created in the `be` directory:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image030.png)<br><br>

We can also search for recently changed directories (`ls -lt`):

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image031.png)<br><br>

Files modified in the last 30 days (`sudo find -type f -mtime -30`):

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image032.png)<br><br>

Another option is to change this `demo` directory to the root directory with `chroot`:

```bash
sudo chroot .
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image033.png)<br><br>

Now we are root on the filesystem and can navigate more easily and run various commands to get more information:

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image034.png)<br><br>

Since this is a snapshot of an image, we can search locations expected to have credentials and other sensitive data:

```
/root/.ssh/*
/home/ubuntu/.ssh/*
/etc/passwd
/etc/shadow
/etc/groups
/.aws/credentials
```

The ubuntu user was logging in via the <key> SSH key:

```bash
cat /home/ubuntu/.ssh/authorized_keys
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image035.png)<br><br>

This key was also used by root:

```bash
cat /root/.ssh/authorized_keys
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image036.png)<br><br>

Searching through the logs provides additional information:

```bash
ls -lt /var/log
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image037.png)<br><br>

View history files:

```bash
cat root/.bash_history 
```

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image038.png)<br><br>

![](images/Assessing%20Impact%20Of%20Exposed%20Resources/image039.png)<br><br>

Basically you're looking for anything that could be useful to an adversary---usernames, email addresses, SSH keys, AWS credentials, URLs, domains, IP addresses, hostnames, etc.

By providing management with an accurate assessment of what was available as a result of the exposure, we can increase the effectiveness of our initial response and corrective actions. 
