# Review of Amazon Web Services

Amazon Web Services (AWS) is a cloud services platform providing a wide
range of storage, networking, applications, and computing power services
with pay-as-you-go pricing.  AWS maintains all infrastructure needed
while customers have root level admin access to accounts, services, and
applications.  We need to be familiar with each of these services in
order to support analysis and event reconstruction during AWS-related
incidents.

Here are the services we'll review:

|Category|Service|Description|
|-|-|-|
|[Compute](#compute)|AWS Elastic Compute Cloud (EC2)|Infrastructure as a Service (IaaS)|
||AWS Beanstalk|Platform as a Service (PaaS)|
||AWS Elastic Container Service (ECS)/AWS Fargate|Container Service/Serverless|
||AWS Lambda|Serverless Environment|
|[Networking and Storage](#networking-and-storage)|AWS Virtual Private Cloud (VPC)|Virtual Network inside AWS|      
||Route 53|DNS Service|
||Simple Storage Service (S3)|Object Storage|
|[Access Control](#access-control)|Identity/Access Management|User Access|
||Key Management Service|Encryption Key Control|
|[Logging](#logging)|CloudTrail|User/API Activity|
||Config/notifications|Inventory/Configuration changes|
||Description|Resource description|
||ELB Access|Load balancer traffic|
||S3 Access|S3 Bucket access logs|
||VPC Flow|Flow logs|                                          

## Compute

### Elastic Compute Cloud (EC2)

Before VMs, you needed your own infrastructure, a physical server, and
applications that ran code. 

Virtual machines virtualize hardware components  such as processors,
devices, and memory hardware so that multiple OS's can run on one
machine, sharing the same hardware but isolated from each other.

Infrastructure as a service (IaaS) is where a **cloud provider manages
the infrastructure**, while the **customer only supplies the VMs,
applications, and code**.

The Elastic Compute Cloud (EC2) service is one of these services which
CIS uses to create virtual servers, called instances, that run in
Amazon's environment.  

Amazon owns the physical computers, the network infrastructure, and the
IP space in which the instances run, but only CIS controls access to the
instances and the data they contain.

To look at some instances, go to an account's EC2 Dashboard (Services -->
EC2):

Here you can find details of each instance including volumes attached,
key pairs used, IPs, security groups, etc.

This isn't a perfect fit for some customers as some applications need to
be completely isolated and building/maintaining an entire VM for one
application doesn't scale well.

Platform as a Service (PaaS) addresses this problem.

### AWS Beanstalk

Platform As a Service (PaaS) is where the **cloud provider manages the
infrastructure and the VMs**, while the **customer only supplies the
application and its code**. 

PaaS virtualizes the OS so that multiple applications can run isolated
on the same VM, sharing operating system structures without conflicting
with each other.

The customer is no longer responsible for server configurations,
database setup, security patches, load  balancing, or scaling... it is
all taken care of by the cloud provider.

With PaaS, you still need to configure the environment to match the type
of application you're deploying such as .NET, PHP, Python, Tomcat, etc:

One option here is to deploy a Docker platform which runs applications
as "containers" by packaging them with their required tools, libraries,
and dependencies.

This is a popular option because the containers are easily started and
stopped and can run in any environment running Docker.

AWS also offers this as a separate service.

### AWS Elastic Container Service (ECS) / AWS Fargate

A container service is where the **cloud provider manages the
infrastructure, the VM, and the container service**, while the
**customer only supplies the container and its code**:

Containers virtualize the CPU, memory, storage, and network resources at
the OS level so that multiple container instances can run on the same VM
and they are logically isolated from other applications.

Containers are portable and can run on any compute resource regardless
of operating system and hardware configurations.

Docker is the most popular container application which has public
repositories of containers that can be easily migrated from one host to
another.

To see an account's containers, go to Services --> Elastic Container
Service

Here you can see details about each container and the instance that was
spun up to run it:

AWS Fargate improves on ECS by allowing container deployment without
relying on any underlying infrastructure.

This is considered a "serverless" environment because you just upload
your container and AWS will manage the infrastructure needed to run the
container and your code.

AWS Lambda is another type of serverless environment which involves
running code without a container.

### AWS Lambda

AWS Lambda is where the **cloud provider manages the infrastructure, VM,
the container service, and the container**, while the **customer only
supplies the code**.

Customer-provided code is spun up on demand in response to events and
the customer is not required to manage any infrastructure.

These can be auto-scaled and are frequently used for API calls,
microservices, and webhooks.

To see Lambda functions, go to Services --> Lambda

Here is a list of functions being used:

By clicking on the function name, you can inspect the code that it runs
and how it is configured to run:

## Networking/Storage

### AWS Virtual Private Cloud (VPC)

A Virtual Private Cloud is a virtual network inside AWS where you can
configure your own IP address ranges and subnets.

To see an account's VPCs, go to Services --> VPC

This is a list of VPCs:


### Route 53

Route 53 is AWS's DNS Service where an account can configure the DNS
settings for domains it owns.

To see an account's hosted zones, go to Services --> Route 53

This is the Route 53 page:

Clicking on a domain name will show you all of its DNS records and the
IP/hosts that they are configured to resolve to:

### Simple Storage Service (S3)

The S3 service is for storing data in buckets.  The data inside the
buckets are referred to as objects.

Different policies can be applied to buckets, objects, users, groups,
and roles to control access to them.

To see an account's S3 buckets, go to Services --> S3

Here are several S3 buckets:

Click on the different tabs to show information about the bucket's
properties, permissions, and how it is managed.

S3 buckets, objects, and resources are private by default.  Only the
resource owner (AWS account that created it) can access the resource.

Policies can be applied to allow or deny specific permissions.

Here are some basic S3 permissions:

|||
|-|-|
|s3:PutObject|Add object to bucket|
|s3:PutObjectAcl|Sets ACL on an object|
|s3:GetObject|Access an object|
|s3:GetObjectAcl|Get an object's ACL|
|s3:CreateBucket|Create a bucket|
|s3:ListBucket|List the contents of a bucket|      

There are two types of policies the resource owner can use to control
access to buckets and their objects:

- Entity based policies

- Resource based policies

IAM Entities and AWS Resources are explained in the next section.


## Access Control

### Identity and Access Management

AWS uses Identity and Access Management (IAM) to manage users,
permissions, and access keys to control which AWS resources users can
access. 

#### Managing Users

In AWS, users must authenticate as an IAM entity in order to access
AWS resources.

There are three AWS entities used for access:

|||
|-|-|
|User|An account for a unique individual accessing AWS resources|      
|Group|A collection of one or more IAM users that require the same permissions|
|Role|An account that is assumable by anyone who needs it|

It is a best practice to use roles to access AWS resources.

AWS Resources are the services and objects users want to access and
use.

These are some of the resources that users will access:

- EC2
- ECS
- Lambda
- S3 buckets
- Elastic Load Balancing
- Key Management Service encryption keys

To see an account's users, groups and roles, go to Services --> IAM

These are the users in the ' ' account along with the groups
they belong to:

To see the policies that have been applied to each user, click on the
username:

To see what permissions a policy grants a user, group, or role, click on
Policies and find that specific policy:

#### Managing Permissions

Permissions are assigned to users, groups, and roles by creating and
assigning IAM Policies.

IAM Policies are created and attached to either IAM entities or AWS
resources.

The following is policy attached to an IAM entity (all groups) that
denies all but three IAM users from managing users with the listed
Actions:

The following is a policy attached to an AWS resource (S3 bucket)
which allows all actions to be performed on all objects in the bucket
by the root account:

It is important to note how AWS processes its
rules---in S3, user context is checked, then bucket context, and
finally object context.

This is a good flow chart showing what happens when a
user attempts to access an object in an S3 bucket:

               
![](images/Review%20of%20Amazon%20Web%20Services/image017.png)


### Key Management Service

#### Managing Access Keys

Access keys provide API access to AWS resources and consist of an
access key ID and secret access key. 

You can see the access keys for a user by clicking on their Security
Credentials tab in IAM:

It's important to note that this is basically like a username and
password---single factor authentication.

Anyone with the key ID and secret access key will have the same level
of access as the account owner who has logged in using multifactor
authentication (MFA) provided by their CAC and PIN.

For this reason, AWS keys must be tightly controlled:

**No Root Access Keys**

- Root access keys have full access to all AWS resources and should not be used at all

- Root account activity should only be performed in the AWS Management console using Multifactor Authentication (MFA) and should not be used for daily operations

**Control User Access Keys**

- User access keys should be rotated every 90 days

- User access keys that are no longer being used should be deleted

- IAM account policies should utilize least privilege to limit access to job requirements


## Logging

Here are the logs that currently give us the best information:

|Name|Description|
|-|-|
|[Cloudtrail](#cloudtrail)|Monitoring of API calls, user activity, console sign-ins, changes to resources and services|
|[Config](#config)|A detailed inventory of AWS resources, their configurations, and configuration changes|
|[Config Notification](#config-notification)|Logs generated when a specific action or condition is triggered|
|[Description](#description)|Shows start time, owner ID, region, and a brief description|
|[ELB Access Logs](#elb-access-logs)|Web requests showing client & backend IPs & ports, status codes, user-agent strings|
|[S3 Bucket Access Logs](#s3-bucket-access-logs)|Access to S3 buckets and their objects|
|[VPC Flow Logs](#vpc-flow-logs)|Flow logs, source/dest ip and port info, size|


### CloudTrail

These monitor user activity such as logons, changes to resources, and
API calls.

View in the console by going to Services --> CloudTrail:

### Config

These show inventory and change details and can be useful to get current
information on instances:

### Config Notification

These logs are created when a specific condition is triggered such as a
bucket policy change like below:

### Description

These logs give a brief description of the resource:

### ELB Access Logs

These are web requests that are hitting the load balancers.

### S3 Bucket Access Logs

Logs requests to S3 buckets and objects... 

### VPC Flow Logs

Flow logs provide basic information about network connections such as IP
address, port, bytes and whether the connection was accepted or
rejected.

<br>

While monitoring these logs, we should be looking for:

1. Use of the root account which has unrestricted access to all AWS
    resources

2. MFA not enabled for IAM users with a console password

3. Credentials/access keys unused for 90 days

4. Access keys not rotated at least every 90 days

5. Weak IAM password policies

6. Presence of root account access keys

7. MFA not enabled for root account

8. IAM policies attached directly to users

9. IAM policies that allow full "\*:\*" admin privileges

10. CloudTrail logging plus log file validation not enabled

11. Publicly accessible CloudTrail log S3 buckets

12. AWS config not enabled

13. VPC Flow logs not enabled

14. S3 bucket access logging not enabled

15. Unauthorized API calls

16. Console logins not using MFA

17. Root account usage

18. Unauthorized IAM policy changes

19. Unauthorized CloudTrail configuration changes

20. Unauthorized S3 bucket policy changes

21. Unauthorized AWS Config configuration changes

22. Unauthorized Network ACL changes

23. Unauthorized changes to network gateways

24. Unauthorized security group changes

25. Unauthorized route table changes

26. Unauthorized VPC changes

27. Unauthorized SNS subscribers

28. Console failed logins

29. Disabling or deletion of Customer Master Keys (CMK)

30. Ingress rules allowing 0.0.0.0/0 to admin services

31. Default VPC security group not restricting all traffic

32. VPC peering route tables that are not least access
