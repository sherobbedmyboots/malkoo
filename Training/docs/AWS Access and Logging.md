# AWS Access and Logging

Amazon Web Services (AWS) is a cloud services platform providing a wide
range of storage, networking, applications, and computing power services
with pay-as-you-go pricing.  AWS maintains all infrastructure needed
while customers have root level admin access to accounts, services, and
applications.

The Elastic Compute Cloud (EC2) service is used by customers to create virtual servers, called instances, that run in Amazon's
environment.  Amazon owns the physical computers, the network
infrastructure, and the IP space in which the instances run, but only
the customer controls access to the instances and the data they contain.

## Access

If the instance is connected to Active Directory, you should be able to
log in the usual way (net use, psexec, RDP) using your AD credentials. 
If this isn't possible, you can also find out information about the
instance using the AWS management console.

AWS uses Identity and Access Management (IAM) to manage users, user
permissions, and access keys to control which AWS resources users can
access.  There are three AWS entities used for access:

- User
- Group
- Role

AWS users and groups use key pairs to access an instance.  A public key
is embedded in the instance and only a user or group presenting the
correct private key is granted access.  The private key authenticates
the user/group and allows either SSH or RDP access.  To connect to a
Linux instance, you would need an SSH client (Putty) and a private key
file (filename.pem).  To connect to a Windows instance, a private key is
required to decrypt the local admin password and access via RDP.

An AWS role is an identity you can associate a policy with, used to
delegate access to users, groups, applications, and services. 

Choose a role and log into the [AWS management
console](https://signin.aws.amazon.com/saml).

![](images/AWS%20Access%20and%20Logging/image001.png)


Instances can run in one of many availability zones (AWS regions) in
different locations.

![](images/AWS%20Access%20and%20Logging/image002.png)


To see a list of instances, select the Services dropdown, click on EC2,
then click on Instances.  This will list all the instances, their type,
ID and current state.  By selecting the box by an instance you can see
information such as the private IP address, description, security
groups, network interfaces, devices, launch time, etc.

Some good sources of information here:

| | |
|-|-|
|Instance ID|can be used to monitor and locate logs involving the host|
|Virtual Private Cloud (VPC)|the isolated public- or private-facing subnet that the instance was launched into|
|Launch Time|time the instance was launched|
|Public IP/DNS|the public IP address and hostname of the instance|


Under the NETWORK & SECURITY section there is also good info:

| | |
|-|-|
|Security Groups|these are similar to a host-based firewall which defines rules allowing inbound and outbound traffic|
|Elastic IPs|these stay assigned to a DHS AWS account rather than being randomly selected from a pool and released when the instance stops|
|Network Interfaces|the public, private, and secondary private IP addresses for each instance|

## Logging

Many of our AWS instances are connected to Active Directory, receiving weekly vulnerability
scans, running endpoint security products, and logging OS and
application logs.  In addition to this there are AWS-specific
logs such as Cloudtrail, Cloudwatch, ELB, Description, and Config. 

When investigating a
specific system, it may be easier to first identify the indexes and
sourcetypes containing logs for the associated application first.  For
example:

![](images/AWS%20Access%20and%20Logging/image003.png)


![](images/AWS%20Access%20and%20Logging/image004.png)


In this case it may be easier to sort by the different indexes than
the different sourcetypes---unless you're only interested in logs
of one sourcetype.  From here you can narrow the scope by either looking
for the specific host you're interested in or the specific
index/sourcetype you want.

You can also start with one of the sourcetypes that are not
application-specific:

![](images/AWS%20Access%20and%20Logging/image005.png)


Here are descriptions for each of these:

| | |
|-|-|
|Description|shows start time, owner ID, region, and a brief description|
|Cloudtrail|monitoring of API calls, user activity, console sign-ins, changes to resources and services|
|Cloudwatch|monitoring of AWS resources and applications, mostly being used for resource utilization|
|ELB Access Logs|web requests showing client & backend IPs & ports, status codes, user-agent strings|
|Config|a detailed inventory of AWS resources, their configurations, and configuration changes|
|Config notification|logs generated when a specific action or condition is triggered|


And here are some example searches using these:

```
sourcetype="aws:description" public_dns_name=* | table private_ip_address id region owner_id private_dns_name public_dns_name description start_time
```

```
sourcetype="aws:cloudtrail" | table eventType eventSource awsRegion userIdentity.accountId eventName sourceIPAddress userIdentity.type userIdentity.invokedBy
```

```
sourcetype="aws:elb:access_logs"  request!="*health_check*"
| rename elb_status_code as status
| lookup httpcodes.csv status OUTPUT status_description
| stats count by status status_description client_port backend_port request
```

```
sourcetype="aws:config" | table configuration.privateIpAddress configuration.description resourceType configuration.engine configuration.engineVersion configuration.instanceCreateTime configuration.masterUsername configuration.privateDnsName
```
