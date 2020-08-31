# Investigating AWS Internet Gateways

An AWS Internet Gateway (IGW) is a virtual route allowing EC2 instances in our AWS environment to communicate with the Internet.  

This training document will review IGW requirements and common investigative tasks using Splunk, the AWSPowerShell module, and the [Get-AWSFlowLogs.ps1](scripts/Get-AWSFlowLogs.ps1) script.

- [Internet Gateway Requirements](#igw-requirements)
- [Using AWSPowerShell](#using-awspowershell)
- [Using Splunk](#using-splunk)
- [Obtaining Flow Logs](#obtaining-flow-logs)	


<br>

## Internet Gateway Requirements

Once an IGW is attached to a VPC, for an instance to have access to the Internet there are four additional requirements:

- The [VPC](#vpcs) contains a Route Table with a route to the IGW
- The instance has an [ENI](#enis) with a public IP or an Elastic IP address
- The instance has a [Security Group](#security-groups) allowing the traffic
- The VPC has a [Network Access Control List (NACL)](#network-access-control-lists) allowing the traffic


### VPCs

A VPC is an isolated virtual network assigned to an AWS account which reaches across all regions.  Subnets are added to VPCs and are associated with route tables which instances use to pass traffic to and from other hosts.

To use an IGW, the route table associated with an instance's subnet must contain a route that directs Internet-bound traffic to the IGW (0.0.0.0/0 for IPv4 or ::/0 for IPv6).

### ENIs

An Elastic Network Interface (ENI) is a logical networking component in a VPC that represents a virtual network card.  It can be attached to an instance, detached, attached to another instance, and so on... its attributes follow it wherever it is used. 

To use an IGW, an instance must have a public IPv4 address or an Elastic IP address that's associated with its private IPv4 address.

### Security Groups

A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.  Security groups are for instances, are stateful, and only utilize allow rules.

Each security group has inbound rules (ingress) that control the inbound traffic to instances and outbound rules (egress) that control the outbound traffic.

To use an IGW, an instance must have a security group which allows Internet-bound traffic.

### Network Access Control Lists

Network ACLs (NACL) are for subnets, apply to all instances in a subnet, are stateless, and utilize both allow and deny rules.

To use an IGW, an instance's VPC must have a NACL which allows Internet-bound traffic.

<br>

Two ways we can confirm if these four requirements were met are:

- [Using AWSPowerShell](#using-awspowershell)
- [Using Splunk](#using-splunk)


## Using AWSPowerShell

One common scenario is when you're investigating a suspicious IP address and want to determine if it was able to send and receive traffic to and from the Internet.  For this example let's use `1.1.1.1`.

The first step would be getting details about the instance that has that IP address.  First get a session token with the [Get-TempAWSCreds.ps1](scripts/Get-TempAWSCreds.ps1) script:

![](images/Investigating%20AWS%20Internet%20Gateways/image010.png)<br><br>

Then use [AWSPowerShell](https://www.powershellgallery.com/packages/AWSPowerShell/3.3.365.0) cmdlets to get the information you need. First, check for a route table in the region that would route traffic to an IGW:


```powershell
Get-EC2RouteTable -ProfileName 123456789012 -Region <region> | select -exp Routes | select GatewayId,DestinationCidrBlock,State
```

<br>

No IGWs are listed:

![](images/Investigating%20AWS%20Internet%20Gateways/image013.png)<br><br>

If they were it would look similar to this one in another region except this one is blackholed instead of active:

![](images/Investigating%20AWS%20Internet%20Gateways/image014.png)<br><br>


Next determine if the instance has a public IP address:

```powershell
Get-EC2Instance -ProfileName 123456789012 -Region <region> | select -exp Instances | ? PrivateIpAddress -eq '1.1.1.1'
```

<br>

No public IP address is listed:

![](images/Investigating%20AWS%20Internet%20Gateways/image011.png)<br><br>

Save the instance to an object and get its assigned Security Groups:

```powershell
$instance = Get-EC2Instance -ProfileName 123456789012 -Region <region> | select -exp Instances | ? PrivateIpAddress -eq '1.1.1.1'
$instance.SecurityGroups
```

<br>

![](images/Investigating%20AWS%20Internet%20Gateways/image015.png)<br><br>


For each security group, we need to look at the rules.  The following function parses the properties of a security group object and makes it more easily read:

```powershell
function Get-Rules ($sg) {
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
```

<br>

Running the function on each security group shows us all the traffic rules applied to the instance:

![](images/Investigating%20AWS%20Internet%20Gateways/image016.png)<br><br>


The security groups applied allow outbound traffic to the Internet.  Finally, let's check the NACL.


First we need the VpcId of the VPC it's on:

```powershell
$instance = Get-EC2Instance 123456789012 -Region <region> | select -exp Instances | ? PrivateIpAddress -eq '1.1.1.1'
$instance.VpcId
```

<br>

![](images/Investigating%20AWS%20Internet%20Gateways/image012.png)<br><br>

With the VPC ID, we can get the details of the NACL that's attached to it:

```powershell
$e=(Get-EC2NetworkAcl -ProfileName 123456789012 -Region <region> | ? VpcId -eq vpc-abc123de).Entries
$e | select CidrBlock,Egress,Protocol,RuleAction,RuleNumber | ft -auto
```

<br>

![](images/Investigating%20AWS%20Internet%20Gateways/image017.png)<br><br>

The allow all rules are processed before the deny all rules for both ingress and egress.  The `-1` in the Protocol is a wildcard value.  All four requirements could have been met, we'll need flow logs for further investigation.


## Using Splunk

Another scenario is receiving an email alert like this one:

![](images/Investigating%20AWS%20Internet%20Gateways/image001.png)<br><br>

Running the search shows an IGW (`igw-1234567890abcde`) was successfully attached to a VPC:

![](images/Investigating%20AWS%20Internet%20Gateways/image002.png)<br><br>

Adding `OR eventName=createRoute` to this search shows us if any routes were created during that time:

![](images/Investigating%20AWS%20Internet%20Gateways/image003.png)<br><br>

The route created sends all traffic (0.0.0.0/0) to the IGW that was attached and meets our first requirement:

![](images/Investigating%20AWS%20Internet%20Gateways/image004.png)<br><br>


Next, we need to determine if any instances on that VPC had a public IP address:

```
sourcetype="aws:config" configurationItemStatus="ResourceDiscovered" resourceType="AWS::EC2::Instance" "vpc-00000000" 
| rename configuration.networkInterfaces{}.association.publicIp AS publicIp, configuration.instanceId as instanceId, configuration.launchTime AS launchTime
| rename configuration.networkInterfaces{}.association.publicDnsName AS publicDnsName, configuration.instanceType AS instanceType
| table _time instanceId instanceType publicIp publicDnsName launchTime
```
<br>

These logs show one instance was launched in the VPC minutes after the IGW was attached and it had a public IP address:

![](images/Investigating%20AWS%20Internet%20Gateways/image005.png)<br><br>

The third requirement is a security group assigned to this instance that allows the traffic.  The `relationships` field in this log contains the name of the security group assigned along with other information about the instance:

![](images/Investigating%20AWS%20Internet%20Gateways/image006.png)<br><br>

To see the security group's rules, find where the security group was created with:

```
sourcetype="aws:config" resourceId=sg-1111111111 resourceType="AWS::EC2::SecurityGroup"
```
<br>

The security group allows all traffic and ports (0.0.0.0/0) and all protocols outbound:

![](images/Investigating%20AWS%20Internet%20Gateways/image007.png)<br><br>


The fourth requirement is an NACL attached to the VPC that would allow the traffic.  First bring up the VPC's info with:

```
sourcetype="aws:config" configurationItemStatus=ResourceDiscovered resourceId=vpc-000000000
```

<br> 

Now its `relationships` field will give us all resources associated with the VPC including the NACL:

![](images/Investigating%20AWS%20Internet%20Gateways/image008.png)<br><br>

We can look at the details of the NACL using its `resourceId`:

```
sourcetype="aws:config" configurationItemStatus=ResourceDiscovered resourceId=acl-22222222222
| rename configuration.entries{}.cidrBlock AS cidrBlock, configuration.entries{}.egress AS egress, configuration.entries{}.protocol AS protocol, configuration.entries{}.ruleAction AS ruleAction, configuration.entries{}.ruleNumber AS ruleNumber
| dedup cidrBlock egress protocol ruleAction ruleNumber
| table cidrBlock egress protocol ruleAction ruleNumber	
```
<br>

We can see the rules that apply to traffic in the VPC and the order in which they are applied:

![](images/Investigating%20AWS%20Internet%20Gateways/image009.png)<br><br>

For both ingress and egress rules, all traffic (0.0.0.0/0) is allowed before it is denied.  So all the requirements were there for the instance to have Internet access.

Again, we need flow logs to confirm.

## Obtaining Flow Logs

Flow logs represent "flows" of traffic containing a source IP and port, a destination IP and port, and the protocol used.  

Traffic that is not captured in AWS flow logs include:

- DHCP traffic
- DNS traffic to Amazon DNS servers
- Amazon Windows license activation traffic
- Instance metadata traffic to/from 169.254.169.254
- Amazon Time Sync traffic to/from 169.254.169.123
- Traffic to the default VPC router
- Traffic to/from a Network Load Balancer 

Use the `Get-EC2FlowLogs` cmdlet to verify flow logs are being collected on the VPC of interest:

```powershell
Get-EC2FlowLogs -ProfileName 123456789012 -Region <region>
```

<br>

![](images/Investigating%20AWS%20Internet%20Gateways/image019.png)<br><br>

With the name of an ENI, you can obtain flow logs in object form using the [Get-AWSFlowLogs.ps1](scripts/Get-AWSFlowLogs.ps1) script.  In this case let's find the ENI for 1.1.1.1:

![](images/Investigating%20AWS%20Internet%20Gateways/image018.png)<br><br>

Now provide the account ID and ENI name as arguments and capture the results in a variable:

![](images/Investigating%20AWS%20Internet%20Gateways/image020.png)<br><br>

Now filter and search based on any of the properties (source IP, dest IP, ports, date, time, etc.):

![](images/Investigating%20AWS%20Internet%20Gateways/image021.png)<br><br>


## Summary

Try using the [AWSPowerShell](https://www.powershellgallery.com/packages/AWSPowerShell/3.3.365.0) cmdlets and [Get-AWSFlowLogs.ps1](scripts/Get-AWSFlowLogs.ps1) script to pull flow logs for Elastic Network Interfaces (ENI) and store them in objects for easier filtering and searching.


## Update

As discussed, when an IGW is attached to a VPC there are four things required for an instance to use the IGW:

-   The instance is on a VPC that contains a Route Table with a route to the IGW
-   The instance is on a VPC that has a Network Access Control List (NACL) allowing the traffic
-   The instance has an ENI with a public IP or an Elastic IP address
-   The instance has a Security Group allowing the traffic


The [Get-IGWInfo]() function has been added to the [AWSmodule](scripts/AWSmodule.psm1) to quickly check for these four requirements when we receive an alert and identify:

-   VPCs that are allowing traffic to the IGW
-   Instances on these VPCs that can use the IGW


If this function is run and the IGW has already been terminated, you will get this message:

```powershell
Get-IGWInfo -accountid 12345667890 -GatewayId igw-abcdefg1234567890
```

![](images/Investigating%20AWS%20Internet%20Gateways/image023.png)<br><br>

But if the IGW is still up, and there are VPCs and/or instances able to use the IGW, you will get information necessary for further investigation and monitoring:

![](images/Investigating%20AWS%20Internet%20Gateways/image024.png)<br><br>
