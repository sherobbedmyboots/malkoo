# Using Docker on Windows

Docker is an open-source platform that automates creating and deploying applications using containerization. Docker for Windows runs as a service and manages all containers which are accessed using a REST API.  The `docker.exe` command line tool is used with the API to create, run, and remove containers.

**Benefits**:

- Portability - deploys the exact same artifacts that have been tested across different hardware and OS's
- Security - isolates an application from the host system and other applications running on the system
- Lightweight - increases efficiency by using only necessary libraries and dependencies

**Terminology**:

|Term|Definition|
|-|-|
|Image|an executable package containing the application code, a runtime, libraries, variables, configuration files, etc.|
|Container|a runtime instance of an image|
|Dockerfile|defines a container's environment, maps files and ports to host system|
|Registry|a storage server for Docker images|
|Docker Hub|the original registry hosting thousands of images|

<br>

This training document will give a basic introduction to the following:

- [Install and Configure Docker](#install-and-configure-docker)
- [Load and Run a Docker Image](#load-and-run-a-docker-image) 
- [Investigate a Docker Container](#investigate-a-docker-container)


### Install and Configure Docker

There are two primary ways to run Docker on Windows:

- [Docker Toolbox](https://docs.docker.com/toolbox/overview/) - Legacy systems use VirtualBox to run Docker environment
- [Docker for Windows](https://www.docker.com/docker-windows) - Windows 10 uses Hyper-V virtualization to run Docker environment


#### Docker Toolbox

I used the following steps to set up Docker Toolbox on my Windows 7 host:

- Installed Docker Toolbox from Software Center which also installed VirtualBox
- Downloaded the [boot2docker ISO](https://github.com/boot2docker/boot2docker/releases/download/v17.03.0-ce/boot2docker.iso) and saved it in the `~\.docker\machine\cache` directory
- Configured Hyper-V boot configuration with `bcdedit /set hypervisorlaunchtype off`
- Turned off Hyper-V using Windows Features, restarted


Starting it with the Docker Quickstart Terminal fails reporting that VTX is not enabled and a machine cannot be created:

![](images/Using%20Docker%20on%20Windows/image003.png)<br><br>

You can build one from the command line with the `--virtualbox-no-vtx-check` option:

First open PowerShell and add Docker directory to your path:

```powershell
$env:PATH += ';C:\Program Files\Docker Toolbox\'
```

Then create a machine named `default`:

```powershell
docker-machine create default --virtualbox-no-vtx-check
```
During this process, you'll need to enter in admin credentials to create network adapters for VirtualBox.

The build will fail again...

![](images/Using%20Docker%20on%20Windows/image004.png)<br><br>


One more setting needs to be changed:

- Open Network and Sharing Center and go to the Change adapter settings in the sidebar
- Right-click on the host-only adapter in the list of adapters and then Properties --> Configure --> Driver tab --> Update driver button
- Select `Browse my computer` --> `Let me Pick...`  --- You should see the list with just host-only driver in it
- Select it and click `Next`

This time the `default` machine has already been created, all we need to do is start it using the Docker Quickstart Terminal or using PowerShell with:

```powershell
docker-machine start default
```

![](images/Using%20Docker%20on%20Windows/image002.png)<br><br>

We now have a bash shell which we can use to control the Docker VM we just created.

Add the Docker Toolbox directory to your path with:

```
PATH=$PATH:'/c/Program Files/Docker Toolbox'
```

#### Docker for Windows

I used the following steps to set up Docker Toolbox on my Windows 10 host:

- Downloaded from https://store.docker.com/editions/community/docker-ce-desktop-windows
- Installed as admin (a sign out is required)

You must be an admin user or a member of the "docker-users" group to run it:

![](images/Using%20Docker%20on%20Windows/image005.png)<br><br>

When Docker for Windows starts, you will see the following message reporting Docker is now running and you can use it from a PowerShell prompt:

![](images/Using%20Docker%20on%20Windows/image006.png)<br><br>

Docker can pull images from the online repository and run them with the `docker run` command.

Both tools at this point will be unable to pull from the repository because they are not proxy-aware:

![](images/Using%20Docker%20on%20Windows/image008.png)<br><br>


In Docker Toolbox, you can change the proxy settings on the Docker VM with:


```
docker-machine ssh default
sudo -s
echo "export HTTP_PROXY=http://<ip>" >> /var/lib/boot2docker/profile
echo "export HTTPS_PROXY=http://<ip>" >> /var/lib/boot2docker/profile
exit
exit
docker-machine restart default
```

For Docker for Windows:

Right click on the Taskbar icon --> `Settings` --> `Proxies` and select `Manual proxy configuration`:

![](images/Using%20Docker%20on%20Windows/image007.png)<br><br>


Once configured, the Docker service will restart.  Now we're able to reach the proxy, but are forbidden from requesting that specific page:

![](images/Using%20Docker%20on%20Windows/image009.png)<br><br>

This is because we don't have the correct User Agent string in our requests.  

To demonstrate this, here is a request for www.example.com using PowerShell's Invoke-WebRequest:

![](images/Using%20Docker%20on%20Windows/image010.png)<br><br>

If we set the user agent string to contain the required string, the request is successful:

![](images/Using%20Docker%20on%20Windows/image011.png)<br><br>

So to pull down Docker images from the Docker Hub, or any other Docker registry, we would need to modify the User Agent string for the Docker application so the traffic would make it through the proxies.  But there is another way to load a Docker image---by loading a tar archive with the `docker load` command.


## Load and Run a Docker Image

To create a tar archive of a docker image, first run it on a system that can access the Docker Hub over the network.

There are two ways to do this:

- [Pull From Remote Repository](#pull-from-remote-repository)
- [Build Using Dockerfile](#build-using-dockerfile)


### Pull From Remote Repository

You can pull an image from the Docker Hub and run it with `docker run <image>`:

![](images/Using%20Docker%20on%20Windows/image014.png)<br><br>

Now find the image you just pulled down in the output of the `docker image ls` command:

![](images/Using%20Docker%20on%20Windows/image015.png)<br><br>

And save the image as a tar archive with the `docker save` command:

![](images/Using%20Docker%20on%20Windows/image016.png)<br><br>

This tar archive can be loaded using the `-i` switch and run on a machine that doesn't have access to a Docker registry:

```
docker load -i hello-world.tar
docker run hello-world
```

![](images/Using%20Docker%20on%20Windows/image017.png)<br><br>


### Build Using Dockerfile

You can also build your own image using a Dockerfile to specify its dependencies and runtime.

First create a Dockerfile:

```python
# Use an official Python runtime as a parent image
FROM python:2.7-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variable
ENV NAME World

# Run app.py when the container launches
CMD ["python", "app.py"]
```

Then create the `app.py` file:

```python
from flask import Flask
from redis import Redis, RedisError
import os
import socket

# Connect to Redis
redis = Redis(host="redis", db=0, socket_connect_timeout=2, socket_timeout=2)

app = Flask(__name__)

@app.route("/")
def hello():
    try:
        visits = redis.incr("counter")
    except RedisError:
        visits = "<i>cannot connect to Redis, counter disabled</i>"

    html = "<h3>Hello {name}!</h3>" \
           "<b>Hostname:</b> {hostname}<br/>" \
           "<b>Visits:</b> {visits}"
    return html.format(name=os.getenv("NAME", "world"), hostname=socket.gethostname(), visits=visits)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
```

And finally a `requirements.txt` file:

```python
Flask
Redis
```

Now we have the three files needed to build the Docker image:

![](images/Using%20Docker%20on%20Windows/image018.png)<br><br>

Build it using `docker build -t friendlyhello .`:

![](images/Using%20Docker%20on%20Windows/image019.png)<br><br>

Once it completes, you can see your new image is listed with `docker image ls`:

![](images/Using%20Docker%20on%20Windows/image020.png)<br><br>

This is 137 MB in size.  We can compress it down to 27 MB using `xz -9 <file>`:

![](images/Using%20Docker%20on%20Windows/image021.png)<br><br>

This file can be hosted anywhere on the Internet, say an S3 bucket, downloaded into our environment, and loaded as a Docker image on one of our machines:

```
docker load -i friendlyhello.tar.xz
```

![](images/Using%20Docker%20on%20Windows/image022.png)<br><br>

Running it with the `-p` switch maps the host's port 4000 to the app's port 80:

![](images/Using%20Docker%20on%20Windows/image023.png)<br><br>

The container that is now running is a simple web server but a good example of how one of our systems could have untrusted code running within a trusted program (Docker).

## Investigate a Docker Container

This `friendlyhello` app running in a container could be untrusted code, so how do we find out more about it?

First let's look at the network connection.  We see the process that's using port 4000 is `vpnkit`:

![](images/Using%20Docker%20on%20Windows/image024.png)<br><br>

Notice the path of the executable and its parent process name:

```
Get-ActiveProcesses | ? ProcessId -eq 7992
```

![](images/Using%20Docker%20on%20Windows/image025.png)<br><br>

At this point, we know that Docker is using `vpnkit.exe` to hold port 4000 open.  We can check for running containers using `docker container ls`:

![](images/Using%20Docker%20on%20Windows/image026.png)<br><br>

Including the `-a` will show all containers on the system, even the ones not currently running:

![](images/Using%20Docker%20on%20Windows/image027.png)<br><br>

You can find the `docker.exe` process and see the time created, account used, and command line details:

```
Get-ActiveProcesses | ? Name -eq docker.exe
```

![](images/Using%20Docker%20on%20Windows/image028.png)<br><br>

Also let's look at the other processes spawned by the `com.docker.service` process:

![](images/Using%20Docker%20on%20Windows/image029.png)<br><br>

The `com.docker.proxy.exe` process lists the VM that Docker is using in its command line arguments:

```
Get-ActiveProcesses | ? Name -eq com.docker.proxy.exe
```

![](images/Using%20Docker%20on%20Windows/image030.png)<br><br>

This is the MobyLinuxVM, the default VM created by Docker on install:

![](images/Using%20Docker%20on%20Windows/image031.png)<br><br>

Use `docker inspect` to gather various details about the running container:

![](images/Using%20Docker%20on%20Windows/image032.png)<br><br>

## Summary

Now that Docker is available on the Software Center, we need to be familiar with all the different ways it can be used to bypass security controls or evade monitoring.  Download or create an image for testing and start practicing different methods for detecting and gathering information on Docker containers running in our environment.

The `friendlyhello` image used in the examples above can be downloaded using [this link](http://exercise-pcap-download-link.s3.amazonaws.com/friendlyhello.tar.xz).