# Investigating Docker Containers

In the majority of our investigations, we're trying to identify the code responsible for interesting files, processes, and network connections on a system.  Containers are portable, lightweight applications running code in a sandboxed environment.  As containers become more prevalent, we need to be familiar with the quickest and most effective ways to gather information and artifacts from containers during incidents.

- [Review of Docker Terminology](#review-of-docker-terminology)
- [Acquiring a Docker Image](#acquiring-a-docker-image)
	- [Pull From a Registry](#pull-from-a-registry)
	- [Download a Tar Archive](#load-from-a-tar-archive)
	- [Build From a Dockerfile](#build-from-a-dockerfile)
- [Running a Container](#running-a-container)
- [Obtaining Information](#obtaining-information)
- [Interacting with Containers](#interacting-with-containers)
- [Obtaining Artifacts](#obtaining-artifacts)
	- [Copying Files](#copying-files)
	- [Copying Containers](#copying-containers)
	- [Copying Images](#copying-images)
		- [Creating Images From Containers](#creating-images-from-containers)
		- [Acquiring Images From Registry](#acquiring-images-from-registry)
		- [AWS Registries](#aws-registries)
- [List of Commands](#list-of-commands)
	- [Images](#images)
	- [Containers](#containers)
	- [Miscellaneous](#miscellaneous)


## Review of Docker Terminology

Docker containers are similar to VMs except they use the host's OS instead of their own.  In a container, an application runs in a sandboxed environment and has everything it needs to run.


An [image](https://docs.docker.com/glossary/?term=image) is a combination of configuration files and layer files used to make containers. It is simliar to installation ISO files for physical servers and VMs---it does not have a state and it never changes.

A [container](https://docs.docker.com/glossary/?term=container) is a runtime instance of an image similar to a VM snapshot.  You can start and stop it, export it to run on another Docker instance, or commit its file changes and settings to create a new image.

A [layer](https://docs.docker.com/glossary/?term=layer) is a modification to an image, represented by an instruction in the Dockerfile. When an image is built, each layer is applied in sequence to create the final image. When an image is pulled, only the layers not cached are downloaded.  When an image is updated or rebuilt, only layers that change need to be updated.

A [repository](https://docs.docker.com/glossary/?term=repository) is a set of Docker images with `library` being the default repository containing Docker official images. Each image in a repository is labeled using [tags](https://docs.docker.com/glossary/?term=tag) with `latest` being the default tag. 

A [registry](https://docs.docker.com/glossary/?term=registry) is a hosted service containing repositories of images which responds to the [Docker Registry API](https://docs.docker.com/registry/spec/api/). Docker Hub has thousands of images that can be quickly and easily searched, pulled, and run.


Summary:

- Registries host repositories of images that can be downloaded via `docker pull` or the Registry API
- A Dockerfile is a set of instructions used to create an image
- Images are used to create containers and do not change
- Containers are always changing but their changes do not persist after they die
- Containers can be saved as images to keep their changes
- Volumes are used to save and share container data on host
- Docker maps container ports to host ports to control network access


## Acquiring a Docker Image

When investigating a Docker container, it is important to establish how the image made it onto the machine. Here are three different methods of acquiring an image:

- [Pull From a Registry](#pull-from-a-registry)
- [Download a Tar Archive](#load-from-a-tar-archive)
- [Build From a Dockerfile](#build-from-a-dockerfile)

### Pull From a Registry

You can pull images from a registry using `docker pull` or by using the [Docker Registry API](https://docs.docker.com/registry/spec/api/).  The `Get-DockerImage` function uses the registry API to perform the same actions as the `docker pull` command---it downloads the required layers and configuration files for an image and loads it into Docker:

![](images/Investigating%20Docker%20Containers/image001.png)<br><br>

### Download a Tar Archive

Another option is to just download an already-created tar file of an image from an external location and load it into Docker:

![](images/Investigating%20Docker%20Containers/image003.png)<br><br>

The `docker import` method is used for container tar files created with `docker export` while the `docker load` method is used for image tar files created with `docker save`.

### Build from a Dockerfile

A third option is building an image on the local system.  To do this, you need a Dockerfile that lists the layers needed and the commands that will be run to build it:

```bash
FROM  node:10-alpine
RUN   npm config set user-agent=xxxxxxxx
 && export http_proxy=http://xxxxxxxx:80 \
 && export https_proxy=http://xxxxxxxx:80 \
 && npm install http-server -g
COPY  html /html
EXPOSE  8080
EXPOSE  4444
CMD  ["http-server","/html","&"]
```

<br>

Here is a list of instructions used in Dockerfiles:

|Instruction|Description|
|-|-|
|FROM|The base or parent image|
|LABEL|Metadata|
|ENV|Sets environment variables|
|RUN|Runs command which creates an image layer|
|[COPY/ADD]|Copies files to the container|
|CMD|Run-time commands (are overwritten by command line args)|
|WORKDIR|Sets working directory|
|ARG|Variables passed to Docker at build-time|
|ENTRYPOINT|Persistent run-time commands (command line args are appended)| 
|EXPOSE|Documents ports to be published|
|VOLUME|Mounts directory for accessing and storing data|

<br>

Docker performs each command in the Dockerfile creating a layer for each step to track the differences between previous and current versions of the image:

![](images/Investigating%20Docker%20Containers/image002.png)<br><br>

When you download an image, you download only the layers you don't have.  Since the `node:10-alpine` image was already cached, that layer didn't need to be downloaded.

Now there are three images:

![](images/Investigating%20Docker%20Containers/image004.png)<br><br>

## Running a Container

We can start a container with `docker run`.  The `jslab` image is configured to run `http-server /html &` on launch, or you can provide a command to run such as `sh` or `node` to interact with the container.

The command `docker run -d -p 4000:8080 -p 4444:4444 jslab` starts the `jslab` container detached (`-d`) and maps host ports `4000` and `4444` to container ports `8080` and `4444` respectively.

![](images/Investigating%20Docker%20Containers/image005.png)<br><br>

After finding the container's ID with `docker ps`, we can use it to get some details about what the container is doing using different docker commands:

![](images/Investigating%20Docker%20Containers/image051.png)<br><br>

We can also run the `nodejs` program in the container interactively with `docker exec`:

![](images/Investigating%20Docker%20Containers/image007.png)<br><br>

Exit the interactive session by pressing `Ctrl-P` then `Ctrl-Q`.  Now try it with alpine's shell program `sh`:

![](images/Investigating%20Docker%20Containers/image006.png)<br><br>

Listing network connections shows what looks to be a webserver on port `8080`:

![](images/Investigating%20Docker%20Containers/image022.png)<br><br>

Listing processes reveals the directory and pages that the web server is hosting:

![](images/Investigating%20Docker%20Containers/image008.png)<br><br>

Since port `8080` on the container is mapped to port `4000` on the host, visit `localhost:4000` to render the web page:

![](images/Investigating%20Docker%20Containers/image009.png)<br><br>

It looks like it could be some type of a training lab:

![](images/Investigating%20Docker%20Containers/image010.png)<br><br>

Yes, it's definitely a lab for analyzing malicious browser and JavaScript techniques:

![](images/Investigating%20Docker%20Containers/image011.png)<br><br>

But if we didn't know what this was, what are some ways we could find out?

## Obtaining Information

The `docker info` command provides various information about the Docker environment:

![](images/Investigating%20Docker%20Containers/image012.png)<br><br>

The `docker inspect` command can be used to gather information about both containers and images:

![](images/Investigating%20Docker%20Containers/image013.png)<br><br>

![](images/Investigating%20Docker%20Containers/image014.png)<br><br>

List all containers, running and not, with `docker ps -a`:

![](images/Investigating%20Docker%20Containers/image015.png)<br><br>

Show history of an image with `docker history`:

![](images/Investigating%20Docker%20Containers/image016.png)<br><br>

You can use the `Get-InspectImagesInfo` function to print a summary of docker images available with more detailed information saved to the `$inspectImages` variable:

![](images/Investigating%20Docker%20Containers/image045.png)<br><br>

The `Get0InspectContainersInfo` function does the same with containers:

![](images/Investigating%20Docker%20Containers/image046.png)<br><br>

## Interacting with Containers

Attaching to the container with `docker attach <c-id>` allows you to see the output of the command running in the container.  Here we can see web requests made to the web server while the container is running:

![](images/Investigating%20Docker%20Containers/image017.png)<br><br>

Copy files back and forth from the container with `docker cp`:

![](images/Investigating%20Docker%20Containers/image018.png)<br><br>

![](images/Investigating%20Docker%20Containers/image019.png)<br><br>

See changes that have been made to the container with `docker diff <c-id>`:

![](images/Investigating%20Docker%20Containers/image021.png)<br><br>

These files can be used to determine what occurred inside the container:

![](images/Investigating%20Docker%20Containers/image023.png)<br><br>

## Gathering Artifacts

- [Copying Files](#copying-files)
- [Copying Containers](#copying-containers)
- [Copying Images](#copying-images)


### Copying Files

We can capture the output of the `docker diff` command into an array:

![](images/Investigating%20Docker%20Containers/image024.png)<br><br>

Then for each filename in the array, use `docker cp` to copy it to a directory named `artifacts` on the local system:

![](images/Investigating%20Docker%20Containers/image025.png)<br><br>

But if you're investigating a remote system, you'll want to capture the files into objects:

![](images/Investigating%20Docker%20Containers/image026.png)<br><br>

We can automate this process using the `Get-ContainerChangedFiles` function:

![](images/Investigating%20Docker%20Containers/image027.png)<br><br>


### Copying Containers

The `docker export` command is used to persist a container.

Exporting our container, which happens to be a very small one, results in a 78 MB tar file:

![](images/Investigating%20Docker%20Containers/image028.png)<br><br>

This is small enough to store in a variable (< 2 GB) but for larger files we'll need to copy the file over to another system via SMB or similar method.  A good option is using `Start-BitsTransfer -source $source -destination $dest -asynchronous` which will automatically resume the transfer if interrupted and using `Get-BitsTransfer` to check progress.


### Copying Images

- [Creating Images From Containers](#creating-images-from-containers)
- [Acquiring Images From Registry](#acquiring-images-from-registry)
- [AWS Registries](#aws-registries)

### Creating Images From Containers

We can also create an image of the container and its changes with `docker commit`:

![](images/Investigating%20Docker%20Containers/image029.png)<br><br>

Now the image can be saved to a tar archive with `docker save`.

### Acquiring Images From Registry

You may be working an incident where an image of interest is being stored on another system or in a Docker registry. Obtaining a copy of the image could provide significant artifacts and context to the investigation. 

This Splunk search returns a number of repository/images in our environment:

```splunk
index=* "docker pull"
| rex field=_raw "docker pull (?<registry>[\.\-\:a-zA-Z0-9]+)/(?<repotag>[\.\:\-a-zA-Z0-9]+)[\s\"]{1}" 
| stats values(repotag) count by registry
```

![](images/Investigating%20Docker%20Containers/image032.png)<br><br>

Once you've identified a registry, list all repository/images on it using the `Get-RepoImages` function:

![](images/Investigating%20Docker%20Containers/image031.png)<br><br>

List the available tags for an image with the `Get-ImageTags` function:

![](images/Investigating%20Docker%20Containers/image041.png)<br><br>

Identify the layers of an image with the `Get-ImageManifest` function:

![](images/Investigating%20Docker%20Containers/image042.png)<br><br>

Pulling the image with Docker errors due to an expired cert:

![](images/Investigating%20Docker%20Containers/image043.png)<br><br>

But the image can be pulled, extracted and loaded into Docker with the `Get-DockerImage` function:

![](images/Investigating%20Docker%20Containers/image044.png)<br><br>

### AWS Registries

The AWS API can be used to locate internal registries (154 returned by this search) in our AWS environment and download images stored there:

![](images/Investigating%20Docker%20Containers/image030.png)<br><br>

Use `Get-ECRRepository` to list repositories in a registry:

![](images/Investigating%20Docker%20Containers/image033.png)<br><br>

Use `Get-ECRImage` to list the images available in each repository:

![](images/Investigating%20Docker%20Containers/image034.png)<br><br>

Use `Get-ECRImageMetadata` to see the image size and when it was pushed:

![](images/Investigating%20Docker%20Containers/image039.png)<br><br>

If you try to pull it with Docker, it asks for credentials:

![](images/Investigating%20Docker%20Containers/image038.png)<br><br>

There are two ways to authenticate.  The first option is using `Get-ECRLoginCommand` which returns a username, password, and `docker login` command:

![](images/Investigating%20Docker%20Containers/image037.png)<br><br>

The other option is using `Get-ECRAuthorizationToken` which returns a Base64-encoded token containing the same login information:

![](images/Investigating%20Docker%20Containers/image036.png)<br><br>

You can either pipe the docker command to IEX or manually enter in the command and credentials with the `docker login` command:

![](images/Investigating%20Docker%20Containers/image035.png)<br><br>

Now that Docker has the proper credentials, the image can be pulled:

![](images/Investigating%20Docker%20Containers/image040.png)<br><br>








## List of Docker Commands

- [Containers](#containers)
- [Images](#images)
- [Miscellaneous](#miscellaneous)

### Containers

|Command|Description|
|-|-|
|`docker ps`|List containers|
|`docker diff <c-id>`|See container filesystem changes|
|`docker exec <c-id> <command>`|Run a command in a container|
|`docker export`|Export container filesystem as tar archive|
|`docker logs <c-id>`|Get container logs|
|`docker port <c-id>`|Get container port mappings|
|`docker rename <c-name> <new-name>`|Rename a container|
|`docker restart <c-name>`|Restart a container|
|`docker create`|Create a new container|
|`docker rm <c-id>`|Remove a container|
|`docker run <image> <command>`|Run a command in a new container|
|`docker [start\|stop] <c-id>`|Start or stop a container|
|`docker kill <c-id>`|Kill a running container|
|`docker top <c-id>`|Display a container's running processes|
|`docker update`|Update a container configuration|
|`docker inspect <c-id>`|Get container settings|
|`docker attach <c-id>`|Attach stdin, stout, error to a container|
|`docker cp <c-id>:<source> <dest>`|Copy from container to local filesystem|
|`docker cp <source> <c-id>:<dest>`|Copy from local filesystem to container|	
|`docker stats`|Show live resource usage of running containers|

### Images

|Command|Description|
|-|-|
|`docker build`|Build an image from a Dockerfile|
|`docker commit`|Create a new image from container changes|
|`docker history <image>`|See image history|
|`docker images`|List images|
|`docker import <tar-file>`|Create image from tar archive|
|`docker load <tar-file>`|Load an image from a tar archive|
|`docker pull <image>`|Pull image or repo from a registry|
|`docker push <image>`|Push image or repo to a registry|
|`docker rmi <image>`|Remove an image|
|`docker save`|Save an image to a tar archive|
|`docker search`|Search for an image on Docker Hub|


### Miscellaneous

|Command|Description|
|-|-|
|`docker info`|See information on docker environment|
|`docker [login\|logout] -u <username> <registry>`|Log in/out to a Docker registry|
