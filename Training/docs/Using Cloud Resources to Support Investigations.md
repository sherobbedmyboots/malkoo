# Using Cloud Resources to Support Investigations

Cloud computing platforms like [Amazon Web Services](https://aws.amazon.com/), [Microsoft Azure](https://azure.microsoft.com/en-us/), and [Google Cloud Platform](https://cloud.google.com/) offer services where consumers can rent instead of buy compute resources paying only for what they need or use.  They host resources on infrastructure which is spread across multiple regions and datacenters using various edge points of presence providing scalable and reliable operations.

- [The Big Three Cloud Providers](#the-big-three-cloud-providers)
  - [Amazon Web Services](#amazon-web-services)
  - [Microsoft Azure](#microsoft-azure)
  - [Google Cloud Platform](#google-cloud-platform)
- [Cloud Resources](#cloud-resources)
  - [Instances](#instances)
  - [Applications](#applications)
  - [Containers](#containers)
  - [Functions](#functions)
- [Use Cases](#use-cases)
  - [Gathering OSINT](#gathering-osint)
  - [Performing Reconnaissance](#performing-reconnaissance)
  - [Malware Analysis](#malware-analysis)

<br>

## The Big Three Cloud Providers

There are a number of other cloud providers (Digital Ocean, VMWare, IBMCloud, Rackspace), but this training document reviews the most popular three and how some of their services can be used to support investigations.

- [Amazon Web Services](#amazon-web-services)
- [Microsoft Azure](#microsoft-azure)
- [Google Cloud Platform](#google-cloud-platform)

### Amazon Web Services

This is currently the most popular provider of the three and first became available for use in 2006.  The current list of IP ranges used by Amazon is available [here](https://ip-ranges.amazonaws.com/ip-ranges.json).

To quickly get this list, use:

```powershell
$z=Invoke-RestMethod https://ip-ranges.amazonaws.com/ip-ranges.json
$z.prefixes.ip_prefix
```

<br>

Use the `Get-AmazonAddressSpace` function to automate this:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image003.png)<br><br>

Here is a list of previous AWS-related training documents:

- [AWS Access and Logging](AWS%20Access%20and%20Logging.md)
- [Review of Amazon Services](Review%20of%20Amazon%20Web%20Services.md)
- [AWS IAM Best Practices](AWS%20IAM%20Best%20Practices.md)
- [Investigating AWS Internet Gateways](Investigating%20AWS%20Internet%20Gateways.md)
- [Using the AWS Module](Using%20the%20AWS%20Module.md)

<br>

### Microsoft Azure  

[Azure](https://portal.azure.com/) is Microsoft's cloud service provider, started in 2010.  Here are a few of the services available:

|Category|Service|
|-|-|
|Compute |VMs, App Service, Container Instances, Kubernetes Service, Functions|
|Networking|Virtual Network, Gateways, DNS, Load Balancer, CDN|
|Storage |Disk, File, Archive, Backup, Data|
|AI|Cognitive Services, Bot Service, Machine Learning, Databricks, Search|
|Analytics |HDInsight, Data Factory, Stream Analytics|

<br>

A current list of Azure IP ranges can be downloaded [here](https://www.microsoft.com/en-us/download/details.aspx?id=41653).  

To quickly get this list, use:

```powershell
[xml]$x = Invoke-WebRequest https://download.microsoft.com/download/0/1/8/018E208D-54F8-44CD-AA26-CD7BC9524A8C/PublicIPs_20190715.xml
$x.AzurePublicIpAddresses.Region | %{$_.Iprange}
```

<br>

Use the `Get-AzureAddressSpace` function to automate this:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image004.png)<br><br>

You can use the Azure portal, Azure CLI, or Azure PowerShell, to manage Azure resources.

Here is the portal dashboard which shows a summary of services and management tools:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image005.png)<br><br>

The Azure Cloud Shell is an interactive shell environment that you can use to interact with resources from inside your browser using Azure CLI or Azure PowerShell:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image007.png)<br><br>

You can also interact with resources from any machine using the [Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/?view=azps-2.7.0).  First log in interactively with `Connect-AzAccount`:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image023.png)<br><br>

### Google Cloud Platform   

[Google Cloud Platform](https://cloud.google.com) was created in 2011 and offers a host of similar services:

|Category|Service|
|-|-|
|Compute |Instances, Applications, Containers, Functions|
|Networking|Virtual Network, DNS, Load Balancer, CDN|
|Storage |Storage, BigTable, DataStore, SQL, Persistent Disk|
|Cloud AI|Machine Learning, Vision, Speech, Natural Language, Translation, Jobs|
|Big Data |BigQuery, DataFlow, DataProc, DataLab, Pub/Sub, Geonomics  |

<br>

Google Compute Engine IP address ranges change from time to time.  To get a current list, first get a TXT record for `_cloud-netblocks.googleusercontent.com` which returns a list of domains.  Second, get a TXT record for each of these domains which returns the current list of IP ranges.

Use the `Get-GoogleCloudAddressRange` function to automate this:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image001.png)<br><br>

If you're searching with Splunk, use the `splunk` parameter to specify a field and it will return a string that can be copied and pasted in Splunk:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image002.png)<br><br>

Here is the dashboard which shows a summary of services and management tools:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image006.png)<br><br>

The GCP Cloud Shell is an interactive shell environment that you can use to interact with resources from inside your browser:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image008.png)<br><br>

You can also interact with resources from any machine using the [Google Cloud SDK](https://cloud.google.com/sdk/).  First log in with `gcloud auth login`:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image018.png)<br><br>

You'll be prompted to choose an account to use:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image019.png)<br><br>

Then you must provide authorization for the Google Cloud SDK to access the account via OAuth token:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image020.png)<br><br>

Once you're logged in you can specify a project and begin making API calls:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image021.png)<br><br>


## Cloud Resources

There are many types of cloud resources that can be useful during an investigation but we'll just cover a few basic ones here:

- [Instances](#instances)
- [Applications](#applications)
- [Containers](#containers)
- [Functions](#functions)

### Instances  

You can quickly create a VM in either cloud provider using a template or uploading your own disk image.  Azure provides a nice interface where you can set options and see the rate the machine will incur charges:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image009.png)<br><br>

Once VMs are started, list them using the console or the Azure shell:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image010.png)<br><br>

Connect to instances through the browser using SSH or the serial console:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image011.png)<br><br>

Here's an example of uploading your own image using Google Cloud Platform using [REMnux](https://remnux.org):

First configure SSH and authentication on the VM:

```bash
# Set sshd to start on boot
sudo nano /etc/rc.local

# Add the follwoing to the file before `exit 0`
sudo service ssh start

# Set up authentication
sudo nano /etc/ssh/sshd_config

# Add the following to the file
PermitRootLogin yes
```

<br>

When complete, upload the disk image file to a Google Cloud bucket, and import it as an image:

```bash
# Create a bucket
gsutil mb gs://remnux-in-the-cloud/

# Copy the virtual disk image to the bucket
gsutil cp REMnuxV6-disk1.vmdk gs://remnux-in-the-cloud/REMnuxV6-disk1.vmdk

# Import the disk image
gcloud compute images import image-1 --source-file gs://remnux-in-the-cloud/REMnuxV6-disk1.vmdk --os ubuntu-1404
```

<br>

Once complete, it will show under imported images:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image022.png)<br><br>

Now you can create an instance with the image, and when it comes up SSH to it through the browser:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image026.png)<br><br>

> If trouble connecting, select the settings icon in top right corner and select ***Change Linux Username*** and enter "remnux"

<br>

Notice that when connecting to the instance through the browser, the connection to the REMnux VM originates from Google Cloud's IP address space:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image029.png)<br><br>


### Applications

There are quick and easy ways to stand up an application no matter what programming language is being used.  To demonstrate, we'll use [this simple nodejs geolocation application](https://github.com/atstpls/geolocation).

Create a project to use:

```
gcloud projects create [YOUR_PROJECT_ID] --set-as-default
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image060.png)<br><br>


Create an app with it:

```
gcloud app create --project=[YOUR_PROJECT_ID]
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image061.png)<br><br>


Download the code to your cloud storage:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image062.png)<br><br>


To run this app, you'll need an API key from [ipstack.com](https://ipstack.com/) and can add it to a `.env` file with:

```
echo 'KEY=1234567890abcdef1234567890' > .env
```

<br>

Install dependencies and start the app:

```
npm install
npm start
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image063.png)<br><br>

Preview the app with ***Web Preview*** button:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image064.png)<br><br>

If the app is working locally, you're now ready to deploy.  Press `Ctrl+C` to stop the app and deploy the code with:

```
gcloud app deploy
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image065.png)<br><br>

Now the application is live at your project's url `https://<project-id>.appspot.com`:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image066.png)<br><br>

Any application that visits this page will receive geolocation data associated with its IP address:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image067.png)<br><br>

The app can be edited and updated... To clean up, go to the [Cloud Resource Manager](https://console.cloud.google.com/cloud-resource-manager) page, select the project, and delete it:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image068.png)<br><br>

### Containers

Here's an example of deploying a container using Google Cloud Platform.

First, build a custom image or pull an existing image and tag it with:

```
docker tag <image> gcr.io/<project>/<image>:<tag>
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image056.png)<br><br>


Then push it to your chosen container registry with:

```
docker push gcr.io/<project>/<image>:<tag>
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image055.png)<br><br>


Change to the desired project and configure some settings in the `gcloud` client or in the console:

```
export PROJECT_ID=<project id>
gcloud config set compute/zone <zone>
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image040.png)<br><br>


At this point you will need to enable the GKE API if you haven't before:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image042.png)<br><br>


Create a cluster with:

```
gcloud container clusters create <cluster name> --num-nodes=<num>
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image041.png)<br><br>


Deploy the container to the cluster and expose its ports to the Internet:

```
kubectl create deployment <container name> --image=gcr.io/<project id>/<image>
kubectl expose deployment <container name> --type=LoadBalancer --port 8080 --target-port 8080
```

<br>

Now, check the resources you've created with the following commands:

```
gcloud compute instances list
kubectl get pods
kubectl get service
kubectl get deployment
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image043.png)<br><br>

The `kubectl get service` command shows the IP address assigned to the container.  Visit to confirm it is working:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image045.png)<br><br>

To clean up, use:

```
kubectl delete service <container name>
gcloud container clusters delete <cluster name>
```
<br>

### Functions

Cloud functions are blocks of arbitrary code you can run in the cloud when a specific condition is met.  The most simple example is the default Hello World function that runs when a URL is visited:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image051.png)<br><br>

When you enable it, visiting the trigger URL returns the message "Hello World!:"

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image052.png)<br><br>


Here is an example of creating a simple geolocation function using [this code](https://github.com/ministryofprogramming/gcf-geolocation):

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image047.png)<br><br>

Edit the `index.json` to match:

```js
const cors = require('cors')

function _geolocation(req, res) {
  const data = {
    country: req.headers["x-appengine-country"],
    region: req.headers["x-appengine-region"],
    city: req.headers["x-appengine-city"],
    cityLatLong: req.headers["x-appengine-citylatlong"],
    userIP: req.headers["x-appengine-user-ip"]
  }
  res.json(data)
};

exports.geolocation = (req, res) => {
  const corsHandler = cors({ origin: true })

  return corsHandler(req, res, function() {
    return _geolocation(req, res);
  });
};
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image048.png)<br><br>

Edit the `package.json` to match:

```js
{
  "name": "gfc-geolocation",
  "version": "0.0.1",
  "dependencies": {
    "cors": "^2.8.4"
  }
}
```

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image049.png)<br><br>

Now when a visitor goes to the trigger URL, their geolocation data is returned:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image050.png)<br><br>

## Use Cases  

Here are some examples where cloud resources may be useful:

- [Gathering OSINT](#gathering-osint)
- [Performing Reconnaissance](#performing-reconnaissance)
- [Malware Analysis With REMnux](#malware-analysis)


### Gathering OSINT

There are a number of different OSINT gathering tools like [Spiderfoot](https://github.com/smicallef/spiderfoot) that are extremely valuable during an investigation but may not be available to use on your workstation or may be restricted to specific hosts it can contact if deployed in our environment.

In this case you may want to deploy a container with [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine/).

Here I'm running a scan on one of the IPs involved in a recent incident involving ELF malware

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image057.png)<br><br>

Spiderfoot returns lots of data it discovered is or was related to the IP address:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image058.png)<br><br>

Affiliated hostnames for example:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image059.png)<br><br>


### Performing Reconnaissance

There are investigations where you can't risk interacting with another system directly, but you may consider using a clean, isolated machine hosted by a cloud provider.  

In this case you may want to create a VM with [Google Compute Engine](https://cloud.google.com/compute/).

Here is a brand new VM being used to view the `bins` directory on a system that was recently observed delivering Linux malware.

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image014.png)<br><br>

Using this machine, we can download one of the malware samples that are being served to victims:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image015.png)<br><br>

The `file` program confirms it is an ELF executable:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image016.png)<br><br>

We can download additional tools such as [FLOSS](https://github.com/fireeye/flare-floss) and see that it contains some interesting strings:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image017.png)<br><br>


### Malware Analysis

Instead of downloading tools one at a time to inspect this malware, we can download the malware to our REMnux VM and begin static analysis of the file.

The `readelf` tool gives us some general information about the executable:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image030.png)<br><br>

Use `xorsearch` to identify if XOR encoding was used---the string `http` XOR encoded with the key `0x54` was observed several times:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image031.png)<br><br>

Using `xorstrings` to search for any other strings encoded with key `0x54`reveals some of the files, commands,  and processes the malware uses:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image032.png)<br><br>

The shell commands used to deliver second stage malware to victim machines is also in the decoded data.  Using programs from the `/bin/busybox` utility, each file is downloaded and saved as a randomly named file:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image033.png)<br><br>

The commands then change the permissions of each file, call it with argument `owari.backdoor`, and execute `busybox OWARI`:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image034.png)<br><br>

Finally, it moves to the `/tmp` directory and uses `busybox` to delete all the malware downloaded and kills all the processes it doesn't need anymore:

![](images/Using%20Cloud%20Resources%20to%20Support%20Investigations/image035.png)<br><br>

Additional research shows this malware belongs to the Owari [IOT botnet](https://www.cisco.com/c/dam/m/hr_hr/training-events/2019/cisco-connect/pdf/radware_the_dna_of_mirai__modern_iot_attack_botnets_cisco.pdf), a Marai variant that performs default password attacks, can scan for exploits, and can be used to carry out a variety of DDoS attacks.  The second stage malware is being delivered from an IP address [identified as serving IOT malware](https://www.fortinet.com/blog/threat-research/a-wicked-family-of-bots.html) last year.
