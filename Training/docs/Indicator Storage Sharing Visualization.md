## Indicator Storage, Sharing, and Visualization

Indicators are used to drive many of our processes such as hunting,
incident response, and malware analysis.  Their use significantly
improves the ability to anticipate, predict, and respond to adversary
operations.  Once we obtain indicators from a malware sample, a threat
data feed, or from an external party, we need to store them in one place
so they can be easily reviewed, fed to tools, or shared with third
parties for collaborative analysis.

This walkthrough will cover:

- [Storing indicators](#storing-indicators) using MISP
- [Sharing indicators](#sharing-indicators) through standards such as STIX and OpenIOC
- [Visualizing an Incident](#visualizing-an-incident) using Maltego


## Storing Indicators

### Malware Information Sharing Platform (MISP)

[MISP](http://www.misp-project.org/) is an open source platform used by
analysts, incident handlers, and malware reverse engineers to store and
share threat indicators.  Technical and non-technical information about
malware samples, incidents, attackers, and intelligence are stored in a
database where they are indexed and available for searching similar to
logs in Splunk.  Analysts can search MISP to correlate relationships
between attributes and indicators from malware, attacks, and analysis.

MISP is also used to share information about threats in a variety of
outputs to integrate with other systems and tools:

- Import bulk, batch, OpenIOC, GFI sandbox, ThreatConnectCSVs

- Export for IDS and SIEMs in STIX, OpenIOC, plain text, CSV, XML, and
    JSON formats

The MISP Docker image includes the software and all its dependencies. 
The container runs with its own filesystem, process listing, and network
stack.  This way you can quickly build, run, and tear down containers
with minimal effect on the host system.

The MISP docker image is saved locally on REMnux.  To see a list of
docker images on the host type `docker images`.

To see a list of running docker containers, type `docker ps`.

To kill a container, type `docker kill <container id>`.

The MISP container should start by itself when you boot the VM. 

If for some reason it isn't running, to start the MISP docker container,
type:

```bash
sudo docker run -d -p 443:443 -v /dev/urandom:/dev/random --env-file=/opt/misp-docker/env.txt --restart=always --name misp misp/misp`
```

Switches:

|Switch|Description|
|-|-|
|`-d`|automatically detach container and run in background|
|`-p`|map container ports to host ports|
|`-v`|map container volumes to host volumes|

Once the container is started, type `firefox https://localhost &` to
browse to the MISP web interface and log in.

This is the main screen:

![](images/Indicator%20Storage%20Sharing%20Visualization/image001.png)


To import our list of indicators, click `Add Event`

In the Event Info box, type "Indicator Exercise" and click `Add`

Click `Populate from...` --> `Freetext Import`

Open the `~/indicators.txt` file by typing `cat indicators.txt`, and
copy and paste the list of indicators into MISP and click `Submit`

Review the types and categories of each, make any changes that are
needed:

For example, the email address should be categorized as
**whois-registrant-email** instead of **email-src**
or **email-dst**

And the TLS certificate fingerprints should be
**x509-fingerprint-sha1** instead of **sha1**

Since there is not a **x509-fingerprint-sha256** type
available, put it in the comments section and make the type
**sha256**

When complete, click `Submit`

On the left menu, click `Publish Event` and when prompted to publish
click `Yes`

Scroll down and review all the indicators that were imported:

![](images/Indicator%20Storage%20Sharing%20Visualization/image002.png)


You can also add indicators individually by using the `Add Attribute`
page:

![](images/Indicator%20Storage%20Sharing%20Visualization/image003.png)


Other good open source platforms for storing and sharing indicators
include [CRITS](https://crits.github.io/) and
[threat_note](https://github.com/defpoint/threat_note).

## Sharing Indicators

There are several formats used for sharing threat indicators making it
easier to view them and ingest into tools.  Two of these are OpenIOC and
STIX.

### Open Sourced Indicators of Compromise (OpenIOC)

[OpenIOC](http://www.openioc.org/) is a Mandiant-created XML schema used
to describe technical characteristics that identify a threat,
methodology, or other evidence of compromise.  Simple signatures are
very easy for an intruder to circumvent and this format allows creating
combinations of individual conditions that can be used to identify
specific activity.

Here is an example of what a simple OpenIOC indicator could look like
for our incident (shown in Mandiant's IOC Editor):

![](images/Indicator%20Storage%20Sharing%20Visualization/image004.png)


This is similar to the indicators that can be created in FireEye HX's
Indicator page which search for the presence of values you specify:

![](images/Indicator%20Storage%20Sharing%20Visualization/image005.png)


To add an OpenIOC file to our event in MISP:

Choose `Populate From...`  then click `OpenIOC Import`

Click `Browse`, select the file named
"`84b76110-2d2a-4f26-90a4-f121804f44ed.ioc`" and select `Open`, and then
`Upload`

You should see a success message:

![](images/Indicator%20Storage%20Sharing%20Visualization/image006.png)


And now the OpenIOC file is associated with our event:

![](images/Indicator%20Storage%20Sharing%20Visualization/image007.png)


### Structured Threat Information Expression (STIX)

[STIX](https://stixproject.github.io/about/) is a MITRE/DHS-developed
language utilizing XML for describing threat information to be shared
between platforms, individuals, products, and organizations.

To export in STIX format:

Select `Event Actions` --> `Export`

If `Generate` button is unavailable, go to `Global Actions` -->
`Dashboard` and under Changes since last visit, click `Reset`

Return to the event and it should now show as Published

Then continue with the export:

On the STIX row, click the `Generate` button.  After it completes,
click the `Download`

Click `OK` to save

Check Downloads folder for a file named "misp.stix.ADMIN.xml"

## Visualizing an Incident

### Maltego

Maltego is an open source, interactive data-mining tool which is very
good at querying for and displaying relationships between indicators
from various data sources.

Start Maltego by typing `maltego_community` in the terminal

If the Start a Machine window appears, select `Footprint L2` and click
`Next`

(If at any time you're prompted to log in, you will need to create your
own account on the
[Paterva](https://www.paterva.com/web7/community/community.php) website
and log in with it)

Enter "unioncentralorchids.com" for the domain and click `Next`

As Maltego begins working, remove the items you don't want (Select item,
right click, delete) and rearrange the remaining items (select item,
click and drag).

Depending on what you choose to keep, you should be starting with
something that looks similar to this:

![](images/Indicator%20Storage%20Sharing%20Visualization/image008.png)


To run a transform, select the `unioncentralorchids.com` item, Right Click
--> `PATERVA CTAS` --> `Domain owner detail` --> `To email address`

Delete any unwanted items.

Run another transform by selecting the `unioncentralorchids.com` item,
Right Click --> `PATERVA CTAS` --> `Domain owner detail` --> `To entities from whois`

Delete any unwanted items.

Now, you should have something that looks similar to this:

![](images/Indicator%20Storage%20Sharing%20Visualization/image009.png)


Select `sherobbedmyboots19@gmail.com`, Right Click --> `Passive Total` --> `Whois Search by Email Address`

Highlight both domains that appeared, Right Click --> `PATERVA CTAS` -->
`Domain owner detail` --> `To entities from whois`

Delete any unwanted items.

You can create your own entity by selecting the Entity Palette on the
left side of the screen, selecting the entity, and dragging it onto your
graph.

Run transforms on some of the entities and add some indicators manually
to build a picture of the incident and how the indicators relate to each
other.

By visualizing an incident, it's easier to understand adversary
operations and the infrastructure involved.  Here's an example using
some of the indicators discovered from our last scenario:

![](images/Indicator%20Storage%20Sharing%20Visualization/image010.png)
