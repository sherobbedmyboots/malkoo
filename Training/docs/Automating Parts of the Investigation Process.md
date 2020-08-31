# Automating Parts of the Investigation Process 

Recently, there have been several repositories hosted on Github that we have had to search through for sensitive information.  In each incident, there have been steps we've repeated which provides an opportunity to implement automation.  This training document walks through one way of automating some of the manual steps involved with investigating public repositories containing sensitive information.

- [Identify Manual Steps](#identify-manual-steps)
- [Automate Steps](#automate-steps)

## Identify Manual Steps

First let's walk through some examples and identify the manual steps that are needed using several recent Github spills:

<br>

Working the above incidents, we've performed the following each time:

- [Obtain Copy of Repo](#obtain-copy-of-repo)
- [Search Repo for Sensitive Information](#search-repo-for-sensitive-information)
- [Identify Repo History](#identify-repo-history)


### Obtain Copy of Repo

We usually perform this by downloading the repo as a zip file.  This method doesn't download the history of the repo so let's configure a Docker container to clone repos with Git.

Use the following to configure `apt`:

```
echo 'Acquire::http::User-Agent "xxxx";' > /etc/apt/apt.conf
echo 'Acquire::http::Proxy "http://xxxxxxxx:80";' >> /etc/apt/apt.conf
echo 'Acquire::https::Proxy "http://xxxxxxxx:80";' >> /etc/apt/apt.conf
```

<br>

Then configure the host's default proxy:

```
export http_proxy=http://xxxxxxx:80 
export https_proxy=http://xxxxxxx:80
```

<br>

Update packages, upgrade, and install `git`:

```
apt-get update
apt-get upgrade -y 
install git -y
```

<br>

Now we can download any repository using:

```
git clone <repo>
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image006.png)<br><br>


### Search Repo for Sensitive Information

To search the repo we'll need external tools such as `bulk_extractor` which we can download easily with `git`.

The following clones the `bulk_extractor` repo and installs the tool on our Docker container:

```
apt-get install sudo make -y
git clone https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
echo y | sudo bash etc/CONFIGURE_UBUNTU18.bash
chmod +x ./bootstrap.sh && ./bootstrap.sh
./configure
make
sudo make install
```

<br>

The following runs `bulk_extractor` on one a repo and places all results in the `<repo-results>` directory:

```
bulk_extractor -o <repo-results> -R <repo>
```

<br>

Here are some ways we can filter out the files we need.  First show all the files that are not empty with:

```
find <results-dir> -not -empty -ls
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image007.png)<br><br>

Search through the histogram files looking for matches to sensitive strings/patterns:

```bash
grep -h 'mydomain\|yourdomain' $results/*histogram.txt
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image008.png)<br><br>

Search for IP Addresses:

```bash
grep -E -h "(10)[\.][0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3}" $results/*histogram.txt
grep -E -h "(172)[\.](1[6-9]|2[0-9]|3[0-1])[\.][0-9]{1,3}[\.][0-9]{1,3}" $results/*histogram.txt
grep -E -h "(192)[\.](168)[\.][0-9]{1,3}[\.][0-9]{1,3}" $results/*histogram.txt
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image009.png)<br><br>

Search for Hostnames:

```bash
grep -R -E -oh "xxxx[0-9]{2}xxxx" $name/*
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image010.png)<br><br>

Search for email addresses:

```bash
grep -h 'domain\.com' $results/email_histogram.txt
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image011.png)<br><br>

Search for passwords:

```bash
grep -R -h 'password=' $name/*
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image012.png)<br><br>

Search for AWS creds:

```bash
grep -R -P -h '(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])' $name/*
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image013.png)<br><br>

```bash
grep -R -P -h '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])' $name/*
```

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image015.png)<br><br>

### Identify Repo History

Downloading the zip file does not obtain git history:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image005.png)<br><br>

But these two repos were downloaded with `git clone` and we can see their history with `git log`:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image003.png)<br><br>

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image004.png)<br><br>


Use `git show` to identify content that was either added or deleted:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image014.png)<br><br>

Other options with `git log` can be used to display the information needed depending on the scenario:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image016.png)<br><br>


## Automate Steps

To automate these steps, let's make a Dockerfile that runs all of the commands needed to build our "reposearch" container:

```
FROM ubuntu:18.04
RUN echo 'Acquire::http::User-Agent "xxxxxxx";' > /etc/apt/apt.conf
RUN echo 'Acquire::http::Proxy "http://xxxxxxx:80";' >> /etc/apt/apt.conf
RUN echo 'Acquire::https::Proxy "http://xxxxxxx:80";' >> /etc/apt/apt.conf
RUN export http_proxy=http://xxxxxxx:80
RUN export https_proxy=http://xxxxxxx:80
RUN apt-get update
RUN apt-get upgrade -y 
RUN apt-get install sudo git make -y
RUN git clone https://github.com/simsong/bulk_extractor.git
RUN cd bulk_extractor
RUN echo y | sudo bash etc/CONFIGURE_UBUNTU18.bash
RUN chmod +x ./bootstrap.sh && ./bootstrap.sh
RUN ./configure
RUN make
RUN sudo make install
CMD ["/bin/bash"]
```


To build with the Dockerfile, you'll need the `ubuntu:18.04` image loaded in Docker:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image001.png)<br><br>

Use the `ubuntu:18.04` image:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image002.png)<br><br>

Once you have it, use the Dockerfile to build the image:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image017.png)<br><br>

Then use the image to run a container:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image018.png)<br><br>

[Bulk Extractor]() is already installed and ready to go.

We can also make a script that downloads the repo and searches it for sensitive information:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image019.png)<br><br>

```
#!/bin/bash

name=$(echo $1 | cut -d '/' -f 5 | cut -d '.' -f 1)
results=$name-results

git clone $1 1>/dev/null

bulk_extractor -o $results -R $name 1>/dev/null

# domains
grep -h 'mydomain\|yourdomain' $results/*histogram.txt

# ip addresses
grep -E -h "(10)[\.][0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3}" $results/*histogram.txt
grep -E -h "(172)[\.](1[6-9]|2[0-9]|3[0-1])[\.][0-9]{1,3}[\.][0-9]{1,3}" $results/*histogram.txt
grep -E -h "(192)[\.](168)[\.][0-9]{1,3}[\.][0-9]{1,3}" $results/*histogram.txt

# hostnames
grep -R -E -oh "xxxx[0-9]{2}xxxx" $name/*

# emails
grep -h 'domain\.com' $results/email_histogram.txt

# passwords
grep -R -h 'password=' $name/*

# access keys
grep -R -P -h '(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])' $name/*

# secret keys
grep -R -P -h '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])' $name/*
```

<br>

It downloads the repo, runs `bulk_extractor` on it, and immediately begins running our searches:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image020.png)<br><br>


Now we can quickly clone and search any repo for custom sensitive information with `bulk_extractor`:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image021.png)<br><br>

There are also a number of other tools designed just for Github:


We can add a line to the script which prints out the history of the repo:

```bash
cd $name
git log --stat
```


![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image023.png)<br><br>

Now the history is included in the output of the script:

![](images/Automating%20Parts%20of%20the%20Investigation%20Process/image022.png)<br><br>
