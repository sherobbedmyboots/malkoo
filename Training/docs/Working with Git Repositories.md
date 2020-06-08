# Working with Git Repositories

Git is a distributed version control system (DVCS) used to collaboratively modify files.  It can coordinate and track changes to files made by multiple users and systems at different times.


- [Overview and Concepts](#overview-and-concepts)
	- [Working Directory](#working-directory)
	- [Index](#index)
	- [HEAD](#head)
- [Setup](#setup)
	- [Create Account](#create-account)
	- [Install Git Application](#install-git-application)
	- [Configure Command Line Access](#configure-command-line-access)
- [Common Tasks](#common-tasks)
	- [Running Code from a Repository](#running-code-from-a-repository)
	- [Contributing to a Repository](#contributing-to-a-repository)
	- [Creating and Sharing a Gist](#creating-and-sharing-a-gist)
	- [Investigating a Repo](#investigating-a-repository)


## Overview and Concepts

Git tracks changes to a repository by taking snapshots of local filesystems and merging them with the filesystem on the remote repository.  When working with a repository, you create a copy of a repository on your system that you can edit, stage, and commit using the three "trees":

|Tree|Description|
|-|-|
|[Working Directory](#working-directory)|The local files on your system|
|[Index](#index)|Staging area for changed files that are to be committed|
|[HEAD](#head)|Version of filesystem with all committed changes|

<br>

### Working Directory

You typically start with a local copy of a remote repository.  You can clone a remote repository on your local machine (your Working Directory) and make changes to the files in the form of additions, deletions, moves, etc.

### Index

When you're ready to add these changes to the staging area (Index), you use `git add <filename>` to add a file or `git add .` to add a directory.  These files are now staged and ready to be committed.

### HEAD

To commit these, use `git commit -m "Some type of description"` to move the staged files into the HEAD tree.  These files are now officially updated in your local repository but not the remote repository that all other users can access.

To push these changes to the remote repository, use `git push` which will cause Git to log in to the remote repository with your account and upload your changes so that everyone can see them.

Any users that also have that repository stored locally on their machines now will not have the most recent version with your changes.  To update their local repository, they must use `git pull` which will cause Git to log in with their account and update their local repository to the current version.


## Setup

To interact with our Git repositories, complete the following:

- [Create Account](#create-account)
- [Install Git Application](#install-git-application)
- [Configure Command Line Access](#configure-command-line-access)
- [Configure SSH Access](#configure-ssh-access)

## Create Account

Create your account.

### Install Git Application

Install Git.

Check to see if it is in your path:

![](images/Working%20with%20Git%20Repositories/image004.png)<br><br>

If not in your path, add it:

```powershell
$env:PATH += ';C:\Program Files\Git\cmd;C:\Program Files\Git'
```

And add to your PowerShell profile:

```powershell
Add-Content -Path $profile -Value ';C:\Program Files\Git\cmd;C:\Program Files\Git'
```


### Configure Command Line Access

Configure your account for command line access:

```powershell
git config --global user.name "<username>"
git config --global user.email "<email address>"
```
<br>

Check to ensure account is configured:

```powershell
git config --global --list
```

<br>

Using the `--global` flag affects all repositories you work with and stores the information in the `.gitconfig` file:

![](images/Working%20with%20Git%20Repositories/image003.png)<br><br>

With username and email set, when you try to push you will be prompted for a password. To prevent this we'll generate an SSH key to use.

### Configure SSH Access

Use `git-bash.exe` to create an SSH key pair. Run it to open a bash shell:

![](images/Working%20with%20Git%20Repositories/image005.png)<br><br>

Create an SSH key and accept the default settings:

![](images/Working%20with%20Git%20Repositories/image006.png)<br><br>

Start the ssh-agent in the background:

![](images/Working%20with%20Git%20Repositories/image009.png)<br><br>

And add the private key to the ssh-agent:

![](images/Working%20with%20Git%20Repositories/image010.png)<br><br>

Now we need to put the public key on the Git repo.  

Go to https://github.com/settings/keys and select **New SSH key**:

![](images/Working%20with%20Git%20Repositories/image007.png)<br><br>


Copy the public key to your clipboard with:

```powershell
Get-Content ~\.ssh\id_rsa.pub | Set-Clipboard
```

<br>

Give the key a name, paste into the box and select **Add SSH key**.  You now have the SSH key associated with your account:

![](images/Working%20with%20Git%20Repositories/image008.png)<br><br>

You should receive an email reporting a new key was added:

![](images/Working%20with%20Git%20Repositories/image012.png)<br><br>

Now configure Git to access the repository over SSH by setting the remote origin with:

```powershell
git remote set-url origin ssh://git@github.com:<username>/<repository>.git
```

Now you should be all set up to interact with the repository using a PowerShell session.

## Common Tasks

This will walkthrough performing the following common tasks:

- [Running Code From a Repository](#running-code-from-a-repository)
- [Contributing to a Repository](#contributing-to-a-repository)
- [Creating and Sharing a Gist](#creating-and-sharing-a-gist)
- [Investigating a Repository](#investigating-a-repository)

<br>

### Running Code From a Repository

The most common way to run code from a remote repository is to clone it to the local system with `git clone`:

```powershell
git clone https://github.com/<username>/<repository>.git
```

You now have access to the repository and can run code it contains such as the scripts in the `scripts` directory:

![](images/Working%20with%20Git%20Repositories/image016.png)<br><br>

Another option is to download code from a repository and run it in memory.  The following downloads a file containing a PowerShell function, imports the function, and runs it with the supplied argument:

```powershell
wget -uri https://gist.githubusercontent.com/jaredcatkinson/8da3c638e0612830deec5a6befa1164e/raw/fd09138dd626adb3be8717f8321e33775b8c2480/ConvertFrom-Base64.ps1 | IEX | ConvertFrom-Base64 -Base64String  SABlAGwAbABvACAAVwBvAHIAbABkACEA
```

![](images/Working%20with%20Git%20Repositories/image017.png)<br><br>


### Contributing to a Repository

The first time you push changes to a repository over SSH, you'll be prompted to add the host to your known hosts file:

![](images/Working%20with%20Git%20Repositories/image011.png)<br><br>


Use `git status` to see the changes you've made, `git add .` to stage them, and `git commit -m "<message>"` to commit them:

![](images/Working%20with%20Git%20Repositories/image015.png)<br><br>

Then use `git push` to push your changes to the remote repository:

![](images/Working%20with%20Git%20Repositories/image017.png)<br><br>


### Creating and Sharing a Gist

A Gist is a way to share small, single files and can be created as public (shows up in searches for gists) or secret (not searchable, but still shareable and discoverable).

The common way to creat a gist is to open https://gist.github.com in a browser, enter a name and description, post your content, and select **Create secret gist** or **Create public gist**:

![](images/Working%20with%20Git%20Repositories/image020.png)<br><br>


A public gist can be shared with others by using the [link](https://gist.github.com/<username>/<gist>) and can also be found using searches:

![](images/Working%20with%20Git%20Repositories/image021.png)<br><br>

A secret gist won't show up in searches for gists, but can also be shared with a [link](https://gist.github.com/<username>/<gist>):

![](images/Working%20with%20Git%20Repositories/image022.png)<br><br>



### Investigating a Repository

You may need to investigate a publicly accessible repository.  To do this you would clone the repo to your local system:

![](images/Working%20with%20Git%20Repositories/image001.png)<br><br>

Then you can search it for keywords or patterns as usual:

![](images/Working%20with%20Git%20Repositories/image014.png)<br><br>

Navigate into the repository and use `git log` to see files that were changed, added, or deleted:

![](images/Working%20with%20Git%20Repositories/image019.png)<br><br>

## Summary

Get familiar with how Git works and how to access and examine the code and data that can be hosted on a repository.  More and more investigations will require a good understanding of how these files are stored, accessed, and used (as well as misused).

I strongly recommend using PowerShell for all Git operations, but if you prefer working with a GUI instead, try using `gitk` to open Git's GUI application:

![](images/Working%20with%20Git%20Repositories/image013.png)<br><br>
