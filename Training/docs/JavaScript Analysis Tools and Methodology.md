# JavaScript Analysis Tools and Methodology

There isn't one tool or analysis technique that will work for analyzing all forms of JavaScript code---you need to be able to use different techniques which can be categorized into three general methods: [Automated Tools Analysis](#automated-tools-analysis), [In-Browser Analysis](#in-browser-analysis), and [Manual Analysis](#manual-analysis).

When a script runs, it has everything it needs to carry out its various tasks, whether that's deobfuscating and running, or checking for specific conditions, or checking for a kill switch before it decrypts itself.  Understanding its structure and purpose requires controlling and observing execution of the code and identifying the actions that are being (or will be) taken.

This document will review:

- [Automated Tools Analysis](#automated-tools-analysis)
- [In-Browser Analysis](#in-browser-analysis)
- [Manual Analysis](#manual-analysis)
- [Practicing Analysis with JSLab](#practicing-analysis-with-jslab)
	- [JSLab Setup](#jslab-setup)
	- [JSLab Operation](#jslab-operation)
	- [Practicing In-Browser Analysis](#practicing-in-browser-analysis)
	- [Practicing Manual Analysis](#practicing-manual-analysis)


## Automated Tools Analysis

There are several popular tools used to deobfuscate and beautify JavaScript using various evasion techniques. It's worth a shot to try one or more of these first to see if a script can be quickly deobfuscated by one of these tools.

[JSDetox](http://www.relentless-coding.com/projects/jsdetox/) is a great option and is also available as a REMnux [Docker image](https://hub.docker.com/r/remnux/jsdetox/).

To use, paste in the obfuscated code:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image028.png)<br><br>

In this case it returns three lines of code:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image029.png)<br><br>

Others include [JS Beautifier](https://beautifier.io) and [JSNice](http://jsnice.org) which will attempt to organize JavaScript code and make it more readable:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image036.png)<br><br>

## In-Browser Analysis

The most common method is to use a browser's debugging tools to interact with a web page as it is loaded and executed in the browser.  Most major browsers all have debugging tools installed by default.

[DevTools](https://developers.google.com/web/tools/chrome-devtools/) comes with the Google Chrome browser:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image001.png)<br><br>

Mozilla Firefox:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image037.png)<br><br>

IE/Edge:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image038.png)<br><br>

Each browser has a few unique features the others don't have, but they all provide a way to inspect three important properties of every web page: `Elements`, `Sources`, and the `Network`---as well as a way to interact with the Document Object Model (DOM) using the `Console`.

Use the `Elements` tab (`Inspector` in Firefox) to see the structure and components of the HTML page:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image041.png)<br><br>

Use the `Sources` tab (`Debugger` in Firefox/IE) to display page content organized by filesystem and domain:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image042.png)<br><br>

Use the `Network` tab to inspect all files requested over the network by the page:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image043.png)<br><br>

Use the `Console` tab to interact with the DOM and perform JavaScript functions:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image044.png)<br><br>

## Manual Analysis

There are several different ways to use JavaScript engines without a browser: 

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image002.png)<br><br>

NodeJs is great for building and manipulating JavaScript objects:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image040.png)<br><br>

V8 is the JavaScript engine used in Google Chrome.  There is a REMnux docker image you can pull with `Get-DockerImage`:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image039.png)<br><br>

The `cscript.exe` program runs JavaScript files and comes packaged in Windows:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image045.png)<br><br>

The JavaScript engine used in Mozilla Firefox (SpiderMonkey) can also be used to run `.js` files:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image046.png)<br><br>

As well as run as a shell:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image047.png)<br><br>

Using JS engines without a browser requires you to define variables that the script is expecting to see when running in a browser environment (`document`, `window`, `history`, etc).  

For instance, the REMnux docker container defines some common variables using the `objects.js` file.  Referencing this file when running a script file will print code that would be executed in a browser.

We can do this same thing with SpiderMonkey.  This `unknown.js` file builds a string and passes it to the `eval` function which would execute it in a browser:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image048.png)<br><br>

But we are outside the browser, so there is no `eval` function defined:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image049.png)<br><br>

We can create an `objects.js` file which defines the `eval` function (as `print`) and provide it as an argument:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image051.png)<br><br>

Now when the script runs it will call `eval`, but this `eval` will make the script *print* what it *would have* executed if it were running in a browser:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image050.png)<br><br>

## Practicing Analysis with JSLab

Analysts don't need to be JavaScript experts---the goal is to be able to bypass different evasion techniques and explain a code's purpose.  We acquire these skills by working with basic encoding and obfuscation methods and testing the different ways malware probes for and extracts information from a victim's browser in a controlled environment.

The JSLab Docker container is one way to do this. It contains a web server hosting three web pages that simulate techniques used by malware.  You can simulate the victim by browsing to these pages.  You can simulate the attacker by using the container to listen on port 4444.  The container also contains a JavaScript runtime environment, NodeJs.

- [JSLab Setup](#jslab-setup)
- [JSLab Operation](#jslab-operation)
- [Practicing In-Browser Analysis](#practicing-in-browser-analysis)
- [Practicing Manual Analysis](#practicing-manual-analysis)

### JSLab Setup

The `jslab.tar.gpg` file is located on the OOB at `/CSIRT/Sample-Files`.

Use `gpg` to decrypt and enter ```/4[q_i3`L&>:;>pFXY3`g>msh``` as the password when prompted:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image030.png)<br><br>

Load it into Docker with `docker load` and check the image was loaded successfully with `docker images`:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image031.png)<br><br>

Start the container with `docker run --name jslab -d -p 4000:8080 -p 4444:4444 jslab` and ensure it's running with `docker ps`:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image032.png)<br><br>

Use the `sh` program on the container using `docker exec -it jslab sh` and listen on port 4444 with `nc -nlvp 4444`:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image033.png)<br><br>

To exit netcat use `Ctrl + C`.  To exit the shell press `Ctrl + P` then `Ctrl + Q`.  You can now use NodeJs with `docker exec -it jslab node`:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image034.png)<br><br>


### JSLab Operation

The JSLab container serves three purposes: hosts the web server, host NodeJs, and allow the analyst to simulate attacker infrastructure using Netcat:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image003.png)<br><br>

Use `localhost:4000` to browse to the web pages on Linux versions of Docker and Docker for Windows:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image004.png)<br><br>

For Docker Toolbox, you need to find the Docker machine's IP address using the `docker-machine ip` command:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image005.png)<br><br>

The environment variable used in the scripts `${window.location.hostname}` will find the Docker container either way:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image006.png)<br><br>

Now you can navigate to the different web pages:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image025.png)<br><br>

To inspect different ways to embed code and extract information from browsers, visit the `operation.html` page:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image026.png)<br><br>

For example, listen on port 4444 with Netcat while you simulate a session hijack:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image052.png)<br><br>

To inspect different ways to obfuscate code, visit the `evasion.html` page:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image027.png)<br><br>

For example, figure out how to execute the scripts using context-based, encryption-based, and kill switch evasion techniques: 

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image053.png)<br><br>


### Practicing In-Browser Analysis

The `analysis.html` page has one button which loads a single script file (`script.js`) that is heavily obfuscated:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image007.png)<br><br>

Use prettify `{}` button to expand the code---in this case everything is obfuscated so we'll need to find another way:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image008.png)<br><br>

Here is a method to identify all the variables created when a script is loaded:

- First, refresh the page so that the script is not loaded yet
- Capture all `window` variables into an array (`a`)
- Now load the script (which immediately tries to make a POST request)
- Capture all `window` variables into an array (`b`)

The "before" array (`a`) is then compared to the "after" array (`b`) and the differences (new variables created) are stored in array (`c`):

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image009.png)<br><br>


Now we have all the new variables that were created as a result of the script being loaded in array (`c`).

Some of these variables were created by the web page in order to load the script (`d` and `aa`) or were created in one of the above steps when creating arrays (such as `v`) and can be removed:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image010.png)<br><br>

Remove them with the `splice()` method:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image011.png)<br><br>

The first object `_0xd151` is an array containing over 1,000 values:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image023.png)<br><br>

We can perform searches for interesting strings using regex within NodeJs:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image024.png)<br><br>

We can assume that this object contains all the strings that the code will be using.  But we need to identify and explain the functions being used as well.

The next object, `deployJava`, has 53 different properties:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image012.png)<br><br>

We can filter by property type to see only strings:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image014.png)<br><br>

Or only functions:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image013.png)<br><br>

When we look at one of the functions more closely, many identifiers have been manipulated:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image015.png)<br><br>

We get around this using regex which replaces each manipulated identifier with its original value:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image016.png)<br><br>

This allows us to copy and paste it into a text editor for additional analysis:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image017.png)<br><br>

Since we can use this regex formula on other objects obfuscated in the same way, let's save to a function called `doIt` and try it on a different function:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image018.png)<br><br>

Now we can copy this and paste in a text editor for manual analysis:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image019.png)<br><br>


### Practicing Manual Analysis

Inspecting each individual function requires manual analysis. After deobfuscating this function, there are still random variables:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image020.png)<br><br>

Look at each line one by one, see what code does, and name the function or variable accordingly to get a better idea of what the script originally looked like before obfuscation:

![](images/JavaScript%20Analysis%20Tools%20and%20Methodology/image021.png)<br><br>

Now we can see it checks various browser conditions, builds content based on the results, and attempts to execute it using `document.write` and `document.body.appendChild`.  
