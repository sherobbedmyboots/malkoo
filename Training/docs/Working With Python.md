# Working With Python

Python is a very powerful, general-purpose programming language with a wide range of uses for security analysts and engineers.  This document will give a quick refresher on basic syntax and components and walk through an example of building a basic program to accomplish a specific task.

- [Setup](#setup)
	- [Install Python](#install-python)
	- [Configure IDLE](#configure-idle)
	- [Configure Visual Studio Code](#configure-visual-studio-code)
	- [Using Docker Container](#using-docker-container)
- [Python Refresher](#python-refresher)
	- [Variables and Methods](#variables-and-methods)
	- [Lists and Dictionaries](#lists-and-dictionaries)
	- [Iterations and Conditional Statements](#iterations-and-conditional-statements)
	- [Filesystem and Networking](#filesystem-and-networking)
	- [Exception Handling](#exception-handling)
	- [Functions and Modules](#functions-and-modules)
- [Building a Python Program](#building-a-python-program)
	- [Format URL Path](#format-url-path)
	- [Load Configuration Settings](#load-configuration-settings)
	- [HTTPS Proxy Request](#https-proxy-request)
	- [Check Indicator](#check-indicator)
	- [Print Results](#print-results)
	- [Main Function](#main-function)

<br>

## Setup

### Install Python

One option is to install Python on your workstation.  [Python 3.7.2](https://www.python.org/) is currently available for download in the Software Library.

Once installed, check to ensure `python.exe` is in your path with:

```powershell
Get-Command python | Select Source
```

<br>

If not, add the directory Python was installed in to your path variable and retest.

### Configure IDLE

Python on Windows comes with Idle, an interactive interpreter:

![](images/Working%20With%20Python/image009.png)<br><br>


### Configure Visual Studio Code

A great alternative to IDLE is [Visual Studio Code](https://code.visualstudio.com/) which is also currently available in the Software Library:

![](images/Working%20With%20Python/image008.png)<br><br>

Once installed, check to ensure `code.exe` is in your path:

```powershell
Get-Command python | Select Source
```

<br>

If not, add it to your path variable.  The VS Code [Python extension](https://marketplace.visualstudio.com/itemdetails?itemName=ms-python.python) provides code formatting and debugging features.

### Using Docker Container

Another way to run Python on your workstation is to download one of the official Python Docker images:

![](images/Working%20With%20Python/image007.png)<br><br>

And create a container with it:

![](images/Working%20With%20Python/image018.png)<br><br>

## Python Refresher

Python is an interpreted language.  The code is interpreted and compiled at runtime.

![](images/Working%20With%20Python/image010.png)<br><br>


It can also be used as an interactive shell:

![](images/Working%20With%20Python/image011.png)<br><br>


Here are some basic building blocks commonly used to write programs in Python:

- [Variables and Methods](#variables-and-methods)
- [Lists and Dictionaries](#lists-and-dictionaries)
- [Iterations and Conditional Statements](#iterations-and-conditional-statements)
- [Filesystem and Networking](#filesystem-and-networking)
- [Exception Handling](#exception-handling)
- [Functions and Modules](#functions-and-modules)


### Variables and Methods

Python is "dynamically and strongly typed" which means it knows the type of data based on the syntax used but can be changed on the fly.  In Python, data can be stored in memory as an integer, float, string, etc.

Open a Python shell and create an integer named `x` and check its type:

```python
x = 1
type(x)
```

<br>

Create a string named `y` equal to "long test string" and do the same:

```python
y = "long test string"
type(y)
```

<br>

Each type of variable has different methods that can be called on it.  List all variables and methods of these variables using `dir()`:

![](images/Working%20With%20Python/image012.png)<br><br>


Call different methods from each of the two variables:

![](images/Working%20With%20Python/image013.png)<br><br>


Show all variables and methods accessible in the current namespace with `globals()`:

![](images/Working%20With%20Python/image014.png)<br><br>


### Lists and Dictionaries

A list is an array, or a collection of elements.  Create a list containing the strings "one", "two", and "three", and try adding and removing items:

```python
x = []
type(x)
x.append("one")
x.append("two")
x.append("three")
x.remove("three")
```

<br>

A tuple is a list that cannot be modified.  Create a tuple:

```python
x = ("one", "two", "three")
type(x)
```

<br>

A dictionary is like a hashtable in PowerShell---each element is a key and its associated value (item).  Create a dictionary and add to it:

```python
x = {'apple':'red', 'orange':'orange', 'grape':'purple'}
x['banana'] = 'yellow'
```

![](images/Working%20With%20Python/image015.png)<br><br>


### Iterations and Conditional Statements

For loops are one way to iterate through lists and dictionaries.

```python
for fruit in x:
    print("An " + fruit + " a day keeps the doctor away")
```

<br>

The print command executes for each element in `x`:

![](images/Working%20With%20Python/image036.png)<br><br>

Conditional statements are decision points.  The following if/elif/else statements check the value of x and print a different string depending on its value:

```python
if "apple" in x:
	print("apple is present")
elif "orange" in x:
	print("orange is present")
else:
	print("apple and orange are not present")
```

![](images/Working%20With%20Python/image016.png)<br><br>


### Filesystem and Networking

Read contents of a file into a variable:

```python
with open('C:\\Users\\userone\\webshelltest.json') as file:
	data = json.load(file)
```

<br>

Now the contents of the .json file are inside the `data` variable and can be accessed:

![](images/Working%20With%20Python/image035.png)<br><br>


Use a socket to make network connections:

```python
import socket
s = socket.socket()
target = '10.10.10.10'
port = 22
s.connect((target,port))
print(s.recv(1024))
```

<br>

The system returns an SSH banner:

![](images/Working%20With%20Python/image029.png)<br><br>


### Exception Handling

Another host may not have port 22 open and will throw an exception:

![](images/Working%20With%20Python/image031.png)<br><br>


We can build in exception handling with:

```python
try:
	s.connect((target, port))
except Exception as e:
	print("[-] ERROR: "+str(e))
```

<br>

Now the exception is captured and printed to the screen:

![](images/Working%20With%20Python/image030.png)<br><br>

We can now add some additional actions to be performed when we attempt to connect to a host that does not have port 22 open.


### Functions and Modules

Functions allow us to easily call a series of frequenty-used commands.  Create a `testSsh()` function with:

```python
def testSsh (target):
	s = socket.socket()
	port = 22

	try:
		s.connect((target, port))
		print(s.recv(1024))
	except Exception as e:
		print("[-] ERROR: "+str(e))
```

<br>

Once we define the function, we can call it using different targets:

![](images/Working%20With%20Python/image032.png)<br><br>


A module is a collection of related functions.  Python comes installed with some common modules like `time`:

![](images/Working%20With%20Python/image033.png)<br><br>

Use `dir(<module>)` to see a module's functions:

![](images/Working%20With%20Python/image034.png)<br><br>

You import modules to make their functions accessible to your script. Modules can be installed locally or over the network using `pip install`.




## Building a Python Program

To demonstrate building a Python program, we'll inspect the functions of a small Python program that interfaces with the [FireEye ISight API](https://www.fireeye.com/solutions/intelligence-api.html) and checks a single indicator for associated actors, malware families, and threat categories:

- [Format URL Path](#format-url-path)
- [Load Configuration Settings](#load-configuration-settings)
- [HTTPS Proxy Request](#https-proxy-request)
- [Check Indicator](#check-indicator)
- [Print Results](#print-results)
- [Main Function](#main-function)

<br>

There are many different endpoints for this API, but we're only going to focus on the [pivot/indicator](https://docs.fireeye.com/iSight/index.html#/pivot_indicator) one for this example.

The [documentation](https://docs.fireeye.com/iSight/index.html#/) provides some examples of the way the requests must be structured:

![](images/Working%20With%20Python/image019.png)<br><br>

We could keep the endpoint the same but we'll pass it as an argument so that we can interface with other endpoints if needed.  

So for a basic request we will need to pass the script three arguments:

1. an endpoint (`pivot/indicator`)
2. a key (`ip`, `domain`, `hash`, etc.)
3. a value (`166.217.82.218`, `microsoftupdated.net`, etc.)

Since the format of the URL is different depending on which key is used, let's start by creating a function that evaluates this condition and formats the URL path accordingly.


### Format URL Path

The `formatUrlPath()` function handles the different formats that are required for different keys:

![](images/Working%20With%20Python/image020.png)<br><br>


If the key is a `fileName`, it is checked for backslashes (`%5C`) that are common in full file paths.  If present, only the last value, the name of the file, is saved.  It is also changed to all lowercase:

```python
    if type == 'fileName':
        indicator = indicator.split('%5C')[-1].lower()
```

<br>

If the type is a `url`, the `?value=` parameter is built into the `urlPath` variable.  If not, the type and indicator arguments are added to the ENDPOINT argument to form the `urlPath`:

```python
    if type == 'url':
        urlPath = '/' + ENDPOINT + '/' + type + '?value=' + indicator
    else:
        urlPath = '/' + ENDPOINT + '/' + type + '/' + indicator
```

<br>

The final result is passed back to the function that called it with `return`:

```python
return urlPath
```

<br>

The `main()` function will capture this result in a variable so it can pass it to other functions:

![](images/Working%20With%20Python/image021.png)<br><br>

After it has constructed the URL path, it will load the required configuration settings by calling the `loadConfig()` function.

### Load Configuration Settings

This function defines some variables needed to make the web request such as the proxy, headers, and credentials to be used:

![](images/Working%20With%20Python/image022.png)<br><br>

The [Authentication](https://docs.fireeye.com/iSight/index.html#/authentication) documentation explains how the credentials are to be combined with a timestamp, an Accept-Version header, and an Accept header to authenticate to the endpoint.

First we need to open the file containing credentials and capture the public and private keys in variables:

```python
 with open('C:\\Users\\userone\\credentials.json') as creds:
	    credentials = json.load(creds)
    public_key = credentials['public']
    private_key = credentials['private']
```

<br>

Next, define the other variables needed, concatenate, and hash:

```python
    accept_header = 'application/json'
    accept_version = '2.5'
    time_stamp = email.utils.formatdate(localtime=True)
    string = urlPath + accept_version + accept_header + time_stamp
    key = bytelist()
    key.extend(map(ord, private_key))
    hashed = hmac.new(key, string.encode('utf-8'), hashlib.sha256)
```

<br>

The proxies must be set to reach external addresses.  Notice that the variable is defined as a **global** variable before it is given values which will make it exist outside of this function and available to other functions:

```python
    global proxy 
    proxy = {
        'http':'http://<proxy-address>:80',
        'https':'http://<proxy-address>:80',
    }
```

<br>

A second global variable is the `headers` dictionary which will also be passed to the function making the web request:


```python
    global headers 
    headers = {  
        'Host':'api.isightpartners.com:443',
        'Proxy-Connection':'keep-alive',
        'Accept': accept_header,
        'Accept-Version': accept_version,
        'X-Auth': public_key,
        'X-Auth-Hash': hashed.hexdigest(),
        'Date': time_stamp,
        'User-Agent':'<user-agent>',
    }
```

<br>

The result of this function is the two global variables we created: `proxy` and `headers`, so nothing is returned back to the `main()` function.

Now we need to define how the web request is made.


### HTTPS Proxy Request

This function allows us to make a request through the proxy:

![](images/Working%20With%20Python/image023.png)<br><br>

An HTTP client is created, connects to the proxy using HTTPS, and sends an HTTP request through the created tunnel:

```python
    https = urllib.request.http.client.HTTPSConnection(proxy[0], proxy[1])
    https.set_tunnel(host, port, headers=headers)
    https.connect()
    https.request(method, url, headers=headers)
```

<br>

The contents of the response and the status code is returned to the function that called it:

```python
    response = https.getresponse()
    return response.read(), response.status
```

Next, we need a function that uses the `HTTPSProxyRequest()` function to obtain data from the ISight API.


### Check Indicator

This function sends an HTTP request with our `urlPath` variable to the ISight API and captures the response received:

![](images/Working%20With%20Python/image024.png)<br><br>

The first line makes the web request using the `HTTPSProxyRequest()` function and captures the results in the `r` variable:


```python
    r = HTTPSProxyRequest('GET','api.isightpartners.com',urlPath, ('<proxy-address>',80))
```

<br>

The `r` variable now holds what was returned by the `HTTPSProxyRequest()` function---a list whose second value (`[1]`) contains the request's status code.

This first part compares the status code to `200` (Success) and returns the data received if a match.  The second part compares the status code to `204` (No Content) and reports no indicator was found if a match:

```python
    if r[1] == 200:
        json_data = json.loads(r[0])
        return json_data
    elif r[1] == 204:
        print("RESULT: Indicator not found")
        exit()
```

<br>

If neither of these conditions are met, the function prints out an error message along with the status code received:

```python
    else:
        print("ERROR: HTTP Code: "+str(r[1]))
        exit()
```

<br>

The result of an indicator that is not found can be seen here when running the script:

![](images/Working%20With%20Python/image027.png)<br><br>

If an indicator *is* found, the data is returned to the `main()` function, and we will need another function to sort it and display it to the user. 

### Print Results

This function takes the data received from the API (a JSON object) as an argument and extracts the data we want---associated actors, malware families, and threat categories:

![](images/Working%20With%20Python/image025.png)<br><br>

First, empty lists are created for storing the information we're interested in:

```python
    actors = []
    families = []
    categories = []
```

<br>

Then each indicator in the JSON object is captured in an list named `pubinds`.  We iterate through each object in this list and if it has a property named `actors`, `malwareFamily`, or `ThreatScape`, its contents are added to the respective list we created above:

```python
    pubinds = data['message']['publishedIndicators']
    for i in pubinds:
        act = i.get('actor','None')
        if act is not None:
            actors.append(act)
        fam = i.get('malwareFamily','None')
        if fam is not None:
            families.append(fam)
        cat = i.get('ThreatScape', 'None')
        if cat is not None:
            categories.append(cat)
```

<br>

The last part prints the number of associated indicators received (`len(pubinds)`) as a string, as well as the contents of each list we created: 

```python
    print("Related indicators: " + str(len(pubinds)))
    print("Associated actors: " + ', '.join(set(actors))) 
    print("Associated malware families: " + ', '.join(set(families)))
    print("Associated threat categories: " + ', '.join(set(categories)))
```

<br>

The result of this function is seen here:

![](images/Working%20With%20Python/image027.png)<br><br>

This is where the script exits, but let's take a look at how these functions work together to accomplish this.

### Main Function

The `main()` function is called when the script is run and should provide a clear picture of what the script is doing:

![](images/Working%20With%20Python/image028.png)<br><br>

The first line sends all three command line arguments to the `formatUrlPath()` function and captures the results in the `urlPath` variable:

```python
    urlPath = formatUrlPath(sys.argv[1], sys.argv[2], sys.argv[3])
```

<br>

The second line passes the now-properly formatted URL path to the `loadConfig()` function to create the `proxy` and `headers` global variables:

```python
    loadConfig(urlPath)
```

<br>

The URL path is passed to the `checkIndicator()` function which uses the `HTTPProxyRequest()` function to send an HTTP request to the API:

```python
    data = checkIndicator(urlPath)
```

<br>

The JSON object (`data`) is passed to the `printResults()` function where the objects we want are parsed and printed to the screen:

```python
    printResults(data)
```

<br>

The `main()` function is usually the last function to be defined, and after this the `main()` function is called to begin executing the script:

```python
main()
```
