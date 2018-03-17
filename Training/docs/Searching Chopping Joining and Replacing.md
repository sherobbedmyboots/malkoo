# Searching Chopping Joining and Replacing

Scripting is useful for increasing efficiency and reducing the time required to perform complex tasks such as parsing logs and deobfuscating the contents of malicious files.

Common scripting functions include:

- Searching for a string or pattern
- Chopping large chunks of text into smaller parts
- Joining small chunks of text into larger parts
- Replacing strings or patterns with other strings and patterns

<br>

This training reviews these common functions demonstrating their use with several different scripting languages:

|Scripting Language|Searching|Chopping|Joining|Replacing|
|-|-|-|-|-|
|[Nodejs](#nodejs)|`includes()`, `match()`|`split()`|`join()`|`replace()`|
|[PowerShell](#powershell)|`Select-String`, `contains()`|`split()`|`-join`|`replace()`|
|[Bash](#bash)|`grep`|`cut`, `awk`|`IFS`|`sed`|
|[Python](#python)|`in`, `re.findall()`|`split()`|`join()`|`replace()`|

The examples use the following file on the OOB:

	/CSIRT/Sample-Files/html2/obfuscated1.js

<br>

## Nodejs


|Operation|Method|
|-|-|
|[Searching](#searching-with-nodejs)|`includes()`, `match()`|
|[Chopping](#chopping-with-nodejs)|`split()`|
|[Joining](#joining-with-nodejs)|`join()`|
|[Replacing](#replacing-with-nodejs)|`replace()`|

<br>


Open the `obfuscated1.js` file and view the contents:

```javascript
// Save file contents to a variable
var file = require('fs')
var contents = file.readFileSync('C:\\obfuscated1.js', 'UTF-8')

// See raw contents
contents

// Print contents
console.log(contents)
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image001.png)<br><br>


### Searching with Nodejs

Search for strings using the `includes()` method:

```javascript
// Determine if contents contains the string 'function'
contents.includes('function')
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image002.png)<br><br>


Search for regular expressions using the `match()` method:


```javascript
// Define regular expression
var regexp = /function [\w]+/gi

// Search contents for pattern
contents.match(regexp)
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image003.png)<br><br>


### Chopping with Nodejs

Save the regex matches to a variable named `matches` and extract the function names using the `split` method:

```javascript
// Assign to variable
var matches = contents.match(regexp)

// Split by space character
matches[0].split(' ')

// Split by space and extract the second item
matches[0].split(' ')[1]

```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image004.png)<br><br>


Now apply a function that splits every element in the `matches` array and pulls out the function name:

```javascript
// Create function that splits/extracts and assign to variable
var functionNames = matches.map(function(i){return i.split(' ')[1]})

// View variable
functionNames
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image005.png)<br><br>

### Joining with Nodejs

Join together elements of an array using the `join()` method:

```javascript
// Join elements of array 
matches.join('|||')
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image034.png)<br><br>


### Replacing with Nodejs

Replace the 'r' in the first function name using the `replace()` method:

```javascript

// Replace character in one object
functionNames[0].replace('r','000')

// Replace characters in all objects in the array
functionNames.map(function(i){return i.replace('r','000')})
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0066.png)<br><br>


Now try replacing every 'r' in the `contents` variable with and without the `g` (global) flag:

```javascript

// Replace the first occurrrence of 'r'
contents.replace('r','000')

// Replace every occurrence of 'r'
contents.replace(/r/g, '000')
```



![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0077.png)<br><br>


## PowerShell

|Operation|Method|
|-|-|
|[Searching](#searching-with-powershell)|`Select-String`, `contains()`|
|[Chopping](#chopping-with-powershell)|`split()`|
|[Joining](#joining-with-powershell)|`-join`|
|[Replacing](#replacing-with-powershell)|`replace()`|

<br>

Open the `obfuscated1.js` file and view the contents:


```powershell

# Save file contents to variable
$contents = Get-Content .\obfuscated.js -Encoding UTF8

# View contents
$contents
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0088.png)<br><br>


### Searching with PowerShell

Search for strings using the `contains()` method:

```powershell

# Search contents for string
$contents[0].contains('function')
```


Because PowerShell's `Get-Content` cmdlet reads the file into an array of string objects, we need to specify the first object in the array:

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image009.png)<br><br>


Now search using the `Select-String` cmdlet:

```powershell

$contents | Select-String -AllMatches function
```

This will return the string that contained the matches.  To see the actual matches, expand the `Matches` and `Value` properties:

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0066.png)<br><br>


This uses `Select-String` to search for regular expressions and expands the properties using the `ForEach-Object` cmdlet (`%`):

```powershell

$contents | Select-String -AllMatches 'function [\w]+' | %{$_.Matches} | %{$_.Value}
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image010.png)<br><br>


### Chopping with PowerShell

Save the regex matches to a variable named `$matches` and extract the function names using the `split()` method:

```powershell
# Assign to variable
$matches = $contents | Select-String -AllMatches 'function [\w]+' | %{$_.Matches} | %{$_.Value}

# Split by space character
$matches[0].split(' ')

# Split by space and extract the second item
$matches[0].split(' ')[1]

```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image011.png)<br><br>

Now apply a function that splits every element in the `$matches` array and pulls out the function name:

```powershell
# Assign results of function to a variable
$functionNames = $matches | %{$_.split(' ')[1]}

# View variable
$functionNames
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image012.png)<br><br>

### Joining with PowerShell

Use the `-join` operator to join elements of an array with one or more characters:

```powershell

# Join elements of an array
$matches -join '|||'
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image033.png)<br><br>


### Replacing with PowerShell

Replace the 'r' in the first function name using the `replace()` method:

```powershell

# Replace character in one object
$functionNames[0].replace('r','000')

# Replace characters in all objects in the array
$functionNames | %{$_.replace('r','000')}
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0133.png)<br><br>


Now replace every 'r' in the contents variable with the `replace()` method:

```powershell
# Replace every occurrence of 'r' with '000'
$contents.replace('r','000')
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0144.png)<br><br>



## Bash


|Operation|Method|
|-|-|
|[Searching](#searching-with-bash)|`grep`|
|[Chopping](#chopping-with-bash)|`cut`, `awk`|
|[Joining](#joining-with-bash)|`IFS`|
|[Replacing](#replacing-with-bash)|`sed`|

<br>


Open the `obfuscated1.js` file and view the contents:

```bash
# Save file contents to a variable
contents=$(<obfuscated1.js)

# Print contents
echo $contents
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image015.png)<br><br>


### Searching with Bash

Search for strings using `grep` with the `-o` switch:

```bash
echo $contents | grep -o function
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0166.png)<br><br>


`grep` can also take regular expressions:


```bash
echo $contents | grep -o 'function \w\+'
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0177.png)<br><br>


### Chopping with Bash

Save the regex matches to a variable named `matches` and extract the function names using `cut`:

```bash
# Assign to variable
matches=$(echo $contents | grep -o 'function \w\+')

# Split by space character and extract second field
echo $matches | cut -d ' ' -f 2

```


Notice that we are dealing with text now instead of objects:

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0188.png)<br><br>


To get the function names, select a delimiter (`-d`) and fields (`-f`) with `cut` or print the fields with `awk`:

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image0199.png)<br><br>


### Joining with Bash

Using the Internal Field Separator (IFS), elements of an array can be joined by a character:

```bash
# Create an array
functionNames=('profileShockwave' 'driveBy' 'sessionHijack')

# Join elements of array with the '|' character
( IFS=$'|'; echo "${functionNames[*]}" )

```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image032.png)<br><br>



### Replacing with Bash

Replace the first 'r' in the `$contents` variable using `sed`:

```bash
# Replace first occurrence of 'r' with '000'
echo $contents | sed 's/r/000/'
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image021.png)<br><br>


Now replace every 'r' in the `$contents` variable using `sed` with the `g` (global) flag:

```bash
# Replace every occurrence of 'r' with '000'
echo $contents | sed 's/r/000/g'
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image020.png)<br><br>




## Python


|Operation|Method|
|-|-|
|[Searching](#searching-with-python)|`in`, `re.findall()`|
|[Chopping](#chopping-with-python)|`split()`|
|[Joining](#joining-with-python)|`join()`|
|[Replacing](#replacing-with-python)|`replace()`|

<br>


Open the `obfuscated1.js` file and view the contents:

```python
# Save file contents to a variable
file = open('c:\\obfuscated1.js', 'r')
contents = file.read()

# View raw contents
contents

# Print contents
print(contents)
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image022.png)<br><br>


### Searching with Python
Search for strings using the `in` operator or the the `findall()` method:

```python

# Determine if variable contains string
'function' in contents

# Find all occurrences of a string in variable
import re
re.findall('function', contents) 

```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image023.png)<br><br>


Search for regular expressions using the `findall()` method:

```python
# Find all occurrences of regex pattern
re.findall('function [\w]+', contents)
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image024.png)<br><br>


### Chopping with Python

Save the regex matches to a variable named `matches` and extract the function names using the `split` method:

```python
# Assign to variable
matches = re.findall('function [\w]+', contents)

# Split by space character
matches[0].split(' ')

# Split by space and extract the second object
matches[0].split(' ')[1]

```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image025.png)<br><br>


Now create a function that splits every element in the `matches` array and pulls out the function name:

```python
# Create function to extract name
def extract(i): return i.split[1]

# Apply function to every value in array
list(map(extract, matches))
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image026.png)<br><br>

Then put the results into an array named `functionNames`:

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image027.png)<br><br>

### Joining with Python

Use the `join()` method to join elements of an array together:

```python
# Join elements of array with '|||'
'|||'.join(functionNames)

# If objects in array, change to strings before join
'|||'.join(map(str,functionNames))
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image031.png)<br><br>


### Replacing with Python

Replace the 'r' in the first function name using the `replace()` method:

```python

# Replace character in one object
functionNames[0].replace('r','000')
```

![](images/Searching%20Chopping%20Joining%20and%20Replacing/image028.png)<br><br>


Now make a function that makes the replacement and apply it to every element in the array:

```python
# Define function that replaces characters
def repl(i): return i.replace('r', '000')

# Apply function on all elements in array
list(map(repl, functionNames))

```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image029.png)<br><br>


Now replace every 'r' in the `contents` variable using the `replace()` method:

```python
# Replace the first occurrrence of 'r'
contents.replace('r','000')
```


![](images/Searching%20Chopping%20Joining%20and%20Replacing/image030.png)<br><br>

## Summary

These are some basic examples of how you can manipulate the contents of files more quickly and more efficiently.  Pick a scripting language you feel comfortable with and try deobfuscating one of the following files:

	/CSIRT/Sample-Files/html2/obfuscated1.js
	/CSIRT/Sample-Files/html2/obfuscated2.js
	/CSIRT/Sample-Files/html2/obfuscated3.js

