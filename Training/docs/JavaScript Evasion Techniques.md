# JavaScript Evasion Techniques

JavaScript is a high level language designed with very human-readable source code for ease of use. When a script is loaded, the source code is delivered to the client's JavaScript engine which interprets it, resolves all the functions, optimizes it for execution, and compiles it to assembly to run in the browser.  Since the source code is sent to the client's browser for execution, when malicious JavaScript is downloaded it can be inspected by security tools and incident responders.

Evasion techniques transform the source code into something that has the exact same functionality, but is much more difficult to search and understand. Some are designed to bypass specific detection tools while others are used to extend the time required for manual analysis or ensure the code executes in a specific environment.  This document will demonstrate how different evasion techniques can be used to help malicious JavaScript code evade detection and analysis.


- [Tools](#tools)
	- [Node.js](#node.js)
	- [Sublime Text 3](#sublime-text-3)
	- [Test Files](#test-files)
- [Encoding](#encoding) 
	- [Base64](#base64)
	- [ASCII Codes](#ascii-codes)
	- [Unicode](#unicode) 
	- [Hex](#hex)
	- [Octal](#octal)
	- [Binary](#binary)
	- [Xor](#xor)
	- [Url](#url)
	- [Double Url](#double-url)
	- [Non-alphanumeric](#non-alphanumeric)
- [Obfuscation](#obfuscation)
	- [Minifying](#minifying)
	- [Manipulating Control Flow](#manipulating-control-flow)
	- [Manipulating Identifiers](#manipulating-identifiers)
	- [Dead Code Insertion](#dead-code-insertion)
	- [Different Object Notations](#different-object-notations)
	- [Locking](#locking)
	- [Encryption](#encryption)
	- [Different Contexts](#different-contexts)
	- [Combinations](#combinations)

<br>

## Tools

For these exercises, you need a JS engine, a text editor, and the test files:

- [Node.js](#node.js)
- [Sublime Text 3](#sublime-text-3)
- [Test Files](#test-files)


### Node.js

Node.js is a powerful interactive shell for Javascript.  It was built on the V8 engine, the same one used in the Google Chrome browser, and allows building full applications with JavaScript.  Node.js basically took the JS engine out of a browser and gave it new APIs to provide access to sockets and the filesystem.

Open up the Node.js shell and type some basic JavaScript commands in:

![](images/JavaScript%20Evasion%20Techniques/image026.png)<br>

The file `functions.js` is a module containing a collection of JavaScript functions that can be loaded into the shell by typing:

```javascript
var f = require("/html/files/functions.js")
```

To see a list of the functions, type `f.` then hit the `Tab` key twice:


![](images/JavaScript%20Evasion%20Techniques/image034.png)<br>


### Sublime Text 3

First see if the [Sublime-HTMLPrettify](https://github.com/victorporof/Sublime-HTMLPrettify) package is already installed by pressing `Ctrl + SHIFT + H` to prettify the `obfuscated.js` file.

If it doesn't work:
- Download [Package Control](https://packagecontrol.io/Package%20Control.sublime-package) and place it in your `%APPDATA%\Sublime Text 3\Installed Packages` directory.
- Download [Sublime-HTMLPrettify](https://github.com/victorporof/Sublime-HTMLPrettify), unzip and place in your `%APPDATA%\Sublime Text 3\Packages` directory.
- Restart Sublime Text 3


### Test Files

These can be found on the OOB:

	html2/aes.js
	html2/alert.js
	html2/functions.js
	html2/index.html
	html2/obfuscated1.js
	html2/obfuscated2.js
	html2/obfuscated3.js
	html2/original.js


To set these up, do the following:

- Put the entire `html2` directory on your Windows VM Desktop
- Open PowerShell prompt from the Desktop and type `python -m http.server`
- Open Chrome and navigate to `localhost:8000/html2/index.html`


## Encoding

Encoding is commonly used to evade detection by regex-based filters and searches for suspicious keywords and patterns. 

- [Base64](#base64)
- [ASCII Codes](#ascii-codes)
- [Unicode](#unicode) 
- [Hex](#hex)
- [Octal](#octal)
- [Binary](#binary)
- [Xor](#xor)
- [Url](#url)
- [Double Url](#double-url)
- [Non-alphanumeric](#non-alphanumeric)


One at a time, uncomment each of these (highlight and hit `Ctrl + /` to uncomment multiple lines) and reload the page to verify that they execute the JavaScript code `alert(1)` in a browser causing this pop-up message:

![](images/JavaScript%20Evasion%20Techniques/image016.png)


### Base64

The `atob` function decodes the Base64-encoded JavaScript and `eval` executes it:

![](images/JavaScript%20Evasion%20Techniques/image006.png)

You can use Node.js to encode/decode Base64 with the following functions:

![](images/JavaScript%20Evasion%20Techniques/image007.png)<br><br>


### ASCII Codes

The `alert(1)` string can be written using ASCII code which is converted to characters and executed by `eval`:

![](images/JavaScript%20Evasion%20Techniques/image027.png)

In Node.js, use the `decToAsc` and `ascToDec` functions:

![](images/JavaScript%20Evasion%20Techniques/image028.png)<br><br>


### Unicode

The `alert(1)` string in Unicode is executed by the `eval` command: 

![](images/JavaScript%20Evasion%20Techniques/image012.png)

In Node.js, use the `unescape` function:

![](images/JavaScript%20Evasion%20Techniques/image017.png)<br><br>

### Hex

The `alert(1)` string in Hex is executed by the `eval` command: 

![](images/JavaScript%20Evasion%20Techniques/image013.png)

In Node.js, use the `unescape` function:

![](images/JavaScript%20Evasion%20Techniques/image018.png)<br>

Or pass an array to the `hexToAsc` function:

![](images/JavaScript%20Evasion%20Techniques/image035.png)<br><br>

### Octal

The `alert(1)` string in Octal is executed by the `eval` command: 

![](images/JavaScript%20Evasion%20Techniques/image014.png)

In Node.js, use the `unescape` function:

![](images/JavaScript%20Evasion%20Techniques/image019.png)<br>

Or pass an array to the `octToAsc` function:

![](images/JavaScript%20Evasion%20Techniques/image036.png)<br><br>

### Binary

Here each binary number is converted to an ASCII character creating a string that is executed by `eval`:

![](images/JavaScript%20Evasion%20Techniques/image015.png)

In Node.js, use the `binToAsc` and `ascToBin` functions:

![](images/JavaScript%20Evasion%20Techniques/image020.png)<br><br>


### XOR

By XOR'ing the `alert(1)` string with a key (in this case the number 77), the encoded string `,!(?)9e|d` is decoded and executed by `eval`:

![](images/JavaScript%20Evasion%20Techniques/image008.png)

In Node.js, use the `xor` function to encode and decode:

![](images/JavaScript%20Evasion%20Techniques/image021.png)<br><br>


### URL
 
URL encoding can also be used to encode the characters that make up the string `alert(1)`:

![](images/JavaScript%20Evasion%20Techniques/image009.png)

In Node.js, decode with the `unescape` function:

![](images/JavaScript%20Evasion%20Techniques/image022.png)<br><br>


### Double URL

The `%` characters from above can also be encoded using their URL-encoded value, `%25`:

![](images/JavaScript%20Evasion%20Techniques/image010.png)

In Node.js, use nested `unescape` functions to decode:

![](images/JavaScript%20Evasion%20Techniques/image023.png)<br><br>


### Non-alphanumeric

Tools such as JJencode and AAencode can encode JavaScript code using only symbols:

![](images/JavaScript%20Evasion%20Techniques/image011.png)


This technique can be used with any symbols, not just the ones used above.  In cases like these, the specific encoding scheme is unknown and deobfuscation will require stepping through the code or executing it in a controlled environment.

<br>

## Obfuscation

The following techniques are commonly used to make analysis and reverse engineering difficult for incident responders:

- [Minifying](#minifying)
- [Manipulating Control Flow](#manipulating-control-flow)
- [Manipulating Identifiers](#manipulating-identifiers)
- [Dead Code Insertion](#dead-code-insertion)
- [Different Object Notations](#different-object-notations)
- [Locking](#locking)
- [Encryption](#encryption)
- [Different Contexts](#different-contexts)
- [Combinations](#combinations)


### Minifying

When JavaScript is minified, it is compressed and made into one continuous line. Removing all the whitespace, comments, and formatting is one way to decrease source code human readability.

This is the contents of the `obfuscated.js` file: 

![](images/JavaScript%20Evasion%20Techniques/image001.png)

You can use the Sublime-HTMLPrettify package in Sublime Text to add some formatting with `Ctrl + SHIFT + H`:

![](images/JavaScript%20Evasion%20Techniques/image002.png)<br><br>


### Manipulating Control Flow

Source code is generally easier to read and understand if logically related components are grouped together.  Control flow obfuscation reorders variables, methods, arrays, statements, loops, and expressions.

In the `obfuscated.js` file, the functions and statements have been moved to random positions to complicate the flow of the code.  This removes the logical order that the code was originally written with and forces an analyst to search the entire contents of the page to find code blocks that are related to each other.

Also, most of the members and strings have been moved into an array at the beginning of the code and are referenced using their position in the array.  This removes the context of each string and the function that uses it which makes it even  more difficult to read through the code.   

However, some of the properties and function names are recognizable and this would allow an analyst to still understand what objects are being used and what actions are being performed:

![](images/JavaScript%20Evasion%20Techniques/image029.png)<br>

To prevent this, any identifiers that may reveal functionality can be disguised.
<br>

### Manipulating Identifiers

This technique changes functions, arguments, and variables being used in order to make them unrecognizable.  

Examples:

- Changing function names to meaningless sequences of characters
- Encoding identifiers
- Reversing identifiers
- Splitting and rejoining identifiers
- Replacing identifiers with expressions

<br>

In the `obfuscated2.js` file, the function names have been assigned meaningless names:

![](images/JavaScript%20Evasion%20Techniques/image037.png)<br>

And the values in the array have been Hex-escaped:

![](images/JavaScript%20Evasion%20Techniques/image032.png)<br>

In this case, the function names can be deobfuscated with the `revStr` function:

![](images/JavaScript%20Evasion%20Techniques/image038.png)<br>

Splitting strings into smaller chunks and rejoining them as the code executes is a common way to obfuscate suspicious functions such as `eval`:

![](images/JavaScript%20Evasion%20Techniques/image039.png)<br>

Here is the `eval` function written as an expression that is interpreted when the code executes:

![](images/JavaScript%20Evasion%20Techniques/image040.png)<br><br>


### Dead Code Insertion

Dead code insertion adds confusion to source code and increases the complexity of the control flow.

In the `obfuscated3.js` file, code has been added that doesn't affect the main functionality of the program.  It's purpose is to force reverse engineers to waste time debugging or analyzing code that is meaningless. 

![](images/JavaScript%20Evasion%20Techniques/image031.png)<br><br>


### Different Object Notations

JavaScript uses both dot and bracket notation:

|Type|Example|
|-|-|
|Dot|`document.script.length`|
|Bracket|`document['script']['length']`|

<br>

They are functionally equivalent:

![](images/JavaScript%20Evasion%20Techniques/image033.png)



### Locking

Locking can be used to ensure the JavaScript code only executes before, after, or between specific dates or only on systems belonging to specific domains.  Before the code executes, it checks for specific conditions and will only run if the required conditions are met.  

The following code acts as a kill switch, creating a Date object and checking it to see if it is before or after the kill date:

```javascript
function checkFirst() { 
	var killDate = 'Tue Feb 04 2018 07:08:32 GMT-0600 (Central Standard Time)';
	var d = new Date();
	if (d < killDate) {
		runIt();
	}
	else {
		alert('There was a problem... exiting!');
	}
}
```

If the code that makes this check is discovered by the analyst, it can easily be bypassed by either changing the logic or calling the function that would have executed had the date check passed:

![](images/JavaScript%20Evasion%20Techniques/image041.png)


For this reason, the piece of code responsible for checking for a kill switch is usually protected with encryption.<br><br>

### Encryption

The use of encryption helps hide the presence of functions or strings that could be used to reverse the code.  But since the code executes on the client's browser, the key must be present somewhere in the web page's code.

For example, this would be the process to encrypt the date checking function above:

The date checking function is assigned to a variable:

```javascript
var u = 'var killDate = \'Tue Feb 04 2018 07:08:32 GMT-0600 (Central Standard Time)\'; var d = \
   new Date();if(d < killDate){runIt();}else{alert(\'There was a problem... exiting!\');}'
```
<br>

The contents of the variable are then encrypted with a key: 


```javascript
var encrypted = CryptoJS.AES.encrypt(u, "abcdefghijklmnopqrstuvwxyz");
// U2FsdGVkX18EccRtV54NS3nUcJi+/2lIT6cRoY1YSSQ00hCk06kMmAejpyHW888uM6E3GNviqSqJaTm00n5P
// F5KUlGTmFCN8oRlPMDdbj/B4MmkCWGnxWZGM1gb2uyErIWV/QPF/clz1zE8d3POpghxAc+f0OXhoQ3kN9hzb
// H0pSnrzkHfZqq+3B3NxqKBSgIqPA3VDTHgz/8z0Qn7DBjxKLrNo1sLWtXtJcnddJJmXn2OHi1h9869t4MwBF18hG
```
<br>

The key and the encrypted function are placed on the page and a second function (runEncryptedCheck) decrypts the code and executes it:


```javascript
function runEncryptedCheck() {
	var x = 'U2FsdGVkX18EccRtV54NS3nUcJi+/2lIT6cRoY1YSSQ00hCk06kMmAejpyHW888uM6E3GNv\
	iqSqJaTm00n5PF5KUlGTmFCN8oRlPMDdbj/B4MmkCWGnxWZGM1gb2uyErIWV/QPF/clz1zE8d3POpghx\
	Ac+f0OXhoQ3kN9hzbH0pSnrzkHfZqq+3B3NxqKBSgIqPA3VDTHgz/8z0Qn7DBjxKLrNo1sLWtXtJcndd\
	JJmXn2OHi1h9869t4MwBF18hG'
	var decrypted = CryptoJS.AES.decrypt(x, "abcdefghijklmnopqrstuvwxyz");
	var command = decrypted.toString(CryptoJS.enc.Utf8)
	eval(command);
}
```

<br>

For this technique to be successful, the encryption key, the `eval` command, and even the use of the CryptoJS library should all be obfuscated in some way to hide the fact that encryption is being used.  Because if we determine encryption is used and identify both the key and the encrypted command, we can also use the CryptoJS library to decrypt the function: 
     

![](images/JavaScript%20Evasion%20Techniques/image042.png) <br><br>


### Different Contexts

JavaScript can be used to access different contexts including the DOM and other external content such as scripts, PDFs, Flash, Java, etc.  If a script is written that requires content from two or more contexts in order to function, then attempting deobfuscation with only one context will most likely be unsuccessful.

In the function below, the encryption key has been modified to require content (one character) from an external script:

```javascript
function runContextCheck() {
		
	// The encrypted function is set to 'x'
	var x = 'U2FsdGVkX18EccRtV54NS3nUcJi+/2lIT6cRoY1YSSQ00hCk06kMmAejpyHW888uM6E3GN\
	viqSqJaTm00n5PF5KUlGTmFCN8oRlPMDdbj/B4MmkCWGnxWZGM1gb2uyErIWV/QPF/clz1zE8d3POpg\
	hxAc+f0OXhoQ3kN9hzbH0pSnrzkHfZqq+3B3NxqKBSgIqPA3VDTHgz/8z0Qn7DBjxKLrNo1sLWtXtJc\
	nddJJmXn2OHi1h9869t4MwBF18hG'
	
	// The external script "demo_script_src.js" is downloaded from an external site
	d=document;ee=d.createElement("script");ee.src="https://www.w3schools.com/jsref/demo_script_src.js";

	// The 's' character from the loaded script is used to complete the encryption key
	var y = 'abcdefghijklmnopqr' + ee.src.split('_src.j')[1] + 'tuvwxyz';
	
	// If the script was successfully downloaded, the encrypted command can be decrypted 
	var decrypted = CryptoJS.AES.decrypt(x, y);
	var command = decrypted.toString(CryptoJS.enc.Utf8)
	eval(command);
}
```
<br>

If the script cannot be downloaded, the encryption key will be incomplete and the function cannot run or be decrypted for analysis.


<br>


### Combinations

The example above used both different contexts and encryption which adds to the steps required to deobfuscate and analyze the code.  Combining multiple different evasion techniques in this way often results in a higher level of obfuscation than using a single technique by itself. 

Here are some other examples:

Mixing different object notations with string-splitting and replacements:

```javascript
navigator.plugins['Shockwave Flash'].description
```

can be changed to 

```javascript
navigator['plu' + 'gin' + 's']['Shoc' + 'kwa' + 've Fl' + 'ash']['desc' + 'rip' + 'artion'['replace'] \
   (/artion/,'tion')]
```

<br>
Mixing splitting with encoding:

```javascript
String.fromCharCode(101)+'va'+'l'+'(' + String.fromCharCode(97) + 'ler' + String.fromCharCode(116) \ 
   + '(1)'+')'
```

which is interpreted as:

![](images/JavaScript%20Evasion%20Techniques/image030.png)<br><br>


## Summary

Using DevTools, Node.js, and the functions.js module, try to deobfuscate each of the following files and see how closely you can match the original code:

- obfuscated1.js
- obfuscated2.js
- obfuscated3.js


