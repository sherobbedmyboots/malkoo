# Browser-Based Malware and JavaScript

Browser-based attacks may drop files or may exist only in the browser.

Get the page with curl or wget --useragent and statically examine
Or visit the page and perform dynamic analysis

Run wireshark then open in NetworkMiner to extract files

Understanding the Flow of Execution, use Fiddler web proxy to see which URLs are accessed and how

Use Chrome Developer Tools to see all files, network traffic, etc. associated with the page

Scripts can redirect to malicious pages or deliver exploits and are often obfuscated in some way.

Delivery
inserting arbitrary code on a compromised website
social engineering to 



- [Basic Browser Operation](#basic-browser-operation)
	- [HTML Documents](#html-documents)
	- [Document Object Model](#document-object-model)
	- [XMLHttpRequest](#xmlhttprequest)
- [JavaScript](#javascript)
	- [Obfuscation](#obfuscation)
	- [Web Assembly](#web-assembly)
- [Malware Using JavaScript](#malware-using-javascript)
	- [JavaScript Downloaders](#javascript-downloaders)
	- [Cryptominers](#cryptominers)
	- [Man in the Browser Attacks](#man-in-the-browser-attacks)




## Basic Browser Operation

On a basic level, a browser is used to receive and execute instructions from arbitrary servers on the Internet over IP. The two most common ways to deliver these instructions are by using an HTML or XHTML document.


### HTML Document

HyperText Markup Language (HTML) is the primary language used for displaying web pages.  An HTML document is a hierarchical structure of elements making up the contents of the web page.  These elements are defined using tags which specify an element's attributes.

|Tag|Element|
|-|-|
|`<html>`|The HTML document|
|`<head>`|Container for metadata|
|`<title>`|Title of the document|
|`<h1>` to `<h6>`|Headings|
|`<a>`|Links are used to navigate from page to page|
|`<img>`|Images displayed on page|
|`<p>`|Paragraphs contain text to be displayed|
|`<style>`, `<link>`|Cascading Style Sheets (CSS) control the appearance of the HTML document|
|`<iframe>`|IFrames display a web page within a web page|
|`<script>`|JavaScript is used for dynamic and interactive content|	
|`<form>`|Forms are used to collect user input|


A browser requests a web page using a HTTP/HTTPS GET request, parses the HTML code in the file it recieves, and begins to render all the data it contains.

This data can be:
	
	- Text to read
	- Images to view
	- Links that can be clicked
	- Documents that need to be loaded (HTML, CSS)
	- Scripts that need to run (JavaScript, VBScript)
	- Files that need to be run by a browser plugin (Flash, Silverlight, Java)

As the browser parses the HTML, retrieving and loading all this data into memory, it builds a structured representation of the web page called the Document Object Model, or DOM.


### Document Object Model

The DOM is a virtual map of the web page that is currently loaded in the browser. This in-memory representation of all HTML elements of the web page is used to display and update the page.  By representing all HTML elements as objects, scripts running in the browser can read and modify the rendered document dynamically.

JavaScript, for example, can access the DOM using the `document` object:

```javascript
document.getElementsbyTagName
```


Scripts called by the HTML document run in this environment and use it to share functions and global variables.  The scripts can access the DOM and manipulate parts of the web page.  If the scripts need to interact with something outside this context, they must use one of the Web APIs provided by the browser.

One of the most popular Web APIs provided by browsers is XMLHttpRequest.


### XMLHttpRequest

XMLHttpRequest allows a client to load additional content from the Web without loading a new document.  Parts of the page can be updated without interrupting the user's browsing session.

### DOM


### AJAX

Asynchronous JavaScript and XML (AJAX) helped JavaScript create dynamic web applications which sparked an open source revolution
Data could be loaded in the background avoiding reloading the page, resulting in more dynamic applications


Then plugins were created that could execute platform-independent programs on an end user machine such as Flash or Java.

Web APIs are provided by the browser to be used by JavaScript.

One of these is 





















For example, visit a web page with Google Chrome and open DevTools by pressing F12.










JavaScript accesses 

The DOM has objects, properties, and methods.
| | |
|-|-|
|objects|children, document, elements, forms, frames, images, links, location, scripts, window|
|properties|content, data, document, fileName, length, name, parent, self, type|
|methods|appendChild, clear, evaluate, getElementsByName, open, removeChild, setTimeout, write|


JavaScript events have properties and methods:

| | |
|-|-|
|properties|button, data, domain, event, length, origin, source, target|
|methods|click, createEvent, createEventObject|
|events|nbeforeunload, onclick, ondblclick, ondrag, ondrop, onload, onmouseover, onresize, onselect, onstart, onstop|












Browser-based malware must first find a way to execute code in the browser.

This code can be HTML, CSS, JavaScript, or even a bytecode file run by a browser plugin.

## Linked and Embedded External Content

Here are the common ways to link and embed external content in a web page:

- [Links](#links)
- [IFrames](#iframes)
- [Images](#images)
- [Stylesheets](#stylesheets)
- [Scripts](#scripts)
- [Plugins](#plugins)


### Links

The most basic way to reference external content is:

```html
<a href="http://www.example.com/">Click here</p>a>
```

### IFrames
Used to embed documents into the current page, can be used in an attack to load current page into an overlay while code runs in the background.

```html
<iframe src="http://www.example.com"></>iframe>
```

### Images

Can be used for XSS attacks

```html
<img src="http://www.example.com/picture.png">
```

### Stylesheets


```html
<link rel=stylesheet href="http://"
<style> 
```

### Scripts

JavaScript and VBScript can be executed:

```html
<script type="text/javascript" src="analytics.js"></script>
```

[Here](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet) is a cheat sheet showing the many variations that can be used.

Stored Cross site scripting - the browser visits the site and is made to run untrusted content
```html
http://www.example.com/index.html#title=<script>document.location="http://evilsite.com"</script>
```

User visits a page that has XXS code

Reflective XSS - User receives a link to a page that echos requests.  Link contains code that's echoed back to browser and executed.
```html
http://www.example.com/index.html#title=<script>document.location="http://evilsite.com"</script>
```

DOM XSS - client side JavaScript dynamically modifies a rendered page based on content in the URL
```html
http://www.example.com/index.html#title=<script>document.location="http://evilsite.com"</script>
```

Drive-by Downloads


### Plugins

Browser plug-ins allow different file formats to be displayed in the browser.  They are initialized by the web page to render content.  Many times the plug-in applications are given special privilges to show these different formats in the browser window.  

| | |
|-|-|
|Windows Media Player|embedded audio and video|
|Apple QuickTime|embedded audio and video|
|Adobe Reader|embedded PDFs|
|Microsoft Office|embedded word documents and spreadsheets|
|Adobe Flash|embedded videos|
|Java||
|ActiveX Controls||
|Adobe Flash|JavaScript-based language called ActionScript|
|Microsoft Silverlight||


```html
<object data="player.swf" type="application/x-shockwave-flash">
<embed src=>
<applet>
```












## JavaScript

JavaScript is the primary scripting language used on the world wide web.  It is a single threaded runtime with a single call stack---which means it does one thing at a time.  

Here are some popular JavaScript engines:
 | 
-|-
V8      open source, developed by Google, written in C++
Rhino           managed by the Mozilla Foundation, open source, developed entirely in Java
SpiderMonkey           the first JavaScript engine, which back in the days powered Netscape Navigator, and today powers Firefox
JavaScriptCore        open source, marketed as Nitro and developed by Apple for Safari
KJS          KDE’s engine originally developed by Harri Porten for the KDE project’s Konqueror web browser
Chakra (JScript9)          Internet Explorer
Chakra (JavaScript)          Microsoft Edge
Nashorn          open source as part of OpenJDK, written by Oracle Java Languages and Tool Group parses code, compiles it to machine code, and executes it while monitoring and optimizing


Each browser has their own JavaScript engine and provides a sandboxed JavaScript execution environment for every HTML document displayed.  The sandbox limits the JavaScript to specific, predefined methods and properties within the browser.  This ensures a script from a random site can't delete your hard drive in the same way an executable from a random site. 

JavaScript Objects

| | |
|-|-|
|document|DOM of the current page|
|navigator|OS and plug-in information|



To improve performance, more application logic for a page was pushed to the client for execution.  This way the user's session was more responsive.


### JIT Compilers

JavaScript is a high level language that was designed in a way to sacrifice speed for ease of use.  The JavaScript engine parses the human-readable code, resolves all the functions, and executes the code.  While JavaScript interprets each script, it does a lot of lookups, type conversions, etc. to optimize it for execution.

JIT compilers speed up performance by translating JS code into machine code
It watches code as it runs, sees what's run many times
if function runs many times, it's sent to the compiler to optimize, creates a faster version of the function



```javascript
appendChild()
document.write()
```




### VBScript

Has access to the DOM APIs as well






## Man in the Browser Attacks

A Man in the Browser (MitB) attack is when injected JavaScript establishes a communication channel and obtains persistence in the browser.  This allows an attacker to eavesdrop on browser operations, hijack GET and POST requests, and relay traffic intended for a legitimate server back to the attacker where he can modify requests and responses. 

The victim's browser can be "hooked" a number of ways including Cross Site Scripting (XSS), 

They are hidden to the user, hidden to the server, can read and modify content within current page, doesn't require victim intervention

Commonly used by banking malware.  Occurs entirely in browser





Previous attempts include Java machine and byte code, .NET runtime is IL format

(java, flash?)



V8 - used in Chrome and Node.js
has heap for memory allocation and stack for code execution


## Node.js

Node.js was built on the V8 engine and allows building full applications with JavaScript.

(V8), Electron

Node
build full applications with js
- C++ APIs
- provides sockets, filesystem access
- took js engine out of browser, gave it new APIs
plugins were dying, no replacement
JS isn't good with optimizations


### asm.js
JS is a high level language (textual), these are harder to optimize code with

asm.js is a compiler target compatible with plain JS
takes C/C++, compiles it to JS, JS is translated into native code
improves performance by only using code that can be optimized ahead of time
JS engine doesn't need to interpret the code, it immediately compiles it to assembly


## Web Assembly

Web Assembly is a low level (binary) direct successor to asm.js, a lower level version of js
It is a general purpose virtual architecture with open standard with cross-browser support
universal, safe,  runs as quickly as native code, allow code re-use between Web and native platforms
runs a binary in the browser sandbox
except, regular assembly is specific to an architecture
on web, architecture of client machine is unknown
WASM is machine code for a conceptual machine, not a physical machine
wasm is smaller (binary)
large computations are slower on JS.  With wasm, we can control exactly how memory is allocated and freed making it faster



### Concept

Web Assembly is similar to writing and compiling code to run on an Operating System.

C programs can be compiled for either Windows, Linux, or Mac and for the x64 or x86 architecture.  The compiler scans the entire program and creates an optimized executable containing binary code for the CPU to execute.  After this, the executable should run on any machine with the appropriate OS and architecture.

Web Assembly is similar as it allows you to compile a C program into WASM that will run on any of the major browsers--Safari, Chrome, Firefox, and Edge.  This is a huge performance boost because the browser is being given code that's already been optimized.  It's basically running native code on the browser.

WASM doesn't replace JavaSscript, but complements it by enabling hybrid designs (WASM + JS).
OS-independent web.
JavaScript loads a web assembly module, instantiates it, and calls its functions.


### Example

Crypto-mining, using a machine's CPU to mine cryptocurrency, is a good example of scripts that can run quietly in the browser without the user's knowledge.

Many crypto miners that do not ask permission to run are being labeled as malware since they are in essence stealing the user's computer resources.

There are many types of cryptocurrency, one we've been seeing lately is Monero which is mined by sites such as Coinhive.



