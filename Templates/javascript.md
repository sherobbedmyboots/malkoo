# Browser Malware



- [Basic Browser Operation](#basic-browser-operation)
- [Web Page Components](#web-page-components)
- [JavaScript](#javascript)
- [Web Assembly](#web-assembly)






## Basic Browser Operation

On a basic level, a browser is used to access HTML pages over IP.

Using HTTP GET requests, a browser requests a web page, parses its HTML, and renders the data it contains on the screen.

The data contains text, images, and links to other pages.

A POST request submits user data using forms for interactive tasks.

As browsers developed, new features were created for different things. 

CSS was used to change the way content is displayed.

First you could add fonts, embed external documents.

Then you could embed other programming languages such as JavaScript and VBScript.

Then plugins were created that could execute platform-independent programs on an end user machine such as Flash or Java.


Web APIs are provided by the browser to be used by JavaScript.

One of these is XMLHttpRequest which allows a client to retrieve data from a URL without doing a page refresh.  Parts of the page can be updated without interrupting the user's browsing session.


To improve performance, more application logic for a page was pushed to the client for execution.  This way the user's session was more responsive.




## Web Page Components

Basic components that make up a web page:

- [HTML Document](#html-document)


### HTML Document

This is a hierarchical structure of tags, attributes, and parameters containing the contents of the web page.

Elements such as <head>, <title>, <body>, <img>, <div>, and <p> are used to label text, images, and components of the web page.

The two main types are HTML and XHTML which is an extended version of HTML that is XML-based.







Everything is parsed and read into memory creating the Document Object Model (DOM)



Linked/embedded external content

- [Links](#links)
- [Frames](#frames)
- [Images](#images)
- [Stylesheets](#stylesheets)
- [Scripts](#scripts)
- [Plugins](#plugins)


### Links

The most basic way to reference external content is:

```html
<a href="http://www.example.com/">Click here</p>a>
```

### Frames

```html
<iframe src="http://www.example.com"></>iframe>
```

### Images

```html
<img src="http://www.example.com/picture.png">
```

### Stylesheets

Controls the appearance of the HTML document
```html
<link rel=stylesheet href="http://"
<style> 
```

### Scripts

JavaScript and VBScript can be executed:

```javascript
<script type="text/javascript" src="analytics.js"></script>
```

### Plugins

Browser plug-ins allow different file formats to be displayed in the browser.  Many times the plug-in applications are given special privilges to show these different formats in the browser window.  

|Windows Media Player|embedded audio and video|
|Apple QuickTime|embedded audio and video|
|Adobe Reader|embedded PDFs|
|Microsoft Office|embedded word documents and spreadsheets|
|Adobe Flash|embedded videos|


#### Java

#### ActiveX Controls

#### Adobe Flash
JavaScript-based language called ActionScript

#### Microsoft Silverlight

```html
<object data="player.swf" type="application/x-shockwave-flash">
<embed src=>
<applet>
```







## JavaScript

JavaScript is the primary scripting language used on the world wide web.  It is a single threaded runtime with a single call stack---which means it does one thing at a time.  

Here are some popular JavaScript engines:

V8 — open source, developed by Google, written in C++
Rhino — managed by the Mozilla Foundation, open source, developed entirely in Java
SpiderMonkey — the first JavaScript engine, which back in the days powered Netscape Navigator, and today powers Firefox
JavaScriptCore — open source, marketed as Nitro and developed by Apple for Safari
KJS — KDE’s engine originally developed by Harri Porten for the KDE project’s Konqueror web browser
Chakra (JScript9) — Internet Explorer
Chakra (JavaScript) — Microsoft Edge
Nashorn, open source as part of OpenJDK, written by Oracle Java Languages and Tool Group
parses code, compiles it to machine code, and executes it while monitoring and optimizing


Each browser has their own JavaScript engine and provides a sandboxed JavaScript execution environment for every HTML document displayed.  The sandbox limits the JavaScript to specific, predefined methods and properties within the browser.  This ensures a script from a random site can't delete your hard drive in the same way an executable from a random site. 

JavaScript Objects

| | |
|-|-|
|document|DOM of the current page|
|navigator|OS and plug-in information|


#### Document Object Model

An in-memory representation of all of the HTML elements of the current web page.  The browser uses this to display and update the page.

JavaScript accesses the DOM using the document object:

```javascript
document.getElementsbyTagName
```





Scripts called by the HTML document run in this environment and use it to share functions and global variables.  The scripts can access the DOM and manipulate parts of the web page.  If the scripts need to interact with something outside this context, they must use Web APIs provided by the browser.

Browser-provided Web APIs:

- [DOM]
- [ajax(XMLHTTPRequest)]
- [setTimeout]


### DOM


### AJAX

Asynchronous JavaScript and XML (AJAX) helped JavaScript create dynamic web applications which sparked an open source revolution
Data could be loaded in the background avoiding reloading the page, resulting in more dynamic applications
this led to jquery, 
server side (Node.JS)
Web application frameworks (AngularJs, React, Knockout)


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



JS is a high level language (textual), these are harder to optimize code with

asm.js is a compiler target compatible with plain JS
takes C++, compiles it to JS, JS is translated into native code



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



