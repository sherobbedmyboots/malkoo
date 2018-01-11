# Browser Malware



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


Basic components that make up a web page:

- [HTML Document](#html-document)


### HTML Document

This is a hierarchical structure of tags, attributes, and parameters containing the contents of the web page.

Elements such as <head>, <title>, <body>, <img>, <div>, and <p> are used to label text, images, and components of the web page.

The two main types are HTML and XHTML which is an extended version of HTML that is XML-based.

The tags are parsed and 

CSS is use



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





### Stylesheets

```css

```


### Scripts

```javascript
<script type="text/javascript" src="analytics.js"></script>
```


### Plugins




High

single threaded runtime, single call stack (one thing at a time)

---
since js is high level (human written) and meant to be easy to use
as the code is interpreterd, it does a lot of lookups, type conversions, etc. to optimize and execute it

run native code on the browser

Java machine and byte code
.NET runtime is IL format














browser sandboxes
- shady code on website won't delete hard drive because of sandbox
- shady binary may 

(java, flash?)

JS
V8 — open source, developed by Google, written in C++
Rhino — managed by the Mozilla Foundation, open source, developed entirely in Java
SpiderMonkey — the first JavaScript engine, which back in the days powered Netscape Navigator, and today powers Firefox
JavaScriptCore — open source, marketed as Nitro and developed by Apple for Safari
KJS — KDE’s engine originally developed by Harri Porten for the KDE project’s Konqueror web browser
Chakra (JScript9) — Internet Explorer
Chakra (JavaScript) — Microsoft Edge
Nashorn, open source as part of OpenJDK, written by Oracle Java Languages and Tool Group
parses code, compiles it to machine code, and executes it while monitoring and optimizing


Browser provides WebAPIs
- DOM
- ajax(XMLHTTPRequest)
- setTimeout

sacrificed speed for ease of use,  dynamically typed


JIT compilers speed up performance by translating JS code into machine code
watches code as it runs, sees what's run many times
if function runs many times, it's sent to the compiler to optimize, creates a faster version of the function

V8 - used in Chrome and Node.js
has heap for memory allocation and stack for code execution


Node (V8), Electron


Asynchronous JavaScript and XML (AJAX)ax helped JS create dynamic web applications which sparked an open source revolution
Data could be loaded in the background avoiding reloading page, resulting in more dynamic applications
this led to jquery, 
server side (Node.JS)
Web application frameworks (AngularJs, React, Knockout)



Node
build full applications with js
- C++ APIs
- provides sockets, filesystem access
- took js engine out of browser, gave it new APIs
plugins were dying, no replacement
JS isn't good with optimizations



JS is a high level language (textual), these are harder to optimize code with
asm.js 
compiler target compatible with plain JS
takes C++, compiles it to JS, JS is translated into native code


Web Assembly is a low level (binary) direct successor to asm.js, a lower level version of js
It is a general purpose virtual architecture with open standard with cross-browser support
universal, safe,  runs as quickly as native code, allow code re-use between Web and native platforms
runs a binary in the browser sandbox
except, regular assembly is specific to an architecture
on web, architecture of client machine is unknown
WASM is machine code for a conceptual machine, not a physical machine
wasm is smaller (binary)


large computations are slower on JS.  With wasm, we can control exactly how memory is allocated and freed making it faster


OS - C programs can be compiled for either Win, Lin, Mac.. x64 or x86

Web - emmc compiles a c program into WASM for all browsers--Safari, Chrome, Firefox, Edge
hand the browser optimized code

Doesn't replace JS, but expands web.  Enables hybrid designs (WASM + JS)


JS loads a web assembly module and instantiate it.
