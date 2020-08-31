# JavaScript Analysis with NodeJs and DevTools

JavaScript is the primary scripting language used on the world wide web.  [Node.js](https://nodejs.org/en/) and [DevTools](https://developers.google.com/web/tools/chrome-devtools/) are two tools that allow us to examine code within JavaScript files to perform static and dynamic analysis.  

This document will use the `c.min[1].js` file to demonstrate several analysis techniques that can help when dealing with JavaScript files that utilize obfuscation and are difficult to read and understand.

- [Introduction to NodeJs](#introduction-to-nodejs)
- [Examining JavaScript with NodeJs](#examining-javascript-with-nodejs)
- [Introduction to DevTools](#introduction-to-devtools)
- [Examining JavaScript with DevTools](#examining-javascript-with-devtools)

The following are located on the OOB:

    c.min[1].js
    check.js

<br>    

## Introduction to NodeJs

[Node.js](https://nodejs.org/en/) is an open-source, server side JavaScript environment. It is cross-platform and runs on macOs, Linux, and Windows.  The Node shell or REPL (Read-Eval-Print-Loop), is a virtual environment used to execute JavaScript.

To use Node.js for analysis, you need to be familiar with the following:

- [Objects](#objects)
- [Functions](#functions)
- [Modules](#modules)


### Objects

Objects are containers that have properties and methods.  Node.js can be used to create objects with properties and methods:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image031.png)<br><br>

There are many objects already created when you first open Node.js.  For example, the process Node.js is running in is an object that you can access:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image032.png)<br><br>


### Functions

Functions are objects that are used to perform actions.  They can be defined, called, and passed as arguments:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image033.png)<br><br>


### Modules

A module is a collection of objects and functions organized in files to be reused throughout a Node.js application.  Each module has its own context.  In Node.js, there are three types of modules---**core modules** that automatically load in the process, **local modules** that are created locally, and **third party modules** that are created externally and are imported.

To see Node.js's currently loaded modules, type `module`.  Right now, we don't have any but we can use a core module that's already been loaded, `http`:

Type the following to create a web server on your local machine:

```javascript
http.createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end('Hello World!');
}).listen(8080);
```

<br>

Browse to `http://localhost:8080` and confirm the web server is listening:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image034.png)<br><br>

Now, create a local function by typing the following:

```javascript
var log = {
            info: function (info) { 
                console.log('Info: ' + info);
            },
            warning:function (warning) { 
                console.log('Warning: ' + warning);
            },
            error:function (error) { 
                console.log('Error: ' + error);
            }
    };

module.exports = log
```

Now check again with `module`, we have three functions that make up our log module.

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image035.png)<br><br>


The `module.exports` object is an object that exposes available modules.  We can now call one of these functions either by using dot notation with `module.exports.info("hello")` or by using Square Bracket notation with `module['exports']['info']("hello")`:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image036.png)<br><br>

Now, import a third party module by downloading and importing the `functions.js` file from our repository with the `require()` function:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image037.png)<br><br>



## Examining JavaScript with NodeJs

Open `cs.min[1].js_` in Sublime:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image001.png)<br><br>

Save it as a .js file and you will see it is minified:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image002.png)<br><br>

Prettify it to get an idea of the file's structure:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image003.png)<br><br>

The first variable defined in the file, `_0x6cec`, is an array of base64-encoded values.  We can use Node.js to define the array and manipulate values it contains.

Cut and paste the entire second line of the file (`var _0x6cec = ['d3JhcA==', 'cHJldg==', 'KF58Oylccyo='...`) into Node.js then display one of the values it contains:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image004.png)<br><br>

It contains 425 values, all Base64-encoded.

We now need to see how these values are used.  There are only two times this array is referenced in the script---both times are in the function just below it.

Copy the `_0xc6ce` function over to Node.js.  Now you can use this function to call values.

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image007.png)<br><br>

The function decodes the Base64-encoded values and also shifts all the values by 280 (0x118).

This `_0xc6ce` function is what is used to retrieve and deobfuscate the values from the `_0x6cec` array and is referenced over 1400 times in the file which you can see using `Ctrl-F`.  Our next step is finding every instance in the script where this function is called and replacing it with the deobfuscated value it calls.

The best way to start is to pick a small function to test some regex on.  Pick a function and save it as a string in Node.js:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image008.png)<br><br>

Define a regular expression as variable `re` and demonstrate you can use it to replace the obfuscated value of the variable with "whatever" you want, including the deobfuscated value:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image009.png)<br><br>


The replace method looks for the pattern we assigned to `re` and replaces it with the result of the function call we gave it... `_0xc6ce(0x2)`. 

When using regex, several variables are created including `capture` which is the values captured by the search.  Using an in-line function, we can use the value captured as part of our replacement:


![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image012.PNG)<br><br>

Now let's use the value captured and the `eval` command to replace the function call with the actual result of the function call:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image013.png)<br><br>


Try with a few more values to ensure your regex is working properly:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image014.png)<br><br>


Now we want to do this with all the obfuscated values in the file.  First, make a new file with the rest of the JavaScript code by copying and pasting everything after the `0xc6ce` function into a new text document and saving as `c.min[2].js`.  Then use Node.js to read it into a variable called `file`:


```javascript
// Read the contents of the file into the file variable
var file = fs.readFileSync("C:\\c.min[2].js", 'utf8');

// Perform replacements
file = file.replace(re, function (capture){return eval(capture)});

// Write the file variable to the file
fs.writeFileSync("C:\\c.min[2].js", file);
```


If successful, the `c.min[2].js` file contains all the deobfuscated values where they are called in the code.

Now we have some additional obfuscation.

Start by prettifying the code again.

Find `path = /;` and replace with `path = '/';` using `Ctrl + h` in Sublime.

Begin separating functions:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image015.png)<br><br>

As you can see they are all nested within each other and all have similar names (a, b, c, d...).  

Another thing we can do here is use a site like [JSNice](http://jsnice.org/) to rearrange the functions in a more organized manner.

Cut and paste the original `c.min[1].js` file into the left window at [JSNice](http://jsnice.org/) and click `Nicify Javascript`.  As you scroll the nicified output, you will find interesting parts of the code like this one:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image016.png)<br><br>

Some of the values are still obfuscated so load the values of `module["exports"]` into Node.js as a multiline string, starting and ending with the backtick (\`) character:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image017.png)<br><br>

Our old `re` won't work since these function calls use double quotes instead of single quotes so update the regex syntax:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image018.png)<br><br>

Run the same replace method saving the results into a new variable named `new_string`, and then view its contents by splitting it with newlines:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image019.png)<br><br>


Instead of deobfuscating one function at a time, you may want to run their nicified file through the same deobfuscation technique we used on the original file.

If so, cut and paste the nicified output into a new text file, remove the `_0x6cec` array and `_0xc6ce` function, and save as `deob.js`.

Then do the following in Node.js:


```javascript
// Read the contents of the file into the file variable
var file = fs.readFileSync("C:\\deob.js", 'utf8');

// Perform replacements
file = file.replace(re, function (capture){return eval(capture)});

// Write the file variable to the file
fs.writeFileSync("C:\\deob.js", file);
```


You'll need to replace `path=/;` with `path='/';` and `</script>` with `'</script>'` again to get Sublime to properly format.  Now we can see the `module["exports"]` was correctly deobfuscated:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image020.png)<br><br>


Keep in mind, [JSNice](http://jsnice.org/) performs code analysis and uses prediction algorithms to rename all variables and functions (a, b, c, d...) to names that are more meaningful. 

If we try to import the `modules.export` object, we will get an error for several of the variables not being defined, such as `MessageChannel`.  This is because the file is designed to run in a browser and expects certain objects to be available that are not present in the Node.js environment.

Finally, let's take a closer look at how some of the objects in `modules.exports` are being used.  One of the values is `"ID_URL" : "https://ids.cdnwidget.com"`.  If we search the entire file for the string "ID_URL" to see where it is used, we see it's only referenced one other time within code that appears to be building a URI:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image021.png)<br><br>

The URI appears to be built with various information about the client machine.  If we resolve all the variable names used, we can get a general idea of what the URL would have looked like had the client made a request.  Or we can do this by running the file in a Chrome browser and examining it with Chrome's DevTools.

## Introduction to DevTools

Chrome's [DevTools](https://developers.google.com/web/tools/chrome-devtools/) allows us to interact with a web page as it is loaded and executed in the browser.  To demonstrate some basic features, open Chrome, press `F12` to open DevTools, and navigate to `http://www.example.com`.

Along the top of the DevTools window are tabs. The first one, `Elements`, allows us to inspect the HTML and CSS of a page.  This simple page is made up of a single header and two paragraphs (one of which includes a link):

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image038.PNG)<br><br>

The `Console` tab shows log output such as this error for the `favicon.ico` page.  It also allows us to interact with the Document Object Model (DOM) by navigating the DOM tree, call functions, or even perform basic calculations:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image039.PNG)<br><br>

The `Sources` tab shows the source of all content displayed on the page organized by filesystem and domain.  In this case, the website consists of a single html file named `index.html` from the domain `www.example.com`:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image040.PNG)<br><br>

The `Network` tab shows all files requested over the network while loading the web page.  In this case, the html document resulted in a 200 OK while the favicon.ico resulted in a 403 Forbidden:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image041.PNG)<br><br>

The response and headers can be examined for each request by selecting the file:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image042.PNG)<br><br>

Let's look at the `c.min[1].js` file in DevTools so we can examine the variables and functions that it loads into the DOM.


## Examining JavaScript with DevTools

First, create a test page and save it as `testpage.html`:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image024.png)<br><br>

Make sure the `c.min[1].js` file is in the same directory as this file, then navigate to the directory and start a web server by typing `python -m http.server` (or `python -m SimpleHTTPServer` for Python 2).

Open Chrome and press `F12` to open Developer Tools.  Load the test page by navigating to `http://localhost:8000/testpage.html` in Chrome.  

Now that the script is loaded into the DOM for this page, we can access its functions and variables in the console:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image026.png)<br><br>

In the Network tab, you'll see that `testpage.html` loaded `c.min[1].js` and immediately after this two failed web requests were observed:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image025.png)<br><br>

In the Console, we also see the errors logged for each unsuccessful web request:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image023.png)<br><br>

We can inspect the contents of the web requests by selecting them and using the `Headers`, `Preview`, `Response`, and `Timing` tabs:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image027.png)<br><br>

Notice this is the same URL that we saw was being built in the function we discovered while looking at the `modules.exports` object.  Scroll down to see the parameters that were passed with this request that DevTools has parsed:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image028.png)<br><br>

One of the parameters passed, `log`, appears to be a JSON object containing keys and values.  One of them, the `GCS2` parameter, is my base64-encoded IP address which we can decode with the `atob()` function:

![](images/JavaScript%20Analysis%20with%20NodeJs%20and%20DevTools/image030.png)<br><br>

## Summary

After performing some static analysis with [Node.js](https://nodejs.org/en/) and some dynamic analysis with [DevTools](https://developers.google.com/web/tools/chrome-devtools/), we now we have a better idea of what this file is designed to do.

If you would like some more practice on a JavaScript file that is not quite so obfuscated, try using [Node.js](https://nodejs.org/en/) and [DevTools](https://developers.google.com/web/tools/chrome-devtools/) to perform analysis on the `check.js` file. 
