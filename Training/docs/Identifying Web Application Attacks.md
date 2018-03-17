# Identifying Web Application Attacks

The majority of web applications involve a client that makes requests, a
server that processes the requests, and a database that stores
information.  Clients are typically browsers running JavaScript with various plugins such as Flash and Silverlight. Typical servers run Apache or IIS with programming languages like PHP, Python, Django, and ASP using databases such as MySQL, Oracle, SQL Server, and PostgreSQL for storage.

The examples reviewed here involve a client using a browser to interface
with Apache and IIS over HTTP---but the same principles apply no matter
what applications, databases, or protocols are involved.


## HTTP Review

In HTTP, a client communicates to a server using requests.  GET requests
ask for content from the server, POST requests send content to the
server.  

Certain data that needs to be exchanged between the client and server is
carried back and forth using parameters.  Parameters are found in the
URL for GET requests and in the body for POST requests.  Also requests
have headers that contain additional data needed for the applications to
communicate with each other such as content type, content length,
user-agent, etc. 

HTTP is a stateless protocol and the server needs something to associate
requests that are from the same user.  This is called session tracking
and is usually accomplished by the server passing a session token to the
client which it uses to identify itself. 

Three common methods are:

|||
|-|-|
|Cookies|These are sent in the HTTP header for the browser to store, mark as secure, and send back with every request to identify its session|
|URI parameters|This is sent in the URL such as 'sessionid-12345'|
|Hidden form fields|These are pre-populated, hidden form fields sent to the browser to be passed to the server with the next request|

Most attacks on web applications consist of the application being
tricked into treating data as code.  If data provided to the server by
the client is not filtered and/or encoded properly, an attacker can
submit code instead of data that will end up being executed by the
application.

Others, like path traversal, involve a user doing things that a normal
user is not expected to do such as requesting files that are outside the
web root and not meant to be shared.

Here are some common web application attacks and examples of each:

- [Path Traversal](#path-traversal)
- [Local File Inclusion](#local-file-inclusion)
- [Remote File Inclusion](#remote-file-inclusion)
- [OS Command Injection](#os-command-injection)
- [SQL Injection](#sql-injection)
- [Cross-Site Scripting](#cross-site-scripting)

## Path Traversal

Path traversal is when a client is able to successfully request files on
the server that aren't meant to be shared.  This can be used to read or
modify sensitive and critical files as well as execute code.

Here is an example of one of a scanner attempting to read sensitive
files on a target server:

![](images/Identifying%20Web%20Application%20Attacks/image001.png)


## Local File Inclusion

Another way to view a server's sensitive files is to modify a parameter
in order to trick the web application into retrieving and rendering
files locally. 

Local File Inclusion (LFI) can be used to view configuration files in the web root that may
contain sensitive data or combined with path traversal to view files
outside of the web root.  This method can also be used to execute code on the server by modifying
the parameter to point to a file that contains code.

The example below is assigning well-known world-readable system files to
various parameters in an attempt to read them.  Notice the "%00" included after some of the filenames.  This is a null
string used to defeat the application's attempt to filter by filename
suffix.               

![](images/Identifying%20Web%20Application%20Attacks/image002.png)


## Remote File Inclusion

A web application can also be tricked into retrieving and rendering
files hosted on a remote server. Remote File Inclusion (RFI) is when the parameter points to a remote resource instead of a local file on the
server.
                                         

This allows the attacker to force the server to load a page from a
malicious server which can be used to execute arbitrary code under the
privileges of the web application.

Below shows what it looks like when a remote resource is assigned to a
request parameter:

![](images/Identifying%20Web%20Application%20Attacks/image003.png)


## OS Command Injection

Command injection consists of an attacker injecting and executing OS
commands on the web server using the web interface.  When the web
application does not perform input validation on data supplied by the
client, it can be used as an HTTP parameter which gets passed as an
argument for an OS command.

This can be used against any application that passes shell commands to
the OS improperly.  Here is an example of a scanner testing a
server for the Shellshock Vulnerability CVE-2014-6271 which allows an
attacker to pass shell commands (`echo` in this case) to the victim OS via
headers in a GET request:

![](images/Identifying%20Web%20Application%20Attacks/image004.png)


## SQL Injection

SQL Injection (SQLI) is most commonly due to a lack of sanitized user input in
HTML forms.  When this happens, a user can dynamically affect the SQL statements
being passed on to database and can possibly read, create, modify, and
delete the data stored there.  Common uses are to bypass authentication, enumerate and dump a database,
and to execute code on the victim server.

A variation called "Blind SQLI" refers to the attacker not being able to
see the direct results of the SQL queries.  In this situation, the attacker may force the server to perform
sleep/wait functions, pings, HTTP requests, or DNS queries to confirm
the success of his SQL queries.

Below is an example of a client injecting SQL commands into web requests
in an attempt to extract data from the backend database:

![](images/Identifying%20Web%20Application%20Attacks/image005.png)


## Cross-Site Scripting

Cross-Site Scripting (XSS) takes advantage of servers not encoding data properly and
injects arbitrary HTML and JavaScript in order to run a payload in the
user's browser.  It can be used to steal a user's cookie and session info, bypass
authentication, or redirect a user's browser to a malicious page. 

Examples include creating a fake login form, creating code that sends
cookies to the attacker, injecting a browser exploit, or forcing the
browser to perform some other action within the web application.
     

There are 3 general categories:

|||
|-|-|
|Reflected|An application that echos user input is given the payload which is echoed back in a response and executed|
|Stored|The code is stored in the backend of an application so that the payload is executed on each visit|
|DOM based|An application that generates page elements based on user input is given the payload which is executed dynamically when a browser renders the page|

Here is an example where a scanner is attempting to execute JavaScript on a remote server:

![](images/Identifying%20Web%20Application%20Attacks/image006.png)
