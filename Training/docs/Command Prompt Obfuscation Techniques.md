# Command Prompt Obfuscation Techniques

Command Prompt is a command line interface program found on modern Windows operating systems.  This document will review common obfuscation techniques used by malware when utilizing the Command Prompt program to execute code on victim systems. 

- [Junk Code](#junk-code)
- [Environment Variables](#environment-variables)
- [For Loop Encoding](#for-loop-encoding)
- [Reverse Encoding](#reverse-encoding)
- [Character Substitution](#character-substitution)
- [Combining Techniques](#combining-techniques)

This is just a collection of basic examples---for a full examination of the creation, use, and detection of these techniques, see this [FireEye blog post](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html) and [associated whitepaper](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf).


## Junk Code

Escape characters such as `^` can be used to obscure strings tools use for detection such as `powershell` or `whoami`:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image006.png)<br><br>

The same thing can be accomplished using double quotes (`"`):

![](images/Command%20Prompt%20Obfuscation%20Techniques/image007.png)<br><br>

Parenthesis can also be added without changing functionality:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image008.png)<br><br>

Commas and semicolons can be added as well:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image009.png)<br><br>

## Environment Variables

Environment variables are also leveraged to avoid using specific strings.  See all environment variables with the `set` command:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image001.png)<br><br>

Individual characters from one of these variables can be used to obfuscate commands, in this case `whoami`:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image002.png)<br><br>

Malware can also define its own variables to do this same thing:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image003.png)<br><br>

In both examples, the `whoami` command is executed without using the string `whoami`.

Using just what we've seen so far, it is possible to significantly obfuscate a simple command like `whoami /priv`:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image010.png)<br><br>

## For Loop Encoding

Words present in variables can also be retrieved using a for loop.  Here, the string `powershell` is present in the output of the command `set | findstr PSM` and is used to start PowerShell without using the string `powershell`:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image004.png)<br><br>

Splitting the output by instances of the `s` and `\` characters leaves two instances of the string `powershell` that can be interpreted by cmd.exe:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image005.PNG)<br><br>


The following For loop builds the `whoami /priv` string from letters in the `u` variable:

```
cmd /V:ON /C "set u=/miavhrowp && FOR %A IN (8 5 7 3 1 2 10 0 9 6 2 4 13) DO set f=!f!!u:~%A,1!&& IF %A==13 CALL %f:~-12%"
```

![](images/Command%20Prompt%20Obfuscation%20Techniques/image011.png)<br><br>

## Reverse Encoding

The following For loop builds the `whoami /priv` command from letters in the `u` variable in which the command is in reverse order:

```
cmd /V:ON /C "set r=virp/ imaohw&& FOR /L %A IN (11 -1 0) DO set f=!f!!r:~%A,1!&&IF %A==0 CALL %f:~-12%"
```

![](images/Command%20Prompt%20Obfuscation%20Techniques/image012.png)<br><br>

This can be obfuscated even more with a For loop that only uses every 3rd character in the `u` variable:

```
cmd /V:ON /C "set r=v64iCsr99pBv/kA 7 iWwmTpaF8oJ2h6Hw&& FOR /L %A IN (33 -3 0) DO set f=!f!!r:~%A,1!&&IF %A==0 CALL %f:~-12%"
```
![](images/Command%20Prompt%20Obfuscation%20Techniques/image013.png)<br><br>

## Character Substitution

Individual characters can be substituted after variables have been defined to completely obfuscate a command.

First a variable is set to a string which will be modified shortly after.  The first string uses `X` instead of `i` and the following command replaces the `X`'s with `i`'s so the command successfully runs:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image014.png)<br><br>

This can be used in layers, each one replacing a different character in the string:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image015.png)<br><br>

Here is a command that replaces all characters in the `c` variable to create the string `whoami /priv`:

```
cmd /V:ON /C "set c=YeZQjX bTCX# && set d=!c:X=i! && set e=!d:Z=o! && set f=!e:j=m! && set g=!f:Y=w! && set h=!g:T=p! && set k=!h:Q=a! && set l=!k:b=/! && set m=!l:C=r! && set n=!m:#=v! && CALL !n:e=h!"
```

![](images/Command%20Prompt%20Obfuscation%20Techniques/image016.png)<br><br>

## Combining Techniques

Experiment with different combinations of [junk code](#junk-code), [environment variables](#environment-variables), [For loop encoding](#for-loop-encoding), [reverse encoding](#reverse-encoding), and [character substitution](#character-substitution) to get good at reversing them.

Here is a command that uses several of these techniques:

```
cmd /V:ON /C ";,;,;,;,;,,,,,s^e^t t^l^l^l^l^L^L=^p&& set h=!tllllLL:p=v!&&,;;,,,        ;;,,,C^A^L^L """"!COmSpeC:~3,1!^h"!CoMMOnPRogRaMFiles:~5,1!""""""""!programdata:~8,1!"^m""^i^"""" "/!alLUsersprOfILe:~3,1!!alluSErSprOfile:~4,1!!PrOgrAmfILes:~12,1!!h!"
```

![](images/Command%20Prompt%20Obfuscation%20Techniques/image020.png)<br><br>

## Deobfuscation Example

Here is an example of how to break down obfuscated commands to basic components so you can begin deobfuscation and anaylsis.  This obfuscated command was taken from a recent sample:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image033.png)<br><br>

Paste the obfuscated code to a text editor such as Sublime Text 3:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image034.png)<br><br>

Organize the deobfuscated blob into individual commands and arguments so you can see what's going on.  If using Sublime, save as a `.cmd` file to apply correct formatting:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image035.png)<br><br>

Use Sublime's WordWrap function to format very long strings:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image036.png)<br><br>

Now that we can see that the blob is being used to write a .bat file on the system, we can set some of the same variables to see what the contents of the .bat file would be.

First, open `cmd.exe` and set the variable that's being used as an alphabet key:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image037.png)<br><br>

When trying to do this same thing with the next variable, it doesn't completely interpret the variable encoding, but does remove the carots (`^`) that were present:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image018.png)<br><br>

Just copy and paste this output and echo it again to see the actual command:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image019.png)<br><br>

Another option is using PowerShell which is great for manipulating strings. 

First save the encoded payload to a variable:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image038.png)<br><br>

Then replace the carots (`^`) with nothing:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image039.png)<br><br>

Copy this output and paste in `cmd`:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image040.png)<br><br>

Do the same thing with the second blob:

![](images/Command%20Prompt%20Obfuscation%20Techniques/image041.png)<br><br>

At the end of the `.bat` file the first variable (payload) gets piped to the second variable (call to powershell):

![](images/Command%20Prompt%20Obfuscation%20Techniques/image042.png)<br><br>
