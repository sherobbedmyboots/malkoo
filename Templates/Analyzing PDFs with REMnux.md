# Analyzing PDFs with REMnux
 
Here is a walkthrough showing how the REMnux VM can be used to
investigate a malicious PDF detected on one of our systems. 
 
In this example, a malicious PDF named "InfosecCheatSheet.pdf" was
received by a user in an email.  When Invincea prevented it from being
opened, the user downloaded it to their share drive to open it.  A few
days later during a weekly scan, AV alerted and flagged the file as
possible malware.  The file is located on the OOB at:
 
                InfosecCheatSheet.pdf
 
## Malicious PDFs
 
PDFs have a wide range of functionality that can be used by an attacker
to execute arbitrary code on the system after the PDF is opened:
 
- JavaScript
- Embedded documents
- ActionScript through embedded Flash objects and HTML-formatted
    content
- Multimedia, sound, movie
- Launching commands
- Connecting to a URI
 
The most common technique is using embedded JavaScript to execute
commands and drop malicious software on the victim system. 
 
## Basic Structure of a PDF
 
A PDF is composed of a header, a list of objects, a cross reference
table (xref), and a trailer:
 
|Structure|Description|
|-|-|
|Header|Identifies the file as a PDF|
|Objects|Contain the text, fonts, graphics, and dynamic components|
|Xref|Table with offsets of objects in the file|
|Trailer|Lists the number of objects and the offset of the xref table|
 
Streams are used to store large amounts of data and are decompressed
with filters when the document is opened.  Malicious JavaScript is
almost always compressed to prevent it from being visible to analysts
and detection tools.
 
## Basic Flow of Analysis
 
| | |
|-|-|
|1. [Review Structure and Contents](#review-structure-and-contents)|Locate malicious components such as embedded JavaScript|
|2. [Extract JavaScript](#extract-javascript)|Parse the file to find the JavaScript|
|3. [Deobfuscate JavaScript](#deobfuscate-javascript)|Reveal JavaScript code|
|4. [Extract Shellcode](#extract-shellcode)|Isolate the mechanics of the exploit|
|5. [Create Shellcode executable](#create-shellcode-executable)|Create a skeletal executable for analysis|
|6. [Analyze Executable](#analyze-executable)|Look at strings, examine with disassembler, step through with debugger|
 
 
### Review Structure and Contents
 
Use `pdf2txt` to show the text contained in the PDF document:
 
`pdf2txt.py InfosecCheatSheet.pdf`                            
 
Use `pdfimages` to list the images contained in the PDF document and show their
dimensions, size, and object numbers (4 and 8).  You can also write
them to JPEG files using the `-j` option:
 
`pdfimages -list InfosecCheatSheet.pdf`
 
 
Use `pdfinfo` to show PDF metadata such as the creator, date and time created,
producing application (in this case LibreOffice), file size, and PDF
version.
 
`pdfinfo InfosecCheatSheet.pdf`
 
 
Use `pdfwalker` to browse the structure of the PDF:
 
`pdfwalker InfosecCheatSheet.pdf`
 
 
Use `pdfid` to scan for keywords that indicate JS, deobfuscation, encryption, URIs:
 
`pdfid.py InfosecCheatSheet.pdf`
 
 
`pdfid` counts the number of risky keywords found such as:
 
|Keyword|Description|
|-|-|
|/JS, /JavaScript|use of JavaScript|
|/AA, /OpenAction, /Action, /Names|use of automatic actions to launch JS without user interaction|
|/AcroForm|use of Adobe forms|
|/JBIG2Decode|presence of compressed objects|
|/RichMedia|multimedia objects such as Flash|
|/ObjStm|object streams, can be used for obfuscation|
|/URI|access a resource by its URL|
|/Launch|runs a program or opens a document|
|/SubmitForm, /GoToR|send data to a URL|
|/Page|number of pages in the PDF document. Most malicious PDF document have only one page|
|/Encrypt|document has DRM or needs a password to be read|
|/XFA|is for XML Forms Architecture|
 
 
 
Running `pdfid` shows the document has 26 objects, 7 streams, 3 pages,
some JavaScript, and some automatic actions:
 
|Object|Count|
|-|-|
|/JS|1||
|/JavaScript|1|
|/AA|1|
|/OpenAction|2|
|/Launch|1|
 
               
 
So next we need to investigate the JavaScript.
 
### Extract JavaScript
 
JavaScript can be used to interact with dynamic elements, browser
plug-ins, in SWFs, PDFs, and packet captures.  JavaScript in PDFs  is
often compressed to hide its functionality from analysts and tools. 
When examining a PDF, you need to extract data from objects, then
decompress or decode for further analysis.
 
Here are some ways it is hidden, obfuscated, and made to prevent
detection and analysis:
 
- Compression and encoding with multiple algorithms
 
- JavaScript that is split across multiple objects
 
- Objects out of order with many references
 
- PDF files referring to each other or embedded within other PDF files
 
- Objects with multiple versions in a single PDF document
 
 
 
Use `pdfextract` to extract JavaScript, streams, attachments, embedded files and images from a PDF.
 
This command extracts all JavaScript:
 
`pdfextract --js InfosecCheatSheet.pdf`
 
 
 
 
 
Use `pdf-parser` to parse and display the components that make up the PDF:
 
`pdf-parser.py \<options\> InfosecCheatSheet.pdf`
 
Options:
 
|Option|Description|
|-|-|
|--stats|displays statistics of the objects found in the PDF document|
|--search|looks for a string in indirect objects|
|--filter|applies the filter(s) to the stream|
|--raw|makes pdf-parser output raw data|
|--object|outputs the data of the indirect object which ID was specified|
|--reference|allows you to select all objects referencing the specified indirect object|
|--type|select all objects of a given type|
 
 
 
We discovered earlier that the document contains JavaScript:
 
Typing `pdf-parser.py --search JavaScript InfosecCheatSheet.pdf`
shows the object that contains JavaScript.
 
There is not much JavaScript to extract, but we need to find out what it
is launching.
 
And we know that there are /Action objects in the PDF.
 
Typing `pdf-parser.py --type /Action InfosecCheatSheet.pdf` shows the
objects that are automated action types (23 and 24).
 
To look at just one object use the `--object` option:
 
Typing `pdf-parser.py --object 24 InfosecCheatSheet.pdf` shows object
24.
 
Object 24 contains cmd.exe which is always interesting.  To see what
objects reference object 24:
 
Typing `pdf-parser.py --reference 24 InfosecCheatSheet.pdf` shows
object 1 references object 24.  It also references objects 9, 16, and 2.
 
To see objects 9, 16, and 2, use the object option again:
 
Type `pdf-parser.py --object 9 InfosecCheatSheet.pdf`
 
Type `pdf-parser.py --object 16 InfosecCheatSheet.pdf`
 
Type `pdf-parser.py --object 2 InfosecCheatSheet.pdf`
 
Performing more `--object`  and `--reference` commands on the remaining
/Action type objects will allow you to determine which objects reference
each other, and the order in which they execute and/or call each other. 
For example:
 
Object 23 is an /Action type object that contains JavaScript and is
referenced by Object 17
 
Object 17 launches Object 23 via /OpenAction
 
Object 17 also launches Object 19 via /Names
 
Object 19 references 20, which references 21 via /Names, which
references 22, which contains a stream
 
The stream in Object 22 requires further investigation using the
`--filter` option.
 
                               
 
### Deobfuscate JavaScript
 
Typing `pdf-parser.py --object 22 InfosecCheatSheet.pdf --filter`
will show the object in uncompressed form.
 
This could have been more JavaScript that would require further
deobfuscation, but looking at the stream now that it's uncompressed
shows it is a binary file starting with the letters "MZ".  Further down
you can read that the program cannot be run in DOS mode.  This is an
executable that can provide a wealth of information about the attack and
how it works.
 
You can use `pdfextract -s InfosecCheatSheet.pdf` to extract all the
streams that were found in the document, but object 22 is not in the
group of objects that gets extracted.
 
Another option is to use `peepdf` to extract data:
 
`peepdf -i InfosecCheatSheet.pdf`
 
This will drop you into a prompt where you can dump object 22 to a
file by typing `object 22 > 22.txt`
 
Exit the interactive session, check the contents of the file with
`head 22.txt` and you'll see the "MZ" indicating we've extracted the
object we want.
 
Running strings on the file with `strings 22.txt` gives us some
indicators:
 
                192.168.2.110
                PAYLOAD:
                KERNEL32.dll
                wininet
 
To make an HTML report on the PDF document, you can use `pdfxray_lite`:
 
`pdfxray_lite.py -f InfosecCheatSheet.pdf --r REPORT`
 
Once the report is generated, use `firefox <name-of-report>` to
view.
 
### Extract Shellcode
 
Typically you'll find shellcode in JavaScript as a Unicode-encoded
string which is translated into binary content with the unescape
function.  The Unicode-encoded shellcode would then need to be
converted to binary to analyze it.  In this case, we have found a
binary executable in an object and just need to extract it from the
object for analysis.
 
### Create Shellcode Executable
 
In this example, we do not need to create an executable from shellcode.
 
### Analyze Executable
 
Drop back into the PPDF prompt by typing   `peepdf -i
InfosecCheatSheet.pdf` and run the following commands:
 
```
rawstream 22 > 22.out
decode file 22.out fl > decoded.out
exit
```
 
Now check the file properties of the decoded file by running `file
decoded.out` and you should see the following:
 
```
decoded.out:    PE32+ executable (GUI) x86-64, for MS Windows
```
 
You can now get the executable's hash, scan it with AV, or perform
dynamic analysis on a Windows box to see how it behaves.
 
In Part Two, we'll look at a malicious PDF that uses heavily obfuscated
JavaScript to deliver shellcode and will require more work for
performing steps 4 through 6.