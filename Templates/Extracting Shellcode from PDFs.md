# Extracting Shellcode from PDFs
 
This time we’ll look at a malicious PDF that uses heavily obfuscated JavaScript to deliver shellcode.  In this example, a user opened a PDF named “Free-Money-Seminar.pdf” which resulted in network connections to an unknown host.  The user explained he clicked on a link which opened a worthless coupon which he then closed and deleted.  So far, no suspicious activity has been observed when opening the PDF with the same version of Adobe Reader and several other different PDF readers.  The document is located on the OOB at:

Interactive behavior analysis provides great insight into the characteristics and functionality of malware.  But what if we are unable to replicate the attack on our analysis machine?   Submitting the PDF for automated analysis (Hybrid, Malwr, etc.) might give us a quick assessment on what the malware may attempt to do on a generic system but may not provide enough details.  Static analysis could result in a few indicators but may not reveal how the malware operates or other indicators that only become available when it runs in memory.  In this case, manual code analysis will allow us to extract key artifacts and help determine what happened on the victim machine.

Basic Flow of PDF Analysis
 
1.       Review Structure and Contents                         Locate malicious components such as embedded JavaScript
2.       Extract JavaScript                                                     Parse the file to find the JavaScript
3.       Deobfuscate JavaScript                                         Reveal JavaScript code
4.       Extract Shellcode                                                     Isolate the mechanics of the exploit
5.       Create Shellcode executable                              Create a skeletal executable for analysis
6.       Analyze Shellcode executable                            Look at strings, examine with disassembler, step through with debugger
 
 
So first we’ll examine the PDF and search for JavaScript:
 
 
1.       Review Structure and Contents
 
 
pdfimages                                  Lists images inside file
 
Usage:                                          pdfimages -list Free-Money-Seminar.pdf
 
 
This shows there aren’t any images in the PDF.
 
 
 
pdfinfo                                         Scans for set of words and counts the occurrences in the document
 
Usage:                                          pdfinfo Free-Money-Seminar.pdf
 
 
Not much PDF metadata is shown—just the number of pages (2), the size (13.6 KB), and the version (1.5).
 
 
 
pdfwalker                                   GUI that allows you browse the structure of the PDF
 
Usage:                                          pdfwalker Free-Money-Seminar.pdf
 
 
By looking at the PDF’s structure, you can see JavaScript code within a stream object.
 
 
pdfid                                             Scans for keywords that indicate JS, deobfuscation, encryption, URIs
 
Usage:                                          pdfid.py Free-Money-Seminar.pdf
 
 
This confirms the PDF contains some interesting keywords:
 
/OpenAction                                                      use of automatic actions to launch JS without user interaction
/AcroForm                                                          use of Adobe forms
/JBIG2Decode                                                   presence of compressed objects
/ObjStm                                                               object streams, can be used for obfuscation
 
            
So next we need to investigate the JavaScript.
 
 
 
2.       Extract JavaScript
 
 
You can do a quick extraction of all JavaScript with pdfextract:
 
pdfextract                                   Extracts various data out of PDFs
 
Usage                                           pdfextract -j Free-Money-Seminar.pdf
 
 
This will extract the JavaScript in the document but it can also do streams, attachments, embedded files and images.
 
You can navigate to and inspect the stream that was extracted by typing cd Free-Money-Seminar.dump/scripts && cat script*
 
Now we can see the stream extracted from object 6 contains obfuscated Javascript.
 
                               
 
3.       Deobfuscate JavaScript
 
 
There are several ways to deobfuscate javascript including command line tools Spidermonkey, d8, firebug, rhino-debugger… but for this example let’s use JSUNPACK at http://jsunpack.jeek.org.
 
Copy the contents of the script you extracted and paste it into the window of the main page for JSUNPACK to decode.
 
JSUNPACK should find several instances of shell code which we want to extract and analyze.
 
 
 
4.       Extract Shellcode
 
 
A large part of the shell code discovered is near the top of the script file, as a Unicode-encoded string inside the variable named nBAYwWIelJZqYVjaloH.
 
Copy the contents of this string (without the quotation marks) by selecting all à right-click à copy.
 
Open a new file by typing nano free.uni and paste the copied string into the file.
 
Save with Ctrl + O and then exit by typing Ctrl + X.
 
You now have the Unicode-encoded shellcode inside the file free.uni.
 
 
 
5.       Create Shellcode Executable
 
 
To analyze this shellcode as we would an executable, we can use the following commands to convert it into a properly formatted executable.
 
First we need to convert the shell code into hex format:
 
Execute the command:    unicode2hex-escaped < free.uni > free.hex
 
Then, convert the hex into an executable by typing  shellcode2exe.py –s free.hex
 
That creates an executable named “free.exe”
 
 
 
6.       Analyze Shellcode Executable
 
 
Now you can analyze the shellcode as you would any other Windows PE (run strings, PEStudio, etc.), examine with disassembler, or step through with debugger.
 
This will also run on your Windows 10 Analysis VM allowing you to do interactive analysis if you run it from the command line like this:  C:\>.\free.exe
 
 
 
 
Questions
 
1.       Now that it runs, what IP and port does the shellcode contact?
 
2.       What file does it try to download?
 
3.       How could you confirm the file that the shellcode tries to download?
 
4.       What signs would you look for in other systems to determine if they were compromised with this specific implant?
 
 
 
 
 
 
 
 
 
 

 
 
 
 
 
 
 
