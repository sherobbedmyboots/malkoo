# Bits Bytes and Encoding
 
This is a quick review on bits and bytes, the way they are used to
interface with computers, and the need for encoding.  Many security
issues stem from the fact that bytes can represent either code or data. 
The failure of an OS or application to handle each in the proper way can
result in compromise.  Also, a good analyst must be able to interpret
bytes correctly when analyzing packet captures, malicious programs, and
shellcode in order to accurately explain what happened on a system or
the network. 
 
- [Bits and Bytes](#bits-and-bytes)
- [Binary Octal Decimal and Hex](#binary-octal-decimal-and-hex)
- [Computer Architecture](#computer-architecture)
- [Programs](#programs)
- [Encoding](#encoding)
- [Summary](#summary)
 
## Bits and Bytes
 
Code (computer processing instructions) and data (text, images) are
meant to be handled differently, but often look similar when in binary
form.  This is because they are both represented by bits.
 
A bit, or binary digit, is the smallest unit of storage.  It only has
two states:  1 or 0
 
Computers store and process these bits using voltage and magnetism in
order to perform tasks.
 
When voltage is used, the presence of a voltage is expressed as the 1
(aka ON) and the absence of voltage is expressed as a 0 (aka OFF).  The
same goes when magnetism is used... magnetized is 1 and demagnetized is
0.
 
Vacuum tubes, transistors, and now integrated circuits (chips) have all
been used in computing and digital communications to control voltages in
order to store and process information.  Just like a song is "stored" in
the grooves of a record and retrieved when the record is played, a
computer stores information using voltages. 
 
Magnetism is used to store information permanently.  A hard drive stores
bits using magnetism which persists even when the power is switched off.
 
Since one bit is too small to be useful, 8 together were named as a
"byte" so that different combinations could represent different things.
 
One byte can have 256 unique values.     
 
`11111111` is the number `255`.   
 
`00000001` is the number `1`.
 
## Binary Octal Decimal and Hex
 
Binary numbers are more easily expressed in Octal, Decimal, and Hex.
 
Binary is based on two numbers (base 2), Octal is based on 8, Hex on
16...
 
As an example, let's convert a byte to all three:
 
Imagine we have one byte.  It's made up of 8 bits that can be either on
or off (1 or 0). 
 
There are 255 possible numbers we can make but we set this one equal to
the number 65:
 
`01000001` -->  This the number `65` expressed in binary
 
We can convert this byte into its binary, octal, or hex form if we need
to by changing the base (2, 8, or 16):
 
![](images/Bits%20Bytes%20and%20Encoding/image001.png)
 
 
So we have the same value (the number 65) expressed in 4 different ways:
 
|Binary|Octal|Decimal|Hex|
|-|-|-|-|
|01000001|101|65|41|                      
 
 
## Computer Architecture
 
There are two main parts to a computer: 
 
- Central Processing Unit (CPU)
- Memory
 
### CPU
 
CPUs read in bytes which they store and process in memory.  The type
of CPU determines how memory is addressed and modified. 
 
For example, a 16-bit processor can only use 16-bit addresses and
accept 16-bit commands.  Likewise, a 64-bit processor uses 64-bit
addresses and commands.
 
For this reason, bytes were strung together to make "words" which are
made up of the number of bits that are manipulated as a unit by a
specific CPU. 
 
- 16-bit processors use 2-byte words, called a word (WORD)
- 32-bit processors use 4-byte word, called a double word (DWORD)
- 64-bit processors use 8-byte words, called a quad word (QWORD)
 
Instructions are fed to the CPU in words which tell it to access,
manipulate, and move data in memory.
 
### Memory
 
Memory is a numbered sequence of fixed-size storage locations.
Each location has an address and the size of each location is called a
byte. 
 
A single value can be stored in each location (0-255). 
The CPU stores programs and their data with these values.
 
## Programs
 
Programs are collections of instructions for the CPU that allow the computer to perform a number of different tasks.  The first computers were programmed using 1's and 0's, also called binary data or machine code.
 
### Machine Language
 
This is a stream of binary data, 1's and 0's---raw bytes being fed to a computer.
 
It is the only language a computer can process directly, but humans find
it easier to express it in Hex:
 
`\xFF \xE4` instead of `11111111 11100100`
 
These are hex characters representing bytes:
 
![](images/Bits%20Bytes%20and%20Encoding/image002.png)
 
 
 
### Assembly Language
              
Assembly is the lowest level of programming language.  It is used to
directly manipulate the processor registers.
 
Machine language is represented as human-readable processor instructions
which are easier to memorize
 
`JMP ESP` instead of `\xFF \xE4`
 
An assembler maps these instructions to machine code to be fed to the
CPU.
 
 
Each line is an instruction made up of an operation code (opcode) and
one or two arguments (operands):
 
![](images/Bits%20Bytes%20and%20Encoding/image003.png)
 
                                
### High-Level Languages
 
These languages are more intuitive and make programming easier by
describing a program in a more natural language: 
 
They also make programs more portable.  Variables, arrays, objects,
functions, and loops are used to express machine code.
 
Examples are C, C++, Python, and Ruby
 
![](images/Bits%20Bytes%20and%20Encoding/image004.png)
 
 
High-Level languages must be translated into binary code before CPU can execute them using either a compiler or an interpreter.
 
| | |
|-|-|
|Compiler|Scans entire program and creates program executable (takes easy-to-read code and crunches it into assembly)|
||Runs through entire program then generates error|
||Used by C, C++|
|Interpreter|Translates instruction by instruction|
||Stops when first error is met|
||Used by Python, Ruby|
 
## Encoding
 
In order to feed programs to a computer that only understands 1's and
0's, it's necessary to map each human-readable command to bytes using
assemblers, compilers, and interpreters.
 
In the same way, for computers to store and transfer information for
writing systems (letters, numbers, symbols), it was necessary to map
each of these characters to bytes.
 
### ASCII
 
Similar to how Morse code used only dots and dashes to represent English
characters, ASCII uses the 1's and 0's in a byte.
 
This introduces yet another way to express a byte:
 
|Binary|Octal|Decimal|Hex|ASCII|
|-|-|-|-|-|
|01000001|101|65|41|A|
|01000010|102|66|42|B|
|01000011|103|67|43|C|
|01000100|104|68|44|D|
|01000101|105|69|45|E|
 
 
Using  ASCII, all unaccented English letters could be represented using
the lower 7 bits (0-127) of a byte.
 
65 translated to the letter A, 32 translated to a space, etc...
 
0-31 were translated to control characters like beep (7), tab (9), and
newline (10,13).
 
Since the lower 7 bits only allowed 128 combinations, other character
sets like Arabic, Chinese, Japanese, etc. could not be represented.
 
To work around this, the upper-most bit (used for upper-128 values
128-255) was used for custom characters for different languages and
purposes using code pages.
 
### Unicode
 
Unicode was invented to encompass all possible characters and introduced
the use of code points.  In order to be backward compatible with ASCII,
it assigned English characters special code points---for instance code
point U+0041 is the letter A.
 
UTF-16 stores every character as two bytes.  65,535 different code
points which covers most of the common languages.  But, this resulted in
many zeros for plain ASCII text that doesn't use the high-order byte.
 
UTF-8 encoding was created so that the lower 128 would be stored in only
one byte, and only 128 and above stored in multiple bytes.  This makes
English text look exactly the same in UTF-8 as in ASCII
 
ASCII and Unicode encoding are great for viewing binary data, but not
for transferring it.  The binary numbers they use also happen to be
common control characters for many other protocols.  Because of this,
these numbers frequently get incorrectly interpreted as code.
 
For example, SMTP is a purely ASCII text-based protocol.  All commands
and message contents are transferred in ASCII format.  When this
protocol sees binary data, it interprets it as code instead of data. 
Early on, this prevented emails from carrying binary files such as
images, executables, audio, and videos.
 
Multipurpose Internet Mail Extensions (MIME) was created to solve this
problem by encoding binary files into files that use safe characters. 
Once the files were transferred, they were converted back to the
original binary data.
 
Base64 is a common way to accomplish this.
 
### Base64
 
Base64 encodes arbitrary bytes into ASCII so that they can only be
interpreted as text and are free of special characters and/or control
characters.
 
The bytes for the 64 characters (A-B, a-z, 0-9, +, /) are rarely used
for special combinations and control characters and are very common
ensuring the data can be correctly decoded at its destination.
 
Base64 is also used by many other applications for avoiding delimiter
collisions.
 
### URL Encoding
 
Also called "percent encoding", this is another example of applications
that have problems with non-alphanumeric characters.  Special characters
must be encoded before they are included in a URL so a space becomes
"%20" or "+" and the "&" character becomes "%26", etc...
 
A great tool for encoding and decoding as well as many other conversion
tasks is [CyberChef](https://gchq.github.io/CyberChef/). 
 
Type your string in the Input, drag an operation on the left to the
"Recipe" area, and you'll see the result of the operation in the Output:
 
You can also stack recipes in the order you want them to execute.  By
adding on Extract URLs, it pulls out all the URLs after it decodes it:
 
## Summary
 
Computers only understand 1's and 0's... they read instructions in
bytes, which are made up of bits, and are grouped together to make
words.
 
These bytes can represent code or data---analysts must know which one in
order to interpret the bytes correctly.                                     
 
### Code
 
The first programs were written in series of 1\'s and 0\'s.  It was
easier for humans to express this machine code in octal, and even easier
in hex.
 
`\xFF \xE4` instead of `11111111 11100100`
 
Assembly is the lowest level of programming and is used to directly
manipulate the processor registers.  It maps human-readable instructions
to machine code. 
 
`JMP ESP` instead of `\xFF \xE4`               
 
Higher level languages are used to write more complex programs and
require a compiler or interpreter to convert to machine code.
 
### Data
 
Encoding transforms information (such as the letter A) into raw data
(bytes).  Characters need to be encoded when they are stored and
transferred.
 
ASCII used 0-255 to display characters, but the international standard
is Unicode which can translate any character from any known writing
system in the world.
 
Base64, URL-encoding, etc. is used to encode data into safe characters
to prevent other applications and protocols from interpreting it
incorrectly.
 
### Interpreting Code and Data
 
The way bytes should be expressed depends on how they are intended to be
interpreted:
 
#### 1. Computers read binary data   (01000001)
 
> CPU's only understand 1's and 0's.  So all data is eventually converted to 1's and 0's for processing, storage, and transfer.
 
#### 2. Humans read and write characters   (A)
 
> Humans prefer to read and write words instead of 1's and 0's.  So all files and data are read and written using ASCII/Unicode characters.
 
#### 3. Humans express bytes in hex    (0x41)
 
> It's easier to look at packet bytes and shellcode in hex than in binary, octal, or decimal:
               
![](images/Bits%20Bytes%20and%20Encoding/image005.png)