# Debugging a Windows Program
 
 
Most malware authors write their malware in a high level language and compile it into machine code.  Malware analysts and reverse engineers use tools that convert this machine code into assembly, and use it to discover how the program operates.
 
An assembly-level debugger is one of these tools.  It can be used to completely control program execution and allows us to analyze malware while it’s running on a system. 
 
This document will cover:
 
- [Review of Programs](#review-of-programs)
- [Introduction to x64dbg](#introduction-to-x64dbg)
- [Programs in Memory](#programs-in-memory)
- [Stepping Through the Program](#stepping-through-the-program)
- [Using Breakpoints](#using-breakpoints)
- [Patching a Program](#patching-a-program)
 
 
 
## Review of Programs
 
There are three major components that are needed to write a simple program:
 
Variables                             Objects that hold data and that can be changed
Operators                           Used for arithmetic, comparison, and various string operations 
Functions                            Perform a specific action (with or without an argument) that may be needed multiple times in a program
 
 
Here is a simple program written in C containing each of these:
 
![](./images/Debugging%20a%20Windows%20Program/image001.png)
 
 
- There is a variable (MAX_LEN) that is defined as being equal to the number 20.
 
- There is a function (sayGo) that prints a message containing the variable it is passed.
 
- An operator (==) is used to compare the results of a function (strcmp) to the number 0.
 
 
It is easy to see what the program is capable of when looking at the source code, but the majority of malware is analyzed after it has already been compiled.
 
 
 
A compiler like GCC is used to convert the source code into an executable containing machine code which are low-level instructions for a CPU:
 
 
![](./images/Debugging%20a%20Windows%20Program/image002.png)
 
 
 
 
Once it’s compiled, the program does what it’s been programmed to do.
 
And although we can run it over and over, giving it different inputs, we may not be able to discover all of its functionality since we don’t understand how it was designed.
 
![](./images/Debugging%20a%20Windows%20Program/image003.png)
 
 
 
A malware analyst can use disassembly and debugging tools to translate the machine code into assembly code.
 
Seeing the exact instructions that are passed to the CPU helps explain what the program does and also shows us the functions it uses (printf, scanf, strcmp, sayGo):
 
 
![](./images/Debugging%20a%20Windows%20Program/image004.png)
 
 
 
Simply using a disassembler reveals the program has additional functionality.
 
We can now report the general flow of the program without having access to the source code.
 
![](./images/Debugging%20a%20Windows%20Program/image005.png)
 
 
We can learn even more about a program if we use an assembly-level debugger and watch as it executes in memory.
 
 
 
 
## Introduction to x64dbg Debugger
 
We will be using x64dbg, a user-mode debugger, to examine this program.  Debugging kernel-mode malware such as rootkits and device drivers requires a kernel debugger such as WinDbg.
 
X64dbg is used for 64 bit programs and x32dbg is used for 32 bit programs.
 
Both of these are also assembly-level debuggers used by malware analysts and reverse engineers to examine compiled malware.  Source-level debuggers are used by programmers to analyze source code.
 
 
 
When a program is loaded into memory, the CPU begins reading its instructions which tell it to access, manipulate, and move data in memory.
 
There are four major components involved as this happens:

|Component |Description | 
|-|-|
|Code                 |                                    Each instruction in the program is executed.  Some instructions manipulate data. Some instructions call functions from the libraries (DLLs) the program has loaded.| 
|Stack               |                                      This is a Last In First Out (LIFO) data structure the CPU uses to store temporary data values—A POP reads from the stack, a PUSH writes to the stack| 
|Registers/EFLAGS   |                         These are small areas of fast memory the CPU uses for logical operations and temporary storage during processing| 
|Memory of program |                      The memory locations allocated to a program which are constantly being read, written, or modified|

 
 
When a program is running, it is repeatedly fetching data from memory, storing it in registers, performing operations on the data, and saving back to memory over and over again.
 
 
 
Drag the GoTeam.exe file into the x64dbg shortcut on the desktop and the program will open in a paused state.
 
You should now see four windows:

| | | |
|-|-|-| 
|CPU  |                                     (top left)           |                   The debugger displays the assembly code with associated | commands
|Registers |                            (top right)             |              Shows values in the registry |
|Dump |                                   (bottom left)        |             Shows contents of memory |
|Stack  |                                   (bottom right)    |               Shows data on the stack |
 
 
### CPU
 
![](./images/Debugging%20a%20Windows%20Program/image006.png)
 
 
This shows the disassembled output of all instructions in the current module.
 
The first column is process memory address, the second is the machine code in hex, the third is their associated opcodes and operands, and the fourth is for additional information such as ASCII string values.
 
 
 
- Registers            
 
![](./images/Debugging%20a%20Windows%20Program/image007.png)
 
 
This shows the current values of all the registers and EFLAGS.
 
There are three types:
 
- General Purpose
- Segments
- Special Purpose
 
 
General Purpose              (32 bit registers begin with the letter “E” for extended)
                                                (64 bit registers begin with the letter “R”)
 
EAX                        Accumulator                                      holds result of multiplication or division operations
EBX                        Base                                                      holds
ECX                        Counter                                               holds number of times a loop should repeat
EDX                        Data                                                       holds
ESI                          Source Index                                     source of transfer operation
EDI                         Destination Index                            destination of transfer operation
 
Segments           
 
CS                           Code                                     Points to code
DS                           Data                                       Points to code  
SS                           Stack                                     Points to stack
ES                           Extra                                      Points to extra data
FS                           F segment                           Points to more extra data
GS                          G segment                          Points to more extra data
 
Special Purpose
 
EFLAGS
 
CF                           Carry                                     Set if arithmetic operation resulted in a carry
PF                           Parity                                    set if number of set bits in LSB is multiple of two
AF                           Adjust                                   set if carrying BCD numbers
ZF                           Zero                                       Set if result of an operation is zero
SF                           Sign                                        Set if result of an operation is negative
TF                           Trap                                      
DF                           Direction                             
OF                          Overflow                             Set if arithmetic operation results in value too large to contain
 
Pointers
 
EIP                          Instruction pointer          Points to address of next instruction to be executed
EBP                        Base Pointer                      used by functions to locate local variables
ESP                         Stack pointer                     points to the currently executing program’s stack
 
 
 
- Stack Pane                         
 
![](./images/Debugging%20a%20Windows%20Program/image008.png)
 
 
This shows the stack which is used to store local variables, pass arguments, store return addresses, etc.
                                                                       
Data is “pushed on” or “popped off” the stack:
 
push 5                   this adds value of 5 to the stack
 
Value on stack would be 00000005
 
 
Functions use the stack to store their parameters and local variables. 
 
When a function is called, the following happens:
 
- Parameters are pushed to the stack                push 1
push 2
push 3
push 4
 
- Function is called                                                      call <function-name>
 
- Stack frame initialized                                            push ebp                             (address in ebp pushed to the stack)
                                                                                                        mov ebp, esp                    (value of stack pointer moved to ebp)
                                                                                                        sub esp, 10                         (function needs 16 bytes for its local variables)
 
- Function completes                                               
 
- Return value                                                              mov eax, ebx
 
- Clean stack                                                                 mov esp, ebp
                                                                                                        pop ebp
 
- Return to caller function                                       ret
 
- Clean up parameters passed to function       add esp, 10
 
 
 
 
- Dump Pane       
 
![](./images/Debugging%20a%20Windows%20Program/image009.png)
 
 
This is the memory contents of the program displayed in hex and ASCII.
 
It can be used to view the contents of any valid memory location by selecting an address à Right click à Follow in dump
 
Memory is constantly being accessed and written to as the program executes instructions.
 
 
 
 
## Programs in Memory
 
 
When a Windows program executes, it is given a new process with its own PID and address space.
 
The process’s address space contains the executable, all its loaded libraries (DLLs), and blocks of memory for the program to use as it executes its code.
 
The blocks of memory are called segments:
 
                .text                      This is where the compiled, executable code is stored.  It is read-only because nothing needs to be written here and the program’s code shouldn’t be modified during runtime.
                                               
                .data                      This is where initialized variables are stored
 
                .bss                        This is where uninitialized variables are stored
 
                Heap                     This segment of memory is used for whatever the program needs
It is for storing dynamically allocated data and persists for life of the process
 
                Stack                     This is used to store temporary data needed for executing functions
The stack contains stack frames which are collections of all the passed variables, local variables, and return points for each function
The data here only persists for the scope of the function
 
 
You can view the layout of the segments in memory by clicking on the “Memory Map” tab at the top:
 
![](./images/Debugging%20a%20Windows%20Program/image010.png)
 
 
The black highlights where we currently are in the program… we are inside ntdll.dll’s .text segment which is where its executable code is stored.
 
Notice our program’s executable file has been mapped to address 0400000 (default for windows programs).  You can see the where the .text, .data, and .bss sections are mapped as well.
 
Further down you can see where each imported library has been mapped and addressed including kernelbase.dll, msvcrt.dll, kernel32.dll, and ntdll.dll.
 
Go back to the CPU screen.
 
 
 
 
In order for the program to execute its first instruction, we have a few options:
 
- Run the program by pressing  F9                                               This runs the program until a breakpoint is reached
- “Step into” it by pressing F7                                                        This executes a single instruction and pauses the program
- “Step over” the instruction by pressing F8                            This executes the next function and pauses
- Execute until return  Ctrl + F9                                                     This executes all instructions until a return and then pauses
- Execute until user code  Alt + F9                                                This executes until user code and then pauses
 
 
Notice at the top where it says “Module: ntdll.dll”.  This is the module we’re currently in, so if we start single-stepping through code we’d be looking at Microsoft’s code in their ntdll.dll DLL.
 
We want to look at the GoTeam.exe program’s code so we’ll use Alt + F9 to execute code until we get to “user” code.
 
Once you do that, you’ll see we’re now in the goteam.exe main thread.
 
 
 
 
## Stepping Through the Program
 
We’ll step through each of these one at a time with F7 and describe what is happening.
 
 
push rsi                                                                This is pushing the value of the RSI register (00000000) to the stack
 
                                                                                Watch the stack pane and press F7
 
                                                                                Notice the RSI register is red indicating it was just changed
 
 
push rbx                                                              This is pushing the value of the RBX register (00000001) to the stack
 
                                                                                Watch the stack pane and press F7
 
Notice the RBX register is red indicating it was just changed
 
 
sub rsp,28                                                           This is subtracting 0x28 from the value of the RSP register (0060F538)
 
                                                                                Watch the RSP register and press F7
 
                                                                                Notice the RSP register is red indicating it was just changed
 
 
mov rax,qword ptr ds:[4042F0]                  This is moving the value at address 4042F0 to the RAX register                   
 
 
Before we execute this instruction, examine the address by Right Click à Follow in Dump à Address: 4042F0
 
You will be taken to that memory address in the Dump pane.  Notice the value there is 50 30 40 00.
 
This is actually a memory address… 00403050.  It is stored this way because Intel uses “little endianness” which stores the least significant bits to the left.
 
Watch the RAX register as you press F7 and see that the value changes to an address in the goteam module… 00403050.
 
 
cmp dword ptr ds:[rax],2                              This compares the value at the address in RAX (00403050) to the number 2.
 
                What is at this address? 
 
Where is this address?
 
 
Let’s look in the memory map for the segment that contains address 00403050.
 
- is in the .data section which is initialized data.  Double click on the 00403000 row to go to this segment in the Dump pane.
 
A few rows down at the address you can see that a number 2 is in fact at this address:
 
![](./images/Debugging%20a%20Windows%20Program/image011.png)
 
 
So a comparison will take place, and the numbers will be the same… how does the program document this?
 
Press F7 to execute the instruction and watch the RFLAGS
 
 
Notice the following change:
 
ZF           Zero                       1                              Result of the operation was zero
PF           Parity                    1                              Bits set are a multiple of two
 
This is how the CPU keeps track of the results of the comparison operation.
 
The next instruction is a “Jump if Equal” (je) which the program will take since the values were equal.
 
 
je goteam.401A28                                           This will jump to the specified address if the values were equal
 
                                                                                Watch the RIP (instruction pointer) and press F7
 
                                                                                Notice the jump was made and the next instruction to be executed is the instruction at 401A28
 
 
cmp edx,2                                                           This compares the number 2 to the value in the EDX(lower half of RDX) register.
 
                                                                                Since the RDX register contains the number 1, this comparison will not be equal.
 
                                                                                Press F7 and watch the RFLAGS as they record the results
 
 
Notice the RFLAGS that are now set:
 
ZF           Zero                       0                              Result of the operation was zero
AF           Adjust                   1                              No carry over
SF           Sign                        1                              Result was negative
CF           Carry                     1                              Result included a carry
 
                                               
je goteam.401A40                                           This jump should not be taken since the values were not equal.
 
                                                                                Press F7 and watch the RIP simply move to the next instruction
 
cmp edx,1                                                           This compares 1 to the value of EDX (lower half of RDX).  This will evaluate as equal since 1 is in RDX.
 
je goteam.401A72                                           This jump will be taken since the two values compared were equal.
 
call goteam.4026F0                                          This is the first function call.  By pressing F7 we will step into the first instruction of this function.
 
                                                                                Watch the CPU windows and press F7
 
 
We are now inside function 4026F0.
 
Press F7 eight more times and you should be at an instruction that will call ntdll.RtlInitializeCriticalSection
 
 
This is a Microsoft function that is responsible for allocating memory for an object.
 
Press F7 again while watching the name of the current module.  Notice it changes from goteam.exe to ntdll.dll
 
 
We don’t want to step through this program line by line so we’ll back up one instruction with Alt+U and then step OVER it using F8.
 
Press Alt+U to go back one instruction
 
Press F8 to step over the RtlInitializeCriticalSection function
 
 
The next instruction is a jump to address 40278A.  Let’s take this jump by pressing F7.
 
 
mov dword ptr ds:[407988],1                      This will move the number 1 into the memory address 407988.
 
                                                                                Bring up this address in the Dump pane with Right Click à Follow in Dump à Address:  407988
 
                                                                                Notice there is a 00 at that address.
 
                                                                                Press F7 and watch the number 01 be written to this memory location
 
 
mov eax,1                                                           This will move the number 1 into the EAX (lower half of RAX) register.
 
                                                                                Watch the RAX register and press F7
 
add rsp,20                                                           This adds 0x20 to the stack (RSP register)
 
                                                                                Watch the stack window and press F7
 
pop rbx                                                                This pops the value at the top of the stack (00000001) and puts it in the RBX register
 
                                                                                Watch the stack and the RBX register and press F7
 
ret                                                                          This will return to where the function was called from
 
                                                                                Press F7
 
 
Press F7 a few more times and you’ll end up inside ntdll.dll again.  This is not the code we’re interested in, so press Alt+F9 to execute until user code.
 
Verify you are back in goteam.exe.  Press F7 a few more times and you’ll end up back in ntdll.dll again.  Press Alt+F9 to execute until user code.
 
Continue to press F7 until you come to the following functions:
 
![](./images/Debugging%20a%20Windows%20Program/image012.png)
 
A little research will reveal what these functions do:
 
                GetSystemTimeAsFileTime                                         Retrieves the current system date and time in UTC format
                GetCurrentProcessId                                                     Retrieves process ID of the current process
                GetCurrentThreadId                                                      Retrieves thread ID of the current process
                GetTickCount                                                                    Retrieves the number of milliseconds that have elapsed since the system was started
                QueryPerformanceCounter                                        Retrieves the current value of the performance counter, which is a high resolution timestamp
 
 
These are Microsoft functions and we’re not really interested in their code—but we do want to know why the goteam.exe program is calling them and what data it gets back from each function.
 
Since function results are typically stored in the EAX/RAX register, we can step OVER (run and return) each function and then look to see what value each function returned to the program.
 
After stepping over each function, here are the results that were in the RAX register after each completed:
 
 
                GetSystemTimeAsFileTime                         01D36D22
                GetCurrentProcessId                                     00000EFC
                GetCurrentThreadId                                      0000052C
                GetTickCount                                                    0100BAC7
                QueryPerformanceCounter                        00000001
 
 
The three time-related functions return results that appear to require conversion. 
 
But the GetCurrentProcessId and GetCurrentThreadId results can be quickly verified:
 
![](./images/Debugging%20a%20Windows%20Program/image013.png)
 
 
We’ve gathered some information but these are functions that many processes use.  There may be a dozen more of these functions that are called before the program begins to execute code we’re interested in.
 
So instead of stepping through each individual instruction from the beginning like we’ve been doing, a better way is to find interesting functions and then jump straight to them using breakpoints.
 
 
 
 
## Using Breakpoints
 
First let’s take a look at all the function calls detected by the debugger in the goteam.exe module.
 
Make sure you’re in the goteam.exe module, then Right Click à Search For à Current Module à Intermodular Calls
 
We see it calls scanf which is a function that gets input from the user.  Let’s set a breakpoint there by Right Click à Toggle Breakpoint  on that address
 
The address should now be highlighted in red:
 
![](./images/Debugging%20a%20Windows%20Program/image014.png)
 
 
Now hit the Restart button, the top left circular arrow that looks like a refresh button, and the program will be reloaded in the debugger and paused at the first instruction.
 
Press F9 to run the program in the debugger.
 
You will hit a breakpoint… At the bottom you should see a message explaining what breakpoint was hit and what type it was:
 
![](./images/Debugging%20a%20Windows%20Program/image015.png)
 
 
This is a TLS Callback.
 
 
TLS (Thread Local Storage) Callbacks are called by the OS before the application entry point and allows a programmer to define variables before the program begins executing its code.
 
While they can be used to run malicious code, these are legitimate so just press F9 to continue running the program when you hit them.
 
 
You should hit a second TLS callback.  Hit F9 again.
 
The next breakpoint should be the Entry Point of the program.  Hit F9 again.
 
 
 
 
This time the breakpoint we set was reached.  The next instruction to execute will be the call to the scanf function.
 
One interesting thing we can look for is the arguments that are passed to the function.  If a function requires arguments, they are placed on the stack just before the function call.
 
That means we can scroll up to the instruction just before the function call and see:
 
 
lea rcx,qword ptr ds:[40405A]
 
 
This “Load Effective Address” instruction puts the value at the address 40405A into the RCX register.
 
By looking at the RCX register we can see that value is “%s”. 
 
But let’s also look at where that value came from… Right Click à Follow in Dump à Address: 40405A
 
In the Dump pane, we see the “%s” along with other strings “saints” and “Who dat!”  Scroll up a little and you’ll see the string “Enter your favorite sports team:”
 
Notice what part of memory we are in here… if you look at the Memory Map again, you’ll see these values are in the .data segment (initialized data).
 
Seeing how each function uses the program’s data gives us a better understanding of how the program works.
 
 
                               
 
Scanf is a Microsoft function so when we step into it with F7, we will no longer be in our goteam.exe code.
 
Press F7 twice to step into msvcrt.dll, then Hit Alt+F9 to execute until user code.
 
 
Now notice the debugger says the program is running but nothing is happening.  Hit F9 again.  And again.
 
You can hit F9 as many times as you want, but the program has run all the instructions it can.  It is now waiting for input from the user in order to continue executing.
 
So open up the terminal window and type in some input:
 
 
![](./images/Debugging%20a%20Windows%20Program/image016.png)
 
 
Once you hit Enter, the program is paused on the instruction just after the call to scanf.
 
Notice the string you entered into the program is now on the stack.
 
Now slowly step through the following instructions:
 
 
lea rax,qword ptr ss:[rbp-20]                      This puts the value at address rbp-20 (your string) in the RAX register
                                                                               
Watch the RAX register and press F7
 
lea rdx,qword ptr ds:[40405D]                    This puts the value at address 40405D (“%s”) in the RDX register
                                                                               
Watch the RDX register and press F7
 
mov rcx,rax                                                        This moves the value in the RAX register (your string) to the RCX register
                                                                               
Watch the RAX and RCX registers and press F7
 
call goteam.strcmp                                          This will call the strcmp (string compare) function.  The two strings it is comparing are in RAX and RCX.
               
                                                                                Step over this function with F8 and check the result of the function in the RAX register
 
 
 
Notice the value returned is FFFFFFFFFFFFFFFF which means the strings were not the same.
 
Had the strings been the same, the function would have returned all zeros.
 
The next instruction tests to see what the results of the function were:
 
 
test eax,eax                                                       This tests to see if EAX (lower half of RAX) is zero
                                                                               
Press F7 and watch the RFLAGS
 
 
The next instruction will jump to an address based on the results set in the RFLAGS.  (No ZF because result was not zero)
 
 
jne goteam.40162B                                         This will jump to address 40162B because the two strings compared were not equal.
 
 
Let’s say we are really interested in what this program does when the string comparison is successful.  Now that you know what string is, you could go reload the program, go through all the breakpoints, and this time enter “saints” into the program.
 
That wouldn’t take long, but other scenarios might require much more work.  Imagine a complex password check, or a network setting check, or something else that could take a lot of time to work through or set up.
 
In these situations, we can make a change to the program in order to execute the code we are interested in, also known as “patching” the program.
 
 
 
 
## Patching a Program
 
Patching is changing an instruction in the program to force the program to execute the code we’re interested in.
 
Double click on the jne (Jump if Not Equal) instruction, and change the jne to a je (Jump if Equal).  This should make the program act as if we had entered “saints” and  not take the jump we were supposed to take.
 
 
![](./images/Debugging%20a%20Windows%20Program/image017.png)
 
 
 
Once you’ve made the change, press F7 to step into the next instruction.
 
 
Now we avoided making the jump to 40162B and the next instruction is:
 
lea rcx,qword ptr ds:[404064]                                     This moves the value at memory address 404064 into the RCX register
                                                                                               
                                                                                                Watch the RCX register and press F7
 
 
The string “Who dat!” was loaded into the RCX register.  The program is proceeding as if we had entered the correct string.
 
call goteam.printf                                                            This will call the printf function and pass it the string “Who dat!”
 
                                                                                                Press F8 to step over ( run and return) the printf function
 
 
Now bring up the goteam.exe console window and verify that the string was printed to the screen:
 
![](./images/Debugging%20a%20Windows%20Program/image018.png)
 
 
This technique is great for exploring areas of code and functionality that malware authors do not want analysts to see.
 
 
 
## Summary
 
With an assembly-level debugger, we can:
 
- Disassemble a program’s machine code
- Pause execution to examine stack and register content
- Set breakpoints for specific function calls and memory locations
- Patch executables on the fly to examine additional functionality              
 
Next time you are analyzing malware, try using a debugger to discover functionality its author has attempted to hide.
 
 