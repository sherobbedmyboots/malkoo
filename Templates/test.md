| | |
|-|-|
| .text|This is where the compiled, executable code is stored.  It is read-only because nothing needs to be written here and the program’s code shouldn’t be modified during runtime.|
|.data|This is where initialized variables are stored|
|.bss|This is where uninitialized variables are stored|
|Heap|This segment of memory is used for whatever the program needs. It is for storing dynamically allocated data and persists for life of the process|
|Stack|This is used to store temporary data needed for executing functions. The stack contains stack frames which are collections of all the passed variables, local variables, and return points for each function. The data here only persists for the scope of the function|


(gc '.\test.md' -encoding UTF8) -replace "\s{3,}",'|' -replace '^','|' -replace '$','|'