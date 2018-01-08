Function is called                                                     `call <function-name>` 
Stack frame initialized                                            push ebp                             (address in ebp pushed to the stack)
                                                                                                        mov ebp, esp                    (value of stack pointer moved to ebp)
                                                                                                        sub esp, 10                         (function needs 16 bytes for its local variables) 
Function completes                                               
Return value                                                              mov eax, ebx
Clean stack                                                                 mov esp, ebp
                                                                               pop ebp
 
Return to caller function                                       ret
Clean up parameters passed to function       add esp, 10
 



(gc '.\test.md' -encoding UTF8) -replace "\s{3,}",'|' -replace '^','|' -replace '$','|'