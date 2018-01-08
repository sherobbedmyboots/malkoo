 | 
-|-
                GetSystemTimeAsFileTime                         01D36D22
                GetCurrentProcessId                                     00000EFC
                GetCurrentThreadId                                      0000052C
                GetTickCount                                                    0100BAC7
                QueryPerformanceCounter                        00000001






 | | 
-|-|-




 | | | 
-|-|-|-



(gc '.\test.md' -encoding UTF8) -replace "\s{3,}",'|' -replace '^','|' -replace '$','|'