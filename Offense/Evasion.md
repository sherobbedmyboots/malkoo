# Evasion

- Evasive and contain modules that operate only in memory
- Asynchronous payloads, Implemented as reflective DLLs, can bypass AV and IPS	
 	
## Empire

- Has settings for DefaultDelay, DefaultLostLimit, KillDate, WorkingHours, DefaultJitter anti-beaconing
- Usually delivered through browser, flash exploit, via MS Office or Adobe Reader PDF exploit or macro
- Then can migrate to other processes using psinject
- Powershell never started as process, but injected into same memory space as browser
- Delivery via executable such as USB flash drive, SMBRelayX, WebDAV, shared folder is easily caught because PS is started as process

## Cobalt Strike Beacon	
- Covert command and control payload that mimics C2 used by APT and malware, can be delivered with social engineering packages, client-side exploits, and session passing
- Much like meterpreter, it can migrate to another process immediately after staging
- asynchronous low and slow C2 to multiple domains, checks for tasks over DNS/HTTP, downloads tasks as encrypted blobs using HTTP request
 	
## Slingshot	
- Full-featured payload built by Silent Break Security for interactive post-exploitation
- Stealthy, meterpreter-like, reflective dll injection

## Throwback
- HTTP/S Beaconing backdoor and C2 server by Silent Break Security
- Multiple apache servers host php files that collect callback data from the agents

## Pupy	
 	
## Python Meterpreter	
 	
## Meterpreter	
- Use stageless payloads, use valid https certificates if possible
- Default exe templates are well-known, specify your own using msfvenom –x
- Create powershell payloads with msfvenom –f psh to inject meterpreter into memory
- Or create own executable… start with source of very basic program, add function calls to get RWX memory and execute shellcode encoded with shikataganai, compile

 	
## Synchronous Payload 
- User needs to interact with session	
- Veil Evasion used to bypass AV
- Reverse_https_meterpreter used to bypass IPS
- Stageless meterpreter over https bypasses host and network based solutions

## Asynchronous Payload
- Client side attacks, long campaigns	
- Throwback, Pupy, Cobalt Strike Beacon
- Implemented as reflective DLLs
- Can be used with Metasploit with payload/windows/dllinject/ payload type
- Not common, can bypass AV and IPS
 	
## C2 channels	
- ARP or SMB named pipes
- Meterssh or cheetz/c2
- IPv6 or SniffJoke
- TLS through Tor, FASHIONCLEFT, Ncovert, covert_tcp

## Modules that don’t touch disk	
- Empire’s winenum, paranoia, netripper, ninjacopy(technically touches disk), inveigh
- Meterpreter use: execute –H –m –d calc.exe –f c:\\windows\\system32\\whoami.exe –a “/all”
- Sysinfo, getuid, use –l, ps, steal_token, getpid, transport, run win_privs, wifi_list, run enum_logged_on_users –c, window_enum –u, clipboard_get_data are all in-memory
- Meterpreter scripts are being caught, transition to Metasploit-framework post modules (newer ones) and Empire which uses better techniques
- Avoid canned techniques such as stageless and/or encoders from Metasploit $ Veil_Evasion
 	
## BEST	
- Exploits that rely on memory corruption such as browser, Flash, MS Office, Adobe Reader, potential Remote Service
- Use Metasploit framework exploit and Veil-Evasion framework staged Meterpreter listener-less payload (reverse_https with all Paranoid mode configurations set)
- Also requiring an Empire listener and the Empire launcher.dll stager
- Also could use this technique in a dropper (stand alone executable) but AV/HIPS would get a chance to scan it first
- Good droppers are TheShellterProject Stealth mode, infecting known-good PE file with one or more payloads (meterpreter, empire)Add
