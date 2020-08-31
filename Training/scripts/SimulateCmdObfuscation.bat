@ECHO OFF
setlocal EnableDelayedExpansion
color 0C
ECHO. 

SET cmd=C:\Windows\System32\cmd.exe


CLS
ECHO ==========================================================================
ECHO Simulating command prompt obfuscation techniques...
ECHO - Junk Code
ECHO - Environment Variables
ECHO - For Loop Encoding
ECHO - Reverse Encoding
ECHO - Character Substitution
ECHO - Combining Techniques
ECHO.

ECHO [+] Running junk code commands...
^w^h^o^a^m^i ^/^p^r^i^v 0>&1
"w"h"o"a"m"i "/"p"r"i"v 0>&1
(((((whoami))))) 0>&1
;,;,;,;,;,whoami 0>&1

ECHO Running environment variables commands...
cmd /V:ON /C "set x=i123mu[ta0w2otYghJ!lwPqm && call !x:~20,1!!x:~16,1!!x:~12,1!!x:~8,1!!x:~4,1!!x:~0,1!"

ECHO Running for loop encoding commands...
cmd /C "FOR /F "delims=s\ tokens=4" %a IN ('set^|findstr PSM')DO %a Write-Host -Fore Green PS Executed!"

cmd /V:ON /C "^s^e^t u=/miavhrowp && FOR %A IN (8 5 7 3 1 2 10 0 9 6 2 4 13) DO set f=!f!!u:~%A,1!&& IF %A==13 CALL %f:~-12%"

ECHO Running reverse encoding commands...
cmd /V:ON /C "set r=v64iCsr99pBv/kA 7 iWwmTpaF8oJ2h6Hw&& FOR /L %%A IN (33 -3 0) DO set f=!f!!r:~%%A,1! 0>&1 &&IF %%A==0 CALL %%f:~-12% 0>&1"  

ECHO Running character substitution commands...
cmd /V:ON /C "^s^e^t c=YeZQjX bTCX# && ^s^e^t d=!c:X=i! && set e=!d:Z=o! && set f=!e:j=m! && set g=!f:Y=w! && set h=!g:T=p! && set k=!h:Q=a! && set l=!k:b=/! && set m=!l:C=r! && set n=!m:#=v! && CALL !n:e=h!"

ECHO Running combined techniques commands...
cmd /V:ON /C ";,;,;,;,;,,,,,s^e^t t^l^l^l^l^L^L=^p&& set h=!tllllLL:p=v!&&,;;,,,        ;;,,,C^A^L^L """"!COmSpeC:~3,1!^h"!CoMMOnPRogRaMFiles:~5,1!""""""""!programdata:~8,1!"^m""^i^"""" "/!alLUsersprOfILe:~3,1!!alluSErSprOfile:~4,1!!PrOgrAmfILes:~12,1!!h!"

ECHO.
color 07
endlocal