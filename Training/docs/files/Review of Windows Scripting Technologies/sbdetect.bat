@ECHO OFF

SET file="C:\email.doc" 

dir %file% > nul 2>nul

if %ERRORLEVEL% EQU 0 (
	ECHO %file% exists 
	ECHO This is a sandbox
	ECHO Exiting!
	Exit
) ELSE (
	ECHO %file% does not exist
	ECHO Proceeding with infection
	ECHO Starting calc...
	calc.exe
	Exit
)
