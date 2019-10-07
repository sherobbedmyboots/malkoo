Dim objIE

Set objIE = CreateObject("InternetExplorer.Application")
Set s = CreateObject("WScript.Shell")

objIE.Visible = False
objIE.Navigate "https://www.sans.org"

'Wait for page to load
While objIE.ReadyState <> 4 : WScript.Sleep 100 : Wend

'Download was successful
WScript.Echo "Title of page downloaded:"
WScript.Echo objIE.document.title

'Simulate executing downloaded file
WScript.Echo "Executing calc.exe..."
s.run("calc.exe")