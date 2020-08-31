using System;
using System.IO;
using System.Resources;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace SharpPick {
	class RunPS {
		static string DoIt(string cmd) {
			Runspace runspace = RunspaceFactory.CreateRunspace();
			runspace.Open();
			RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
			Pipeline pipeline = runspace.CreatePipeline();

			pipeline.Commands.AddScript(cmd);
			pipeline.Commands.Add("Out-String");
			Collection<PSObject> results = pipeline.Invoke();
			runspace.Close();

			StringBuilder stringBuilder = new StringBuilder();
			foreach (PSObject obj in results) {
				stringBuilder.Append(obj);
			}
			return stringBuilder.ToString().Trim();
		}
		static void Main() {
			Console.WriteLine("Enter your favorite PowerShell command: ");
			string command = Console.ReadLine();
			string results = DoIt(command);
			Console.Write(results);
		}
	}
}