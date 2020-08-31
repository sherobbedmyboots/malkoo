using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System;

[ComVisible(true)] 
public class GoTeam {
        public static void Main() {
                string answer;
                Console.WriteLine("Enter your favorite sports team: ");
                answer = Console.ReadLine();
                if (answer == "saints") {
                        Console.WriteLine("Who dat!");
                }
                else {
                        Console.WriteLine("Go " + answer + "!");
                }
        }
        public void SayGo(string team) {
                Console.WriteLine("Go " + team + "!");
        }
}