using System;

public class GoTeam
{
        public static void Go()
        {
                string answer;
                Console.WriteLine("Enter your favorite sports team: ");
                answer = Console.ReadLine();
                if (answer == "saints") {
                        Console.WriteLine("Who dat!");
                }
                else {
                        Console.WriteLine("Go " + answer + "!");
                }

                uint id;
                id = GetCurrentProcessId();
                Console.WriteLine("Current PID is " + id);
                id = GetCurrentThreadId();
                Console.WriteLine("Current TID is " + id);
        }
        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentProcessId();
        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();
}