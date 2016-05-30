/* The MIT License (MIT)

Copyright (c) 2016 Darren Southern

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

using System;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace WpadAudit
{
    public static class Logger
    {
        private static object Locker = new object();
        
        static Logger()
        {
            Console.WindowWidth = Console.LargestWindowWidth / 2;
            Console.WindowHeight = Console.LargestWindowHeight/2;          
        }

        public static void AddToErrorView(string location, Exception ex)
        {      
            lock (Locker)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write(" - ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(string.Format("{0} {1}",location, ex.Message));
                Console.ForegroundColor = ConsoleColor.White;
            }
        }

        public static void AddToInfoView(Func<bool> condition, string format, params object[] args)
        {
            if (condition())
                AddToInfoView(format, args);
        }

        public static void AddToInfoView(string format, params object[] args)
        {
            try
            {
                lock (Locker)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write(" - ");
                    Console.ForegroundColor = ConsoleColor.White;
                    string[] parts = Regex.Split(format, "\\{\\d\\}");

                    Console.Write(parts[0]);

                    for (int index = 1; index <= args.Length; index++)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(args[index - 1]);
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.Write(parts[index]);
                    }

                    Console.Write("\r\n");
                }
            }
            catch(Exception ex)
            {

            }
        }                
    }
}
