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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace WpadAudit
{
    class Program
    {      
        /// <summary>
        /// Main entry point to get things rockin
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            List<BaseWorker> workers = null;

            try
            {
                if (Configuration.Load())
                {
                    int deviceNumber = GetDeviceNumber();

                    Console.Clear();

                    IPEndPoint pacFileHost = new IPEndPoint(NetworkCapture.GetDeviceIp(deviceNumber), Configuration.PacFileHostPort);

                    workers = new List<BaseWorker>()
                    {                    
                        new PacFileHost( pacFileHost, Configuration.ProxyServerEndPoint, Configuration.HostsToProxy),
                        new Proxy(),
                        new NetworkCapture(deviceNumber, Configuration.PacFileHostPort, Configuration.ProxyServerEndPoint),
                    };

                    List<Task> tasks = new List<Task>();

                    workers.ForEach(worker =>
                    {
                        if (worker.Enabled())
                            tasks.Add(worker.Start());
                    });

                    if (NameServices.FlushNameServices())
                        Task.WaitAny(tasks.ToArray());
                }
            }
            catch (Exception ex)
            {
                Logger.AddToErrorView("Program.Main", ex);
            }
            finally
            {
                if (workers != null)
                    workers.ForEach(worker =>
                    {
                        if (worker != null)
                            worker.Stop();
                    });

                NameServices.FlushNameServices();
                Console.WriteLine("Press any key to exit");
                Console.ReadKey();
            }
        }

        /// <summary>
        /// If a device number is not specified in the config then a UI is presented
        /// to the user to select a device
        /// </summary>
        /// <returns></returns>
        private static int GetDeviceNumber()
        {
            int deviceNumber = 0;

            if (!Configuration.DeviceNumber.HasValue)
            {
                for (; ; )
                {
                    List<string> devices = NetworkCapture.GetDevices().ToList();

                    Console.Clear();
                    Console.WriteLine("Please select a network device to monitor\r\n");

                    for (int index = 0; index < devices.Count; index++)
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.Out.Write("\t{0} - ", index);
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.WriteLine(devices[index]);
                    }

                    ConsoleKeyInfo key = Console.ReadKey();

                    if (!int.TryParse(key.KeyChar.ToString(), out deviceNumber) || deviceNumber > devices.Count())
                    {
                        Logger.AddToInfoView("\r\n{0} is an invalid device number", key.KeyChar);
                        continue;
                    }

                    Configuration.SetupLocalProxyEndPoint(deviceNumber);
                    break;
                }
            }

            return Configuration.DeviceNumber.Value;
        }
    }
}
