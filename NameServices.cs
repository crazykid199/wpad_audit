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
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;

namespace WpadAudit
{
    public class NameServices
    {		
        /// <summary>
        /// 
        /// </summary>
        private static void ClearRegistry()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections", true))
            {
                key.DeleteValue("DefaultConnectionSettings", false);
                key.DeleteValue("SavedLegacySettings", false);
            }            
        }

        /// <summary>
        /// Restarts the Win Http Auto Proxy Svc. This seems to be the easiest method to
        /// force a broadcast name resolution for WPAD
        /// </summary>
        private static void RestartService()
        {
            try
            {
                using (ServiceController service = new ServiceController("WinHttpAutoProxySvc"))
                {
                    if (service.Status == ServiceControllerStatus.Running)
                    {
                        Logger.AddToInfoView("Stopping the {0} service", "WinHttpAutoProxySvc");
                        service.Stop();
                        service.WaitForStatus(ServiceControllerStatus.Stopped);
                        Logger.AddToInfoView("Success");
                    }

                    Logger.AddToInfoView("Starting the {0} service", "WinHttpAutoProxySvc");
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running);
                    Logger.AddToInfoView("Success");
                }
            }
            catch(Exception ex)
            {
                Logger.AddToErrorView("Unable to restart WinHttpAutoProxySvc", ex);
                throw ex;
            }
        }

        /// <summary>
        /// Calls nbtstat -R to flush nbns names, flushes dns cache and restarts the WinHttpAutoProxySvc
        /// </summary>
        public static bool FlushNameServices()
        {
            try
            {
				if( Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX )
	                return true;
				
                Logger.AddToInfoView("Flushing dns and nbt remote name cache");

                ClearRegistry();

                using (Process process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nbtstat.exe",
                        Arguments = "-R",
                        UseShellExecute = false,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                })
                {
                    process.Start();

                    while (!process.StandardError.EndOfStream)
                    {
                        string line = process.StandardError.ReadLine();
                        Logger.AddToInfoView(line);
                    }
                }

                NativeMethods.DnsFlushResolverCache();
                RestartService();
                return true;
            }
            /// This code gets called in cleanup code that cannot impact other code so
            /// ex is handled and false is returned
            catch( Exception ex)
            {
                Logger.AddToErrorView("Failed to FlushNameServices", ex);
                return false;
            }
        }
    }
}
