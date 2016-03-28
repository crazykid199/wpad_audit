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
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace WpadAudit
{
    public class ProcessInfo 
    {
        /// <summary>
        /// Looks up the process associated with the specified local port. This is not supported on Linux and Mac
        /// </summary>
        /// <param name="localPort"></param>
        /// <param name="processName"></param>
        /// <param name="pid"></param>
        /// <param name="processPath"></param>
        			             
        public static void ProcessFromPort(int localPort, out string processName, out int pid, out string processPath)
        {
            processName = string.Empty;
			pid = 0;
            processPath = string.Empty;

			try
            {				
				if( Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX )					
					return;

				IntPtr tcpTablePtr = IntPtr.Zero;
                int tcpTableLength = 0;

                localPort = Utility.ReverseLowInt32(localPort);
          
                uint error = NativeMethods.GetExtendedTcpTable(tcpTablePtr, ref tcpTableLength, false, 2, 4, 0);

                if (error != 0)
                {
                    try
                    {
                        tcpTablePtr = Marshal.AllocHGlobal(tcpTableLength);

                        error = NativeMethods.GetExtendedTcpTable(tcpTablePtr, ref tcpTableLength, true, 2, 4, 0);
                        if (error == 0)
                        {
                            int tableLength = Marshal.ReadInt32(tcpTablePtr);
                            IntPtr ptrRow = (IntPtr)((long)tcpTablePtr + 4);

                            // Use pointer arithmetic to navigate through the records in order
                            // to find the process that maps to the port
                            for (int index = 0; index < tableLength; ++index)
                            {
                                NativeMethods.TcpRow row = (NativeMethods.TcpRow)Marshal.PtrToStructure(ptrRow, typeof(NativeMethods.TcpRow));

                                if (localPort == row.LocalPort)
                                {
                                    processPath = GetModuleFileName(row.OwningPid);
                                    pid = row.OwningPid;
                                    processName = Path.GetFileNameWithoutExtension(processPath);                                                                 
                                }

                                ptrRow = (IntPtr)((long)ptrRow + NativeMethods.TcpRowSize);
                            }
                        }
                        else
                            Logger.AddToErrorView("ProcessMonitor.Monitor", new Exception("Error retrieving the TcpTable"));
                    }
                    catch (Exception ex)
                    {
                        Logger.AddToErrorView("ProcessMonitor.Monitor", ex);
                    }
                    finally
                    {
                        if (tcpTablePtr != IntPtr.Zero)
                            Marshal.FreeHGlobal(tcpTablePtr);
                    }
                }
                else
                    Logger.AddToErrorView("ProcessMonitor.Monitor", new Exception("Error retrieving the TcpTable"));
            }
            catch (Exception ex)
            {
                Logger.AddToErrorView("Process Monitor", ex);
            }
        }

        /// <summary>
        /// Returns the module filename that matches the specified process id. Win32 calls are made
        /// instead of System.Diagnostics.Process because the .Net code consumes a lot of memory during
        /// performance tracing
        /// </summary>
        /// <param name="processId"></param>
        /// <returns></returns>
        public static string GetModuleFileName(int processId)
        {
            IntPtr handle = IntPtr.Zero;
            StringBuilder buffer = new StringBuilder(255);

            try
            {
                Process.EnterDebugMode();

                handle = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryInformation |
                                                    NativeMethods.ProcessAccessFlags.VMRead,
                                                    false,
                                                    processId);

                if (handle == null || handle == IntPtr.Zero)
                    return null;


                // If a process is quickly created and then killed a valid handle can be returned but getmodulefilename
                // will return a length of 0
                uint returnLength = NativeMethods.GetModuleFileNameEx(handle, IntPtr.Zero, buffer, 255);

                if (returnLength == 0)
                    return null;
            }
            catch (Exception ex)
            {
                return null;                
            }
            finally
            {
                Process.LeaveDebugMode();

                if (handle != null && handle != IntPtr.Zero)
                    NativeMethods.CloseHandle(handle);
            }

            return buffer.ToString();
        }
    }    
}
