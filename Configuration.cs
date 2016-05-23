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
using System.Configuration;
using System.Net;
using System.Net.NetworkInformation;

namespace WpadAudit
{
    public static class Configuration
    {
        public static IPAddress         ProxyServer;
        public static int               PacFileHostPort;
        public static string[]          HostsToProxy;
        public static int               CaptureReadTimeout;
        public static int?              DeviceNumber;
        public static bool              EnableLocalProxy;
        public static PhysicalAddress   CaptureMacAddress;
        public static int               ProxyPort;
        public static IPEndPoint        ProxyServerEndPoint;
        public static string            ProcessToPoison;

        /// <summary>
        /// Read settings from the config into an easy to use class
        /// </summary>
        public static bool Load()
        {
            try
            {
                CaptureMacAddress = (PhysicalAddress)GetValue("captureMacAddress", false, (value) => { return PhysicalAddress.Parse(value.ToUpper()); });
                EnableLocalProxy = (bool)GetValue("enableLocalProxy", true, (value) => { return bool.Parse(value); });
                DeviceNumber = (int?)GetValue("deviceNumber", false, (value) => { return int.Parse(value); });                
                PacFileHostPort = (int)GetValue("pacFileHostPort", true, (value) => { return int.Parse(value); });
                ProxyPort = (int)GetValue("proxyPort", true, (value) => { return int.Parse(value); });
                CaptureReadTimeout = (int)GetValue("captureReadTimeout", true, (value) => { return int.Parse(value); });
                ProxyServer = (IPAddress)GetValue("proxyServer", false, (value) => { return IPAddress.Parse(value); });
                ProcessToPoison = (string)GetValue("processToPoison", false, (value) => { return value; });
                HostsToProxy = (string[])GetValue("hostsToProxy", false, (value) =>
                {
                    if (!string.IsNullOrEmpty(value))
                        return value.Split(',');
                    else
                        return null;
                });
           
                
                // Device number needs to be configured at this point
				// in order for the proxy server endpoint to be set
				if( DeviceNumber.HasValue )
				{
				    if( EnableLocalProxy )
                        ProxyServerEndPoint = new IPEndPoint(NetworkCapture.GetDeviceIp(DeviceNumber.Value), ProxyPort);
                    else
                        ProxyServerEndPoint = new IPEndPoint(ProxyServer, ProxyPort);
				}

                return true;
            }
            catch (Exception ex)
            {
                Logger.AddToErrorView("Configuration", ex);
                return false;
            }
        }      

        /// <summary>
        /// Used by the GUI when the user selects a device
        /// </summary>
        /// <param name="deviceNumber"></param>
        public static void SetupLocalProxyEndPoint(int deviceNumber)
        {
            DeviceNumber = deviceNumber;
            ProxyServer = NetworkCapture.GetDeviceIp(DeviceNumber.Value);
            ProxyServerEndPoint = new IPEndPoint(ProxyServer, ProxyPort);
        }

        /// <summary>
        /// Gets the specified setting from the config file and applies the conversion function to it
        /// </summary>
        /// <param name="key"></param>
        /// <param name="required"></param>
        /// <param name="conversionFunc"></param>
        /// <returns></returns>
        public static object GetValue(string key, bool required, Func<string, object> conversionFunc)
        {
            string value = ConfigurationManager.AppSettings[key];

            try
            {
                if (string.IsNullOrEmpty(value) && required)
                    throw new ArgumentException(string.Format("The configuration value {0} is required", key));
                else if (string.IsNullOrEmpty(value))
                    return null;

                return conversionFunc(value);
            }
            catch (Exception ex)
            {
                throw new ArgumentException(string.Format("Unable to parse the value {0} for {1}", value, key));
            }
        }
    }
}
