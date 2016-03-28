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
using System.Net;
using System.Text;
using System.Linq;

namespace WpadAudit
{
    public class PacFileHost : BaseWorker
    {      
        public  HttpListener Listener { get; set; }
        private IPEndPoint   Local { get; set; }
        private IPEndPoint   ProxyServer { get; set; }
        private string       PacFileJavaScript { get; set; }

        private const string UrlPrefixFormat = "http://wpad:{0}/";
        private const string PacFileContentType = "application/x-ns-proxy-autoconfig";
        private const string PacFile = "/wpad.dat";

        public PacFileHost(IPEndPoint local, IPEndPoint proxyServer, string[] urlsToProxy)
        {            
            string prefix = string.Format(UrlPrefixFormat, local.Port);

            this.Listener = new HttpListener();            
            this.Listener.Prefixes.Add(prefix);

            this.Local = local;
            this.ProxyServer = proxyServer;                                    
            this.PacFileJavaScript = this.BuildJavaScriptLogic(urlsToProxy, proxyServer);
        }

        /// <summary>
        /// Builds the javascript that is present in the pac file. If urls are present in the config
        /// file then they are used to create expressions to tell the http client to use the browser.
        /// Else everything is direct
        /// </summary>
        /// <param name="urlsToProxy"></param>
        /// <param name="proxyServer"></param>
        /// <returns></returns>
        private string BuildJavaScriptLogic(string[] hostsToProxy, IPEndPoint proxyServer)
        {
            string code = "function FindProxyForURL(url, host){\r\n";

            if (hostsToProxy == null || hostsToProxy.Length == 0)
                code += string.Format("return \"PROXY {0}:{1}\";\r\n}}\r\n", proxyServer.Address, proxyServer.Port);
            else
            {
                foreach (string host in hostsToProxy)
                    code += string.Format("\tif(shExpMatch(host,\"{0}\")) return \"PROXY {1}:{2}\";\r\n", host.Trim(), proxyServer.Address, proxyServer.Port);

                code += "\treturn \"DIRECT\"\r\n}";
            }

            Logger.AddToInfoView("Generated pac file {0}", code);
            return code;
        }

        /// <summary>
        /// Starts the listener
        /// </summary>
        public override void DoWork()
        {
            try
            {
                HttpListenerContext context = null;

                Logger.AddToInfoView("Starting pac file host {0}", this.Local);
                this.Listener.Start();
                
                for (; ; )
                {
                    if (this.CheckForCancel())
                        return;

                    try
                    {
                        context = this.Listener.GetContext();
                    }
                    catch( HttpListenerException ex )
                    {
                        // Thread aborted exception when cleaning up
                        if (ex.ErrorCode == 995)
                            return;
                    }

                    if (context.Request.LocalEndPoint.Port == 80 && context.Request.RawUrl == PacFile)
                    {
                        int     pid = 0;
                        string  processPath;
                        string processName;
                    
                        // Look up the connection in the tcp table to get the process
                        ProcessInfo.ProcessFromPort(((IPEndPoint)context.Request.RemoteEndPoint).Port, out processName, out pid, out processPath);

                        if (Configuration.DoNotPoisonProcess != null && Configuration.DoNotPoisonProcess.Contains(processName))
                        {
                            context.Response.StatusCode = 404;
                            context.Response.StatusDescription = "Not Found";
                            context.Response.Close();
                        }
                        else
                        {
                            Logger.AddToInfoView("Received request from {0} {1} for wpad.dat", context.Request.RemoteEndPoint.Address, processName);
                            Logger.AddToInfoView("Return pac file with proxy {0}:{1}", this.ProxyServer.Address, this.ProxyServer.Port);

                            byte[] javaScript = UTF8Encoding.Default.GetBytes(this.PacFileJavaScript);
                            context.Response.AddHeader("Cache-Control", "no-cache");
                            context.Response.ContentType = PacFileContentType;
                            context.Response.ContentLength64 = javaScript.Length;
                            context.Response.OutputStream.Write(javaScript, 0, javaScript.Length);
                            context.Response.OutputStream.Close();
                        }
                    }
                }            
            }
            catch( Exception ex )
            {
                Logger.AddToErrorView("Error trying to start pacfile host", ex);
                this.Stop();
            }
        }

        /// <summary>
        /// Stops the listener
        /// </summary>
        public override void CleanUp()
        {
            try
            {
                Logger.AddToInfoView("Stopping the pacfilehost");
                if(this.Listener.IsListening)
                    this.Listener.Stop();
                this.Listener.Close();                                
            }
            catch(Exception ex )
            {
                Logger.AddToErrorView("Error trying to stop pacfile host", ex);
            }
        } 
    }
}