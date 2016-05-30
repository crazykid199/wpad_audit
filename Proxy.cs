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

using Mono.Cecil;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WpadAudit
{    
    public class Proxy : BaseWorker
    {
        private static readonly byte[] ConnectCmdResponse = UTF8Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        private static readonly byte[] ServiceUnavailableResponse = UTF8Encoding.UTF8.GetBytes("HTTP/1.1 503 wpad_audit will not proxy requests\r\n\r\n");

        private const int    Strength = 2048;
        private const string Password = "password";
        private const string ConnectCmd = "CONNECT";
        private const string ConnectRegEx = "(?<=CONNECT ).+(?=\\:)";
        private const string HttpMessageViaProxy = "{0}:{1}(port:{2}) sent an http message through the proxy\r\n{3}";
        private const string ProcessDidNotAcceptCert = "{0}:{1}(port:{2}) did not accept the server certificate from the proxy for {3}";
        private const string ProcessAcceptedCert = "{0}:{1}(port:{2}) acccepted the server certificate from the proxy for {3}\r\n{4}";

        private TcpListener      Server { get; set; }        
        private X509Certificate2 InvalidServerCertificate { get; set; }

        public Proxy()
        {
            this.Server = new TcpListener(Configuration.ProxyServerEndPoint);
        }

        public override bool Enabled()
        {
            return Configuration.EnableLocalProxy;
        }

        /// <summary>
        /// Starts the proxy by waiting for connections
        /// </summary>
        public override void DoWork()
        {
            try
            {                           
                Logger.AddToInfoView("Starting the proxy on {0}", Configuration.ProxyServerEndPoint);
                Server.Start();                

                for (;;)
                {
                    if (this.CheckForCancel())
                        return;
                    
                    InvalidServerCertificate = this.GenerateCert("wpad_audit");
                    TcpClient client = Server.AcceptTcpClient();
                    Task.Factory.StartNew(() => this.HandleClient(client), BaseWorker.StopToken.Token);
                }
            }
            catch(Exception ex)
            {
                Logger.AddToErrorView("Proxy.DoWork", ex);
            }
        }

        public override void CleanUp()
        {
            Logger.AddToInfoView("Stopping the proxy");

            try
            {
                Server.Stop();
            }
            catch(Exception ex)
            {
                Logger.AddToErrorView("Error stopping the proxy.", ex);
            }          
        }

        /// <summary>
        /// Looks for a complete HTTP message. If its a post with body then we dont care
        /// </summary>
        /// <param name="incoming"></param>
        /// <returns></returns>
        public string GetMessageHeaders(Stream incoming )
        {
            StringBuilder textData = new StringBuilder();
            byte[]        buffer = new byte[1024];
            int           bytesRead = 0;

            for (; ; )
            {
                bytesRead = incoming.Read(buffer, 0, buffer.Length);
                textData.Append(UTF8Encoding.UTF8.GetString(buffer, 0, bytesRead));
                
                if ( bytesRead <= 0 || ( textData.Length >= 4 && textData[textData.Length - 1] == '\n' && 
                                            textData[textData.Length - 2] == '\r' && 
                                            textData[textData.Length - 3] == '\n' && 
                                            textData[textData.Length - 4] == '\r'))
                    return textData.ToString();                                    
            }                          
        }

        /// <summary>
        /// Handles the connected client. The connections are terminated with a 503 response. 
        /// </summary>
        /// <param name="client"></param>
        private void HandleClient(TcpClient client)
        {
            try
            {
                if (this.CheckForCancel())
                    return;

                int     remotePort = ((IPEndPoint)client.Client.RemoteEndPoint).Port;
                string  message = string.Empty;
                string  processName = string.Empty;
                int     pid = 0;
                string  processPath;

                using (NetworkStream clientStream = client.GetStream())
                {
                    message = this.GetMessageHeaders(clientStream);
                    
                    // Look up the connection in the tcp table to get the process
                    ProcessInfo.ProcessFromPort(((IPEndPoint)client.Client.RemoteEndPoint).Port, out processName, out pid, out processPath);

                    Func<bool> canDisplay = new Func<bool>(() => { return string.Compare(Configuration.ProcessToDisplay, processName, true) == 0; });

                    Match host = Regex.Match(message, ConnectRegEx);

                    message = SanitizeHttpMessage(message);
                    Logger.AddToInfoView( canDisplay, HttpMessageViaProxy, processName, pid, remotePort, message);

                    // If the process is killed then process path will be null
                    if (!string.IsNullOrEmpty(processPath) && canDisplay() )
                        FindCertificateValidationCallbacks(processPath);

                    // The regex to check for CONNECT failed so this must be HTTP
                    if (!host.Success)
                    {
                        clientStream.Write(ServiceUnavailableResponse, 0, ServiceUnavailableResponse.Length);
                        clientStream.Flush();
                        return;
                    }

                    clientStream.Write(ConnectCmdResponse, 0, ConnectCmdResponse.Length);
                    clientStream.Flush();

                    // Create an ssl stream and generate a certificate for the host and
                    // check to see if the client accepts it
                    using (SslStream clientSslStream = new SslStream(clientStream, true))
                    {
                        try
                        {
                            clientSslStream.AuthenticateAsServer(this.InvalidServerCertificate);
                            message = this.GetMessageHeaders(clientSslStream);

                            if (message.Length == 0)
                                Logger.AddToInfoView(canDisplay, ProcessDidNotAcceptCert, processName, pid, remotePort, host);
                            else
                            {
                                message = SanitizeHttpMessage(message);

                                Logger.AddToInfoView(canDisplay, ProcessAcceptedCert, processName, pid, remotePort, host, message);
                                clientSslStream.Write(ServiceUnavailableResponse, 0, ServiceUnavailableResponse.Length);
                                clientSslStream.Flush();
                            }
                        }
                        catch(IOException)
                        {
                            Logger.AddToInfoView(canDisplay, ProcessDidNotAcceptCert, processName, pid, remotePort, host);
                        }
                    }             
                }
            }        
            catch( Exception ex )
            {
                Logger.AddToErrorView("Proxy.HandleClient", ex);
            }
            finally
            {
                client.Close();
            }
        }

        /// <summary>
        /// Sanitizes the message for display purposes
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        private string SanitizeHttpMessage(string message)
        {
            message = message.Insert(0, "\t");
            message = message.Replace("\r\n", "\r\n\t");
            return message;
        }

        /// <summary>
        /// Generates a self signed certificate for the specified host. In the future this will used to 
        /// test code that implements custom server certificate validation logic
        /// </summary>
        /// <param name="host"></param>
        /// <returns></returns>
        private X509Certificate2 GenerateCert(string host)
        {
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm("SHA256WithRSA");

            X509Name subjectDN = new X509Name("CN=wpad_audit");
            X509Name issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            DateTime notBefore = DateTime.UtcNow.Date;
            DateTime notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, Strength);

            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;            
            Org.BouncyCastle.X509.X509Certificate cert = certificateGenerator.Generate(issuerKeyPair.Private, random);

            Pkcs12Store store = new Pkcs12Store();
            string friendlyName = cert.SubjectDN.ToString();
            X509CertificateEntry certificateEntry = new X509CertificateEntry(cert);
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });
            
            byte[] streamContents;

            using (MemoryStream stream = new MemoryStream())
            {
                store.Save(stream, Password.ToCharArray(), random);
                stream.Flush();
                streamContents = stream.ToArray();
            }

            return new X509Certificate2(streamContents, Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }

        /// <summary>
        /// Determines what assemblies are referenced by the specified assembly
        /// </summary>
        /// <param name="assemblies"></param>
        /// <param name="assemblyDefinition"></param>
        public static void GetReferences(Dictionary<string, AssemblyDefinition> assemblies, AssemblyDefinition assemblyDefinition)
        {
            foreach (var module in assemblyDefinition.Modules)
            {
                foreach (var reference in module.AssemblyReferences)
                {
                    AssemblyDefinition temp = module.AssemblyResolver.Resolve(reference);
                    if (!assemblies.ContainsKey(temp.Name.Name))
                    {
                        assemblies.Add(temp.Name.Name, temp);
                        GetReferences(assemblies, temp);
                    }
                }
            }
        }

        /// <summary>
        /// If the binary specified by path is a valid .NET assembly it will be searched for references
        /// to System.Net.ServicePointManager.set_ServerCertificateValidationCallback
        /// </summary>
        /// <param name="path"></param>
        public static void FindCertificateValidationCallbacks(string path)
        {
            string fileName = Path.GetFileNameWithoutExtension(path);

            try
            {             
                Dictionary<string, AssemblyDefinition> assemblyDefinitions = new Dictionary<string, AssemblyDefinition>();
                AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(path, new ReaderParameters());
                
                assemblyDefinitions.Add(assembly.Name.Name, assembly);

                GetReferences(assemblyDefinitions, assembly);

                foreach (AssemblyDefinition assemblyDefinition in assemblyDefinitions.Values)
                {
                    foreach (ModuleDefinition module in assemblyDefinition.Modules)
                    {
                        IEnumerable<MemberReference> memberReferences = module.GetMemberReferences()
                                                                              .Where(item => item.DeclaringType.FullName == "System.Net.ServicePointManager" &&
                                                                                             item.Name == "set_ServerCertificateValidationCallback");
                        if (memberReferences.Count() > 0)
                            Logger.AddToInfoView("{0} has references to System.Net.ServicePointManager.set_ServerCertificateValidationCallback", fileName);
                    }
                }
            }
            catch(BadImageFormatException)
            {
                Logger.AddToInfoView("{0} is not a .NET assembly", fileName);
            }
            catch(Exception ex )
            {
                Logger.AddToErrorView("Proxy.DecompileAssembly", ex);
            }
        }
    }
}
