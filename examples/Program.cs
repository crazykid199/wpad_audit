using System;
using System.Net;

namespace WpadAuditExample
{
    class Program
    {
        static void Main(string[] args)
        {
            // Example one
            SendRequest("http://httpbin.org/get");
            
            // Example two
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) =>
            {
                return true;
            };

            SendRequest("https://httpbin.org/get");

            Console.WriteLine("Press any key to exit");
            Console.Read();
        }

        static void SendRequest(string url)
        {
            HttpWebRequest request = null;
            HttpWebResponse response = null;
         
            try
            {
                request = (HttpWebRequest)HttpWebRequest.Create(url);
                //request.Proxy = null;
                response = (HttpWebResponse)request.GetResponse();
            }
            catch(WebException ex)
            {
                // Swallow the expection. wpad_audit will short circuit the
                // http connection. Don't really care what happens
                // as long as the request shows up in wpad_audit and the 
                // proxy below resolves to the wpad_audit proxy
            }

            if (request.Proxy != null)
            {
                Uri proxy = request.Proxy.GetProxy(new Uri(url));
                Console.Out.WriteLine("Used proxy {0} for {1}", proxy.Host, url);
            }
        }
    }
}
