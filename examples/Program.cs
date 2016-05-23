using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace WpadAuditExample
{
    class Program
    {
        static void Main(string[] args)
        {
            // Example one
            HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create("http://httpbin.org/get");
            request.GetResponse();

        }
    }
}
