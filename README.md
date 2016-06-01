# wpad_audit
Allows developers and security practitioners a quick and easy method to audit .NET applications for WPAD MITM attacks over HTTP and HTTPS

It works by creating three modules that work together.

⦁ NetworkCapture – Monitors the network for broadcast NBNS queries trying to resolve the hostname WPAD. When it detects a query it replies with an NBNS answer indicating that the WPAD host is the host that wpad_audit is running on.

⦁ PacFileHost – Http listener that listens for HTTP GET requests for the file wpad.dat. When it receives a request, it replies with a dynamic PAC file. The tool can be configured so that only defined hosts are directed to the proxy.

⦁ Proxy – The purpose of the proxy is to determine what applications have made calls to the WinHttpGetProxyForUrl function. When a connection is accepted, it looks at the TCP connection table to determine the PID of the client application. If the connection is made via HTTP, then the process name and HTTP message headers are output and a “503 Service Unavailable” message is returned to the client. If the connection is made via HTTPS, then an untrusted server certificate is used to authenticate the server to the client. If the client continues to send messages, then it has accepted the server certificate and the process should be flagged for review.

Quick Start

To get started with wpad_audit, clone the repository, https://github.com/stillinsecure/wpad_audit.git. 
The repository contains a solution with two projects, the wpad_audit tool, and an example application. Compile the solution and run wpad_audit. The configuration settings for wpad_audit are stored in the app.config file. By default, there is nothing in the app.config that needs to be changed to run the example. The one setting to take note of, however, is the processToDisplay setting. This setting is set to the name of the example process, WpadAuditExample. This setting will cause wpad_audit to only display connections to the proxy from the WpadAuditExample process. To test your applications, you can make processToDisplay empty to display all processes connecting to the proxy, or limit display results by specifying a process name. When wpad_audit is launched, a list of adapters will be displayed. Select the adapter that you would like the server to bind to. Once you select an adapter the server will start. Now that the server is started you can run the WpadAuditExample application.

For a demonstration of wpad_audit, check out the video at https://www.youtube.com/watch?v=rfnBVpPk2gE&feature=youtu.be
