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

namespace WpadAudit
{
    public static class Utility
    {
        public static UInt32 ReverseUInt32(UInt32 value)
        {
            return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
                   (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
        }

        public static UInt16 ReverseUInt16(UInt16 value)
        {
            return (UInt16)((value & 0xFFU) << 8 | (value & 0xFF00U) >> 8);
        }
          
        public static Int32 ReverseLowInt32(Int32 value)
        {
            return (Int32)((value & 0xFF) << 8 | (value & 0xFF00) >> 8);
        }

        /// <summary>
        /// Decodes Netbios name
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public static string DecodeName(string name)
        {
            byte length = (byte)name[0];

            string temp = string.Empty;

            for (int index = 1; index <= 32; index += 2)
            {
                int number = ((((byte)name[index] - 0x41) << 4) | (((int)name[index + 1] - 0x41) & 0xf));
                temp += (char)number;
            }

            temp = temp.Split('\0')[0].Trim();
            return temp;
        }       
    }
}
