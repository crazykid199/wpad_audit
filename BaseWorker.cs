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
using System.Threading;
using System.Threading.Tasks;

namespace WpadAudit
{
    public abstract class BaseWorker 
    {
        public static CancellationTokenSource StopToken = new CancellationTokenSource();
       
        /// <summary>
        /// Optionally starts the worker on a new thread or the current thread
        /// </summary>
        public Task Start()
        {
            if( this.Enabled() )
                return Task.Factory.StartNew(() => this.DoWork(), StopToken.Token);

            return null;
        }

        /// <summary>
        /// Stops the worker and cleans up
        /// </summary>
        public void Stop()
        {
            try
            {                
                StopToken.Cancel();
                this.CleanUp();
            }
            catch( Exception ex )
            {
                // Catch the exception so the other workers can stop
                Logger.AddToErrorView("Worker.Stop", ex);
            }
        }       
        
        /// <summary>
        /// Checks to see the stop token has been set
        /// </summary>
        /// <returns></returns>
        public bool CheckForCancel()
        {
            return StopToken.IsCancellationRequested;
        }

        public virtual bool Enabled()
        {
            return true;
        }

        public abstract void DoWork();
        public abstract void CleanUp();
    }
}
