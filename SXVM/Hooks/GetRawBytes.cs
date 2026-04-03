using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static SXVM.API;

namespace SXVM.Hooks
{
    internal static class GetRawBytes
    {
        internal static unsafe void Hook(string[] args)
        {
            byte[] patch = { 0xC3 };
            IntPtr GetRawBytesAddress = GetManagedFunctionPointer(Assembly.GetExecutingAssembly().GetType().GetMethod(@"GetRawBytes", BindingFlags.Instance | BindingFlags.NonPublic).MethodHandle.Value.ToPointer());
            WriteMemoryBlock(GetRawBytesAddress, patch, (uint)patch.Length);
            patch = null;
            GC.Collect();
        }
    }
}
