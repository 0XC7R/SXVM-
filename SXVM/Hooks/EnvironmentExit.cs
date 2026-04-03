using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SXVM.Hooks
{
    internal static class EnvironmentExit
    {
        internal static void Hook(string[] args)
        {
            HarmonyPatcher.Patch(new HarmonyPatcher.TypeInfo(typeof(Environment), @"Exit", new Type[] { typeof(int) }), typeof(HookedEnvironment.Exit), null);
        }

        private static class HookedEnvironment
        {
            internal static class Exit
            {
                internal static bool Prefix(ref int exitCode)
                {
                    Process.GetCurrentProcess().Kill();
                    return true;
                }
            }
        }
    }
}
