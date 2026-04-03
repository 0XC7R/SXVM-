using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SXVM
{
    internal static class HarmonyPatcher
    {
        private static string _0HarmonyDecryptionKey = @"XTRxaVOMjfXTRxaVOMjfIdEnBLTPVpUxVGBXxhvlxrwdxlTqkattOXmfDqzHIdEnBLTPVpUxVGBXxhvlxrwdxlTqkattOXmfDqzH";

        private static void ClearHarmonyDecryptionKeyFromMemory()
        {
            _0HarmonyDecryptionKey = @"";
            _0HarmonyDecryptionKey = null;
            GC.Collect();
        }

        internal struct TypeInfo
        {
            internal Type InternalMethodType { get; set; }

            internal string InternalMethodName { get; set; }

            internal Type[] InternalTypeParameters { get; set; }

            internal TypeInfo(Type MethodType, string MethodName, Type[] TypeParameters)
            {
                InternalMethodType = MethodType;
                InternalMethodName = MethodName;
                InternalTypeParameters = TypeParameters;
            }
        }

        private static Assembly _0Harmony = null;

        private static string PatchID = @"";

        private static Random random = new Random();

        private static string RandomString(int length)
        {
            const string chars = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        internal static void Initialize()
        {
            if (_0Harmony == null)
            {
                _0Harmony = Assembly.Load(API.Decompress(API.AESDecrypt(API.ExtractResource(@"SXVM.0Harmony.bin"), _0HarmonyDecryptionKey)));
            }
            if (PatchID == @"")
            {
                PatchID = RandomString(10);
            }
            if (_0HarmonyDecryptionKey != null)
            {
                ClearHarmonyDecryptionKeyFromMemory();
            }
        }

        internal static void Patch(TypeInfo originalMethod, Type prefixMethod = null, Type postfixMethod = null)
        {
            if (originalMethod.InternalMethodType != null & originalMethod.InternalMethodName != null & originalMethod.InternalTypeParameters != null)
            {
                if (prefixMethod == null & postfixMethod == null)
                {
                    return;
                }
                else
                {
                    Initialize();
                    Type harmonyType = _0Harmony.GetType(@"HarmonyLib.Harmony");
                    object harmonyInstance = Activator.CreateInstance(harmonyType, PatchID);
                    MethodInfo patchMethod = harmonyType.GetMethod(@"Patch");
                    Type accessToolsType = _0Harmony.GetType(@"HarmonyLib.AccessTools");
                    MethodInfo methodMethod = accessToolsType.GetMethod(@"Method", new Type[] { typeof(Type), typeof(string), typeof(Type[]), typeof(Type[]) });
                    MethodInfo internalOriginalMethod = (MethodInfo)methodMethod.Invoke(null, new object[] { originalMethod.InternalMethodType, originalMethod.InternalMethodName, originalMethod.InternalTypeParameters, null });
                    MethodInfo internalPrefixMethod = null;
                    MethodInfo internalPostfixMethod = null;
                    if (prefixMethod != null)
                    {
                        internalPrefixMethod = (MethodInfo)methodMethod.Invoke(null, new object[] { prefixMethod, @"Prefix", null, null });
                    }
                    if (postfixMethod != null)
                    {
                        internalPostfixMethod = (MethodInfo)methodMethod.Invoke(null, new object[] { postfixMethod, @"Postfix", null, null });
                    }
                    Type harmonyMethodType = _0Harmony.GetType(@"HarmonyLib.HarmonyMethod");
                    if (prefixMethod != null & postfixMethod != null)
                    {
                        object harmonyMethodInstance = Activator.CreateInstance(harmonyMethodType, internalPrefixMethod);
                        object harmonyMethodInstance2 = Activator.CreateInstance(harmonyMethodType, internalPostfixMethod);
                        patchMethod.Invoke(harmonyInstance, new object[] { internalOriginalMethod, harmonyMethodInstance, harmonyMethodInstance2, null, null });
                    }
                    else
                    {
                        if (prefixMethod != null)
                        {
                            object harmonyMethodInstance = Activator.CreateInstance(harmonyMethodType, internalPrefixMethod);
                            patchMethod.Invoke(harmonyInstance, new object[] { internalOriginalMethod, harmonyMethodInstance, null, null, null });
                        }
                        else
                        {
                            object harmonyMethodInstance2 = Activator.CreateInstance(harmonyMethodType, internalPostfixMethod);
                            patchMethod.Invoke(harmonyInstance, new object[] { internalOriginalMethod, null, harmonyMethodInstance2, null, null });
                        }
                    }
                }
            }
        }
    }
}
