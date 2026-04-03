using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection.Emit;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SXVM
{
    internal class SXVM
    {
        private enum AllocationProtectEnum : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private static uint ConvertProtectToFlags(uint protectValue)
        {
            switch (protectValue)
            {
                case 0x01:
                    return 0x02;
                case 0x02:
                    return 0x04;
                case 0x04:
                    return 0x40;
                case 0x08:
                    return 0x80;
                case 0x10:
                    return 0x20;
                case 0x20:
                    return 0x100;
                case 0x40:
                    return 0x400;
                default:
                    return 0x0;
            }
        }

        [DllImport("kernel32.dll")]
        private static extern int VirtualQuery(
            IntPtr lpAddress,
            ref MEMORY_BASIC_INFORMATION lpBuffer,
            IntPtr dwLength
        );

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [HandleProcessCorruptedStateExceptions]
        private static unsafe void WriteMemoryBlock(IntPtr Address, byte[] src, uint size)
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
        private static unsafe byte[] ReadMemoryBlock(IntPtr Address, uint size)
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

        private class DelegateTypeBuilder
        {
            internal static Type BuildDelegateType(MethodInfo methodInfo)
            {
                Type[] parameterTypes = methodInfo.GetParameters().Select(p => p.ParameterType).ToArray();
                Type returnType = methodInfo.ReturnType;

                return BuildDelegateType(parameterTypes, returnType);
            }

            internal static Type BuildDelegateType(Type[] parameterTypes, Type returnType)
            {
                AssemblyName assemblyName = new AssemblyName("DynamicDelegateAssembly");
                AssemblyBuilder assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
                ModuleBuilder moduleBuilder = assemblyBuilder.DefineDynamicModule("DynamicDelegateModule");

                TypeBuilder typeBuilder = moduleBuilder.DefineType(
                    "DynamicDelegateType",
                    TypeAttributes.Sealed | TypeAttributes.Public,
                    typeof(MulticastDelegate)
                );

                ConstructorBuilder constructorBuilder = typeBuilder.DefineConstructor(
                    MethodAttributes.RTSpecialName | MethodAttributes.SpecialName | MethodAttributes.Public | MethodAttributes.HideBySig,
                    CallingConventions.Standard,
                    new Type[] { typeof(object), typeof(IntPtr) }
                );
                constructorBuilder.SetImplementationFlags(MethodImplAttributes.Runtime);

                MethodBuilder methodBuilder = typeBuilder.DefineMethod(
                    "Invoke",
                    MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.NewSlot | MethodAttributes.Virtual,
                    returnType,
                    parameterTypes
                );

                methodBuilder.SetImplementationFlags(MethodImplAttributes.Runtime);

                Type delegateType = typeBuilder.CreateType();
                return delegateType;
            }
        }

        private static Delegate CreateDelegateBasedOn(Delegate originalDelegate)
        {
            MethodInfo methodInfo = originalDelegate.Method;
            Type delegateType = DelegateTypeBuilder.BuildDelegateType(methodInfo);
            return Delegate.CreateDelegate(delegateType, null, methodInfo);
        }

        private MEMORY_BASIC_INFORMATION OP_MBI = new MEMORY_BASIC_INFORMATION();

        private Delegate OP_STUB = null;

        private bool Permanent_Hook = false;

        private bool Exit_Hook = false;

        private IntPtr Address_Hook = IntPtr.Zero;

        private byte[] Original_Hook = null;

        private byte[] OP_Hook = null;

        private static void VM_EXIT()
        {
            try
            {
                Process.GetCurrentProcess().Kill();
            }
            catch
            {
            }
            throw new AccessViolationException();
        }

        private void RestoreVMHook()
        {
            if (Address_Hook == IntPtr.Zero || Original_Hook == null || (uint)Original_Hook.LongLength == 0)
            {
            }
            else
            {
                WriteMemoryBlock(Address_Hook, Original_Hook, (uint)Original_Hook.LongLength);
            }
        }

        private void AddVMHook()
        {
            if (Address_Hook == IntPtr.Zero || OP_Hook == null || (uint)OP_Hook.LongLength == 0)
            {
            }
            else
            {
                WriteMemoryBlock(Address_Hook, OP_Hook, (uint)OP_Hook.LongLength);
            }
        }

        internal void Unhook()
        {
            RestoreVMHook();
        }

        internal void Hook()
        {
            if (OP_Hook == null)
            {
            }
            else
            {
                AddVMHook();
            }
        }

        internal void Hook(IntPtr Address, Delegate OP_HOOK, bool Permanent, bool Exit)
        {
            VirtualQuery(Address, ref OP_MBI, (IntPtr)Marshal.SizeOf(OP_MBI));
            OP_STUB = OP_HOOK;
            Permanent_Hook = Permanent;
            Exit_Hook = Exit;
            Address_Hook = Address;
            Original_Hook = ReadMemoryBlock(Address, (uint)22);
            Delegate CustomEntryPoint = CreateDelegateBasedOn(OP_STUB);
            GCHandle.Alloc(CustomEntryPoint);
            IntPtr ENTRYPOINT_PTR = Marshal.GetFunctionPointerForDelegate(CustomEntryPoint);
            uint oldProtect = 0;
            VirtualProtect(Address, (UIntPtr)11, 0x40, out oldProtect);
            Marshal.WriteByte(Address, 0, 0x48);
            Marshal.WriteByte(Address, 1, 0xB8);
            Marshal.WriteInt64(Address, 2, ENTRYPOINT_PTR.ToInt64());
            Marshal.WriteByte(Address, 10, 0xFF);
            Marshal.WriteByte(Address, 11, 0xE0);
            OP_Hook = ReadMemoryBlock(Address, (uint)22);
            VirtualProtect(Address, (UIntPtr)11, ConvertProtectToFlags(OP_MBI.Protect), out oldProtect);
        }
    }
}
