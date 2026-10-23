    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate bool FlushInstructionCacheD(IntPtr process, IntPtr baseAddr, UIntPtr size);
