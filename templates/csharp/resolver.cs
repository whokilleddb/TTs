    internal static class Resolver
    {
        static System.Collections.Generic.Dictionary<string, IntPtr> _mc;

        static void _init()
        {
            if (_mc != null) return;
            _mc = new System.Collections.Generic.Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
            foreach (ProcessModule m in Process.GetCurrentProcess().Modules)
                _mc[m.ModuleName] = m.BaseAddress;
        }

        internal static IntPtr GetModuleBase(string name)
        {
            _init();
            IntPtr b;
            return _mc.TryGetValue(name, out b) ? b : IntPtr.Zero;
        }

        internal static IntPtr GetExportAddress(IntPtr modBase, string exportName)
        {
            long b = modBase.ToInt64();
            int elfanew = Marshal.ReadInt32(modBase, 0x3C);
            long optHdr = b + elfanew + 24;
            int expRva = Marshal.ReadInt32((IntPtr)optHdr, 0x70);
            if (expRva == 0) return IntPtr.Zero;

            long expDir = b + expRva;
            int numNames = Marshal.ReadInt32((IntPtr)expDir, 24);
            int funcTbl = Marshal.ReadInt32((IntPtr)expDir, 28);
            int nameTbl = Marshal.ReadInt32((IntPtr)expDir, 32);
            int ordTbl = Marshal.ReadInt32((IntPtr)expDir, 36);

            for (int i = 0; i < numNames; i++)
            {
                int nameRva = Marshal.ReadInt32((IntPtr)(b + nameTbl), i * 4);
                string n = Marshal.PtrToStringAnsi((IntPtr)(b + nameRva));
                if (string.Equals(n, exportName, StringComparison.Ordinal))
                {
                    short ord = Marshal.ReadInt16((IntPtr)(b + ordTbl), i * 2);
                    int funcRva = Marshal.ReadInt32((IntPtr)(b + funcTbl), ord * 4);
                    return (IntPtr)(b + funcRva);
                }
            }
            return IntPtr.Zero;
        }

        internal static T GetDelegate<T>(string module, string function) where T : class
        {
            IntPtr mb = GetModuleBase(module);
            if (mb == IntPtr.Zero) return null;
            IntPtr fa = GetExportAddress(mb, function);
            if (fa == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer(fa, typeof(T)) as T;
        }
    }
