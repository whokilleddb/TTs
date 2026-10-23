    internal static class S
    {
        internal static byte[] _k = new byte[] { STRKEY_PH };
        internal static string D(byte[] e)
        {
            char[] r = new char[e.Length];
            for (int i = 0; i < e.Length; i++)
                r[i] = (char)(e[i] ^ _k[i % _k.Length]);
            return new string(r);
        }
        internal static byte[] DB(byte[] e)
        {
            byte[] r = new byte[e.Length];
            for (int i = 0; i < e.Length; i++)
                r[i] = (byte)(e[i] ^ _k[i % _k.Length]);
            return r;
        }
    }
