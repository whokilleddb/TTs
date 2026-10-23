import hashlib
import random


class ShellcodeParser:
    def __init__(self, path):
        self.path = str(path)
        self.raw = None
        self.encoded = None
        self.xor_key = None

    def read(self):
        with open(self.path, "rb") as f:
            self.raw = f.read()
        sha256 = hashlib.sha256(self.raw).hexdigest()
        print(f"[+] Shellcode size:\t\t\t\t{len(self.raw)} bytes")
        print(f"[+] Shellcode SHA256:\t\t\t\t{sha256}")

    def encode(self):
        key_len = 16
        self.xor_key = bytes(random.randint(1, 255) for _ in range(key_len))
        self.encoded = bytes(b ^ self.xor_key[i % key_len] for i, b in enumerate(self.raw))
        key_hex = self.xor_key.hex()
        print(f"[+] XOR key ({key_len}B):\t\t\t\t{key_hex}")

    def encoded_hex_string(self):
        return ", ".join(f"0x{b:02X}" for b in self.encoded)

    def xor_key_hex_string(self):
        return ", ".join(f"0x{b:02X}" for b in self.xor_key)
