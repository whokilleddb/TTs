def main():
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tts.builder import Builder
    from tts.config import Config
    import argparse

    parser = argparse.ArgumentParser(description="TTs - TextTransform Payload Builder")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--shellcode", required=True, help="Path to shellcode file")
    parser.add_argument("--assembly", default=None, help="Assembly name (default: random)")
    parser.add_argument("--delay", type=int, default=8, choices=range(0, 16), metavar="0-15")
    parser.add_argument("--debug", action="store_true", help="Compile assembly with debug output")
    args = parser.parse_args()

    config = Config(
        shellcode=args.shellcode,
        output_dir=args.output_dir,
        assembly_name=args.assembly,
        delay=args.delay,
        debug=args.debug,
    )

    builder = Builder(config)
    builder.run()
