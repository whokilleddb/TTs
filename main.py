import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from tts.config import Config
from tts.builder import Builder


def parse_args():
    parser = argparse.ArgumentParser(
        description="TTs - TextTransform Payload Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    required = parser.add_argument_group("required arguments")
    required.add_argument(
        "--output-dir", required=True, help="Directory to store output in"
    )
    required.add_argument(
        "--shellcode", required=True, help="Path to shellcode file"
    )

    optional = parser.add_argument_group("optional arguments")
    optional.add_argument(
        "--assembly",
        default=None,
        help="Assembly name (default: randomly generated)",
    )
    optional.add_argument(
        "--delay",
        type=int,
        default=8,
        choices=range(0, 16),
        metavar="0-15",
        help="Minutes to delay execution (default: 8, range: 0-15)",
    )
    optional.add_argument(
        "--debug",
        action="store_true",
        help="Compile assembly with debug output",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.shellcode):
        parser.error(f"Shellcode file not found: {args.shellcode}")

    return args


def print_config(args):
    print()
    print("=" * 50)
    print()
    print(f"  Output Directory  : {args.output_dir}")
    print(f"  Shellcode         : {args.shellcode}")
    print(f"  Assembly Name     : {args.assembly or '(random)'}")
    print(f"  Execution Delay   : {args.delay} minutes")
    print(f"  Debug Output      : {'enabled' if args.debug else 'disabled'}")
    print()
    print("=" * 50)
    print()

def banner():
    print(
        r"""
 _______        _ _______                   __                      _____ _          _ _ 
|__   __|      | |__   __|                 / _|                    / ____| |        | | |
   | | _____  _| |_ | |_ __ __ _ _ __  ___| |_ ___  _ __ _ __ ___ | (___ | |__   ___| | |
   | |/ _ \ \/ / __|| | '__/ _` | '_ \/ __|  _/ _ \| '__| '_ ` _ \ \___ \| '_ \ / _ \ | |
   | |  __/>  <| |_ | | | | (_| | | | \__ \ || (_) | |  | | | | | |____) | | | |  __/ | |
   |_|\___/_/\_\\__||_|_|  \__,_|_| |_|___/_| \___/|_|  |_| |_| |_|_____/|_| |_|\___|_|_|
                                                                                         
                                   - Get Shells using TextTransform Utility (@whokilleddb)
"""
    )

def main():
    args = parse_args()
    banner()
    print_config(args)

    config = Config(
        shellcode=args.shellcode,
        output_dir=args.output_dir,
        assembly_name=args.assembly,
        delay=args.delay,
        debug=args.debug,
    )

    builder = Builder(config)
    builder.run()


if __name__ == "__main__":
    main()
