from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    shellcode: Path
    output_dir: Path
    assembly_name: str = None
    delay: int = 8
    debug: bool = False
