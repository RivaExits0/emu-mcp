"""Shared helpers for the emu-mcp test suite."""

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Cross compilers and binutils available for the supported architectures.
TOOLCHAIN = {
    "x64": ("x86_64-linux-gnu-gcc", "x86_64-linux-gnu-nm"),
    "x86": ("i686-linux-gnu-gcc", "i686-linux-gnu-nm"),
    "arm64": ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-nm"),
    "arm": ("arm-linux-gnueabihf-gcc", "arm-linux-gnueabihf-nm"),
}


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def build(src: str, out: str, compiler: str, extra=()) -> str:
    """Compile `src` into `out`; returns the output path (None if unavailable)."""
    if os.path.exists(out):
        return out
    if not have(compiler):
        return None
    cmd = [compiler, "-O0", "-g", "-fno-pie", "-no-pie", "-o", out, src]
    cmd[1:1] = list(extra)
    subprocess.check_call(cmd)
    return out


def nm_addr(binary: str, symbol: str, tool: str = "x86_64-linux-gnu-nm") -> int:
    """Address of `symbol` according to nm (no ARM Thumb mode bit)."""
    out = subprocess.check_output([tool, binary], text=True)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == symbol:
            return int(parts[0], 16)
    raise RuntimeError(f"symbol {symbol} not found in {binary}")
