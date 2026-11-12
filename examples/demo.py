"""End-to-end demo of emu-mcp on a small ELF.

Run from the emu-mcp directory:
    python examples/demo.py
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from emulator import SESSION

SAMPLE_C = os.path.join(ROOT, "tests", "sample.c")
SAMPLE_BIN = os.path.join(ROOT, "tests", "sample_x64")
HOOK_C = os.path.join(ROOT, "tests", "hooktest.c")
HOOK_BIN = os.path.join(ROOT, "tests", "hooktest")


def build(src, out, extra=None):
    if os.path.exists(out):
        return
    cmd = ["x86_64-linux-gnu-gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-o", out, src]
    if extra:
        cmd[4:4] = extra
    subprocess.check_call(cmd)


def nm_addr(binary, symbol):
    out = subprocess.check_output(["x86_64-linux-gnu-nm", binary], text=True)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == symbol:
            return int(parts[0], 16)
    raise RuntimeError(f"symbol {symbol} not found")


def main():
    build(SAMPLE_C, SAMPLE_BIN)
    build(HOOK_C, HOOK_BIN)

    print("=== Demo 1: add(5, 7) ===")
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    add_addr = nm_addr(SAMPLE_BIN, "add")
    r = SESSION.run(add_addr, args=[5, 7])
    print(f"result={r['return_value']} stop={r['stop_reason']} insns={r['instruction_count']}")
    assert r["return_value"] == 12

    print("\n=== Demo 2: XOR decrypt ===")
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    xor_addr = nm_addr(SAMPLE_BIN, "xor_decrypt")
    buf = 0x500000
    ct = bytes([0x10, 0x20, 0x30]).hex()
    r = SESSION.run(xor_addr, args=[buf, 3, 0x55], mem_inputs={hex(buf): ct})
    print(f"stop={r['stop_reason']} mem={SESSION.read_mem(buf, 3, 'hex')}")
    assert SESSION.read_mem(buf, 3, "hex") == "457565"

    print("\n=== Demo 3: CRC32('Hello') ===")
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    crc_addr = nm_addr(SAMPLE_BIN, "crc32_simple")
    buf = 0x600000
    r = SESSION.run(crc_addr, args=[buf, 5], mem_inputs={str(buf): "48656c6c6f"})
    print(f"crc={hex(r['return_value'])} stop={r['stop_reason']}")
    assert r["return_value"] == 0xF7D18982

    print("\n=== Demo 4: hook strlen ===")
    SESSION.reset()
    SESSION.load(HOOK_BIN)
    plt_strlen = 0x401050
    SESSION.hook_call(plt_strlen, 5, "strlen")
    buf = 0x500000
    SESSION.write_mem(buf, "41424300")
    my_len_addr = nm_addr(HOOK_BIN, "my_len")
    r = SESSION.run(my_len_addr, args=[buf])
    print(f"my_len={r['return_value']} stop={r['stop_reason']}")
    assert r["return_value"] == 5

    print("\n=== Demo 5: trace add ===")
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    out = SESSION.trace(add_addr, args=[5, 7], limit=6)
    print(out)
    assert len(out.splitlines()) <= 6

    print("\nALL DEMO CHECKS PASSED")


if __name__ == "__main__":
    main()
