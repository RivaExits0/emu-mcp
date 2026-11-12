"""Smoke tests for emu-mcp emulator."""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from emulator import SESSION

BASE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(BASE, "sample_x64")


def ensure_binary():
    if not os.path.exists(BIN):
        src = os.path.join(BASE, "sample.c")
        subprocess.check_call(
            ["x86_64-linux-gnu-gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-o", BIN, src]
        )


def test_add():
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    r = SESSION.run(0x4011D0, args=[5, 7])
    assert r["return_value"] == 12, r
    assert r["stop_reason"] == "returned"
    print("test_add OK")


def test_xor():
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    buf = 0x500000
    data = bytes([0x10, 0x20, 0x30]).hex()
    r = SESSION.run(0x401180, args=[buf, 3, 0x55], mem_inputs={hex(buf): data})
    assert r["stop_reason"] == "returned"
    assert SESSION.read_mem(buf, 3, "hex") == "457565"
    print("test_xor OK")


def test_crc32():
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    buf = 0x600000
    r = SESSION.run(0x401106, args=[buf, 5], mem_inputs={str(buf): "48656c6c6f"})
    assert r["return_value"] == 0xF7D18982, r
    print("test_crc32 OK")


def test_hook():
    ensure_binary()
    # build hooktest if possible
    hookbin = os.path.join(BASE, "hooktest")
    if not os.path.exists(hookbin):
        src = os.path.join(BASE, "hooktest.c")
        if os.path.exists(src):
            subprocess.check_call(
                ["x86_64-linux-gnu-gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-o", hookbin, src]
            )
    if not os.path.exists(hookbin):
        print("hooktest binary missing, skip")
        return
    SESSION.reset()
    SESSION.load(hookbin)
    SESSION.hook_call(0x401050, 5, "strlen")
    buf = 0x500000
    SESSION.write_mem(buf, "41424300")
    r = SESSION.run(0x401156, args=[buf])
    assert r["return_value"] == 5, r
    print("test_hook OK")


def test_trace_limit():
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    out = SESSION.trace(0x4011D0, args=[5, 7], limit=5)
    assert len(out.splitlines()) <= 5, len(out.splitlines())
    print("test_trace OK")


if __name__ == "__main__":
    test_add()
    test_xor()
    test_crc32()
    test_hook()
    test_trace_limit()
    print("ALL TESTS PASSED")
