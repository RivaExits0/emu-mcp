"""Smoke tests for emu-mcp emulator."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import ROOT, TESTS, build, nm_addr  # noqa: E402
from emulator import SESSION  # noqa: E402

BASE = TESTS
BIN = os.path.join(BASE, "sample_x64")


def ensure_binary():
    if not os.path.exists(BIN):
        build(os.path.join(BASE, "sample.c"), BIN, "x86_64-linux-gnu-gcc")
    assert os.path.exists(BIN), "sample_x64 could not be built"
    return BIN


def addr(name):
    return nm_addr(BIN, name)


def test_add():
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    r = SESSION.run(addr("add"), args=[5, 7])
    assert r["return_value"] == 12, r
    assert r["stop_reason"] == "returned"
    print("test_add OK")


def test_xor():
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    buf = 0x500000
    data = bytes([0x10, 0x20, 0x30]).hex()
    r = SESSION.run(addr("xor_decrypt"), args=[buf, 3, 0x55], mem_inputs={hex(buf): data})
    assert r["stop_reason"] == "returned"
    assert SESSION.read_mem(buf, 3, "hex") == "457565"
    print("test_xor OK")


def test_crc32():
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    buf = 0x600000
    r = SESSION.run(addr("crc32_simple"), args=[buf, 5], mem_inputs={str(buf): "48656c6c6f"})
    assert r["return_value"] == 0xF7D18982, r
    print("test_crc32 OK")


def test_hook():
    ensure_binary()
    # build hooktest if possible
    hookbin = os.path.join(BASE, "hooktest")
    if not os.path.exists(hookbin):
        src = os.path.join(BASE, "hooktest.c")
        if os.path.exists(src):
            build(src, hookbin, "x86_64-linux-gnu-gcc")
    if not os.path.exists(hookbin):
        print("hooktest binary missing, skip")
        return
    SESSION.reset()
    SESSION.load(hookbin)
    SESSION.hook_call(0x401050, 5, "strlen")
    buf = 0x500000
    SESSION.write_mem(buf, "41424300")
    r = SESSION.run(nm_addr(hookbin, "my_len"), args=[buf])
    assert r["return_value"] == 5, r
    print("test_hook OK")


def test_trace_limit():
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    out = SESSION.trace(addr("add"), args=[5, 7], limit=3)
    lines = out.splitlines()
    # the address list is capped by `limit`, the summary lines are extra
    addresses = [line for line in lines if line.startswith("  0x")]
    assert len(addresses) <= 3, out
    assert lines[0].startswith("stop: returned"), out
    assert any(line.startswith("mem reads:") for line in lines), out
    assert any(line.startswith("mem writes:") for line in lines), out
    print("test_trace OK")


def test_trace_pagination():
    """offset pages through the full address list without gaps."""
    ensure_binary()
    SESSION.reset()
    SESSION.load(BIN)
    full = SESSION.trace(addr("add"), args=[5, 7], limit=100)
    everything = [line.strip() for line in full.splitlines() if line.startswith("  0x")]
    assert len(everything) > 3, full
    page = SESSION.trace(addr("add"), args=[5, 7], limit=2, offset=1)
    paged = [line.strip() for line in page.splitlines() if line.startswith("  0x")]
    assert paged == everything[1:3], (paged, everything)
    print("test_trace_pagination OK")


if __name__ == "__main__":
    test_add()
    test_xor()
    test_crc32()
    test_hook()
    test_trace_limit()
    test_trace_pagination()
    print("ALL TESTS PASSED")
