"""Session, memory and limit behaviour of the emulator."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import ROOT, TESTS, build, nm_addr  # noqa: E402
from emulator import MAX_MEM_INPUT, MAX_READ, MAX_WRITE, SESSION  # noqa: E402

SAMPLE_BIN = os.path.join(TESTS, "sample_x64")
HARD_BIN = os.path.join(TESTS, "hardtest_x64")


def ensure_binaries():
    if not os.path.exists(SAMPLE_BIN):
        build(os.path.join(TESTS, "sample.c"), SAMPLE_BIN, "x86_64-linux-gnu-gcc")
    if not os.path.exists(HARD_BIN):
        build(os.path.join(TESTS, "hardtest.c"), HARD_BIN, "x86_64-linux-gnu-gcc")
    assert os.path.exists(SAMPLE_BIN)
    assert os.path.exists(HARD_BIN)


def test_failed_load_resets_the_session():
    """A failed load leaves an empty session behind."""
    ensure_binaries()
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    assert SESSION.loaded is not None
    with pytest.raises(Exception):
        SESSION.load("/nonexistent/binary")
    assert SESSION.loaded is None
    assert SESSION.uc is None
    with pytest.raises(RuntimeError):
        SESSION.run(0x1000)


def test_reset_clears_hooks_and_memory():
    ensure_binaries()
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    SESSION.hook_call(0x500000, 1, "stub")
    SESSION.write_mem(0x600000, "aabb")
    SESSION.reset()
    assert SESSION.hooks == []
    assert SESSION.extra_mem == []
    assert SESSION.loaded is None
    assert SESSION.last_regs == {}


def test_write_mem_is_persisted_across_runs():
    """emu_write_mem data is re-applied whenever the engine is rebuilt."""
    ensure_binaries()
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    buf = 0x500000
    SESSION.write_mem(buf, "0102030405")
    r = SESSION.run(nm_addr(SAMPLE_BIN, "xor_decrypt"), args=[buf, 5, 0xFF])
    assert r["stop_reason"] == "returned", r
    assert SESSION.read_mem(buf, 5, "hex") == "fefdfcfbfa"
    # every run starts from a clean engine: the explicit writes are restored
    # (and XORed again), the writes of the previous run are dropped
    SESSION.run(nm_addr(SAMPLE_BIN, "xor_decrypt"), args=[buf, 5, 0xFF])
    assert SESSION.read_mem(buf, 5, "hex") == "fefdfcfbfa"


def test_read_and_write_limits():
    ensure_binaries()
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    with pytest.raises(ValueError):
        SESSION.read_mem(0x500000, MAX_READ + 1)
    with pytest.raises(ValueError):
        SESSION.read_mem(0x500000, -1)
    with pytest.raises(ValueError):
        SESSION.read_mem(0x500000, 4, "utf8")
    with pytest.raises(ValueError):
        SESSION.write_mem(0x500000, "ab" * (MAX_WRITE + 1))
    with pytest.raises(ValueError):
        SESSION.write_mem(0x500000, "")
    with pytest.raises(ValueError):
        SESSION.write_mem(0x500000, "nothex")
    # reading unmapped memory reports the address
    with pytest.raises(RuntimeError):
        SESSION.read_mem(0x12345678, 4)


def test_mem_inputs_limit():
    ensure_binaries()
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    with pytest.raises(ValueError):
        SESSION.run(nm_addr(SAMPLE_BIN, "add"), args=[1, 2],
                    mem_inputs={"0x500000": "00" * (MAX_MEM_INPUT + 1)})


def test_instruction_limit():
    ensure_binaries()
    SESSION.reset()
    SESSION.load(HARD_BIN)
    r = SESSION.run(nm_addr(HARD_BIN, "factorial"), args=[1000], max_insns=500)
    assert r["stop_reason"] == "instruction limit exceeded", r
    assert r["instruction_count"] <= 501, r
    with pytest.raises(ValueError):
        SESSION.run(nm_addr(HARD_BIN, "factorial"), args=[1], max_insns=0)


def test_unmapped_call_is_reported():
    ensure_binaries()
    SESSION.reset()
    SESSION.load(HARD_BIN)
    r = SESSION.run(nm_addr(HARD_BIN, "apply_op"), args=[0xDEADBEEF, 1, 2])
    assert "unmapped" in r["stop_reason"], r
    assert r["stop_reason"].endswith("0xdeadbeef"), r


def test_trace_argument_validation():
    ensure_binaries()
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    with pytest.raises(ValueError):
        SESSION.trace(nm_addr(SAMPLE_BIN, "add"), limit=0)
    with pytest.raises(ValueError):
        SESSION.trace(nm_addr(SAMPLE_BIN, "add"), offset=-1)


def test_trace_reports_memory_access():
    ensure_binaries()
    SESSION.reset()
    SESSION.load(SAMPLE_BIN)
    out = SESSION.trace(nm_addr(SAMPLE_BIN, "crc32_simple"),
                         args=[0x500000, 4], mem_inputs={"0x500000": "01020304"},
                         limit=20)
    assert "mem reads:" in out, out
    assert "mem writes:" in out, out
    reads = int(out.split("mem reads: ")[1].split("\n")[0])
    writes = int(out.split("mem writes: ")[1].split("\n")[0])
    assert reads > 0, out
    assert writes > 0, out
