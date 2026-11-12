"""Calling convention tests: stack arguments, float arguments and stubs.

Every architecture is exercised with the same source file (tests/abi.c). The
cross compiled binaries are built on demand; tests are skipped when the
toolchain is not installed.
"""

import os
import struct

import pytest

from common import ROOT, TESTS, TOOLCHAIN, build, have
from emulator import SESSION

ARCHES = ["x64", "x86", "arm64", "arm"]
SRC = os.path.join(TESTS, "abi.c")

# architecture -> floating point return register.
# Unicorn does not implement the ARM VFP instruction set, so the 32 bit ARM
# float paths cannot be executed and are not covered here.
FP_RET_REG = {"x64": "xmm0", "arm64": "v0"}

# architecture -> stack pointer register
SP_REG = {"x64": "rsp", "x86": "esp", "arm": "sp", "arm64": "sp"}


def load_abi(arch):
    """Build and load the ABI test binary, returns None when unavailable."""
    compiler, _ = TOOLCHAIN[arch]
    if not have(compiler):
        return None
    binary = build(SRC, os.path.join(TESTS, f"abi_{arch}"), compiler)
    if binary is None:
        return None
    SESSION.reset()
    SESSION.load(binary)
    return binary


def symbol(name):
    """Raw symbol address (keeps the ARM Thumb mode bit)."""
    value = SESSION.loaded.symbols.get(name)
    assert value is not None, f"symbol {name} missing"
    return value


def fp_return(result, arch):
    reg = FP_RET_REG[arch]
    bits = result["registers"].get(reg)
    assert bits is not None, f"register {reg} missing"
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


@pytest.mark.parametrize("arch", ARCHES)
def test_stack_arguments(arch):
    """Arguments beyond the register limit are passed on the stack."""
    if load_abi(arch) is None:
        pytest.skip(f"no toolchain for {arch}")
    r = SESSION.run(symbol("sum7"), args=[1, 2, 3, 4, 5, 6, 7])
    assert r["stop_reason"] == "returned", r
    assert r["return_value"] == 28, r
    r = SESSION.run(symbol("sum10"), args=list(range(1, 11)))
    assert r["stop_reason"] == "returned", r
    assert r["return_value"] == 55, r


@pytest.mark.parametrize("arch", ARCHES)
def test_stack_alignment(arch):
    """The stack pointer is aligned as required by the ABI at entry.

    After a normal return the stack pointer is back at its entry value (plus
    the popped return address), so its alignment proves that the emulated
    function was entered with a correctly aligned stack.
    """
    if load_abi(arch) is None:
        pytest.skip(f"no toolchain for {arch}")
    r = SESSION.run(symbol("sum7"), args=[1, 2, 3, 4, 5, 6, 7])
    assert r["stop_reason"] == "returned", r
    sp = r["registers"][SP_REG[arch]]
    assert sp % 8 == 0, (arch, hex(sp))
    if arch != "arm":
        assert sp % 16 == 0, (arch, hex(sp))


@pytest.mark.parametrize("arch", ARCHES)
def test_negative_and_large_arguments(arch):
    """Negative and oversized arguments must not raise."""
    if load_abi(arch) is None:
        pytest.skip(f"no toolchain for {arch}")
    r = SESSION.run(symbol("sum7"), args=[-1, -2, -3, -4, -5, -6, -7])
    assert r["stop_reason"] == "returned", r
    # the raw register value is reported, so -28 shows up as its unsigned form
    mask = 0xFFFFFFFF if arch in ("x86", "arm") else 0xFFFFFFFFFFFFFFFF
    assert r["return_value"] == (-28) & mask, r
    r = SESSION.run(symbol("sum7"), args=[0x7FFFFFFFFFFFFFFF, 1, 2, 3, 4, 5, 6])
    assert r["stop_reason"] == "returned", r


@pytest.mark.parametrize("arch", [a for a in ARCHES if a in FP_RET_REG])
def test_float_arguments(arch):
    """Floating point arguments use the SIMD argument registers."""
    if load_abi(arch) is None:
        pytest.skip(f"no toolchain for {arch}")
    r = SESSION.run(symbol("add_double"), args=[2.5, 3.25])
    assert r["stop_reason"] == "returned", r
    assert abs(fp_return(r, arch) - 5.75) < 1e-9, r
    r = SESSION.run(symbol("mix_args"), args=[1, 2.5, 3, 4.5])
    assert r["stop_reason"] == "returned", r
    assert abs(fp_return(r, arch) - 11.0) < 1e-9, r


@pytest.mark.parametrize("arch", ARCHES)
def test_call_stub(arch):
    """A stubbed call returns the configured value."""
    if load_abi(arch) is None:
        pytest.skip(f"no toolchain for {arch}")
    SESSION.hook_call(symbol("multiply"), 99, "multiply")
    r = SESSION.run(symbol("call_multiply"), args=[2, 3])
    assert r["stop_reason"] == "returned", r
    assert r["return_value"] == 99, r


@pytest.mark.parametrize("arch", [a for a in ARCHES if a in FP_RET_REG])
def test_float_stub(arch):
    """A stub with a float return value lands in the floating point register."""
    if load_abi(arch) is None:
        pytest.skip(f"no toolchain for {arch}")
    SESSION.hook_call(symbol("add_double"), 2.5, "add_double")
    r = SESSION.run(symbol("add_double"), args=[1.0, 2.0])
    assert r["stop_reason"] == "returned", r
    assert abs(fp_return(r, arch) - 2.5) < 1e-9, r
