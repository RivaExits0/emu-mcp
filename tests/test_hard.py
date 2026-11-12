import os, subprocess, sys, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from emulator import SESSION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "tests", "hardtest_x64")

def ensure():
    if not os.path.exists(BIN):
        src = os.path.join(ROOT, "tests", "hardtest.c")
        subprocess.check_call(["x86_64-linux-gnu-gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-o", BIN, src])

def nm(name):
    out = subprocess.check_output(["x86_64-linux-gnu-nm", BIN], text=True)
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and p[2] == name:
            return int(p[0], 16)
    raise RuntimeError(name)

def run(name, *a, **kw):
    SESSION.reset()
    SESSION.load(BIN)
    addr = nm(name)
    return SESSION.run(addr, *a, **kw), addr

def main():
    ensure()

    # 1. recursion
    r,_ = run("factorial", args=[10])
    print("factorial(10)=", r["return_value"])
    assert r["return_value"] == 3628800

    # 2. function pointer indirect call
    mul_addr = nm("mul")
    add2_addr = nm("add2")
    apply_addr = nm("apply_op")
    SESSION.reset(); SESSION.load(BIN)
    r = SESSION.run(apply_addr, args=[mul_addr, 6, 7])
    print("apply_op(mul,6,7)=", r["return_value"])
    assert r["return_value"] == 42
    SESSION.reset(); SESSION.load(BIN)
    r = SESSION.run(apply_addr, args=[add2_addr, 6, 7])
    print("apply_op(add2,6,7)=", r["return_value"])
    assert r["return_value"] == 13

    # 3. many args (stack)
    r,_ = run("sum8", args=[1,2,3,4,5,6,7,8])
    print("sum8=", r["return_value"])
    assert r["return_value"] == 36

    # 4. struct by pointer
    SESSION.reset(); SESSION.load(BIN)
    pt_addr = 0x500000
    SESSION.write_mem(pt_addr, struct.pack("<qq", 3, 4).hex())
    r = SESSION.run(nm("dist2"), args=[pt_addr])
    print("dist2=", r["return_value"])
    assert r["return_value"] == 25

    # 5. in-place memory
    SESSION.reset(); SESSION.load(BIN)
    buf = 0x600000
    SESSION.write_mem(buf, "0102030405")
    r = SESSION.run(nm("reverse_bytes"), args=[buf, 5])
    print("reversed=", SESSION.read_mem(buf, 5, "hex"))
    assert SESSION.read_mem(buf, 5, "hex") == "0504030201"

    # 6. nested
    r,_ = run("nested", args=[10])
    print("nested(10)=", r["return_value"])
    assert r["return_value"] == 10 + 120 + 36

    # 7. libc hook strcmp
    SESSION.reset(); SESSION.load(BIN)
    SESSION.hook_call(0x401040, 0, "strcmp")  # 0 means equal
    r = SESSION.run(nm("check_str"), args=[0x700000])
    # write "SECRET" somewhere
    SESSION2 = None
    print("check_str (hooked strcmp=0)=", r["return_value"])
    # re-run with different hook value (nonzero => not equal)
    SESSION.reset(); SESSION.load(BIN)
    SESSION.hook_call(0x401040, 5, "strcmp")
    SESSION.write_mem(0x700000, "53454352455400")  # SECRET\0
    r = SESSION.run(nm("check_str"), args=[0x700000])
    print("check_str (hooked strcmp=5)=", r["return_value"])
    assert r["return_value"] == 0

    # 9. global state across runs? each run rebuilds engine => globals reset to initial (0)
    SESSION.reset(); SESSION.load(BIN)
    r = SESSION.run(nm("inc_global"), args=[])
    print("inc_global 1st=", r["return_value"])
    assert r["return_value"] == 1
    # second run resets global to 0 again (expected clean slate)
    r = SESSION.run(nm("inc_global"), args=[])
    print("inc_global 2nd (fresh engine)=", r["return_value"])
    assert r["return_value"] == 1

    # 10. find_byte
    SESSION.reset(); SESSION.load(BIN)
    buf = 0x500000
    SESSION.write_mem(buf, "001122334455")
    r = SESSION.run(nm("find_byte"), args=[buf, 6, 0x33])
    print("find_byte(0x33)=", r["return_value"])
    assert r["return_value"] == 3
    r = SESSION.run(nm("find_byte"), args=[buf, 6, 0x99])
    print("find_byte(0x99)=", r["return_value"])
    assert r["return_value"] == 0xFFFFFFFF

    # 11. instruction limit on recursion bomb
    SESSION.reset(); SESSION.load(BIN)
    r = SESSION.run(nm("factorial"), args=[1000], max_insns=500)
    print("factorial(1000) with limit 500 =>", r["stop_reason"], r["instruction_count"])
    assert r["stop_reason"] == "instruction limit exceeded"

    # 12. unmapped indirect call via corrupted function pointer
    SESSION.reset(); SESSION.load(BIN)
    r = SESSION.run(nm("apply_op"), args=[0xDEADBEEF, 1, 2])
    print("apply_op(bad ptr) =>", r["stop_reason"])
    assert "unmapped" in r["stop_reason"]

    # 13. floating point via xmm registers
    SESSION.reset(); SESSION.load(BIN)
    r = SESSION.run(nm("fadd"), args=[2.5, 3.25])
    val = struct.unpack("<d", struct.pack("<Q", r["registers"]["xmm0"]))[0]
    print("fadd(2.5,3.25)=", val)
    assert abs(val - 5.75) < 1e-9
    SESSION.reset(); SESSION.load(BIN)
    r = SESSION.run(nm("fsquare"), args=[4.0])
    val = struct.unpack("<d", struct.pack("<Q", r["registers"]["xmm0"]))[0]
    print("fsquare(4.0)=", val)
    assert abs(val - 16.0) < 1e-9

    print("\nALL HARD TESTS PASSED")


def test_hard_suite():
    """Pytest entry point: runs the full hard-test scenario set."""
    main()


if __name__ == "__main__":
    main()
