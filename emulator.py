"""Unicorn-based isolated function emulator for emu-mcp."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from unicorn import (
    Uc,
    UC_ARCH_X86, UC_MODE_16, UC_MODE_32, UC_MODE_64,
    UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB,
    UC_ARCH_ARM64,
    UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_INTR,
    UC_ERR_OK,
)
import capstone

from loader import LoadedBinary, load_binary


PAGE = 0x1000
STACK_BASE = 0x70000000
STACK_SIZE = 0x100000
# Highest usable stack address. A margin is kept below the end of the mapped
# stack so that the initial stack pointer always points at mapped memory.
STACK_TOP = STACK_BASE + STACK_SIZE - 0x100
SENTINEL = 0x0F000000
STUB_PAGE = 0x0E000000

# Hard limits keeping a single tool call bounded.
MAX_READ = 4096
MAX_WRITE = 65536
MAX_MEM_INPUT = 1 << 20
MAX_TRACE_ADDRS = 200000
MAX_TRACE_MEM = 1000
DEFAULT_MAX_INSNS = 100000
DEFAULT_TIMEOUT_MS = 5000


@dataclass
class Stub:
    addr: int
    return_value: int
    name: Optional[str] = None
    # True when the stub returns a floating point value (raw IEEE-754 bits).
    is_float: bool = False


@dataclass
class EmuSession:
    loaded: Optional[LoadedBinary] = None
    arch: Optional[str] = None
    hooks: List[Stub] = field(default_factory=list)
    # runtime
    uc: Optional[Uc] = None
    mapped_pages: set = field(default_factory=set)
    thumb: bool = False
    insn_count: int = 0
    stop_reason: str = ""
    trace_enabled: bool = False
    trace_limit: int = 50
    trace_code: List[int] = field(default_factory=list)
    trace_reads: List[Tuple[int, int]] = field(default_factory=list)
    trace_writes: List[Tuple[int, int]] = field(default_factory=list)
    # total number of memory accesses, even when the lists above are capped
    trace_read_count: int = 0
    trace_write_count: int = 0
    # last run info
    last_regs: Dict[str, int] = field(default_factory=dict)
    # persisted writes from emu_write_mem (kept in write order)
    extra_mem: List[Tuple[int, bytes]] = field(default_factory=list)

    # ---------- loading ----------

    def load(self, path: str, arch: Optional[str] = None) -> dict:
        # A new load always starts from a clean session; if the load fails the
        # session stays empty instead of keeping a stale binary around.
        self.reset()
        lb = load_binary(path, arch)
        self.loaded = lb
        self.arch = lb.arch
        self.uc = self._build_engine()
        self.stop_reason = "loaded"
        return {
            "path": lb.path,
            "format": lb.format,
            "arch": lb.arch,
            "segments": len(lb.segments),
            "symbols": len(lb.symbols),
        }

    def reset(self) -> None:
        self.loaded = None
        self.arch = None
        self.hooks = []
        self.uc = None
        self.mapped_pages = set()
        self.thumb = False
        self.insn_count = 0
        self.stop_reason = ""
        self.trace_enabled = False
        self.trace_limit = 50
        self.trace_code = []
        self.trace_reads = []
        self.trace_writes = []
        self.trace_read_count = 0
        self.trace_write_count = 0
        self.extra_mem = []
        self.last_regs = {}

    # ---------- engine ----------

    def _uc_arch_mode(self, thumb: bool = False):
        if self.arch == "x86":
            return UC_ARCH_X86, UC_MODE_32
        if self.arch == "x64":
            return UC_ARCH_X86, UC_MODE_64
        if self.arch == "arm":
            if thumb:
                return UC_ARCH_ARM, UC_MODE_THUMB
            return UC_ARCH_ARM, UC_MODE_ARM
        if self.arch == "arm64":
            return UC_ARCH_ARM64, UC_MODE_ARM
        raise ValueError(f"unknown arch {self.arch}")

    def _page_align_down(self, a):
        return a & ~(PAGE - 1)

    def _map_region(self, uc, base, size, data=None, prot=UC_PROT_ALL):
        if size <= 0:
            return
        aligned = self._page_align_down(base)
        end = base + size
        aligned_end = (end + PAGE - 1) & ~(PAGE - 1)
        cur = aligned
        while cur < aligned_end:
            if cur not in self.mapped_pages:
                uc.mem_map(cur, PAGE, prot)
                self.mapped_pages.add(cur)
            cur += PAGE
        if data:
            uc.mem_write(base, data)

    def _build_engine(self, mem_inputs: Optional[Dict[str, str]] = None, thumb: bool = False) -> Uc:
        if self.loaded is None:
            raise RuntimeError("no binary loaded; call emu_load first")
        self.mapped_pages = set()
        self.thumb = thumb
        arch, mode = self._uc_arch_mode(thumb)
        uc = Uc(arch, mode)
        # map segments
        for base, data in self.loaded.segments:
            end = base + len(data)
            if base < STACK_BASE + STACK_SIZE and end > STACK_BASE:
                raise ValueError(
                    "binary segment at 0x%x overlaps the emulator stack region" % base)
            self._map_region(uc, base, len(data), data)
        # stack
        self._map_region(uc, STACK_BASE, STACK_SIZE)
        # sentinel page: the emulated function "returns" here
        self._map_region(uc, SENTINEL, PAGE)
        # stub pages (a stub may live outside of the loaded binary)
        for st in self.hooks:
            self._map_region(uc, self._page_align_down(st.addr), PAGE)
        # persisted writes
        for addr, data in self.extra_mem:
            self._map_region(uc, addr, len(data))
            uc.mem_write(addr, data)
        # mem_inputs
        if mem_inputs:
            total = 0
            for k, v in mem_inputs.items():
                addr = self._parse_int(k)
                data = self._hex_to_bytes(v)
                total += len(data)
                if total > MAX_MEM_INPUT:
                    raise ValueError(f"mem_inputs exceed the {MAX_MEM_INPUT} byte limit")
                if not data:
                    continue
                self._map_region(uc, addr, len(data))
                uc.mem_write(addr, data)
        return uc

    @staticmethod
    def _parse_int(x) -> int:
        if isinstance(x, int):
            return x
        s = str(x).strip()
        try:
            return int(s, 0)
        except ValueError:
            return int(s, 16)

    @staticmethod
    def _strip_hex(v) -> str:
        s = str(v).strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        s = s.replace(" ", "").replace("\n", "")
        return s

    @staticmethod
    def _hex_to_bytes(v) -> bytes:
        s = EmuSession._strip_hex(v)
        if len(s) % 2:
            s = "0" + s
        if not s:
            return b""
        try:
            return bytes.fromhex(s)
        except ValueError as e:
            raise ValueError(f"invalid hex data: {e}") from None

    # ---------- registers ----------

    def _reg_constants(self):
        # returns dict name->constant for reading
        if self.arch == "x86":
            import unicorn.x86_const as C
            return {
                "eax": C.UC_X86_REG_EAX, "ebx": C.UC_X86_REG_EBX,
                "ecx": C.UC_X86_REG_ECX, "edx": C.UC_X86_REG_EDX,
                "esi": C.UC_X86_REG_ESI, "edi": C.UC_X86_REG_EDI,
                "ebp": C.UC_X86_REG_EBP, "esp": C.UC_X86_REG_ESP,
                "eip": C.UC_X86_REG_EIP,
            }
        if self.arch == "x64":
            import unicorn.x86_const as C
            regs = {
                "rax": C.UC_X86_REG_RAX, "rbx": C.UC_X86_REG_RBX,
                "rcx": C.UC_X86_REG_RCX, "rdx": C.UC_X86_REG_RDX,
                "rsi": C.UC_X86_REG_RSI, "rdi": C.UC_X86_REG_RDI,
                "rbp": C.UC_X86_REG_RBP, "rsp": C.UC_X86_REG_RSP,
                "r8": C.UC_X86_REG_R8, "r9": C.UC_X86_REG_R9,
                "r10": C.UC_X86_REG_R10, "r11": C.UC_X86_REG_R11,
                "r12": C.UC_X86_REG_R12, "r13": C.UC_X86_REG_R13,
                "r14": C.UC_X86_REG_R14, "r15": C.UC_X86_REG_R15,
                "rip": C.UC_X86_REG_RIP,
            }
            for i in range(8):
                regs[f"xmm{i}"] = getattr(C, f"UC_X86_REG_XMM{i}")
            return regs
        if self.arch == "arm":
            import unicorn.arm_const as C
            regs = {}
            for i in range(16):
                regs[f"r{i}"] = getattr(C, f"UC_ARM_REG_R{i}")
            regs["pc"] = C.UC_ARM_REG_PC
            regs["sp"] = C.UC_ARM_REG_SP
            regs["lr"] = C.UC_ARM_REG_LR
            regs["cpsr"] = C.UC_ARM_REG_CPSR
            for i in range(8):
                regs[f"d{i}"] = getattr(C, f"UC_ARM_REG_D{i}")
            return regs
        if self.arch == "arm64":
            import unicorn.arm64_const as C
            regs = {}
            for i in range(31):
                regs[f"x{i}"] = getattr(C, f"UC_ARM64_REG_X{i}")
            regs["sp"] = C.UC_ARM64_REG_SP
            regs["pc"] = C.UC_ARM64_REG_PC
            regs["lr"] = C.UC_ARM64_REG_LR
            for i in range(8):
                regs[f"v{i}"] = getattr(C, f"UC_ARM64_REG_V{i}")
            return regs
        raise ValueError(self.arch)

    def _pc_name(self):
        if self.arch in ("x86",):
            return "eip"
        if self.arch == "x64":
            return "rip"
        if self.arch == "arm":
            return "pc"
        if self.arch == "arm64":
            return "pc"
        return "pc"

    def _sp_name(self):
        if self.arch == "x86":
            return "esp"
        if self.arch == "x64":
            return "rsp"
        if self.arch == "arm":
            return "sp"
        if self.arch == "arm64":
            return "sp"
        return "sp"

    def _ret_reg_name(self):
        if self.arch == "x86":
            return "eax"
        if self.arch == "x64":
            return "rax"
        if self.arch == "arm":
            return "r0"
        if self.arch == "arm64":
            return "x0"
        return "r0"

    def _float_ret_reg_name(self):
        """Register holding a floating point return value (if any)."""
        if self.arch == "x64":
            return "xmm0"
        if self.arch == "arm":
            return "d0"
        if self.arch == "arm64":
            return "v0"
        return ""

    def _word_size(self):
        if self.arch in ("x86", "arm"):
            return 4
        return 8

    def _reg_mask(self, name: str) -> int:
        """Width mask of a general purpose register."""
        if self.arch == "x86":
            return 0xFFFFFFFF
        if self.arch == "arm":
            return 0xFFFFFFFF
        return 0xFFFFFFFFFFFFFFFF

    def _read_regs(self, uc) -> Dict[str, int]:
        out = {}
        for name, c in self._reg_constants().items():
            try:
                out[name] = uc.reg_read(c)
            except Exception:
                pass
        return out

    # ---------- args setup ----------

    @staticmethod
    def _to_int(a) -> int:
        if isinstance(a, bool):
            return int(a)
        if isinstance(a, int):
            return a
        if isinstance(a, str):
            s = a.strip()
            try:
                return int(s, 0)
            except ValueError:
                # maybe hex without 0x
                return int(s, 16)
        return int(a)

    @staticmethod
    def _to_bytes(value: int, size: int) -> bytes:
        """Little endian encoding of an integer, truncated to `size` bytes."""
        mask = (1 << (size * 8)) - 1
        return (value & mask).to_bytes(size, "little")

    @staticmethod
    def _double_bits(value: float) -> int:
        return struct.unpack("<Q", struct.pack("<d", float(value)))[0]

    def _parse_args(self, args) -> List[Tuple[bool, Any]]:
        """Normalize the argument list into (is_float, value) pairs."""
        if args is None:
            return []
        if not isinstance(args, (list, tuple)):
            args = [args]
        parsed: List[Tuple[bool, Any]] = []
        for a in args:
            if isinstance(a, float):
                parsed.append((True, a))
            else:
                parsed.append((False, self._to_int(a)))
        return parsed

    def _stack_base(self, total: int, align: int, mod: int) -> int:
        """Lowest usable stack address for `total` bytes.

        The returned address satisfies `base % align == mod`, which encodes the
        stack alignment required by the corresponding ABI at function entry.
        """
        base = STACK_TOP - total
        base -= (base - mod) % align
        if base < STACK_BASE:
            raise RuntimeError("not enough stack space for the arguments")
        return base

    def _setup_args(self, uc, func_addr, args):
        parsed = self._parse_args(args)
        if self.arch == "x86":
            self._setup_x86_args(uc, func_addr, parsed)
        elif self.arch == "x64":
            self._setup_x64_args(uc, func_addr, parsed)
        elif self.arch == "arm":
            self._setup_arm_args(uc, func_addr, parsed)
        elif self.arch == "arm64":
            self._setup_arm64_args(uc, func_addr, parsed)
        else:
            raise ValueError(f"unknown arch {self.arch}")

    def _setup_x86_args(self, uc, func_addr, parsed):
        """x86 cdecl: every argument is pushed on the stack, right to left."""
        import unicorn.x86_const as C
        # slots: (size, data) in argument order, lowest address first
        slots: List[Tuple[int, bytes]] = []
        for is_float, value in parsed:
            if is_float:
                slots.append((8, struct.pack("<d", value)))
            else:
                slots.append((4, self._to_bytes(value, 4)))
        total = 4 + sum(s[0] for s in slots)  # + return address slot
        # The i386 ABI wants ESP % 16 == 12 at function entry.
        base = self._stack_base(total, 16, 12)
        off = base + 4
        for size, data in slots:
            uc.mem_write(off, data)
            off += size
        uc.mem_write(base, self._to_bytes(SENTINEL, 4))
        uc.reg_write(C.UC_X86_REG_ESP, base)
        uc.reg_write(C.UC_X86_REG_EIP, func_addr & 0xFFFFFFFF)

    def _setup_x64_args(self, uc, func_addr, parsed):
        """x86-64 SysV: integer args in rdi..r9, float args in xmm0..xmm7."""
        import unicorn.x86_const as C
        int_regs = [C.UC_X86_REG_RDI, C.UC_X86_REG_RSI, C.UC_X86_REG_RDX,
                    C.UC_X86_REG_RCX, C.UC_X86_REG_R8, C.UC_X86_REG_R9]
        xmm_regs = [getattr(C, f"UC_X86_REG_XMM{i}") for i in range(8)]
        int_idx = 0
        xmm_idx = 0
        stack_slots: List[Tuple[int, bytes]] = []
        for is_float, value in parsed:
            if is_float:
                bits = self._double_bits(value)
                if xmm_idx < len(xmm_regs):
                    uc.reg_write(xmm_regs[xmm_idx], bits)
                    xmm_idx += 1
                else:
                    stack_slots.append((8, struct.pack("<Q", bits)))
            else:
                val = value & 0xFFFFFFFFFFFFFFFF
                if int_idx < len(int_regs):
                    uc.reg_write(int_regs[int_idx], val)
                    int_idx += 1
                else:
                    stack_slots.append((8, struct.pack("<Q", val)))
        total = 8 + sum(s[0] for s in stack_slots)  # + return address slot
        # The SysV ABI wants RSP % 16 == 8 at function entry.
        base = self._stack_base(total, 16, 8)
        off = base + 8
        for size, data in stack_slots:
            uc.mem_write(off, data)
            off += size
        uc.mem_write(base, struct.pack("<Q", SENTINEL))
        uc.reg_write(C.UC_X86_REG_RSP, base)
        uc.reg_write(C.UC_X86_REG_RIP, func_addr & 0xFFFFFFFFFFFFFFFF)

    def _setup_arm_args(self, uc, func_addr, parsed):
        """ARM AAPCS: core args in r0..r3, float args in d0..d7."""
        import unicorn.arm_const as C
        core_regs = [getattr(C, f"UC_ARM_REG_R{i}") for i in range(4)]
        simd_regs = [getattr(C, f"UC_ARM_REG_D{i}") for i in range(8)]
        core_idx = 0
        simd_idx = 0
        stack_slots: List[Tuple[int, int, bytes]] = []
        for is_float, value in parsed:
            if is_float:
                bits = self._double_bits(value)
                if simd_idx < len(simd_regs):
                    uc.reg_write(simd_regs[simd_idx], bits)
                    simd_idx += 1
                else:
                    stack_slots.append((8, 8, struct.pack("<Q", bits)))
            else:
                val = value & 0xFFFFFFFF
                if core_idx < len(core_regs):
                    uc.reg_write(core_regs[core_idx], val)
                    core_idx += 1
                else:
                    stack_slots.append((4, 4, self._to_bytes(value, 4)))
        # AAPCS wants an 8 byte aligned SP at a public interface.
        total = sum(s[0] for s in stack_slots)
        base = self._stack_base(total, 8, 0)
        off = base
        for size, align, data in stack_slots:
            off = (off + align - 1) & ~(align - 1)
            uc.mem_write(off, data)
            off += size
        uc.reg_write(C.UC_ARM_REG_SP, base)
        uc.reg_write(C.UC_ARM_REG_PC, func_addr | (1 if self.thumb else 0))
        uc.reg_write(C.UC_ARM_REG_LR, SENTINEL | (1 if self.thumb else 0))

    def _setup_arm64_args(self, uc, func_addr, parsed):
        """ARM64 AAPCS64: core args in x0..x7, float args in v0..v7."""
        import unicorn.arm64_const as C
        core_regs = [getattr(C, f"UC_ARM64_REG_X{i}") for i in range(8)]
        simd_regs = [getattr(C, f"UC_ARM64_REG_V{i}") for i in range(8)]
        core_idx = 0
        simd_idx = 0
        stack_slots: List[Tuple[int, bytes]] = []
        for is_float, value in parsed:
            if is_float:
                bits = self._double_bits(value)
                if simd_idx < len(simd_regs):
                    uc.reg_write(simd_regs[simd_idx], bits)
                    simd_idx += 1
                else:
                    stack_slots.append((8, struct.pack("<Q", bits)))
            else:
                val = value & 0xFFFFFFFFFFFFFFFF
                if core_idx < len(core_regs):
                    uc.reg_write(core_regs[core_idx], val)
                    core_idx += 1
                else:
                    stack_slots.append((8, struct.pack("<Q", val)))
        # AAPCS64 wants a 16 byte aligned SP at a public interface.
        total = sum(s[0] for s in stack_slots)
        base = self._stack_base(total, 16, 0)
        off = base
        for size, data in stack_slots:
            uc.mem_write(off, data)
            off += size
        uc.reg_write(C.UC_ARM64_REG_SP, base)
        uc.reg_write(C.UC_ARM64_REG_PC, func_addr & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(C.UC_ARM64_REG_LR, SENTINEL)

    # ---------- stub handling ----------

    def add_stub(self, addr, return_value, name=None):
        addr = self._to_int(addr)
        if isinstance(return_value, float):
            rv = self._double_bits(return_value)
            is_float = True
        else:
            rv = self._to_int(return_value) & self._reg_mask(self._ret_reg_name())
            is_float = False
        st = Stub(addr=addr, return_value=rv, name=name, is_float=is_float)
        self.hooks.append(st)
        return st

    def _same_addr(self, a: int, b: int) -> bool:
        """Compare two code addresses.

        Unicorn reports Thumb addresses without the mode bit, so the low bit
        is ignored on ARM.
        """
        if self.arch == "arm":
            return (a | 1) == (b | 1)
        return a == b

    def _apply_stub(self, uc, stub):
        ws = self._word_size()
        regs = self._reg_constants()
        # set return register
        if stub.is_float:
            freg = self._float_ret_reg_name()
            if freg:
                uc.reg_write(regs[freg], stub.return_value)
        else:
            rr = self._ret_reg_name()
            uc.reg_write(regs[rr], stub.return_value & self._reg_mask(rr))
        # redirect to return address
        if self.arch in ("x86", "x64"):
            sp = uc.reg_read(regs[self._sp_name()])
            retaddr = int.from_bytes(uc.mem_read(sp, ws), "little")
            sp += ws
            uc.reg_write(regs[self._sp_name()], sp)
            pcname = self._pc_name()
            uc.reg_write(regs[pcname], retaddr)
        elif self.arch == "arm":
            import unicorn.arm_const as C
            lr = uc.reg_read(C.UC_ARM_REG_LR)
            uc.reg_write(C.UC_ARM_REG_PC, lr)
        elif self.arch == "arm64":
            import unicorn.arm64_const as C
            lr = uc.reg_read(C.UC_ARM64_REG_LR)
            uc.reg_write(C.UC_ARM64_REG_PC, lr)

    # ---------- run ----------

    def _detect_thumb(self, uc, addr):
        """Decide whether the code at `addr` is Thumb code."""
        if self.arch != "arm":
            return False
        if addr & 1:
            return True
        lb = self.loaded
        if lb is not None:
            # ARM mapping symbols ($t / $a / $d) describe the code state.
            marker = None
            for m_addr, is_thumb in lb.arm_modes:
                if m_addr <= addr and (marker is None or m_addr >= marker[0]):
                    marker = (m_addr, is_thumb)
            if marker is not None:
                return marker[1]
            # A function symbol with bit 0 set marks a Thumb function.
            for value in lb.symbols.values():
                if value & 1 and (value & ~1) == addr:
                    return True
        return self._heuristic_thumb(uc, addr)

    @staticmethod
    def _heuristic_thumb(uc, addr):
        """Fallback heuristic: compare ARM and Thumb disassembly."""
        try:
            data = uc.mem_read(addr, 4)
        except Exception:
            return False
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
        md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        arm_insns = list(md_arm.disasm(data, addr))
        thumb_insns = list(md_thumb.disasm(data[:2], addr))
        if not thumb_insns:
            return False
        if not arm_insns:
            return True
        conds = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"]
        bases = ["mov", "add", "sub", "cmp", "ldr", "str", "stm", "ldm", "b", "bl", "bx", "push", "pop"]
        mn = arm_insns[0].mnemonic.lower()
        for base in bases:
            for cond in conds:
                if mn == base + cond:
                    return True
        return False

    def _prepare(self, func_addr, args, mem_inputs, max_insns, timeout_ms, trace):
        """Build the engine, set up the arguments and install the hooks."""
        if self.loaded is None:
            raise RuntimeError("no binary loaded; call emu_load first")
        func_addr = self._to_int(func_addr)
        if max_insns < 1:
            raise ValueError("max_insns must be >= 1")
        if timeout_ms < 1:
            raise ValueError("timeout_ms must be >= 1")
        args = args or []
        mem_inputs = mem_inputs or {}

        self.trace_enabled = trace
        self.trace_code = []
        self.trace_reads = []
        self.trace_writes = []
        self.trace_read_count = 0
        self.trace_write_count = 0
        self.insn_count = 0
        self.stop_reason = ""

        thumb = self.arch == "arm" and bool(func_addr & 1)
        uc = self._build_engine(mem_inputs=mem_inputs, thumb=thumb)
        if self.arch == "arm" and not thumb:
            if self._detect_thumb(uc, func_addr & ~1):
                thumb = True
                self.thumb = True
                uc = self._build_engine(mem_inputs=mem_inputs, thumb=True)
        self.thumb = thumb
        # map stub pages (a stub may point outside of the loaded binary)
        for st in self.hooks:
            self._map_region(uc, self._page_align_down(st.addr), PAGE)
        self.uc = uc
        # setup args
        self._setup_args(uc, func_addr, args)
        # hooks
        self._install_hooks(uc, max_insns, timeout_ms, trace=trace)
        if self.arch == "arm" and (self.thumb or (func_addr & 1)):
            pc_start = (func_addr & ~1) | 1
        else:
            pc_start = func_addr
        return uc, pc_start

    def _execute(self, func_addr, args=None, mem_inputs=None,
                 max_insns=DEFAULT_MAX_INSNS, timeout_ms=DEFAULT_TIMEOUT_MS,
                 trace=False):
        uc, pc_start = self._prepare(func_addr, args, mem_inputs, max_insns,
                                     timeout_ms, trace)
        t0 = time.time()
        try:
            uc.emu_start(pc_start, 0, timeout=timeout_ms * 1000, count=max_insns)
        except Exception as e:
            if not self.stop_reason:
                self.stop_reason = self._friendly_error(str(e), uc)
        # determine stop reason
        if not self.stop_reason:
            pcname = self._pc_name()
            regs = self._reg_constants()
            try:
                pc = uc.reg_read(regs[pcname])
            except Exception:
                pc = 0
            if pc == SENTINEL:
                self.stop_reason = "returned"
            elif pc == 0:
                # emu_start stops at address 0 without raising an error
                self.stop_reason = "unmapped memory fetch at 0x0"
            else:
                self.stop_reason = "stopped"
        if self.stop_reason == "stopped" and self.insn_count >= max_insns:
            self.stop_reason = "instruction limit exceeded"
        if (not self.stop_reason or self.stop_reason == "stopped") and \
                (time.time() - t0) > timeout_ms / 1000.0:
            self.stop_reason = "timeout"
        self.last_regs = self._read_regs(uc)
        return self.last_regs

    def run(self, func_addr, args=None, mem_inputs=None,
            max_insns=DEFAULT_MAX_INSNS, timeout_ms=DEFAULT_TIMEOUT_MS):
        regs = self._execute(func_addr, args, mem_inputs, max_insns, timeout_ms,
                             trace=False)
        rv = regs.get(self._ret_reg_name())
        return {
            "return_value": rv,
            "registers": regs,
            "instruction_count": self.insn_count,
            "stop_reason": self.stop_reason,
        }

    def trace(self, func_addr, args=None, mem_inputs=None, limit=50, offset=0,
              max_insns=DEFAULT_MAX_INSNS, timeout_ms=DEFAULT_TIMEOUT_MS):
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        self.trace_limit = limit
        self._execute(func_addr, args, mem_inputs, max_insns, timeout_ms,
                      trace=True)
        # build output lines
        lines = []
        lines.append(f"stop: {self.stop_reason}, insns: {self.insn_count}")
        lines.append("called addresses:")
        total = len(self.trace_code)
        page = self.trace_code[offset:offset + limit]
        for a in page:
            lines.append(f"  0x{a:x}")
        if offset + len(page) < total:
            lines.append(f"  ... ({total} total, showing {offset}-{offset + len(page) - 1}, "
                         f"next offset {offset + len(page)})")
        cap = max(1, limit // 5)
        lines.append(f"mem reads: {self.trace_read_count}")
        for a, sz in self.trace_reads[:cap]:
            lines.append(f"  R 0x{a:x} ({sz})")
        if self.trace_read_count > cap:
            lines.append(f"  ... ({self.trace_read_count} total)")
        lines.append(f"mem writes: {self.trace_write_count}")
        for a, sz in self.trace_writes[:cap]:
            lines.append(f"  W 0x{a:x} ({sz})")
        if self.trace_write_count > cap:
            lines.append(f"  ... ({self.trace_write_count} total)")
        return "\n".join(lines)

    def _install_hooks(self, uc, max_insns, timeout_ms, trace):
        regs = self._reg_constants()
        deadline = time.time() + timeout_ms / 1000.0
        # code hook
        def code_hook(uc, address, size, user_data):
            self.insn_count += 1
            if trace and len(self.trace_code) < MAX_TRACE_ADDRS:
                self.trace_code.append(address)
            # stub check
            for st in self.hooks:
                if self._same_addr(address, st.addr):
                    self._apply_stub(uc, st)
                    return
            # instruction limit
            if self.insn_count > max_insns:
                self.stop_reason = "instruction limit exceeded"
                uc.emu_stop()
                return
            # sentinel
            if address == SENTINEL:
                self.stop_reason = "returned"
                uc.emu_stop()
                return
            # wall clock limit (checked periodically to keep the hook cheap)
            if (self.insn_count & 0xFF) == 0 and time.time() > deadline:
                self.stop_reason = "timeout"
                uc.emu_stop()
                return
        def intr_hook(uc, intno, user_data):
            self.stop_reason = f"interrupt/syscall {intno}"
            uc.emu_stop()
        try:
            uc.hook_add(UC_HOOK_INTR, intr_hook)
        except Exception:
            pass
        uc.hook_add(UC_HOOK_CODE, code_hook, begin=1, end=0)

        # memory hooks for trace
        if trace:
            def mem_read_hook(uc, access, address, size, value, user_data):
                self.trace_read_count += 1
                if len(self.trace_reads) < MAX_TRACE_MEM:
                    self.trace_reads.append((address, size))
                return True
            def mem_write_hook(uc, access, address, size, value, user_data):
                self.trace_write_count += 1
                if len(self.trace_writes) < MAX_TRACE_MEM:
                    self.trace_writes.append((address, size))
                return True
            uc.hook_add(UC_HOOK_MEM_READ, mem_read_hook)
            uc.hook_add(UC_HOOK_MEM_WRITE, mem_write_hook)

    def _friendly_error(self, msg, uc):
        # append current PC for context (the helper is idempotent)
        suffix = ""
        if " at 0x" not in msg:
            try:
                regs = self._reg_constants()
                pc = uc.reg_read(regs[self._pc_name()])
                suffix = f" at 0x{pc:x}"
            except Exception:
                suffix = ""
        low = msg.lower()
        if "fetch_unmapped" in low or "fetch unmapped" in low:
            return "unmapped memory fetch" + suffix
        if "read_unmapped" in low or "read unmapped" in low:
            return "unmapped memory read" + suffix
        if "write_unmapped" in low or "write unmapped" in low:
            return "unmapped memory write" + suffix
        if "timeout" in low:
            return "timeout"
        return msg + suffix

    # ---------- memory access ----------

    def read_mem(self, addr, length, fmt="hex"):
        if length < 0 or length > MAX_READ:
            raise ValueError(f"length must be 0..{MAX_READ}")
        if fmt not in ("hex", "ascii"):
            raise ValueError("fmt must be 'hex' or 'ascii'")
        if length == 0:
            return ""
        if self.uc is None:
            if self.loaded is None:
                raise RuntimeError("no session; call emu_load first")
            self.uc = self._build_engine()
        addr = self._to_int(addr)
        try:
            data = self.uc.mem_read(addr, length)
        except Exception as e:
            raise RuntimeError(f"memory read failed at 0x{addr:x}: {e}")
        if fmt == "ascii":
            return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        # hex
        return data.hex()

    def write_mem(self, addr, data_hex):
        data = self._hex_to_bytes(data_hex)
        if not data:
            raise ValueError("data_hex is empty")
        if len(data) > MAX_WRITE:
            raise ValueError(f"write exceeds the {MAX_WRITE} byte limit")
        if self.uc is None:
            if self.loaded is None:
                raise RuntimeError("no session; call emu_load first")
            self.uc = self._build_engine()
        addr = self._to_int(addr)
        # map if needed
        try:
            self._map_region(self.uc, addr, len(data))
        except Exception as e:
            raise RuntimeError(f"cannot map memory at 0x{addr:x}: {e}")
        self.uc.mem_write(addr, data)
        self.extra_mem.append((addr, data))
        return len(data)

    def hook_call(self, addr, return_value, name=None):
        st = self.add_stub(self._to_int(addr), return_value, name)
        return st


# global session
SESSION = EmuSession()
