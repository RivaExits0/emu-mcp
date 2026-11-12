"""Unicorn-based isolated function emulator for emu-mcp."""

from __future__ import annotations

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
SENTINEL = 0x0F000000
STUB_PAGE = 0x0E000000


@dataclass
class Stub:
    addr: int
    return_value: int
    name: Optional[str] = None


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
    # last run info
    last_regs: Dict[str, int] = field(default_factory=dict)
    # persisted writes from emu_write_mem
    extra_mem: Dict[int, bytes] = field(default_factory=dict)
    # to avoid huge trace
    _trace_code_cap: int = 0

    # ---------- loading ----------

    def load(self, path: str, arch: Optional[str] = None) -> dict:
        lb = load_binary(path, arch)
        self.loaded = lb
        self.arch = lb.arch
        self.hooks = []
        self.extra_mem = {}
        self.uc = self._build_engine()
        self.stop_reason = "loaded"
        self.insn_count = 0
        self.trace_code = []
        self.trace_reads = []
        self.trace_writes = []
        return {
            "path": lb.path,
            "format": lb.format,
            "arch": lb.arch,
            "segments": len(lb.segments),
        }

    def reset(self) -> None:
        self.loaded = None
        self.arch = None
        self.hooks = []
        self.uc = None
        self.mapped_pages = set()
        self.insn_count = 0
        self.stop_reason = ""
        self.trace_enabled = False
        self.trace_code = []
        self.trace_reads = []
        self.trace_writes = []
        self.extra_mem = {}
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
            self._map_region(uc, base, len(data), data)
        # stack
        self._map_region(uc, STACK_BASE, STACK_SIZE)
        # sentinel page
        self._map_region(uc, SENTINEL, PAGE)
        # stub pages
        # reserve a page for stubs if needed
        # map stub addresses pages
        for st in self.hooks:
            self._map_region(uc, self._page_align_down(st.addr), PAGE)
        # persisted writes
        for addr, data in self.extra_mem.items():
            self._map_region(uc, addr, len(data))
            uc.mem_write(addr, data)
        # mem_inputs
        if mem_inputs:
            for k, v in mem_inputs.items():
                addr = self._parse_int(k)
                data = self._hex_to_bytes(v)
                if not data:
                    continue
                self._map_region(uc, addr, len(data))
                uc.mem_write(addr, data)
        # sentinel hook via code hook added after (handle in run)
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
        return bytes.fromhex(s)

    # ---------- registers ----------

    def _pc_reg(self):
        if self.arch in ("x86", "x64"):
            return None  # handled separately
        return None

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
            return {
                "rax": C.UC_X86_REG_RAX, "rbx": C.UC_X86_REG_RBX,
                "rcx": C.UC_X86_REG_RCX, "rdx": C.UC_X86_REG_RDX,
                "rsi": C.UC_X86_REG_RSI, "rdi": C.UC_X86_REG_RDI,
                "rbp": C.UC_X86_REG_RBP, "rsp": C.UC_X86_REG_RSP,
                "r8": C.UC_X86_REG_R8, "r9": C.UC_X86_REG_R9,
                "r10": C.UC_X86_REG_R10, "r11": C.UC_X86_REG_R11,
                "r12": C.UC_X86_REG_R12, "r13": C.UC_X86_REG_R13,
                "r14": C.UC_X86_REG_R14, "r15": C.UC_X86_REG_R15,
                "rip": C.UC_X86_REG_RIP,
                "xmm0": C.UC_X86_REG_XMM0,
            }
        if self.arch == "arm":
            import unicorn.arm_const as C
            regs = {}
            for i in range(16):
                regs[f"r{i}"] = getattr(C, f"UC_ARM_REG_R{i}")
            regs["pc"] = C.UC_ARM_REG_PC
            regs["sp"] = C.UC_ARM_REG_SP
            regs["lr"] = C.UC_ARM_REG_LR
            regs["cpsr"] = C.UC_ARM_REG_CPSR
            return regs
        if self.arch == "arm64":
            import unicorn.arm64_const as C
            regs = {}
            for i in range(31):
                regs[f"x{i}"] = getattr(C, f"UC_ARM64_REG_X{i}")
            regs["sp"] = C.UC_ARM64_REG_SP
            regs["pc"] = C.UC_ARM64_REG_PC
            regs["lr"] = C.UC_ARM64_REG_LR
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

    def _word_size(self):
        if self.arch in ("x86", "arm"):
            return 4
        return 8

    def _read_regs(self, uc) -> Dict[str, int]:
        out = {}
        for name, c in self._reg_constants().items():
            try:
                out[name] = uc.reg_read(c)
            except Exception:
                pass
        return out

    # ---------- args setup ----------

    def _setup_args(self, uc, func_addr, args):
        ws = self._word_size()
        arg_ints = [self._to_int(a) for a in args]
        sp_top = STACK_BASE + STACK_SIZE
        # align sp
        if self.arch == "x64":
            sp_top &= ~0xF
        if self.arch == "arm":
            if self.thumb:
                pc = func_addr | 1
            else:
                pc = func_addr
        else:
            pc = func_addr

        if self.arch == "x86":
            import unicorn.x86_const as C
            cur = sp_top
            for a in reversed(arg_ints):
                cur -= ws
                uc.mem_write(cur, a.to_bytes(ws, "little"))
            cur -= ws
            uc.mem_write(cur, SENTINEL.to_bytes(ws, "little"))
            uc.reg_write(C.UC_X86_REG_ESP, cur)
            uc.reg_write(C.UC_X86_REG_EIP, pc)
        elif self.arch == "x64":
            import unicorn.x86_const as C
            import struct
            int_regs = [C.UC_X86_REG_RDI, C.UC_X86_REG_RSI, C.UC_X86_REG_RDX,
                        C.UC_X86_REG_RCX, C.UC_X86_REG_R8, C.UC_X86_REG_R9]
            xmm_regs = [C.UC_X86_REG_XMM0, C.UC_X86_REG_XMM1, C.UC_X86_REG_XMM2,
                        C.UC_X86_REG_XMM3, C.UC_X86_REG_XMM4, C.UC_X86_REG_XMM5,
                        C.UC_X86_REG_XMM6, C.UC_X86_REG_XMM7]
            int_idx = 0
            xmm_idx = 0
            stack_items = []  # list of 8-byte ints
            raw_args = args if isinstance(args, (list, tuple)) else arg_ints
            for a in raw_args:
                if isinstance(a, float):
                    bits = struct.unpack("<Q", struct.pack("<d", a))[0]
                    if xmm_idx < len(xmm_regs):
                        uc.reg_write(xmm_regs[xmm_idx], bits)
                        xmm_idx += 1
                    else:
                        stack_items.append(bits)
                else:
                    val = self._to_int(a)
                    if int_idx < len(int_regs):
                        uc.reg_write(int_regs[int_idx], val)
                        int_idx += 1
                    else:
                        stack_items.append(val)
            cur = sp_top
            for val in reversed(stack_items):
                cur -= 8
                uc.mem_write(cur, val.to_bytes(8, "little"))
            cur -= ws
            uc.mem_write(cur, SENTINEL.to_bytes(ws, "little"))
            if cur % 16 != 8:
                cur -= 8
                uc.mem_write(cur, b"\x00" * 8)
            uc.reg_write(C.UC_X86_REG_RSP, cur)
            uc.reg_write(C.UC_X86_REG_RIP, pc)
        elif self.arch == "arm":
            import unicorn.arm_const as C
            for i, a in enumerate(arg_ints[:4]):
                uc.reg_write(getattr(C, f"UC_ARM_REG_R{i}"), a)
            # stack args
            cur = sp_top
            for a in reversed(arg_ints[4:]):
                cur -= ws
                uc.mem_write(cur, a.to_bytes(ws, "little"))
            if cur % 8:
                cur -= cur % 8
            uc.reg_write(C.UC_ARM_REG_SP, cur)
            uc.reg_write(C.UC_ARM_REG_PC, pc)
            lr_val = SENTINEL | (1 if self.thumb else 0)
            uc.reg_write(C.UC_ARM_REG_LR, lr_val)
        elif self.arch == "arm64":
            import unicorn.arm64_const as C
            for i, a in enumerate(arg_ints[:8]):
                uc.reg_write(getattr(C, f"UC_ARM64_REG_X{i}"), a)
            cur = sp_top
            for a in reversed(arg_ints[8:]):
                cur -= 8
                uc.mem_write(cur, a.to_bytes(8, "little"))
            uc.reg_write(C.UC_ARM64_REG_SP, cur)
            uc.reg_write(C.UC_ARM64_REG_PC, pc)
            uc.reg_write(C.UC_ARM64_REG_LR, SENTINEL)
        # x86/x64 LR not applicable; sentinel already on stack for x86
        if self.arch in ("x86", "x64"):
            # set LR? no
            pass
        # for x86/x64, set sentinel on stack already; but need ensure return reg? no.

    def _to_int(self, a):
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

    def _pack(self, addr, val, ws):
        return val.to_bytes(ws, "little")

    # ---------- stub handling ----------

    def add_stub(self, addr, return_value, name=None):
        if isinstance(return_value, float):
            import struct
            rv = struct.unpack("<Q", struct.pack("<d", return_value))[0]
        else:
            rv = self._to_int(return_value)
        st = Stub(addr=addr, return_value=rv, name=name)
        self.hooks.append(st)
        return st

    def _apply_stub(self, uc, stub):
        ws = self._word_size()
        rv = stub.return_value
        # set return register
        rr = self._ret_reg_name()
        regs = self._reg_constants()
        uc.reg_write(regs[rr], rv)
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
        if self.arch != "arm":
            return False
        if addr & 1:
            return True
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

    def run(self, func_addr, args=None, mem_inputs=None, max_insns=100000, trace=False):
        if self.loaded is None:
            raise RuntimeError("no binary loaded; call emu_load first")
        args = args or []
        mem_inputs = mem_inputs or {}
        func_addr = self._to_int(func_addr)
        if max_insns < 1:
            raise ValueError("max_insns must be >= 1")
        thumb = self.arch == "arm" and bool(func_addr & 1)
        # build engine
        self.trace_enabled = False
        self.trace_code = []
        self.trace_reads = []
        self.trace_writes = []
        self.insn_count = 0
        self.stop_reason = ""
        uc = self._build_engine(mem_inputs=mem_inputs, thumb=thumb)
        if self.arch == "arm" and not thumb:
            if self._detect_thumb(uc, func_addr & ~1):
                thumb = True
                self.thumb = True
                uc = self._build_engine(mem_inputs=mem_inputs, thumb=True)
        # ensure thumb flag reflects
        if self.arch == "arm":
            self.thumb = thumb
        self.mapped_pages  # ensure
        # map stub pages
        for st in self.hooks:
            self._map_region(uc, self._page_align_down(st.addr), PAGE)
        self.uc = uc
        # setup args
        self._setup_args(uc, func_addr, args)
        # hooks
        self._install_hooks(uc, max_insns, trace=False)
        # run
        if self.arch == "arm" and (self.thumb or (func_addr & 1)):
            pc_start = (func_addr & ~1) | 1
        else:
            pc_start = func_addr
        t0 = time.time()
        timeout_us = 5_000_000
        try:
            uc.emu_start(pc_start, 0, timeout=timeout_us, count=max_insns)
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
            if pc == SENTINEL or pc == 0:
                self.stop_reason = "returned"
            else:
                self.stop_reason = "stopped"
        if self.stop_reason and "UC_ERR" in self.stop_reason:
            self.stop_reason = self._friendly_error(self.stop_reason, uc)
        if (not self.stop_reason or self.stop_reason == "stopped") and self.insn_count >= max_insns:
            self.stop_reason = "instruction limit exceeded"
        if time.time() - t0 > 6.0 and self.stop_reason not in ("returned",):
            self.stop_reason = "timeout"
        self.last_regs = self._read_regs(uc)
        rv = self.last_regs.get(self._ret_reg_name())
        return {
            "return_value": rv,
            "registers": self.last_regs,
            "instruction_count": self.insn_count,
            "stop_reason": self.stop_reason,
        }

    def trace(self, func_addr, args=None, mem_inputs=None, limit=50, offset=0):
        if self.loaded is None:
            raise RuntimeError("no binary loaded; call emu_load first")
        args = args or []
        mem_inputs = mem_inputs or {}
        func_addr = self._to_int(func_addr)
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        thumb = self.arch == "arm" and bool(func_addr & 1)
        self.trace_enabled = True
        self.trace_limit = limit
        self._trace_code_cap = limit
        self.trace_code = []
        self.trace_reads = []
        self.trace_writes = []
        self.insn_count = 0
        self.stop_reason = ""
        uc = self._build_engine(mem_inputs=mem_inputs, thumb=thumb)
        if self.arch == "arm" and not thumb:
            if self._detect_thumb(uc, func_addr & ~1):
                thumb = True
                self.thumb = True
                uc = self._build_engine(mem_inputs=mem_inputs, thumb=True)
        if self.arch == "arm":
            self.thumb = thumb
        for st in self.hooks:
            self._map_region(uc, self._page_align_down(st.addr), PAGE)
        self.uc = uc
        self._setup_args(uc, func_addr, args)
        self._install_hooks(uc, 100000, trace=True)
        if self.arch == "arm" and (self.thumb or (func_addr & 1)):
            pc_start = (func_addr & ~1) | 1
        else:
            pc_start = func_addr
        try:
            uc.emu_start(pc_start, 0, timeout=5_000_000, count=100000)
        except Exception as e:
            if not self.stop_reason:
                self.stop_reason = self._friendly_error(str(e), uc)
        if not self.stop_reason:
            regs = self._reg_constants()
            pcname = self._pc_name()
            try:
                pc = uc.reg_read(regs[pcname])
            except Exception:
                pc = 0
            if pc == SENTINEL or pc == 0:
                self.stop_reason = "returned"
            else:
                self.stop_reason = "stopped"
        if self.stop_reason and "UC_ERR" in self.stop_reason:
            self.stop_reason = self._friendly_error(self.stop_reason, uc)
        self.last_regs = self._read_regs(uc)
        # build output lines
        lines = []
        lines.append(f"stop: {self.stop_reason}, insns: {self.insn_count}")
        lines.append("called addresses:")
        end = offset + limit
        for a in self.trace_code[offset:end]:
            lines.append(f"  0x{a:x}")
        if len(self.trace_code) > end:
            lines.append(f"  ... ({len(self.trace_code)} total, offset {offset})")
        lines.append(f"mem reads: {len(self.trace_reads)}")
        for a, sz in self.trace_reads[:max(1, limit // 5)]:
            lines.append(f"  R 0x{a:x} ({sz})")
        lines.append(f"mem writes: {len(self.trace_writes)}")
        for a, sz in self.trace_writes[:max(1, limit // 5)]:
            lines.append(f"  W 0x{a:x} ({sz})")
        # cap total lines to limit + header allowance: keep simple
        if len(lines) > limit:
            lines = lines[:limit]
        return "\n".join(lines)

    def _install_hooks(self, uc, max_insns, trace):
        regs = self._reg_constants()
        # code hook
        def code_hook(uc, address, size, user_data):
            self.insn_count += 1
            if trace or self.trace_enabled:
                if len(self.trace_code) < self.trace_limit * 4:
                    self.trace_code.append(address)
            # stub check
            for st in self.hooks:
                if address == st.addr:
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
        def intr_hook(uc, intno, user_data):
            self.stop_reason = f"interrupt/syscall {intno}"
            uc.emu_stop()
        try:
            uc.hook_add(UC_HOOK_INTR, intr_hook)
        except Exception:
            pass
        uc.hook_add(UC_HOOK_CODE, code_hook, begin=1, end=0)

        # memory hooks for trace
        if self.trace_enabled:
            def mem_read_hook(uc, access, address, size, value, user_data):
                if len(self.trace_reads) < self.trace_limit * 4:
                    self.trace_reads.append((address, size))
                return True
            def mem_write_hook(uc, access, address, size, value, user_data):
                if len(self.trace_writes) < self.trace_limit * 4:
                    self.trace_writes.append((address, size))
                return True
            uc.hook_add(UC_HOOK_MEM_READ, mem_read_hook)
            uc.hook_add(UC_HOOK_MEM_WRITE, mem_write_hook)

        # error handling via try around emu_start already; but unmapped errors raise. We'll catch in run.

    def _friendly_error(self, msg, uc):
        # append current PC for context
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
        if length < 0 or length > 4096:
            raise ValueError("length must be 0..4096")
        if length == 0:
            return "" if fmt == "ascii" else ""
        if self.uc is None:
            if self.loaded is None:
                raise RuntimeError("no session; call emu_load first")
            self.uc = self._build_engine()
        addr = self._to_int(addr)
        # ensure mapped? read may fail if unmapped; let unicorn raise
        try:
            data = self.uc.mem_read(addr, length)
        except Exception as e:
            raise RuntimeError(f"memory read failed at 0x{addr:x}: {e}")
        if fmt == "ascii":
            return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        # hex
        return data.hex()

    def write_mem(self, addr, data_hex):
        if self.uc is None:
            if self.loaded is None:
                raise RuntimeError("no session; call emu_load first")
            self.uc = self._build_engine()
        addr = self._to_int(addr)
        data = self._hex_to_bytes(data_hex)
        if not data:
            raise ValueError("data_hex is empty")
        # map if needed
        try:
            self._map_region(self.uc, addr, len(data))
        except Exception:
            pass
        self.uc.mem_write(addr, data)
        self.extra_mem[addr] = data
        return len(data)

    def hook_call(self, addr, return_value, name=None):
        st = self.add_stub(self._to_int(addr), return_value, name)
        return st


# global session
SESSION = EmuSession()
