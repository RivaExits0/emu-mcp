"""Binary loading helpers for emu-mcp.

Uses LIEF to parse ELF/PE/Mach-O binaries and extract loadable segments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import lief


@dataclass
class LoadedBinary:
    path: str
    arch: str
    format: str
    segments: List[Tuple[int, bytes]] = field(default_factory=list)  # (base_addr, data)
    imagebase: int = 0
    # symbol name -> value (ARM Thumb functions keep the mode bit in the value)
    symbols: Dict[str, int] = field(default_factory=dict)
    # ARM code state markers: (address, is_thumb) taken from $t/$a/$d symbols
    arm_modes: List[Tuple[int, bool]] = field(default_factory=list)


SUPPORTED_ARCHES = {"x86", "x64", "arm", "arm64"}


def _detect_arch_elf(binary) -> str:
    mt = binary.header.machine_type
    name = getattr(mt, "name", str(mt)).upper()
    if "X86_64" in name or "AMD64" in name:
        return "x64"
    if "I386" in name or name == "X86":
        return "x86"
    if "AARCH64" in name:
        return "arm64"
    if "ARM" in name:
        return "arm"
    raise ValueError(f"unsupported ELF architecture: {name}")


def _detect_arch_pe(binary) -> str:
    mt = binary.header.machine
    name = getattr(mt, "name", str(mt)).upper()
    if "AMD64" in name or "X86_64" in name:
        return "x64"
    if "I386" in name:
        return "x86"
    if "ARM64" in name or "AARCH64" in name:
        return "arm64"
    if "ARM" in name:
        return "arm"
    raise ValueError(f"unsupported PE architecture: {name}")


def _detect_arch_macho(binary) -> str:
    cpu = binary.header.cpu_type
    name = getattr(cpu, "name", str(cpu)).upper()
    if "X86_64" in name or "AMD64" in name:
        return "x64"
    if "X86" in name or "I386" in name:
        return "x86"
    if "ARM64" in name or "AARCH64" in name:
        return "arm64"
    if "ARM" in name:
        return "arm"
    raise ValueError(f"unsupported Mach-O architecture: {name}")


def _symbols(binary) -> Dict[str, int]:
    """Collect the symbol table (name -> value) when the format provides one."""
    out: Dict[str, int] = {}
    try:
        iterator = binary.symbols
    except Exception:
        return out
    try:
        for sym in iterator:
            name = getattr(sym, "name", "") or ""
            value = getattr(sym, "value", 0) or 0
            if not name or not value:
                continue
            out.setdefault(name, value)
    except Exception:
        pass
    return out


def _arm_modes(binary) -> List[Tuple[int, bool]]:
    """Collect the ARM/Thumb code state markers ($t, $a, $d)."""
    out: List[Tuple[int, bool]] = []
    try:
        for sym in binary.symbols:
            name = getattr(sym, "name", "") or ""
            value = getattr(sym, "value", 0) or 0
            if not value:
                continue
            if name == "$t":
                out.append((value, True))
            elif name in ("$a", "$d"):
                out.append((value, False))
    except Exception:
        pass
    out.sort()
    return out


def _file_head(path: str, size: int) -> bytes:
    """Read the first `size` bytes of a file (used for PE/Mach-O headers)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _segments_elf(binary) -> List[Tuple[int, bytes]]:
    out = []
    for seg in binary.segments:
        if seg.type != lief.ELF.Segment.TYPE.LOAD:
            continue
        va = seg.virtual_address
        vsz = seg.virtual_size
        try:
            data = bytes(seg.content)
        except Exception:
            data = b""
        # a segment may be pure BSS (no file content)
        size = max(vsz, len(data))
        if size <= 0:
            continue
        # pad to virtual size
        if len(data) < size:
            data = data + b"\x00" * (size - len(data))
        out.append((va, data))
    if not out:
        # fallback to sections
        for sec in binary.sections:
            if sec.virtual_address and sec.size:
                try:
                    data = bytes(sec.content)
                except Exception:
                    data = b""
                if len(data) < sec.size:
                    data = data + b"\x00" * (sec.size - len(data))
                out.append((sec.virtual_address, data))
    return out


def _segments_pe(binary, path: str) -> List[Tuple[int, bytes]]:
    ib = binary.optional_header.imagebase
    out = []
    # PE headers live at the image base and are mapped by the loader
    try:
        hdr_size = int(binary.optional_header.sizeof_headers)
    except Exception:
        hdr_size = 0
    if hdr_size > 0:
        head = _file_head(path, hdr_size)
        if head:
            out.append((ib, head))
    for sec in binary.sections:
        if not sec.virtual_address or not sec.size:
            continue
        try:
            data = bytes(sec.content)
        except Exception:
            data = b""
        vsz = sec.virtual_size if sec.virtual_size else sec.size
        if len(data) < vsz:
            data = data + b"\x00" * (vsz - len(data))
        out.append((ib + sec.virtual_address, data))
    return out


def _segments_macho(binary, path: str) -> List[Tuple[int, bytes]]:
    out = []
    for seg in binary.segments:
        va = seg.virtual_address
        vsz = seg.virtual_size
        try:
            data = bytes(seg.content)
        except Exception:
            data = b""
        size = max(vsz, len(data))
        if size <= 0:
            continue
        if len(data) < size:
            data = data + b"\x00" * (size - len(data))
        # Mach-O segments may contain sections; content already full segment
        out.append((va, data))
    if not out:
        for sec in binary.sections:
            if sec.virtual_address and sec.size:
                try:
                    data = bytes(sec.content)
                except Exception:
                    data = b""
                if len(data) < sec.size:
                    data = data + b"\x00" * (sec.size - len(data))
                out.append((sec.virtual_address, data))
    # the Mach-O header is part of the first segment (file offset 0)
    if out:
        try:
            first = binary.segments[0]
            if int(first.file_offset) == 0:
                head = _file_head(path, 0x1000)
                if head:
                    out.insert(0, (first.virtual_address, head))
        except Exception:
            pass
    return out


def _detect_format(binary) -> str:
    """Identify the binary format in a version independent way."""
    for module, name in ((lief.ELF, "elf"), (lief.PE, "pe"), (lief.MachO, "macho")):
        try:
            if isinstance(binary, module.Binary):
                return name
        except Exception:
            pass
    raw = str(getattr(binary, "format", "")).split(".")[-1].lower()
    if "elf" in raw:
        return "elf"
    if "pe" in raw:
        return "pe"
    if "macho" in raw or "mach" in raw:
        return "macho"
    raise ValueError(f"unsupported binary format: {raw or 'unknown'}")


def load_binary(path: str, arch: str | None = None) -> LoadedBinary:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"binary not found: {path}")
    try:
        binary = lief.parse(path)
    except Exception as e:
        raise ValueError(f"lief could not parse {path}: {e}") from None
    if binary is None:
        raise ValueError(f"lief could not parse: {path}")
    fmt = _detect_format(binary)
    if fmt == "elf":
        detected = _detect_arch_elf(binary)
        segments = _segments_elf(binary)
        symbols = _symbols(binary)
        arm_modes = _arm_modes(binary)
        imagebase = 0
    elif fmt == "pe":
        detected = _detect_arch_pe(binary)
        segments = _segments_pe(binary, path)
        symbols = {}
        arm_modes = []
        imagebase = binary.optional_header.imagebase
    else:
        detected = _detect_arch_macho(binary)
        segments = _segments_macho(binary, path)
        symbols = _symbols(binary)
        arm_modes = []
        imagebase = 0
    if not segments:
        raise ValueError(f"no loadable segments found in {path}")
    a = arch or detected
    if a not in SUPPORTED_ARCHES:
        raise ValueError(f"unsupported arch '{a}'; choose from {sorted(SUPPORTED_ARCHES)}")
    return LoadedBinary(path=path, arch=a, format=fmt, segments=segments,
                        imagebase=imagebase, symbols=symbols, arm_modes=arm_modes)
