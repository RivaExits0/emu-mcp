"""Binary loading helpers for emu-mcp.

Uses LIEF to parse ELF/PE/Mach-O binaries and extract loadable segments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Tuple

import lief


@dataclass
class LoadedBinary:
    path: str
    arch: str
    format: str
    segments: List[Tuple[int, bytes]] = field(default_factory=list)  # (base_addr, data)
    imagebase: int = 0


SUPPORTED_ARCHES = {"x86", "x64", "arm", "arm64"}


def _detect_arch_elf(binary) -> str:
    mt = binary.header.machine_type
    name = getattr(mt, "name", str(mt)).upper()
    if "X86_64" in name:
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
    if "AMD64" in name:
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
    if "X86_64" in name:
        return "x64"
    if "X86" in name:
        return "x86"
    if "ARM64" in name:
        return "arm64"
    if "ARM" in name:
        return "arm"
    raise ValueError(f"unsupported Mach-O architecture: {name}")


def _segments_elf(binary) -> List[Tuple[int, bytes]]:
    out = []
    for seg in binary.segments:
        if seg.type != lief.ELF.Segment.TYPE.LOAD:
            continue
        va = seg.virtual_address
        vsz = seg.virtual_size
        if vsz <= 0:
            continue
        data = bytes(seg.content)
        # pad to virtual size
        if len(data) < vsz:
            data = data + b"\x00" * (vsz - len(data))
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


def _segments_pe(binary) -> List[Tuple[int, bytes]]:
    ib = binary.optional_header.imagebase
    out = []
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
    # headers
    if binary.dos_header is not None:
        pass
    return out


def _segments_macho(binary) -> List[Tuple[int, bytes]]:
    out = []
    for seg in binary.segments:
        va = seg.virtual_address
        vsz = seg.virtual_size
        if vsz <= 0:
            continue
        try:
            data = bytes(seg.content)
        except Exception:
            data = b""
        if len(data) < vsz:
            data = data + b"\x00" * (vsz - len(data))
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
    return out


def load_binary(path: str, arch: str | None = None) -> LoadedBinary:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"binary not found: {path}")
    binary = lief.parse(path)
    if binary is None:
        raise ValueError(f"lief could not parse: {path}")
    fmt_name = str(getattr(binary, "format", "")).split(".")[-1].lower()
    if "elf" in fmt_name:
        detected = _detect_arch_elf(binary)
        segments = _segments_elf(binary)
        fmt = "elf"
    elif "pe" in fmt_name:
        detected = _detect_arch_pe(binary)
        segments = _segments_pe(binary)
        fmt = "pe"
        ib = binary.optional_header.imagebase
    elif "macho" in fmt_name or "mach" in fmt_name:
        detected = _detect_arch_macho(binary)
        segments = _segments_macho(binary)
        fmt = "macho"
    else:
        # try by extension/content
        raise ValueError(f"unsupported binary format: {fmt_name}")
    a = arch or detected
    if a not in SUPPORTED_ARCHES:
        raise ValueError(f"unsupported arch '{a}'; choose from {sorted(SUPPORTED_ARCHES)}")
    lb = LoadedBinary(path=path, arch=a, format=fmt, segments=segments)
    if fmt == "pe":
        lb.imagebase = binary.optional_header.imagebase
    return lb
