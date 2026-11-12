"""emu MCP server: isolate and verify reverse-engineered functions with Unicorn."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    from mcp.server.mcpserver import MCPServer as FastMCP

from emulator import SESSION

mcp = FastMCP("emu")


def _ok(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, ensure_ascii=False)


@mcp.tool()
def emu_load(path: str, arch: Optional[str] = None) -> str:
    """Load a binary (ELF/PE/Mach-O) with LIEF and map its segments into Unicorn memory.

    Use this first, before emulating any function. Architecture is auto-detected
    (x86, x64, arm, arm64) unless `arch` is provided. Resets any previous session.
    """
    try:
        info = SESSION.load(path, arch)
        return _ok(info)
    except Exception as e:
        return f"error: {e}"


@mcp.tool()
def emu_run(func_addr: Any, args: Optional[list] = None, mem_inputs: Optional[Dict[str, str]] = None,
            max_insns: int = 100000) -> str:
    """Emulate a single function in isolation and return its result.

    Use after you have guessed what a function does, to verify the guess against
    known inputs. `args` are passed per calling convention; `mem_inputs` maps
    addresses (hex/dec strings) to hex byte data pre-written to memory.
    Returns return value, main registers, instruction count and stop reason.
    No syscalls/filesystem/network are emulated; unknown calls stop execution.
    """
    try:
        res = SESSION.run(func_addr, args or [], mem_inputs or {}, max_insns)
        # compact registers? keep all
        return _ok(res)
    except Exception as e:
        return f"error: {e}"


@mcp.tool()
def emu_trace(func_addr: Any, args: Optional[list] = None, mem_inputs: Optional[Dict[str, str]] = None,
              limit: int = 50, offset: int = 0) -> str:
    """Trace an emulated function: executed addresses and memory read/write summary.

    Use to understand control flow or memory access of a function. Output is capped
    to `limit` lines. Use `offset` to page through long address lists.
    """
    try:
        return SESSION.trace(func_addr, args or [], mem_inputs or {}, limit, offset)
    except Exception as e:
        return f"error: {e}"


@mcp.tool()
def emu_read_mem(addr: Any, length: int, fmt: str = "hex") -> str:
    """Read up to 4096 bytes from emulated memory.

    `fmt` is "hex" or "ascii". Use to inspect memory after/before a run.
    """
    try:
        if length > 4096:
            return "error: length exceeds 4096"
        return SESSION.read_mem(addr, length, fmt)
    except Exception as e:
        return f"error: {e}"


@mcp.tool()
def emu_write_mem(addr: Any, data_hex: str) -> str:
    """Write hex data to emulated memory. Returns number of bytes written."""
    try:
        n = SESSION.write_mem(addr, data_hex)
        return f"wrote {n} bytes"
    except Exception as e:
        return f"error: {e}"


@mcp.tool()
def emu_hook_call(addr: Any, return_value: Any, name: Optional[str] = None) -> str:
    """Stub a function at `addr`: skip it and return `return_value`.

    Use for libc/API stubs such as malloc, strlen, printf. Prevents unknown-call
    stops. Returns confirmation.
    """
    try:
        st = SESSION.hook_call(addr, return_value, name)
        return _ok({"addr": st.addr, "return_value": st.return_value, "name": st.name})
    except Exception as e:
        return f"error: {e}"


@mcp.tool()
def emu_reset() -> str:
    """Reset the emulator session (unload binary, clear hooks and memory)."""
    try:
        SESSION.reset()
        return "reset ok"
    except Exception as e:
        return f"error: {e}"


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
