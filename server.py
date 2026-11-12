"""emu MCP server: isolate and verify reverse-engineered functions with Unicorn."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

try:  # mcp v1
    from mcp.server.fastmcp import FastMCP
except Exception:  # mcp v2 renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP

from emulator import DEFAULT_MAX_INSNS, DEFAULT_TIMEOUT_MS, MAX_READ, SESSION

mcp = FastMCP("emu")


def _ok(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, ensure_ascii=False, default=str)


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
            max_insns: int = DEFAULT_MAX_INSNS, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> str:
    """Emulate a single function in isolation and return its result.

    Use after you have guessed what a function does, to verify the guess against
    known inputs. `args` are passed per calling convention (floats go to the
    floating point argument registers); `mem_inputs` maps addresses (hex/dec
    strings) to hex byte data pre-written to memory.
    Returns return value, main registers, instruction count and stop reason.
    No syscalls/filesystem/network are emulated; unknown calls stop execution.
    """
    try:
        res = SESSION.run(func_addr, args or [], mem_inputs or {}, max_insns, timeout_ms)
        # compact registers? keep all
        return _ok(res)
    except Exception as e:
        return f"error: {e}"


@mcp.tool()
def emu_trace(func_addr: Any, args: Optional[list] = None, mem_inputs: Optional[Dict[str, str]] = None,
              limit: int = 50, offset: int = 0, max_insns: int = DEFAULT_MAX_INSNS,
              timeout_ms: int = DEFAULT_TIMEOUT_MS) -> str:
    """Trace an emulated function: executed addresses and memory read/write summary.

    Use to understand control flow or memory access of a function. At most
    `limit` addresses are printed per page; use `offset` to page through long
    address lists.
    """
    try:
        return SESSION.trace(func_addr, args or [], mem_inputs or {}, limit, offset,
                              max_insns, timeout_ms)
    except Exception as e:
        return f"error: {e}"


@mcp.tool()
def emu_read_mem(addr: Any, length: int, fmt: str = "hex") -> str:
    """Read up to 4096 bytes from emulated memory.

    `fmt` is "hex" or "ascii". Use to inspect memory after/before a run.
    """
    try:
        if length > MAX_READ:
            return f"error: length exceeds {MAX_READ}"
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
    stops. A float `return_value` is returned in the floating point return
    register. Returns confirmation.
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
