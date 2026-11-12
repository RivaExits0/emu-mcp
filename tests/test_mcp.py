"""End-to-end tests for the emu MCP server over stdio.

The server is started as a real subprocess and driven with the MCP client SDK
so that the tool registration, the argument schemas and the tool results are
all covered.
"""

import asyncio
import contextlib
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from common import build, have  # noqa: E402

try:  # mcp >= 2
    from mcp import ClientSession, StdioServerParameters
except ImportError:  # mcp 1.x
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters
from mcp.client.stdio import stdio_client  # noqa: E402

SAMPLE_BIN = os.path.join(TESTS, "sample_x64")
ABI_BIN = os.path.join(TESTS, "abi_x64")

EXPECTED_TOOLS = [
    "emu_load",
    "emu_run",
    "emu_trace",
    "emu_read_mem",
    "emu_write_mem",
    "emu_hook_call",
    "emu_reset",
]


def ensure_binaries():
    if not os.path.exists(SAMPLE_BIN):
        build(os.path.join(TESTS, "sample.c"), SAMPLE_BIN, "x86_64-linux-gnu-gcc")
    if not os.path.exists(ABI_BIN):
        build(os.path.join(TESTS, "abi.c"), ABI_BIN, "x86_64-linux-gnu-gcc")
    assert os.path.exists(SAMPLE_BIN), "sample_x64 could not be built"
    assert os.path.exists(ABI_BIN), "abi_x64 could not be built"


def symbol(binary, name):
    """Address of a symbol (via nm)."""
    out = subprocess.check_output(["x86_64-linux-gnu-nm", binary], text=True)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == name:
            return int(parts[0], 16)
    raise RuntimeError(f"symbol {name} not found in {binary}")


@contextlib.asynccontextmanager
async def server_session():
    params = StdioServerParameters(command=sys.executable,
                                   args=[os.path.join(ROOT, "server.py")],
                                   cwd=ROOT)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def call_text(result):
    """Text payload of a tool result."""
    assert result.content, "empty tool result"
    return result.content[0].text


def tool_schema(tool):
    """Input schema of a tool (mcp 1.x uses inputSchema, mcp 2.x input_schema)."""
    schema = getattr(tool, "inputSchema", None)
    if schema is None:
        schema = getattr(tool, "input_schema", None)
    assert schema is not None, f"no input schema for {tool.name}"
    return schema


def address_lines(text):
    """Addresses listed by emu_trace."""
    return [line.strip() for line in text.splitlines()
            if line.startswith("  0x")]


def test_list_tools():
    async def body():
        async with server_session() as session:
            listed = await session.list_tools()
            names = [tool.name for tool in listed.tools]
            assert all(name in names for name in EXPECTED_TOOLS), names
            by_name = {tool.name: tool for tool in listed.tools}
            for name in EXPECTED_TOOLS:
                tool = by_name[name]
                assert tool.description, f"{name} has no description"
                assert tool_schema(tool).get("type") == "object", tool_schema(tool)
            # the signatures stay backwards compatible
            run_schema = tool_schema(by_name["emu_run"])
            assert "func_addr" in run_schema["properties"], run_schema
            assert "args" in run_schema["properties"], run_schema
            assert "mem_inputs" in run_schema["properties"], run_schema
            assert "max_insns" in run_schema["properties"], run_schema
            trace_schema = tool_schema(by_name["emu_trace"])
            assert "limit" in trace_schema["properties"], trace_schema
            assert "offset" in trace_schema["properties"], trace_schema

    asyncio.run(body())


def test_full_session():
    ensure_binaries()
    add = symbol(SAMPLE_BIN, "add")
    multiply = symbol(ABI_BIN, "multiply")
    call_multiply = symbol(ABI_BIN, "call_multiply")

    async def body():
        async with server_session() as session:
            # emu_reset works on a fresh session
            assert call_text(await session.call_tool("emu_reset", {})) == "reset ok"

            # emu_load reports the parsed binary
            info = json.loads(call_text(await session.call_tool(
                "emu_load", {"path": SAMPLE_BIN})))
            assert info["format"] == "elf", info
            assert info["arch"] == "x64", info
            assert info["segments"] >= 1, info

            # emu_run returns the result as JSON
            res = json.loads(call_text(await session.call_tool(
                "emu_run", {"func_addr": hex(add), "args": [5, 7]})))
            assert res["return_value"] == 12, res
            assert res["stop_reason"] == "returned", res
            assert res["instruction_count"] > 0, res
            assert res["registers"]["rax"] == 12, res

            # emu_run with an address that is not mapped reports the failure
            res = call_text(await session.call_tool(
                "emu_run", {"func_addr": "0xdeadbeef"}))
            assert res.startswith("error:") or "unmapped" in res, res

            # emu_write_mem + emu_read_mem round trip
            call_text(await session.call_tool(
                "emu_write_mem", {"addr": "0x500000", "data_hex": "AABBCCDD"}))
            text = call_text(await session.call_tool(
                "emu_read_mem", {"addr": "0x500000", "length": 4, "fmt": "hex"}))
            assert text == "aabbccdd", text
            text = call_text(await session.call_tool(
                "emu_read_mem", {"addr": "0x500000", "length": 4, "fmt": "ascii"}))
            assert text == "....", text

            # reading more than 4096 bytes is refused
            text = call_text(await session.call_tool(
                "emu_read_mem", {"addr": "0x500000", "length": 4097}))
            assert text.startswith("error:"), text

            # emu_trace reports the executed addresses and can be paged
            trace = call_text(await session.call_tool(
                "emu_trace", {"func_addr": hex(add), "args": [5, 7], "limit": 3}))
            assert trace.startswith("stop: returned"), trace
            first = address_lines(trace)
            assert 0 < len(first) <= 3, trace
            assert f"0x{add:x}" in first, trace
            paged = call_text(await session.call_tool(
                "emu_trace", {"func_addr": hex(add), "args": [5, 7],
                              "limit": 3, "offset": 3}))
            second = address_lines(paged)
            assert second != first, (first, second)
            assert not set(first) & set(second), (first, second)

            # emu_hook_call stubs a call
            await session.call_tool("emu_load", {"path": ABI_BIN})
            hook = json.loads(call_text(await session.call_tool(
                "emu_hook_call", {"addr": hex(multiply), "return_value": 99,
                                  "name": "multiply"})))
            assert hook["addr"] == multiply, hook
            assert hook["return_value"] == 99, hook
            assert hook["name"] == "multiply", hook
            res = json.loads(call_text(await session.call_tool(
                "emu_run", {"func_addr": hex(call_multiply), "args": [2, 3]})))
            assert res["return_value"] == 99, res
            assert res["stop_reason"] == "returned", res

            # emu_reset clears the session
            assert call_text(await session.call_tool("emu_reset", {})) == "reset ok"
            res = call_text(await session.call_tool(
                "emu_run", {"func_addr": hex(add), "args": [1, 2]}))
            assert res.startswith("error:"), res

    asyncio.run(body())


def test_error_handling():
    ensure_binaries()

    async def body():
        async with server_session() as session:
            # loading a missing file reports an error instead of crashing
            res = call_text(await session.call_tool(
                "emu_load", {"path": "/nonexistent/binary"}))
            assert res.startswith("error:"), res
            assert "not found" in res, res

            # the session stays empty after a failed load
            res = call_text(await session.call_tool(
                "emu_run", {"func_addr": "0x1000"}))
            assert res.startswith("error:"), res

            # invalid hex data is reported
            await session.call_tool("emu_load", {"path": SAMPLE_BIN})
            res = call_text(await session.call_tool(
                "emu_write_mem", {"addr": "0x500000", "data_hex": "zz"}))
            assert res.startswith("error:"), res

            # an unsupported architecture is rejected
            res = call_text(await session.call_tool(
                "emu_load", {"path": SAMPLE_BIN, "arch": "sparc"}))
            assert res.startswith("error:"), res

            # a negative instruction limit is rejected
            res = call_text(await session.call_tool(
                "emu_run", {"func_addr": "0x4011d0", "max_insns": 0}))
            assert res.startswith("error:"), res

    asyncio.run(body())
