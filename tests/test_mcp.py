import asyncio, os, sys, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

def ensure_binary():
    binp = os.path.join(ROOT, "tests", "sample_x64")
    if not os.path.exists(binp):
        subprocess.check_call(["x86_64-linux-gnu-gcc", "-O0", "-g", "-fno-pie", "-no-pie",
                               "-o", binp, os.path.join(ROOT, "tests", "sample.c")])
    return binp

def test_mcp_end_to_end():
    ensure_binary()
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def main():
        params = StdioServerParameters(command="python3", args=["server.py"], cwd=ROOT)
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                tools = await s.list_tools()
                names = [t.name for t in tools.tools]
                assert all(n in names for n in ["emu_load", "emu_run", "emu_trace", "emu_read_mem",
                                                "emu_write_mem", "emu_hook_call", "emu_reset"])
                await s.call_tool("emu_reset", {})
                await s.call_tool("emu_load", {"path": "tests/sample_x64"})
                res = await s.call_tool("emu_run", {"func_addr": 0x4011D0, "args": [5, 7]})
                import json
                data = json.loads(res.content[0].text)
                assert data["return_value"] == 12
                assert data["stop_reason"] == "returned"
                await s.call_tool("emu_write_mem", {"addr": 0x500000, "data_hex": "AABBCCDD"})
                res = await s.call_tool("emu_read_mem", {"addr": 0x500000, "length": 4, "fmt": "hex"})
                assert res.content[0].text == "aabbccdd"
                res = await s.call_tool("emu_trace", {"func_addr": 0x4011D0, "args": [5, 7], "limit": 4})
                assert len(res.content[0].text.splitlines()) <= 4
                await s.call_tool("emu_reset", {})

    asyncio.run(main())
