# emu-mcp

[![CI](https://github.com/WeAreMS/emu-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/WeAreMS/emu-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**emu-mcp** is an MCP server that lets an AI verify reverse-engineering guesses
by emulating single functions in isolation with Unicorn. No syscalls, filesystem,
or network are emulated; unknown calls stop execution and report their address.

## Why

When reverse-engineering a binary, you form hypotheses about what a function
does. `emu-mcp` lets you **run that function with known inputs** in an isolated
emulator and check the result, instead of trusting the guess.

## Features

- Parse ELF / PE / Mach-O binaries with LIEF and auto-detect architecture
  (x86, x64, arm, arm64).
- Emulate a single function with arguments passed per calling convention.
- Pre-write memory inputs, read/write memory, stub libc/API calls.
- Trace executed addresses and memory reads/writes.
- Hard limits on instructions and wall-clock time to prevent runaway emulation.
- Clean, machine-readable JSON output suitable for AI agents.

## Install

```bash
pip install "mcp>=1.0" unicorn capstone lief
```

Or from source:

```bash
git clone https://github.com/WeAreMS/emu-mcp.git
cd emu-mcp
pip install -e .
```

## Run

```bash
python server.py
```

The server speaks MCP over stdio.

## OpenCode integration

Add to `opencode.json`:

```json
"mcp": {
  "emu": {
    "type": "local",
    "command": ["python", "/path/to/emu-mcp/server.py"],
    "enabled": true
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `emu_load(path, arch=None)` | Parse a binary and map its segments into Unicorn memory. |
| `emu_run(func_addr, args=[], mem_inputs={}, max_insns=100000)` | Emulate one function, return value + registers. |
| `emu_trace(func_addr, args=[], mem_inputs={}, limit=50, offset=0)` | Trace addresses and memory access (paginated). |
| `emu_read_mem(addr, length, fmt="hex"\|"ascii")` | Read up to 4096 bytes. |
| `emu_write_mem(addr, data_hex)` | Write hex data to memory. |
| `emu_hook_call(addr, return_value, name=None)` | Stub a call (malloc, strlen, …). |
| `emu_reset()` | Reset the session. |

## Quick example

```bash
make          # build test binaries
python examples/demo.py
```

Or via MCP:

```json
{"tool": "emu_load", "args": {"path": "tests/sample_x64"}}
{"tool": "emu_run", "args": {"func_addr": "0x4011d0", "args": [5, 7]}}
```

Expected: `{"return_value": 12, ...}`.

## Testing

```bash
make test
```

Runs `tests/test_emu.py`, `tests/test_hard.py`, and `examples/demo.py`.
The hard suite covers recursion, function pointers, stack args, structs,
in-place memory, nested calls, libc hooks, floating point, and error cases.

## Architecture

```
server.py      MCP tool definitions (stdio transport)
emulator.py    Unicorn engine, calling conventions, hooks, tracing
loader.py      LIEF-based binary parsing and segment mapping
```

## Security notes

- No syscalls, filesystem, or network are emulated.
- Unknown calls stop execution and report their address.
- Instruction count and wall-clock timeouts prevent runaway emulation.
- Memory is isolated per session; `emu_reset` clears state.

## License

MIT — see [LICENSE](LICENSE).
EOF
echo done