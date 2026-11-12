# emu-mcp

[![CI](https://github.com/RivaExits0/emu-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/RivaExits0/emu-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**emu-mcp** is an MCP server that lets an AI verify reverse-engineering guesses
by emulating single functions in isolation with Unicorn. No syscalls, filesystem,
or network are emulated; unknown calls stop execution and report their address.

> **Turkish / Türkçe:** emu-mcp, Unicorn motoru ile tek bir fonksiyonu izole
> olarak emulate eden bir MCP sunucusudur. Reverse engineering tahminlerini
> doğrulamak için kullanılır. Hiçbir syscall, dosya sistemi veya ağ emüle
> edilmez; bilinmeyen çağrılar durdurulur ve adresi raporlanır.

## Why

When reverse-engineering a binary, you form hypotheses about what a function
does. `emu-mcp` lets you **run that function with known inputs** in an isolated
emulator and check the result, instead of trusting the guess.

Supported architectures: **x86, x64, arm, arm64**.

## Features

- Parse ELF / PE / Mach-O binaries with LIEF and auto-detect architecture.
- Emulate a single function with arguments passed per calling convention
  (System V AMD64 ARM64, etc.).
- Pre-write memory inputs, read/write memory, stub libc/API calls.
- Trace executed addresses and memory reads/writes (paginated with limit/offset).
- Hard limits on instruction count and wall-clock time to prevent runaway emulation.
- x86/x64 stack alignment (RSP 8 mod 16) and ARM SP alignment.
- Floating-point (XMM) argument and return-value stub support.
- Clean, machine-readable JSON output suitable for AI agents.
- No syscalls, filesystem, or network are emulated.
- Unknown calls stop execution and report their address.

## Install

```bash
pip install "mcp>=1.0" unicorn capstone lief
```

Or from source:

```bash
git clone https://github.com/RivaExits0/emu-mcp.git
cd emu-mcp
pip install -e .
```

## Run

```bash
python server.py
```

The server speaks MCP over **stdio**.

## OpenCode Integration

Add to `opencode.json`:

```json
{
  "mcp": {
    "emu": {
      "type": "local",
      "command": ["python", "/path/to/emu-mcp/server.py"],
      "enabled": true
    }
  }
}
```

## MCP Tools

| Tool | Description | When to call |
|------|-------------|--------------|
| `emu_load(path, arch=None)` | Parse a binary and map its segments into Unicorn memory. | First, before any emulation. |
| `emu_run(func_addr, args=[], mem_inputs={}, max_insns=100000)` | Emulate one function, return value + registers. | After `emu_load`. |
| `emu_trace(func_addr, args=[], mem_inputs={}, limit=50, offset=0)` | Trace addresses and memory access (paginated). | After `emu_run` to see execution flow. |
| `emu_read_mem(addr, length, fmt="hex"|"ascii")` | Read up to 4096 bytes from emulated memory. | To inspect memory after emulation. |
| `emu_write_mem(addr, data_hex)` | Write hex data to emulated memory. | To set up inputs before `emu_run`. |
| `emu_hook_call(addr, return_value, name=None)` | Stub a call (malloc, strlen, …) with a fixed return value. | To avoid calling unsupported libc functions. |
| `emu_reset()` | Reset the emulation session (clear memory, registers, hooks). | Between unrelated emulations. |

### Tool: `emu_load`

**Example call:**
```json
{"tool": "emu_load", "args": {"path": "tests/sample_x64", "arch": null}}
```

**Example output:**
```json
{
  "format": "elf",
  "arch": "x64",
  "entry": "0x401000",
  "segments": [
    {"vaddr": "0x400000", "memsz": 0x2000, "filesz": 0x1f00, "offset": 0}
  ],
  "base_address": "0x400000"
}
```

### Tool: `emu_run`

**Example call:**
```json
{"tool": "emu_run", "args": {"func_addr": "0x4011d0", "args": [5, 7], "max_insns": 100000}}
```

**Example output:**
```json
{
  "return_value": 12,
  "stop_reason": "returned",
  "instruction_count": 11,
  "registers": {"rax": 12, "rip": "0x4011db", ...}
}
```

### Tool: `emu_trace`

**Example call:**
```json
{"tool": "emu_trace", "args": {"func_addr": "0x4011d0", "args": [5, 7], "limit": 50, "offset": 0}}
```

**Example output:**
```
stop: returned, insns: 11
called addresses:
  0x4011d0
  0x4011d4
  0x4011d5
  0x4011d8
```

## Testing

```bash
make test
```

Runs `tests/test_emu.py`, `tests/test_hard.py`, and `examples/demo.py`.

The hard suite covers:
- Recursion (factorial)
- Function pointers (indirect calls)
- Stack arguments (many-arg functions)
- Structs by pointer
- In-place memory modification
- Nested calls
- Libc hooks (strcmp)
- Floating point (XMM registers)
- Error cases (unmapped memory, instruction limit)

### Demo

```bash
make demo
```

Expected output:
```
=== Demo 1: add(5, 7) ===
result=12 stop=returned insns=11
...
ALL DEMO CHECKS PASSED
```

## Architecture

```
server.py      MCP tool definitions (stdio transport)
emulator.py    Unicorn engine, calling conventions, hooks, tracing
loader.py      LIEF-based binary parsing and segment mapping
```

## Pagination (`limit` / `offset`)

`emu_trace` supports `limit` and `offset` for long trace lists:
- `limit`: maximum number of trace lines to return (default 50)
- `offset`: number of trace lines to skip (default 0)

## Security Notes

- No syscalls, filesystem, or network are emulated.
- Unknown calls stop execution and report their address.
- Instruction count and wall-clock timeouts prevent runaway emulation.
- Memory is isolated per session; `emu_reset` clears state.

## Limitations

- No real syscall emulation; unknown calls stop execution.
- No filesystem or network access inside the emulator.
- Floating-point support is limited to XMM register stubs.
- Stack alignment follows System V AMD64 ABI; other ABIs may need adjustment.

## License

MIT — see [LICENSE](LICENSE).
