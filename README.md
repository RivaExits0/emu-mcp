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

---

## Why

When reverse-engineering a binary, you form hypotheses about what a function
does. `emu-mcp` lets you **run that function with known inputs** in an isolated
emulator and check the result, instead of trusting the guess.

Supported architectures: **x86, x64, arm, arm64**.

---

## Features

- Parse ELF / PE / Mach-O binaries with LIEF and auto-detect architecture.
- Emulate a single function with arguments passed per calling convention
  (System V AMD64, ARM64, etc.).
- Pre-write memory inputs, read/write memory, stub libc/API calls.
- Trace executed addresses and memory reads/writes (paginated with limit/offset).
- Hard limits on instruction count and wall-clock time to prevent runaway emulation.
- x86/x64 stack alignment (RSP 8 mod 16) and ARM SP alignment.
- Floating-point (XMM) argument and return-value stub support.
- Clean, machine-readable JSON output suitable for AI agents.
- No syscalls, filesystem, or network are emulated.
- Unknown calls stop execution and report their address.

---

## Install

### From PyPI (when published)
```bash
pip install emu-mcp
```

### From GitHub
```bash
pip install git+https://github.com/RivaExits0/emu-mcp.git
```

### From Source
```bash
git clone https://github.com/RivaExits0/emu-mcp.git
cd emu-mcp
pip install -e .[dev]    # or just `pip install -e .` for production
```

> **System requirements (Linux):** `gcc-x86-64-linux-gnu` and `binutils` for building test binaries. On Windows, cross-compilation is not required for the test suite.

---

## Run

```bash
emu-mcp
# or
python -m emu_mcp
```

The server speaks MCP over **stdio**.

---

## Claude Desktop Integration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "emu-mcp": {
      "command": "emu-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

> **Windows:** If installed via pip, `emu-mcp` should be on PATH. Otherwise use full path: `C:\\path\\to\\emu-mcp\\.venv\\Scripts\\emu-mcp.exe`.

---

## OpenCode Integration

Add to `opencode.json`:

```json
{
  "mcp": {
    "emu": {
      "type": "local",
      "command": ["emu-mcp"],
      "enabled": true
    }
  }
}
```

---

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

---

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

---

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

---

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

---

## Supported Architectures

| Architecture | Calling Convention | Status |
|--------------|-------------------|--------|
| x86 (32-bit) | cdecl | ✅ |
| x64 (64-bit) | System V AMD64 | ✅ |
| ARM (32-bit) | AAPCS | ✅ |
| ARM64 (AArch64) | AAPCS64 | ✅ |

---

## Testing

```bash
# Build test binaries (Linux only)
make all

# Run test suite
pytest -q
# or
make test

# Run demo
make demo
# or
python examples/demo.py
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

---

## Architecture

```
src/emu_mcp/
├── server.py      MCP tool definitions (stdio transport)
├── emulator.py    Unicorn engine, calling conventions, hooks, tracing
├── loader.py      LIEF-based binary parsing and segment mapping
└── platform_utils.py  Cross-platform paths, subprocess, file I/O
```

---

## Pagination (`limit` / `offset`)

`emu_trace` supports `limit` and `offset` for long trace lists:
- `limit`: maximum number of trace lines to return (default 50)
- `offset`: number of trace lines to skip (default 0)

---

## Security Notes

- No syscalls, filesystem, or network are emulated.
- Unknown calls stop execution and report their address.
- Instruction count and wall-clock timeouts prevent runaway emulation.
- Memory is isolated per session; `emu_reset` clears state.

---

## Limitations

- No real syscall emulation; unknown calls stop execution.
- No filesystem or network access inside the emulator.
- Floating-point support is limited to XMM register stubs.
- Stack alignment follows System V AMD64 ABI; other ABIs may need adjustment.

---

## 🔗 Related Projects

- **forge-mcp** — Game modding toolkit (hex, PE, APK, Unity, Unreal, tables). Use for hex editing, signature generation, APK repacking.
- **henry-mcp** — Static compatibility analysis for EXE/DLL/APK/Kotlin. Use for checking module compatibility.
- **crash-mcp** — Crash dump analysis (ELF core + Windows minidump). Use for post-mortem debugging.

---

## 📦 Release

- **Latest:** [v0.1.0](https://github.com/RivaExits0/emu-mcp/releases/tag/v0.1.0)
- **Install from release:** `pip install git+https://github.com/RivaExits0/emu-mcp.git@v0.1.0`

### Create Release
```bash
git tag -a v0.1.0 -m "emu-mcp v0.1.0: Initial release"
git push origin v0.1.0
```

---

## License

MIT — see [LICENSE](LICENSE).