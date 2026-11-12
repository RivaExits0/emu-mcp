# emu-mcp

MCP server that lets an AI verify reverse-engineering guesses by emulating
single functions in isolation with Unicorn. No syscalls, filesystem, or network
are emulated; unknown calls stop execution and report their address.

## Install

```bash
pip install mcp unicorn capstone lief
```

## Run

```bash
python /yol/emu-mcp/server.py
```

## OpenCode integration

Add to `opencode.json`:

```json
"mcp": { "emu": { "type": "local", "command": ["python", "/yol/emu-mcp/server.py"], "enabled": true } }
```

## Tools

- `emu_load(path, arch=None)` — parse ELF/PE/Mach-O with LIEF and map segments.
- `emu_run(func_addr, args=[], mem_inputs={}, max_insns=100000)` — emulate one function.
- `emu_trace(func_addr, args=[], mem_inputs={}, limit=50)` — trace addresses and memory access.
- `emu_read_mem(addr, length, fmt="hex"|"ascii")` — read memory (max 4096 bytes).
- `emu_write_mem(addr, data_hex)` — write memory.
- `emu_hook_call(addr, return_value, name=None)` — stub a call (malloc, strlen, ...).
- `emu_reset()` — reset session.

## Example

Compile `tests/sample.c`, then emulate `crc32_simple` / `xor_decrypt` / `add`
to verify expected outputs.
