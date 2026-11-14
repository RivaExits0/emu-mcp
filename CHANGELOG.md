# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-14

### Added
- Initial release of emu-mcp MCP server for isolated function emulation with Unicorn
- 7 MCP tools: `emu_load`, `emu_run`, `emu_trace`, `emu_read_mem`, `emu_write_mem`, `emu_hook_call`, `emu_reset`
- ELF / PE / Mach-O binary parsing with LIEF, auto-detect architecture (x86, x64, arm, arm64)
- Calling convention support: cdecl (x86), System V AMD64 (x64), AAPCS (ARM), AAPCS64 (ARM64)
- Memory pre-write/read, register inspection, instruction tracing with pagination
- libc/API call stubbing (hooks) for unknown calls
- Hard limits on instruction count and wall-clock time
- Stack alignment (RSP 8 mod 16 for x64, SP 8 mod 8 for ARM64)
- Floating-point (XMM) argument and return-value stub support
- Cross-platform support (Windows/Linux) via `platform_utils.py`
- Comprehensive test suite (39 tests passing): recursion, function pointers, stack args, structs, nested calls, libc hooks, XMM registers, error cases
- CI pipeline (GitHub Actions: ubuntu-latest + windows-latest, Python 3.10/3.11/3.12)

### Security
- No syscalls, filesystem, or network emulated
- Unknown calls stop execution and report address
- Instruction count and wall-clock timeouts prevent runaway emulation
- Memory isolated per session; `emu_reset` clears state

[0.1.0]: https://github.com/RivaExits0/emu-mcp/releases/tag/v0.1.0