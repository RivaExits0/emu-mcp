"""Cross-platform path & process helpers for emu-mcp."""

from __future__ import annotations

import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform.startswith("win")
EXE_EXT = ".exe" if IS_WINDOWS else ""


def normalize_path(path: str) -> str:
    return os.path.normpath(path)


def join_paths(*parts: str) -> str:
    return os.path.join(*parts)


def is_executable(path: str) -> bool:
    if IS_WINDOWS:
        return os.path.isfile(path) and path.lower().endswith((".exe", ".bat", ".cmd", ".ps1"))
    return os.path.isfile(path) and os.access(path, os.X_OK)


def which_ex(name: str) -> Optional[str]:
    path = shutil.which(name)
    if path:
        return path
    if IS_WINDOWS and not name.lower().endswith(".exe"):
        return shutil.which(name + ".exe")
    return None


def find_executable(name: str, extra_dirs: Optional[List[str]] = None) -> Optional[str]:
    path = which_ex(name)
    if path:
        return path
    common_dirs = _common_install_dirs()
    if extra_dirs:
        common_dirs.extend(extra_dirs)
    for d in common_dirs:
        c = os.path.join(d, name + EXE_EXT)
        if is_executable(c):
            return c
    return None


def _common_install_dirs() -> List[str]:
    dirs = ["/opt", "/usr/local/bin", "/usr/bin",
            os.path.expanduser("~/.local/bin"), os.path.expanduser("~/bin")]
    if IS_WINDOWS:
        pf = os.environ.get("ProgramFiles", "C:\\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
        localapp = os.environ.get("LOCALAPPDATA", "")
        appdata = os.environ.get("APPDATA", "")
        dirs.extend([pf, pf86,
                     os.path.join(localapp, "Programs") if localapp else "",
                     os.path.join(appdata, "npm") if appdata else "",
                     "C:\\Tools", "C:\\Bin"])
    return [d for d in dirs if d]


def run_cmd(cmd: Sequence[str], timeout: int = 300, cwd: Optional[str] = None,
            env: Optional[dict] = None) -> Tuple[int, str, str, bool]:
    try:
        proc = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout,
                              cwd=cwd, env={**os.environ, **(env or {})})
        return proc.returncode, proc.stdout or "", proc.stderr or "", False
    except subprocess.TimeoutExpired as e:
        return -1, (e.stdout or "" if isinstance(e.stdout, str) else ""), \
               f"timed out after {timeout}s", True
    except Exception as e:
        return -1, "", str(e), False


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def read_file(path: str, binary: bool = False) -> str | bytes:
    mode = "rb" if binary else "r"
    with open(path, mode, encoding=None if binary else "utf-8") as f:
        return f.read()


def write_file(path: str, data: str | bytes, binary: bool = False) -> None:
    mode = "wb" if binary else "w"
    with open(path, mode, encoding=None if binary else "utf-8") as f:
        f.write(data)


def sha256_file(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_relpath(workspace: str, target: str) -> str:
    base = os.path.realpath(workspace)
    tgt = os.path.realpath(target)
    if tgt != base and not tgt.startswith(base + os.sep):
        raise ValueError(f"path escapes workspace: {target}")
    return os.path.relpath(tgt, base)
