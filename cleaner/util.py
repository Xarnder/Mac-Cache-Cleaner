"""Small helpers: sizes, disk usage, and the local log."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path


class DiskUsageError(RuntimeError):
    pass


def expand(relative: str, home: Path) -> Path:
    if not relative or relative.startswith("/") or "\x00" in relative:
        raise ValueError(f"unsafe relative path: {relative!r}")
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe relative path: {relative!r}")
    return home.joinpath(*path.parts)


def format_bytes(size: int) -> str:
    if size < 0:
        size = 0
    units = ("bytes", "KB", "MB", "GB", "TB")
    value = float(size)
    for unit in units:
        if value < 1000 or unit == units[-1]:
            if unit == "bytes":
                return f"{int(value)} bytes"
            return f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} TB"


def format_mtime(path: Path) -> str:
    modified = datetime.fromtimestamp(path.lstat().st_mtime)
    return modified.strftime("%d %b %Y, %H:%M").lstrip("0")


def _demote() -> None:
    try:
        os.nice(10)
    except OSError:
        pass


def _du(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        timeout=timeout,
        cwd="/",
        check=False,
        preexec_fn=_demote,
    )


def disk_usage(path: Path, timeout: int = 180) -> int:
    """Disk usage in bytes via macOS du. Raises DiskUsageError on a bad answer."""
    result = _du(["/usr/bin/du", "-sk", str(path)], timeout)
    expected = str(path)
    for line in result.stdout.splitlines():
        kilobytes, separator, reported = line.partition("\t")
        if separator and reported == expected and kilobytes.isdigit():
            return int(kilobytes) * 1024
    detail = result.stderr.strip() or "du returned no size"
    raise DiskUsageError(detail)


def disk_usage_children(root: Path, timeout: int = 600) -> dict[str, int]:
    """Sizes of direct children, keyed by directory name. Does not follow the root's children."""
    result = _du(["/usr/bin/du", "-d", "1", "-k", str(root)], timeout)
    found: dict[str, int] = {}
    root_name = str(root)
    for line in result.stdout.splitlines():
        kilobytes, separator, reported = line.partition("\t")
        if not separator or not kilobytes.isdigit() or reported == root_name:
            continue
        parent, name = os.path.split(reported)
        if parent == root_name and name not in ("", ".", ".."):
            found[name] = int(kilobytes) * 1024
    if result.returncode != 0 and not found:
        detail = result.stderr.strip() or "du failed"
        raise DiskUsageError(detail)
    return found


def append_log(project_root: Path, event: dict) -> None:
    directory = project_root / "logs"
    directory.mkdir(exist_ok=True)
    payload = {"time": datetime.now().isoformat(timespec="seconds"), **event}
    with (directory / "cleanup.log").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
