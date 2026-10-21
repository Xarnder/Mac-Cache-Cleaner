"""Path checks used both while scanning and again at the moment of deletion.

A path is deletable only when every check agrees: the stored prefix and relative
path join without symlinks, the inode is unchanged, a rule matches that exact
path, and the path is not on the denylist. Client requests carry item ids, never
paths.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .rules import (
    APP_SUPPORT_MANUAL,
    APP_SUPPORT_REVIEW,
    APP_SUPPORT_SKIP,
    DENIED_COMPONENTS,
    DENIED_HOME_PREFIXES,
    ELECTRON_APPS,
    FIXED_BY_ID,
    cursor_partition_relative,
    cursor_partition_spec,
    INSTALLER_NAME,
    EXPORT_NAME,
    INSTALLER_SUFFIXES,
    PROFILE_NAME,
    USER_FILE_ROOTS,
    WHATSAPP_GROUP_CACHE,
    WHATSAPP_GROUP_CACHE_SKIP,
    CHROME_PROFILE_RULES,
    classify_cache_dir,
    sensitive_name,
)

SF_DATALESS = getattr(stat, "SF_DATALESS", 0x40000000)

EXACT_FORBIDDEN_RELATIVE = {
    "",
    "Library",
    "Library/Caches",
    "Library/Logs",
    "Library/Application Support",
    "Library/Application Support/Google",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Cursor",
    "Library/Application Support/Code",
    "Library/Containers",
    "Library/Group Containers",
    "Library/Developer",
    "Library/Developer/Xcode",
    "Downloads",
    "Desktop",
    "Documents",
    "Movies",
    "Pictures",
    "Music",
    "Public",
}

FORBIDDEN_SUFFIXES = (
    ".app",
    ".photoslibrary",
    ".musiclibrary",
    ".tvlibrary",
    ".kext",
    ".framework",
    ".sparsebundle",
    ".abbu",
    ".fcpbundle",
)


class UnsafePath(ValueError):
    """Raised when a path must not be deleted."""


def walk_nofollow(path: Path) -> Path:
    """Absolute path with every component checked. Symlinks are rejected."""
    if not path.is_absolute():
        raise UnsafePath("path is not absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in ("", ".", ".."):
            raise UnsafePath("path escapes its folder")
        current = current / part
        try:
            if current.is_symlink():
                raise UnsafePath("refusing to follow a symlink")
        except UnsafePath:
            raise
        except OSError as exc:
            raise UnsafePath("could not inspect the path") from exc
        if not current.exists():
            raise UnsafePath("path is missing")
    return current


def approved_temp_root() -> Path | None:
    """User temp dir, only when it really lives under /private/var/folders."""
    raw = os.environ.get("TMPDIR")
    if not raw:
        return None
    try:
        resolved = Path(raw).resolve(strict=True)
        base = walk_nofollow(Path("/private/var/folders"))
        relative = resolved.relative_to(base)
    except (OSError, ValueError, UnsafePath):
        return None
    if len(relative.parts) < 2:
        return None
    current = base
    for part in relative.parts:
        current = current / part
        if current.is_symlink() or not current.is_dir():
            return None
    return current


def home_relative(path: Path, home: Path) -> str | None:
    try:
        relative = path.relative_to(home)
    except ValueError:
        return None
    return relative.as_posix()


def is_denied(path: Path, home: Path, *, allow_app_leaf: bool = False) -> str | None:
    """Return a short reason when this path is never a deletion target."""
    try:
        relative = path.relative_to(home)
    except ValueError:
        return None
    text = relative.as_posix()
    if text in EXACT_FORBIDDEN_RELATIVE:
        return "refusing to delete a home or library root"
    for prefix in DENIED_HOME_PREFIXES:
        if text == prefix or text.startswith(prefix + "/"):
            if prefix == "Library/Application Support/Cursor/Partitions" and cursor_partition_relative(text):
                continue
            return f"inside protected data ({prefix})"
    parts = relative.parts
    for index, part in enumerate(parts):
        reason = _forbidden_part(part, allow_app_leaf=allow_app_leaf and index == len(parts) - 1)
        if reason:
            return reason
    return None


def _forbidden_part(part: str, *, allow_app_leaf: bool) -> str | None:
    """Blocked file or folder name. A checked application copy is the one exception."""
    if part in DENIED_COMPONENTS:
        return f"protected name ({part})"
    if part.endswith(FORBIDDEN_SUFFIXES):
        if allow_app_leaf and part.endswith(".app"):
            return None
        return f"protected bundle ({part})"
    return None


def _join_nofollow(prefix: Path, relative: str) -> Path:
    if not relative or "\x00" in relative or relative.startswith("/"):
        raise UnsafePath("empty or absolute relative path")
    parts = Path(relative).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise UnsafePath("relative path escapes its folder")
    prefix_real = walk_nofollow(prefix)
    current = prefix_real
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise UnsafePath("refusing to follow a symlink")
        if not current.exists():
            raise UnsafePath("path disappeared since the scan")
    try:
        current.relative_to(prefix_real)
    except ValueError as exc:
        raise UnsafePath("path escaped its folder") from exc
    if current == prefix_real:
        raise UnsafePath("refusing to delete the folder that contains the targets")
    return current


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return path != root


def _dataless(path: Path) -> bool:
    try:
        flags = path.lstat().st_flags  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False
    return bool(flags & SF_DATALESS)


def _exact(path: Path, home: Path, relative: str) -> bool:
    try:
        return path.relative_to(home).as_posix() == relative and not path.is_symlink()
    except ValueError:
        return False


def _matches_rule(rule_id: str, path: Path, home: Path) -> bool:
    if rule_id == "info-only" or not rule_id:
        return False
    if path.is_symlink():
        return False

    fixed = FIXED_BY_ID.get(rule_id)
    if fixed is not None:
        if path.is_dir() if fixed.kind == "dir" else path.is_file():
            return _exact(path, home, fixed.relative_path)
        return False

    if rule_id == "cache-dir":
        caches = home / "Library" / "Caches"
        if path.parent != caches or not path.is_dir():
            return False
        verdict = classify_cache_dir(path.name)
        return verdict.selectable and verdict.deletion in {"permanent", "trash"}

    if rule_id == "log-dir":
        logs = home / "Library" / "Logs"
        return path.parent == logs and path.is_dir() and not sensitive_name(path.name)

    if rule_id == "google-cache-child":
        root = home / "Library" / "Caches" / "Google"
        return (
            path.parent == root
            and path.is_dir()
            and path.name not in {"Chrome"}
            and not path.name.startswith(".")
            and path.name not in DENIED_COMPONENTS
            and not sensitive_name(path.name)
        )

    if rule_id == "whatsapp-group-cache":
        parent = home.joinpath(*WHATSAPP_GROUP_CACHE.split("/"))
        return (
            path.parent == parent
            and path.is_dir()
            and path.name not in WHATSAPP_GROUP_CACHE_SKIP
            and path.name not in DENIED_COMPONENTS
        )

    if rule_id == "app-support":
        root = home / "Library" / "Application Support"
        try:
            relative = path.relative_to(root)
        except ValueError:
            return False
        if len(relative.parts) != 2 or not path.is_dir():
            return False
        app_name, child = relative.parts
        if app_name in APP_SUPPORT_SKIP or app_name.startswith("com.apple."):
            return False
        if "WhatsApp" in app_name or "whatsapp" in app_name.lower():
            return False
        return child in APP_SUPPORT_MANUAL or child in APP_SUPPORT_REVIEW

    if rule_id.startswith("chrome-profile:"):
        piece = rule_id.split(":", 1)[1]
        spec = next((item for item in CHROME_PROFILE_RULES if item["id"] == piece), None)
        if spec is None:
            return False
        root = home.joinpath(*spec["root"].split("/"))
        try:
            relative = path.relative_to(root)
        except ValueError:
            return False
        subpath = Path(spec["subpath"])
        if len(relative.parts) != 1 + len(subpath.parts):
            return False
        if not PROFILE_NAME.match(relative.parts[0]):
            return False
        return relative.parts[1:] == subpath.parts and path.is_dir()

    if rule_id.startswith("electron:"):
        _prefix, app_id, child_id = rule_id.split(":", 2)
        app = next((item for item in ELECTRON_APPS if item["id"] == app_id), None)
        if app is None:
            return False
        child = next((item for item in app["children"] if item["id"] == child_id), None)
        if child is None:
            return False
        expected = home.joinpath(*app["support"].split("/"), *Path(child["subpath"]).parts)
        return path == expected and path.is_dir()

    if rule_id == "cursor-partition":
        root = home / "Library" / "Application Support" / "Cursor" / "Partitions"
        try:
            relative = path.relative_to(root)
        except ValueError:
            return False
        return cursor_partition_spec(relative.parts) is not None and path.is_dir() and not path.is_symlink()

    if rule_id == "installer":
        return _match_installer(path, home)

    if rule_id == "large-file":
        return _match_large_file(path, home)

    return False


def _match_installer(path: Path, home: Path) -> bool:
    if path.is_symlink():
        return False
    if path.name.endswith(".app"):
        return _match_app_bundle(path, home)
    if not path.is_file():
        return False
    suffix = path.suffix.lower()
    if suffix not in INSTALLER_SUFFIXES and suffix != ".zip":
        return False
    if suffix == ".zip" and (not INSTALLER_NAME.search(path.name) or EXPORT_NAME.search(path.name)):
        return False
    temp = approved_temp_root()
    if temp is not None:
        try:
            relative = path.relative_to(temp)
        except ValueError:
            relative = None
        if relative is not None and len(relative.parts) == 1:
            return True
    return _file_depth_ok(path, home, installer=True)


def _match_app_bundle(path: Path, home: Path) -> bool:
    """An application copy sitting in Downloads or on the Desktop, not an installed app."""
    if path.is_symlink() or not path.is_dir() or not path.name.endswith(".app"):
        return False
    for name in ("Downloads", "Desktop"):
        root = home / name
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if 1 <= len(relative.parts) <= 2:
            return True
    return False


def _match_large_file(path: Path, home: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    if path.suffix.lower() in INSTALLER_SUFFIXES:
        return False
    return _file_depth_ok(path, home, installer=False)


def _file_depth_ok(path: Path, home: Path, *, installer: bool) -> bool:
    limits = {
        "Downloads": 2,
        "Desktop": 2,
        "Documents": 2,
        "Movies": 2,
    }
    if installer:
        limits["Library/Caches"] = 2
        limits["Library/Google"] = 4
        limits["Library/Application Support/Google/GoogleUpdater"] = 3
    for relative_root, depth in limits.items():
        root = home.joinpath(*relative_root.split("/"))
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if 1 <= len(relative.parts) <= depth:
            return True
    return False


def assert_user_file_policy(path: Path, home: Path, *, rule_id: str, deletion: str, kind: str) -> None:
    for name in USER_FILE_ROOTS + ("Pictures", "Music", "Public"):
        root = home / name
        if _under(path, root) or path == root:
            if name in {"Pictures", "Music", "Public"}:
                raise UnsafePath(f"{name} is never deleted")
            if deletion != "trash":
                raise UnsafePath("files in your own folders can only be moved to the Trash")
            if rule_id not in {"installer", "large-file"}:
                raise UnsafePath("this file is not an installer or a reviewed large file")
            if kind == "file":
                return
            if kind == "dir" and rule_id == "installer" and path.name.endswith(".app"):
                return
            raise UnsafePath("folders in your own folders are not deleted, except an application copy you checked")


def validate_item(
    item: dict,
    *,
    home: Path,
    project_root: Path,
    icloud_desktop: bool,
    icloud_documents: bool,
) -> Path:
    """Return the real path to delete, or raise UnsafePath."""
    if item.get("kind") == "info" or item.get("deletion") == "none" or not item.get("selectable"):
        raise UnsafePath("this item is not deletable")
    prefix = Path(item.get("prefix") or "")
    relative = str(item.get("relative") or "")
    candidate = _join_nofollow(prefix, relative)
    if str(candidate) != item.get("path"):
        raise UnsafePath("stored path does not match the checked folder")
    if not candidate.is_absolute():
        raise UnsafePath("path is not absolute")
    rule_id = str(item.get("rule_id") or "")
    allow_app = rule_id == "installer" and candidate.name.endswith(".app")
    for index, part in enumerate(candidate.parts):
        if _forbidden_part(part, allow_app_leaf=allow_app and index == len(candidate.parts) - 1):
            raise UnsafePath("path includes a protected name")

    try:
        project = project_root.resolve()
        if candidate == project or candidate.is_relative_to(project) or project.is_relative_to(candidate):
            raise UnsafePath("refusing to delete the cleaner or a folder that contains it")
    except OSError as exc:
        raise UnsafePath("could not check the cleaner location") from exc

    home_real = walk_nofollow(home)
    if candidate == home_real or home_real.is_relative_to(candidate):
        raise UnsafePath("refusing to delete your home folder")
    for forbidden in (Path("/"), Path("/Users"), Path("/Applications"), Path("/System"), Path("/Library")):
        if candidate == forbidden:
            raise UnsafePath("refusing to delete a system root")

    reason = is_denied(candidate, home_real, allow_app_leaf=allow_app)
    if reason:
        raise UnsafePath(reason)

    if not _matches_rule(rule_id, candidate, home_real):
        raise UnsafePath("path is not one of the approved cleanup locations")

    deletion = str(item.get("deletion") or "")
    kind = str(item.get("kind") or "")
    if deletion not in {"permanent", "trash"}:
        raise UnsafePath("unknown deletion method")
    assert_user_file_policy(candidate, home_real, rule_id=rule_id, deletion=deletion, kind=kind)
    inside_home = _under(candidate, home_real)
    temp = approved_temp_root()
    if temp is not None and not inside_home and (_under(candidate, temp) or candidate == temp):
        if candidate == temp or rule_id != "installer" or deletion != "trash" or kind != "file":
            raise UnsafePath("temporary files can only be installer packages moved to the Trash")

    if _under(candidate, home_real / "Desktop") and icloud_desktop:
        raise UnsafePath("Desktop is in iCloud Drive, so it is not deleted")
    if _under(candidate, home_real / "Documents") and icloud_documents:
        raise UnsafePath("Documents is in iCloud Drive, so it is not deleted")
    if _dataless(candidate):
        raise UnsafePath("file is an iCloud placeholder and is not deleted")

    try:
        info = candidate.lstat()
    except OSError as exc:
        raise UnsafePath("path disappeared since the scan") from exc
    if stat.S_ISLNK(info.st_mode):
        raise UnsafePath("refusing to follow a symlink")
    if info.st_dev != int(item["dev"]) or info.st_ino != int(item["ino"]):
        raise UnsafePath("the item changed since the scan")
    if kind == "dir" and not stat.S_ISDIR(info.st_mode):
        raise UnsafePath("expected a folder")
    if kind == "file" and not stat.S_ISREG(info.st_mode):
        raise UnsafePath("expected a file")
    if len(candidate.parts) < 4:
        raise UnsafePath("path is too shallow to delete")
    return candidate
