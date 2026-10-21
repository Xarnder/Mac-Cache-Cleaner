"""Find cleanup candidates. This module only reads the disk.

Targets come from the tables in rules.py. A folder is never chosen just because
its name contains "Cache", and protected data is not given a deletion id.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
from pathlib import Path

from .rules import (
    APP_SUPPORT_MANUAL,
    APP_SUPPORT_REVIEW,
    APP_SUPPORT_SKIP,
    CATEGORIES,
    CHROME_PROFILE_RULES,
    DENIED_COMPONENTS,
    CURSOR_PARTITION_CACHES,
    ELECTRON_APPS,
    FIXED_RULES,
    INSTALLER_NAME,
    EXPORT_NAME,
    INSTALLER_SEARCH_ROOTS,
    INSTALLER_SUFFIXES,
    LARGE_FILE_ROOTS,
    PRUNE_DIR_NAMES,
    PROCESS_NAME,
    PROFILE_NAME,
    WHATSAPP_GROUP_CACHE,
    WHATSAPP_GROUP_CACHE_SKIP,
    category_label,
    classify_cache_dir,
    risk_label,
    sensitive_name,
)
from .safety import SF_DATALESS, UnsafePath, approved_temp_root, walk_nofollow
from .util import DiskUsageError, disk_usage, disk_usage_children, format_mtime


def processes_running(names: tuple[str, ...]) -> list[str]:
    running = []
    for name in names:
        if not PROCESS_NAME.match(name):
            continue
        result = subprocess.run(
            ["/usr/bin/pgrep", "-x", name],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            running.append(name)
    return running


def read_icloud_flags() -> tuple[bool, bool]:
    """True means that folder is in iCloud and must not be deleted. Fail closed."""

    def flag(key: str) -> bool:
        result = subprocess.run(
            ["/usr/bin/defaults", "read", "com.apple.finder", key],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return True
        return result.stdout.strip() == "1"

    return flag("FXICloudDriveDesktop"), flag("FXICloudDriveDocuments")


def normalize_root(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path)
    try:
        return walk_nofollow(path)
    except UnsafePath:
        resolved = path.resolve()
        if resolved == path:
            raise
        return walk_nofollow(resolved)


class ScanResult:
    def __init__(self, items: list[dict], warnings: list[str], home: str) -> None:
        self.items = items
        self.warnings = warnings
        self.home = home


class Scanner:
    def __init__(
        self,
        home: Path,
        *,
        min_dir_bytes: int,
        min_installer_bytes: int,
        min_large_file_bytes: int,
        aggregate_blocked_below: int,
        process_check,
        progress,
        icloud_desktop: bool,
        icloud_documents: bool,
    ) -> None:
        self.home = home
        self.min_dir_bytes = min_dir_bytes
        self.min_installer_bytes = min_installer_bytes
        self.min_large_file_bytes = min_large_file_bytes
        self.aggregate_blocked_below = aggregate_blocked_below
        self.process_check = process_check
        self.progress = progress or (lambda _message: None)
        self.icloud_desktop = icloud_desktop
        self.icloud_documents = icloud_documents
        self.items: list[dict] = []
        self.warnings: list[str] = []
        self._seen_paths: set[str] = set()
        self._seen_ids: set[str] = set()
        self._process_cache: dict[tuple[str, ...], bool] = {}
        self._small_blocked: list[int] = []

    def note(self, message: str) -> None:
        self.progress(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def app_running(self, names: tuple[str, ...]) -> bool:
        if not names:
            return False
        key = tuple(names)
        if key not in self._process_cache:
            self._process_cache[key] = bool(self.process_check(key))
        return self._process_cache[key]

    def anchor(self, path: Path) -> bool:
        try:
            return walk_nofollow(path) == path and not path.is_symlink()
        except UnsafePath:
            self.warn(f"Skipped {path} because a parent folder is a symlink.")
            return False

    def measure(self, path: Path, timeout: int = 180) -> int | None:
        try:
            return disk_usage(path, timeout=timeout)
        except (DiskUsageError, OSError, subprocess.TimeoutExpired) as exc:
            self.warn(f"Could not measure {path} in one pass: {exc}")
            estimate, truncated = _estimate_usage(path)
            if estimate is None:
                return None
            if truncated:
                self.warn(f"Size shown for {path} is a minimum. The folder can still be deleted.")
            return estimate

    def add(self, item: dict | None) -> None:
        if not item:
            return
        if item["path"] in self._seen_paths or item["id"] in self._seen_ids:
            return
        self._seen_paths.add(item["path"])
        self._seen_ids.add(item["id"])
        self.items.append(item)

    def make(
        self,
        *,
        rule_id: str,
        path: Path,
        prefix: Path,
        relative: str,
        app: str,
        category: str,
        name: str,
        risk: str,
        description: str,
        deletion: str,
        size_bytes: int,
        selectable: bool,
        kind: str,
        requires_app_closed: bool = False,
        processes: tuple[str, ...] = (),
        close_message: str = "",
        risk_label_text: str | None = None,
        group: str = "",
        manual_label: str = "Review manually",
    ) -> dict | None:
        if "\x00" in relative or ".." in Path(relative).parts:
            self.warn(f"Skipped an unsafe relative path under {prefix}.")
            return None
        if prefix.joinpath(*Path(relative).parts) != path:
            self.warn(f"Skipped {path} because it does not sit in the expected folder.")
            return None
        try:
            info = path.lstat()
        except OSError as exc:
            self.warn(f"Could not read {path}: {exc.strerror}")
            return None
        if stat.S_ISLNK(info.st_mode):
            self.warn(f"Skipped symlink {path}.")
            return None
        actual = "dir" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else ""
        if actual != kind:
            return None
        if not self.anchor(prefix):
            return None
        running = requires_app_closed and self.app_running(processes)
        item_id = hashlib.sha256(f"{rule_id}\n{path}".encode()).hexdigest()[:16]
        return {
            "id": item_id,
            "rule_id": rule_id,
            "app": app,
            "category": category,
            "category_label": category_label(category),
            "name": name,
            "path": str(path),
            "prefix": str(prefix),
            "relative": relative,
            "size_bytes": size_bytes,
            "modified": format_mtime(path),
            "risk": risk,
            "risk_label": risk_label_text or risk_label(risk, manual_label=manual_label),
            "deletion": deletion,
            "deletion_label": {"permanent": "Permanent", "trash": "Move to Trash", "none": "Not deleted"}.get(
                deletion, deletion
            ),
            "requires_app_closed": requires_app_closed,
            "processes": processes,
            "close_message": close_message,
            "app_running": running,
            "description": description,
            "kind": kind,
            "dev": info.st_dev,
            "ino": info.st_ino,
            "selectable": selectable,
            "group": group,
        }

    def add_directory(
        self,
        path: Path,
        *,
        prefix: Path,
        relative: str,
        rule_id: str,
        app: str,
        category: str,
        name: str,
        risk: str,
        description: str,
        deletion: str = "permanent",
        requires_app_closed: bool = False,
        processes: tuple[str, ...] = (),
        close_message: str = "",
        selectable: bool = True,
        group: str = "",
        manual_label: str = "Review manually",
        size_bytes: int | None = None,
        allow_small: bool = False,
        measure_timeout: int = 180,
    ) -> None:
        if path.is_symlink() or not path.is_dir():
            return
        if _bad_component(path.name):
            return
        size = self.measure(path, timeout=measure_timeout) if size_bytes is None else size_bytes
        if size is None or size <= 0:
            return
        if not selectable and size < self.aggregate_blocked_below:
            self._small_blocked.append(size)
            return
        if selectable and size < self.min_dir_bytes and not allow_small:
            return
        if not selectable:
            rule_id = "info-only"
            deletion = "none"
            group = group or "system"
        close = close_message or (f"Close {app} before cleaning these files." if requires_app_closed else "")
        self.add(
            self.make(
                rule_id=rule_id,
                path=path,
                prefix=prefix,
                relative=relative,
                app=app,
                category=category,
                name=name,
                risk=risk,
                description=description,
                deletion=deletion,
                size_bytes=size,
                selectable=selectable,
                kind="dir",
                requires_app_closed=requires_app_closed,
                processes=processes,
                close_message=close,
                group=group,
                manual_label=manual_label,
            )
        )

    def add_file(
        self,
        path: Path,
        *,
        prefix: Path,
        relative: str,
        rule_id: str,
        app: str,
        category: str,
        name: str,
        risk: str,
        description: str,
        deletion: str,
        selectable: bool,
        manual_label: str,
        minimum: int,
        requires_app_closed: bool = False,
        processes: tuple[str, ...] = (),
    ) -> None:
        if path.is_symlink() or not path.is_file() or _bad_component(path.name):
            return
        try:
            size = path.lstat().st_size
        except OSError:
            return
        if size < minimum:
            return
        close = f"Close {app} before cleaning these files." if requires_app_closed else ""
        self.add(
            self.make(
                rule_id=rule_id if selectable else "info-only",
                path=path,
                prefix=prefix,
                relative=relative,
                app=app,
                category=category,
                name=name,
                risk=risk if selectable else "blocked",
                description=description,
                deletion=deletion if selectable else "none",
                size_bytes=size,
                selectable=selectable,
                kind="file",
                requires_app_closed=requires_app_closed,
                processes=processes,
                close_message=close,
                manual_label=manual_label,
                group="" if selectable else "system",
            )
        )

    def scan_fixed(self) -> None:
        self.note("Checking known app folders")
        for rule in FIXED_RULES:
            path = self.home.joinpath(*rule.relative_path.split("/"))
            prefix = path.parent
            if rule.kind == "dir":
                self.add_directory(
                    path,
                    prefix=prefix,
                    relative=path.name,
                    rule_id=rule.id,
                    app=rule.app,
                    category=rule.category,
                    name=rule.name,
                    risk=rule.risk,
                    description=rule.description,
                    deletion=rule.deletion,
                    requires_app_closed=rule.requires_app_closed,
                    processes=rule.processes,
                    close_message=rule.close_message,
                    selectable=rule.risk != "blocked",
                    manual_label="Not selected automatically" if rule.risk == "manual" else "Review manually",
                )
            else:
                self.add_file(
                    path,
                    prefix=prefix,
                    relative=path.name,
                    rule_id=rule.id,
                    app=rule.app,
                    category=rule.category,
                    name=rule.name,
                    risk=rule.risk,
                    description=rule.description,
                    deletion=rule.deletion,
                    selectable=rule.risk != "blocked",
                    manual_label="Not selected automatically",
                    minimum=self.min_dir_bytes,
                    requires_app_closed=rule.requires_app_closed,
                    processes=rule.processes,
                )

    def scan_chrome_profiles(self) -> None:
        self.note("Measuring Chrome caches")
        for spec in CHROME_PROFILE_RULES:
            root = self.home.joinpath(*spec["root"].split("/"))
            if not root.is_dir() or root.is_symlink() or not self.anchor(root):
                continue
            try:
                profiles = [
                    entry
                    for entry in root.iterdir()
                    if entry.is_dir() and not entry.is_symlink() and PROFILE_NAME.match(entry.name)
                ]
            except OSError as exc:
                self.warn(f"Could not list Chrome profiles in {root.name}: {exc.strerror}")
                continue
            for profile in profiles:
                target = profile.joinpath(*Path(spec["subpath"]).parts)
                relative = str(Path(profile.name) / spec["subpath"])
                self.add_directory(
                    target,
                    prefix=root,
                    relative=relative,
                    rule_id=f"chrome-profile:{spec['id']}",
                    app="Google Chrome",
                    category="chrome",
                    name=f"{spec['name']} — {profile.name}",
                    risk=spec["risk"],
                    description=spec["description"],
                    requires_app_closed=True,
                    processes=("Google Chrome",),
                )

    def scan_electron(self) -> None:
        self.note("Measuring Cursor and VS Code")
        for app in ELECTRON_APPS:
            root = self.home.joinpath(*app["support"].split("/"))
            if not root.is_dir() or root.is_symlink() or not self.anchor(root):
                continue
            for child in app["children"]:
                target = root.joinpath(*Path(child["subpath"]).parts)
                self.add_directory(
                    target,
                    prefix=root,
                    relative=child["subpath"],
                    rule_id=f"electron:{app['id']}:{child['id']}",
                    app=app["app"],
                    category=app["category"],
                    name=child["name"],
                    risk=child["risk"],
                    description=child["description"],
                    requires_app_closed=True,
                    processes=tuple(app["processes"]),
                    manual_label="Review manually",
                    measure_timeout=900,
                )

    def scan_cursor_partitions(self) -> None:
        """Cursor's embedded browser keeps its own caches, separate from the app Cache folder."""
        root = self.home / "Library" / "Application Support" / "Cursor" / "Partitions"
        if not root.is_dir() or root.is_symlink() or not self.anchor(root):
            return
        try:
            partitions = list(root.iterdir())
        except OSError as exc:
            self.warn(f"Could not list Cursor browser windows: {exc.strerror}")
            return
        for partition in partitions:
            if (
                partition.is_symlink()
                or not partition.is_dir()
                or partition.name.startswith(".")
                or _bad_component(partition.name)
                or partition.name in DENIED_COMPONENTS
            ):
                continue
            for spec in CURSOR_PARTITION_CACHES:
                target = partition.joinpath(*spec["subpath"].split("/"))
                self.add_directory(
                    target,
                    prefix=root,
                    relative=f"{partition.name}/{spec['subpath']}",
                    rule_id="cursor-partition",
                    app="Cursor",
                    category="cursor",
                    name=f"{spec['name']} — {partition.name}",
                    risk=spec["risk"],
                    description=spec["description"],
                    requires_app_closed=True,
                    processes=("Cursor",),
                    manual_label="Review manually",
                    measure_timeout=900,
                )

    def scan_user_caches(self) -> None:
        self.note("Measuring application caches")
        caches = self.home / "Library" / "Caches"
        if not caches.is_dir() or not self.anchor(caches):
            self.warn("~/Library/Caches is not available.")
            return
        try:
            sizes = disk_usage_children(caches)
        except (DiskUsageError, OSError, subprocess.TimeoutExpired) as exc:
            self.warn(f"Could not measure ~/Library/Caches in one pass: {exc}")
            sizes = {}
        try:
            children = list(caches.iterdir())
        except OSError as exc:
            self.warn(f"Could not list ~/Library/Caches: {exc.strerror}")
            return
        for child in children:
            if child.name == "Google" or child.name.startswith(".") or _bad_component(child.name):
                continue
            if child.is_symlink():
                self.warn(f"Skipped symlink ~/Library/Caches/{child.name}.")
                continue
            if not child.is_dir():
                continue
            verdict = classify_cache_dir(child.name)
            size = sizes.get(child.name)
            self.add_directory(
                child,
                prefix=caches,
                relative=child.name,
                rule_id="cache-dir",
                app=verdict.app,
                category=verdict.category,
                name=verdict.name,
                risk=verdict.risk,
                description=verdict.description,
                deletion=verdict.deletion,
                requires_app_closed=verdict.requires_app_closed,
                processes=verdict.processes,
                close_message=verdict.close_message,
                selectable=verdict.selectable,
                size_bytes=size,
                manual_label="Review manually",
            )
        google = caches / "Google"
        if google.is_dir() and not google.is_symlink():
            try:
                extras = list(google.iterdir())
            except OSError:
                extras = []
            for child in extras:
                if child.name in {"Chrome"} or child.name.startswith(".") or _bad_component(child.name):
                    continue
                if child.is_symlink() or not child.is_dir():
                    continue
                self.add_directory(
                    child,
                    prefix=google,
                    relative=child.name,
                    rule_id="google-cache-child",
                    app="Google",
                    category="chrome",
                    name=child.name,
                    risk="manual",
                    description="A Google cache folder outside the Chrome profiles. It is not selected automatically. Chrome profiles are not inside this folder.",
                    selectable=True,
                    manual_label="Review manually",
                )

    def scan_whatsapp_group_caches(self) -> None:
        parent = self.home.joinpath(*WHATSAPP_GROUP_CACHE.split("/"))
        if not parent.is_dir() or parent.is_symlink() or not self.anchor(parent):
            return
        try:
            children = list(parent.iterdir())
        except OSError as exc:
            self.warn(f"Could not list WhatsApp group caches: {exc.strerror}")
            return
        for child in children:
            if child.name in WHATSAPP_GROUP_CACHE_SKIP or child.name.startswith("."):
                continue
            if child.is_symlink() or not child.is_dir():
                continue
            self.add_directory(
                child,
                prefix=parent,
                relative=child.name,
                rule_id="whatsapp-group-cache",
                app="WhatsApp",
                category="whatsapp",
                name=child.name,
                risk="review",
                description="Cache inside the WhatsApp shared container. Lock files are skipped. Photos and messages are not stored in this folder.",
                requires_app_closed=True,
                processes=("WhatsApp",),
            )

    def scan_logs(self) -> None:
        self.note("Measuring logs")
        logs = self.home / "Library" / "Logs"
        if not logs.is_dir() or not self.anchor(logs):
            return
        try:
            sizes = disk_usage_children(logs)
        except (DiskUsageError, OSError, subprocess.TimeoutExpired) as exc:
            self.warn(f"Could not measure ~/Library/Logs: {exc}")
            sizes = {}
        try:
            children = list(logs.iterdir())
        except OSError as exc:
            self.warn(f"Could not list logs: {exc.strerror}")
            return
        for child in children:
            if child.is_symlink() or not child.is_dir() or _bad_component(child.name):
                continue
            if sensitive_name(child.name):
                selectable = False
                risk = "blocked"
                description = "This log folder looks sensitive, so it cannot be deleted here."
            elif child.name in {"DiagnosticReports", "CrashReporter"}:
                selectable = True
                risk = "safe"
                description = "Crash and diagnostic reports. macOS writes new ones if an app crashes again."
            elif child.name.startswith("com.apple."):
                selectable = True
                risk = "review"
                description = "macOS log. Removing it drops diagnostic history. It is not selected with Safe Items."
            else:
                selectable = True
                risk = "review"
                description = "Application log. Removing it drops troubleshooting history for this app. Documents are not in this folder."
            self.add_directory(
                child,
                prefix=logs,
                relative=child.name,
                rule_id="log-dir",
                app=child.name,
                category="logs",
                name="Logs",
                risk=risk,
                description=description,
                selectable=selectable,
                size_bytes=sizes.get(child.name),
            )

    def scan_app_support(self) -> None:
        self.note("Checking application support caches")
        root = self.home / "Library" / "Application Support"
        if not root.is_dir() or not self.anchor(root):
            return
        try:
            apps = list(root.iterdir())
        except OSError as exc:
            self.warn(f"Could not list Application Support: {exc.strerror}")
            return
        for app_dir in apps:
            if (
                app_dir.is_symlink()
                or not app_dir.is_dir()
                or app_dir.name.startswith(".")
                or app_dir.name in APP_SUPPORT_SKIP
                or app_dir.name.startswith("com.apple.")
                or "whatsapp" in app_dir.name.lower()
                or _bad_component(app_dir.name)
            ):
                continue
            try:
                children = list(app_dir.iterdir())
            except OSError:
                continue
            for child in children:
                if child.is_symlink() or not child.is_dir() or _bad_component(child.name):
                    continue
                if child.name in APP_SUPPORT_REVIEW:
                    risk = "review"
                    description = "Crash dumps or logs stored next to the app. The app can write new ones. Not selected with Safe Items."
                elif child.name in APP_SUPPORT_MANUAL:
                    risk = "manual"
                    description = "The folder name looks like a cache. That is not enough to select it automatically. Quit the app, then check this path before deleting."
                else:
                    continue
                self.add_directory(
                    child,
                    prefix=root,
                    relative=f"{app_dir.name}/{child.name}",
                    rule_id="app-support",
                    app=app_dir.name,
                    category="caches",
                    name=child.name,
                    risk=risk,
                    description=description,
                    manual_label="Review manually",
                )

    def scan_installers(self, *, include_temp: bool) -> None:
        self.note("Looking for old installers")
        for relative_root, depth in INSTALLER_SEARCH_ROOTS:
            root = self.home.joinpath(*relative_root.split("/"))
            self._scan_installer_tree(root, depth)
        if not include_temp:
            return
        temp = approved_temp_root()
        if temp is None:
            return
        try:
            entries = list(temp.iterdir())
        except OSError as exc:
            self.warn(f"Could not list temporary files: {exc.strerror}")
            return
        cutoff = _now() - 24 * 60 * 60
        for entry in entries:
            if entry.is_symlink() or not entry.is_file():
                continue
            try:
                if entry.lstat().st_mtime > cutoff:
                    continue
            except OSError:
                continue
            self._consider_installer(entry, temp)

    def _scan_installer_tree(self, root: Path, max_depth: int) -> None:
        if not root.is_dir() or root.is_symlink() or not self.anchor(root):
            return
        bundles = root in {self.home / "Downloads", self.home / "Desktop"}
        for path in _walk_files(root, max_depth, app_bundles=bundles):
            if path.name.endswith(".app"):
                self._consider_app_bundle(path, root)
            else:
                self._consider_installer(path, root)

    def _consider_app_bundle(self, path: Path, root: Path) -> None:
        if path.is_symlink() or not path.is_dir() or not path.name.endswith(".app"):
            return
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            return
        size = self.measure(path)
        if size is None or size < self.min_installer_bytes:
            return
        self.add_directory(
            path,
            prefix=root,
            relative=relative,
            rule_id="installer",
            app="Old installation",
            category="installers",
            name=path.name,
            risk="manual",
            description=(
                "Application copy left in Downloads or on the Desktop. "
                "It is moved to the Trash, and only if you check it. "
                "Applications in the Applications folder are never removed."
            ),
            deletion="trash",
            selectable=True,
            manual_label="Not selected automatically",
            size_bytes=size,
            allow_small=True,
        )

    def _consider_installer(self, path: Path, root: Path) -> None:
        suffix = path.suffix.lower()
        if suffix not in INSTALLER_SUFFIXES and suffix != ".zip":
            return
        if suffix == ".zip" and (not INSTALLER_NAME.search(path.name) or EXPORT_NAME.search(path.name)):
            return
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            return
        self.add_file(
            path,
            prefix=root,
            relative=relative,
            rule_id="installer",
            app="Installer",
            category="installers",
            name=path.name,
            risk="manual",
            description="Installer or disk image. It is moved to the Trash, and only if you check it. The Downloads folder itself is never removed.",
            deletion="trash",
            selectable=True,
            manual_label="Not selected automatically",
            minimum=self.min_installer_bytes,
        )

    def scan_large_files(self) -> None:
        self.note("Looking for large files")
        for relative_root, depth in LARGE_FILE_ROOTS:
            root = self.home.joinpath(*relative_root.split("/"))
            if not root.is_dir() or root.is_symlink() or not self.anchor(root):
                continue
            icloud = (relative_root == "Desktop" and self.icloud_desktop) or (
                relative_root == "Documents" and self.icloud_documents
            )
            for path in _walk_files(root, depth):
                if path.suffix.lower() in INSTALLER_SUFFIXES or path.name in DENIED_COMPONENTS:
                    continue
                relative_parts = path.relative_to(root).parts
                if any(part.endswith(".app") for part in relative_parts[:-1]):
                    continue
                if any(part in DENIED_COMPONENTS or part in PRUNE_DIR_NAMES for part in relative_parts):
                    continue
                try:
                    if stat.S_ISLNK(path.lstat().st_mode):
                        continue
                    flags = getattr(path.lstat(), "st_flags", 0)
                except OSError:
                    continue
                dataless = bool(flags & SF_DATALESS)
                description = "Large file shown for review only. It is moved to the Trash, not deleted permanently, and it is never checked for you."
                selectable = not icloud and not dataless
                if icloud or dataless:
                    description = "This file is in iCloud Drive, so it is shown for size only and cannot be deleted here."
                self.add_file(
                    path,
                    prefix=root,
                    relative=path.relative_to(root).as_posix(),
                    rule_id="large-file",
                    app="Large file",
                    category="large",
                    name=path.name,
                    risk="manual" if selectable else "blocked",
                    description=description,
                    deletion="trash",
                    selectable=selectable,
                    manual_label="Not selected automatically",
                    minimum=self.min_large_file_bytes,
                )

    def scan_system_caches(self) -> None:
        self.note("Checking system caches")
        root = Path("/Library/Caches")
        try:
            if not root.is_dir():
                return
            sizes = disk_usage_children(root, timeout=90)
        except (DiskUsageError, OSError, subprocess.TimeoutExpired) as exc:
            self.warn(f"System caches were not measured: {exc}")
            return
        total = 0
        count = 0
        for name, size in sizes.items():
            if _bad_component(name) or size <= 0:
                continue
            total += size
            count += 1
        if count == 0:
            return
        self.add(
            {
                "id": "system-caches-summary",
                "rule_id": "info-only",
                "app": "macOS",
                "category": "caches",
                "category_label": category_label("caches"),
                "name": "System caches",
                "path": "/Library/Caches",
                "prefix": "",
                "relative": "",
                "size_bytes": total,
                "modified": "",
                "risk": "blocked",
                "risk_label": "Not deleted by this tool",
                "deletion": "none",
                "deletion_label": "Not deleted",
                "requires_app_closed": False,
                "processes": (),
                "close_message": "",
                "app_running": False,
                "description": f"{count} folders in /Library/Caches. Cleaning them would need an administrator and can affect every account, so this tool does not delete them and will not ask for a password.",
                "kind": "info",
                "dev": 0,
                "ino": 0,
                "selectable": False,
                "group": "system",
            }
        )

    def finish_aggregate(self) -> None:
        if not self._small_blocked:
            return
        count = len(self._small_blocked)
        total = sum(self._small_blocked)
        self.add(
            {
                "id": "small-system-caches",
                "rule_id": "info-only",
                "app": "macOS",
                "category": "caches",
                "category_label": category_label("caches"),
                "name": "Small system caches",
                "path": f"{count} small macOS cache folders in ~/Library/Caches",
                "prefix": "",
                "relative": "",
                "size_bytes": total,
                "modified": "",
                "risk": "blocked",
                "risk_label": "Not deleted by this tool",
                "deletion": "none",
                "deletion_label": "Not deleted",
                "requires_app_closed": False,
                "processes": (),
                "close_message": "",
                "app_running": False,
                "description": "Small macOS caches grouped together. They are visible so the total is honest, and they cannot be deleted here.",
                "kind": "info",
                "dev": 0,
                "ino": 0,
                "selectable": False,
                "group": "system",
            }
        )

    def run(self, *, include_system: bool, include_temp: bool) -> None:
        self.scan_fixed()
        self.scan_chrome_profiles()
        self.scan_electron()
        self.scan_cursor_partitions()
        self.scan_user_caches()
        self.scan_whatsapp_group_caches()
        self.scan_logs()
        self.scan_app_support()
        self.scan_installers(include_temp=include_temp)
        self.scan_large_files()
        if include_system:
            self.scan_system_caches()
        self.finish_aggregate()
        order = {category_id: index for index, (category_id, _label, _note) in enumerate(CATEGORIES)}
        self.items.sort(key=lambda item: (order.get(item["category"], 99), -item["size_bytes"], item["name"]))
        self.note("Scan finished")


def perform_scan(
    home: Path | None = None,
    *,
    min_dir_bytes: int = 1_000_000,
    min_installer_bytes: int = 1_000_000,
    min_large_file_bytes: int = 200_000_000,
    aggregate_blocked_below: int = 20 * 1024 * 1024,
    include_system_caches: bool | None = None,
    include_temp: bool | None = None,
    icloud_desktop: bool | None = None,
    icloud_documents: bool | None = None,
    process_check=None,
    progress=None,
) -> ScanResult:
    root = normalize_root(home or Path.home())
    real_home = normalize_root(Path.home())
    on_this_mac = root == real_home
    if icloud_desktop is None or icloud_documents is None:
        if on_this_mac:
            detected_desktop, detected_documents = read_icloud_flags()
            icloud_desktop = detected_desktop if icloud_desktop is None else icloud_desktop
            icloud_documents = detected_documents if icloud_documents is None else icloud_documents
        else:
            icloud_desktop = False if icloud_desktop is None else icloud_desktop
            icloud_documents = False if icloud_documents is None else icloud_documents
    if include_system_caches is None:
        include_system_caches = on_this_mac
    if include_temp is None:
        include_temp = on_this_mac
    scanner = Scanner(
        root,
        min_dir_bytes=min_dir_bytes,
        min_installer_bytes=min_installer_bytes,
        min_large_file_bytes=min_large_file_bytes,
        aggregate_blocked_below=aggregate_blocked_below,
        process_check=process_check or processes_running,
        progress=progress,
        icloud_desktop=bool(icloud_desktop),
        icloud_documents=bool(icloud_documents),
    )
    scanner.run(include_system=include_system_caches, include_temp=include_temp)
    return ScanResult(scanner.items, scanner.warnings, str(root))


def _estimate_usage(path: Path, limit: int = 100_000) -> tuple[int | None, bool]:
    """Allocated size without du. Stops after `limit` files so a huge tree cannot stall the scan."""
    total = 0
    seen = 0
    try:
        for directory, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames[:] = [
                name
                for name in dirnames
                if name not in {".", ".."} and not os.path.islink(os.path.join(directory, name))
            ]
            for name in filenames:
                full = os.path.join(directory, name)
                if os.path.islink(full):
                    continue
                try:
                    info = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                blocks = getattr(info, "st_blocks", 0)
                total += int(blocks) * 512 if blocks else max(0, int(info.st_size))
                seen += 1
                if seen >= limit:
                    return total, True
    except OSError:
        return None, False
    return total, False


def _bad_component(name: str) -> bool:
    return (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
        or "\n" in name
        or "\r" in name
    )


def _now() -> float:
    return time.time()


def _walk_files(root: Path, max_depth: int, *, app_bundles: bool = False):
    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink() or entry.name in {".", ".."} or _bad_component(entry.name):
                continue
            try:
                info = entry.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISDIR(info.st_mode):
                if app_bundles and entry.name.endswith(".app") and not entry.name.startswith(".") and depth + 1 <= max_depth:
                    yield entry
                    continue
                if entry.name in PRUNE_DIR_NAMES or entry.name.startswith("."):
                    continue
                if depth + 1 < max_depth:
                    stack.append((entry, depth + 1))
                continue
            if stat.S_ISREG(info.st_mode) and depth + 1 <= max_depth:
                yield entry
