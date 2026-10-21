"""Deletion. Permanent removal never uses a shell and never follows symlinks.

Ordinary files (installers, large files, archives) are renamed into the Trash.
Cache and log directories are removed in place, because moving hundreds of
thousands of cache files to the Trash is slow and easy to get wrong. The
confirmation screen says which method applies to each path.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
from pathlib import Path

from .safety import UnsafePath, validate_item


def _unlink_file(path: Path, dev: int, ino: int) -> None:
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        info = os.lstat(path.name, dir_fd=parent)
        if (
            info.st_dev != dev
            or info.st_ino != ino
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
        ):
            raise UnsafePath("file changed since the scan")
        os.unlink(path.name, dir_fd=parent)
    finally:
        os.close(parent)


def _allocated(info: os.stat_result) -> int:
    blocks = getattr(info, "st_blocks", 0)
    if blocks:
        return int(blocks) * 512
    return max(0, int(info.st_size))


def _remove_once(root_fd: int, root_dev: int) -> tuple[int, int]:
    """Delete one pass inside an already-opened directory. Does not remove that directory.

    A locked or unreadable file is skipped so the rest of a large cache still goes.
    Returns how many entries could not be removed, and how many bytes were unlinked.
    """
    blocked = 0
    freed = 0
    stack: list[tuple[int, list[str] | None, int, str | None, int | None]] = [
        (root_fd, None, 0, None, None)
    ]
    try:
        while stack:
            directory, names, index, name, parent = stack[-1]
            if names is None:
                try:
                    listing = [
                        entry
                        for entry in os.listdir(directory)
                        if entry not in {".", ".."} and "/" not in entry and "\x00" not in entry
                    ]
                except OSError:
                    listing = []
                    blocked += 1
                stack[-1] = (directory, listing, 0, name, parent)
                continue
            if index >= len(names):
                stack.pop()
                if parent is not None and name is not None:
                    os.close(directory)
                    try:
                        os.rmdir(name, dir_fd=parent)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        blocked += 1
                continue
            current = names[index]
            stack[-1] = (directory, names, index + 1, name, parent)
            try:
                info = os.lstat(current, dir_fd=directory)
            except FileNotFoundError:
                continue
            except OSError:
                blocked += 1
                continue
            if info.st_dev != root_dev:
                raise UnsafePath("refusing to leave this volume")
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                try:
                    os.unlink(current, dir_fd=directory)
                except FileNotFoundError:
                    continue
                except OSError:
                    blocked += 1
                    continue
                freed += _allocated(info)
                continue
            try:
                child = os.open(
                    current,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
            except FileNotFoundError:
                continue
            except OSError:
                try:
                    os.unlink(current, dir_fd=directory)
                    freed += _allocated(info)
                except OSError:
                    blocked += 1
                continue
            stack.append((child, None, 0, current, directory))
    except Exception:
        while stack:
            directory, _names, _index, _name, parent = stack.pop()
            if parent is not None:
                os.close(directory)
        raise
    return blocked, freed


def _remove_contents(root_fd: int, root_dev: int) -> tuple[int, int]:
    """Two passes, so a file that was busy for a moment can be removed on the second."""
    blocked, freed = _remove_once(root_fd, root_dev)
    if blocked:
        again_blocked, again_freed = _remove_once(root_fd, root_dev)
        return again_blocked, freed + again_freed
    return blocked, freed


def permanent_delete(path: Path, dev: int, ino: int) -> tuple[int, int]:
    """Remove a file or a directory tree. Returns entries still present, and bytes unlinked."""
    if path.is_symlink():
        raise UnsafePath("refusing to follow a symlink")
    info = path.lstat()
    if info.st_dev != dev or info.st_ino != ino:
        raise UnsafePath("the item changed since the scan")
    if stat.S_ISREG(info.st_mode):
        _unlink_file(path, dev, ino)
        return 0, _allocated(info)
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafePath("unsupported file type")

    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        current = os.lstat(path.name, dir_fd=parent)
        if (
            current.st_dev != dev
            or current.st_ino != ino
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISDIR(current.st_mode)
        ):
            raise UnsafePath("the item changed since the scan")
        directory = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)

    try:
        opened = os.fstat(directory)
        if opened.st_dev != dev or opened.st_ino != ino:
            raise UnsafePath("the item changed since the scan")
        blocked, freed = _remove_contents(directory, dev)
    finally:
        os.close(directory)

    if blocked:
        return blocked, freed

    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            current = os.lstat(path.name, dir_fd=parent)
        except FileNotFoundError:
            return 0, freed
        if current.st_dev != dev or current.st_ino != ino or not stat.S_ISDIR(current.st_mode):
            raise UnsafePath("the folder changed while it was being emptied")
        try:
            os.rmdir(path.name, dir_fd=parent)
        except OSError:
            if path.exists():
                return 1, freed
            raise
    finally:
        os.close(parent)
    return 0, freed


def move_to_trash(path: Path, dev: int, ino: int, trash_root: Path) -> Path:
    if path.is_symlink():
        raise UnsafePath("refusing to follow a symlink")
    info = path.lstat()
    if info.st_dev != dev or info.st_ino != ino or stat.S_ISLNK(info.st_mode):
        raise UnsafePath("the item changed since the scan")
    if trash_root.is_symlink() or not trash_root.is_dir():
        raise UnsafePath("the Trash is not available")
    try:
        path.relative_to(trash_root)
    except ValueError:
        pass
    else:
        raise UnsafePath("refusing to delete something already in the Trash")

    destination = trash_root / f"{path.name} {secrets.token_hex(4)}"
    try:
        os.rename(path, destination)
    except OSError as exc:
        if exc.errno == errno.EXDEV:
            raise UnsafePath("this file is on another volume, so it was left in place") from exc
        raise
    return destination


def delete_item(
    item: dict,
    *,
    home: Path,
    project_root: Path,
    icloud_desktop: bool,
    icloud_documents: bool,
    trash_root: Path,
) -> dict:
    """Delete one scanned item. Returns a result record and does not raise for a refused path."""
    record = {
        "id": item.get("id"),
        "path": item.get("path"),
        "deletion": item.get("deletion"),
        "size_bytes": int(item.get("size_bytes") or 0),
    }
    try:
        path = validate_item(
            item,
            home=home,
            project_root=project_root,
            icloud_desktop=icloud_desktop,
            icloud_documents=icloud_documents,
        )
        dev = int(item["dev"])
        ino = int(item["ino"])
        if item["deletion"] == "trash":
            destination = move_to_trash(path, dev, ino, trash_root)
            record["status"] = "removed"
            record["freed_bytes"] = 0
            record["trashed_bytes"] = record["size_bytes"]
            record["trash_path"] = str(destination)
            return record
        before = record["size_bytes"]
        _blocked, unlinked = permanent_delete(path, dev, ino)
        if path.exists():
            record["status"] = "error"
            record["error"] = (
                "some files were still in use, so they were left in place. Quit the app and clean this again to finish."
            )
            record["freed_bytes"] = unlinked
            return record
        record["status"] = "removed"
        record["freed_bytes"] = before
        record["trashed_bytes"] = 0
        return record
    except UnsafePath as exc:
        record["status"] = "skipped"
        record["error"] = str(exc)
        record["freed_bytes"] = 0
        return record
    except OSError as exc:
        record["status"] = "error"
        record["error"] = exc.strerror or "could not delete this item"
        record["freed_bytes"] = 0
        return record
