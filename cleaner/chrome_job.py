"""A Terminal command for Chrome caches that are selected while Chrome is open.

The page writes the selected Chrome items here. The command refuses to delete
anything until Google Chrome and Google's updater have quit, then uses the same
checks as the page.
"""

from __future__ import annotations

import json
import re
import secrets
import shlex
from pathlib import Path

from .delete import delete_item
from .scan import normalize_root, processes_running, read_icloud_flags
from .util import append_log, format_bytes

JOB_ID = re.compile(r"^[0-9a-f]{16}$")
CHROME_PROCESSES = (
    "Google Chrome",
    "Google Chrome Helper",
    "GoogleUpdater",
    "GoogleSoftwareUpdateAgent",
)
QUIT_HINT = {
    "Google Chrome": "Quit Google Chrome from the Chrome menu, then run this command again.",
    "Google Chrome Helper": "Google Chrome is still running in the background. Quit Chrome, then run this command again.",
    "GoogleUpdater": "Quit Google updater, then run this command again.",
    "GoogleSoftwareUpdateAgent": "Quit Google software update, then run this command again.",
}


def chrome_items_waiting(items: list[dict]) -> list[dict]:
    return [
        item
        for item in items
        if item.get("category") == "chrome" and item.get("requires_app_closed") and item.get("app_running")
    ]


def _jsonable(item: dict) -> dict:
    return {key: list(value) if isinstance(value, tuple) else value for key, value in item.items()}


def save_chrome_job(project_root: Path, items: list[dict]) -> str:
    logs = project_root / "logs"
    logs.mkdir(exist_ok=True)
    for old in logs.glob("chrome-clean-*.json"):
        if JOB_ID.fullmatch(old.stem.removeprefix("chrome-clean-")):
            old.unlink()
    job_id = secrets.token_hex(8)
    payload = {"id": job_id, "items": [_jsonable(item) for item in items]}
    temporary = logs / f".chrome-clean-{job_id}.json"
    target = logs / f"chrome-clean-{job_id}.json"
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(target)
    return job_id


def chrome_command(project_root: Path, job_id: str) -> str:
    return f"cd {shlex.quote(str(project_root))} && /usr/bin/python3 -m cleaner --clean-chrome {job_id}"


def _job_path(project_root: Path, job_id: str) -> Path | None:
    if not JOB_ID.fullmatch(job_id):
        return None
    path = project_root / "logs" / f"chrome-clean-{job_id}.json"
    if path.parent != project_root / "logs":
        return None
    return path


def clean_chrome_job(
    job_id: str,
    *,
    project_root: Path,
    home: Path | None = None,
    trash_root: Path | None = None,
    process_check=processes_running,
    icloud_desktop: bool | None = None,
    icloud_documents: bool | None = None,
) -> int:
    """Delete the saved Chrome selection. Returns a process exit code."""
    path = _job_path(project_root, job_id)
    if path is None or not path.is_file():
        print("That command is out of date. Copy a new one from the page. Nothing was deleted.")
        return 2
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("The saved Chrome selection could not be read. Copy a new command from the page.")
        return 2
    items = payload.get("items") if isinstance(payload, dict) else None
    if payload.get("id") != job_id or not isinstance(items, list) or not items:
        print("The saved Chrome selection is not valid. Copy a new command from the page.")
        return 2

    running = process_check(CHROME_PROCESSES)
    if running:
        print("Nothing was deleted.")
        for name in running:
            print(QUIT_HINT.get(name, f"{name} is still open. Quit it, then run this command again."))
        return 1

    if home is None:
        home = normalize_root(Path.home())
    if trash_root is None:
        trash_root = Path.home() / ".Trash"
    if icloud_desktop is None or icloud_documents is None:
        detected_desktop, detected_documents = read_icloud_flags()
        icloud_desktop = detected_desktop if icloud_desktop is None else icloud_desktop
        icloud_documents = detected_documents if icloud_documents is None else icloud_documents

    print(f"Chrome cache cleanup · {len(items)} location{'' if len(items) == 1 else 's'}")
    results = [
        delete_item(
            item,
            home=home,
            project_root=project_root,
            icloud_desktop=bool(icloud_desktop),
            icloud_documents=bool(icloud_documents),
            trash_root=trash_root,
        )
        for item in items
        if isinstance(item, dict)
    ]
    removed = [item for item in results if item.get("status") == "removed"]
    skipped = [item for item in results if item.get("status") == "skipped"]
    errors = [item for item in results if item.get("status") == "error"]
    freed = sum(int(item.get("freed_bytes") or 0) for item in results)
    for item in removed:
        print(f"Removed  {format_bytes(int(item.get('freed_bytes') or item.get('size_bytes') or 0))}  {item.get('path')}")
    for item in skipped:
        print(f"Skipped  {item.get('path')}: {item.get('error')}")
    for item in errors:
        print(f"Error    {item.get('path')}: {item.get('error')}")
    print(f"Freed {format_bytes(freed)}.")
    append_log(
        project_root,
        {
            "event": "clean-chrome",
            "freed_bytes": freed,
            "removed": [item.get("path") for item in removed],
            "skipped": [item.get("path") for item in skipped],
            "errors": [item.get("path") for item in errors],
        },
    )
    if skipped or errors or len(removed) != len(items):
        return 1
    return 0
