"""Command line entry. Scanning flags never delete anything."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .chrome_job import clean_chrome_job
from .rules import CATEGORIES
from .scan import perform_scan
from .server import serve
from .util import format_bytes


def assert_not_root(euid: int | None = None) -> None:
    if euid is None:
        euid = os.geteuid()
    if euid == 0:
        print("Refusing to run as root. Open it from your own account.", file=sys.stderr)
        raise SystemExit(1)


def print_report(result, *, dry_run: bool) -> None:
    items = result.items
    safe = [item for item in items if item["selectable"] and item["risk"] == "safe"]
    review = [item for item in items if item["selectable"] and item["risk"] == "review"]
    manual = [item for item in items if item["selectable"] and item["risk"] == "manual"]

    print("Mac Cache Cleaner")
    print("Dry run. Nothing will be deleted." if dry_run else "Scan only. Nothing will be deleted.")
    print()
    print(f"Safe to delete:           {format_bytes(sum(item['size_bytes'] for item in safe))}")
    print(f"Review recommended:       {format_bytes(sum(item['size_bytes'] for item in review))}")
    print(f"Needs an explicit choice: {format_bytes(sum(item['size_bytes'] for item in manual))}")
    if result.warnings:
        print()
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")
    print()
    for category_id, label, note in CATEGORIES:
        group = [item for item in items if item["category"] == category_id and item["kind"] != "info"]
        info = [item for item in items if item["category"] == category_id and item["kind"] == "info"]
        print(f"{label}")
        print(f"  {note}")
        if not group and not info:
            print("  Nothing large enough to list.")
            print()
            continue
        for item in group:
            flag = item["risk"]
            print(f"  [{flag}] {item['app']} — {item['name']}  {format_bytes(item['size_bytes'])}")
            print(f"         {item['path']}")
            print(f"         {item['description']}")
            if item.get("requires_app_closed"):
                print(f"         {item['close_message']}")
        for item in info:
            print(f"  [not deleted] {item['name']}  {format_bytes(item['size_bytes'])}")
            print(f"         {item['description']}")
        print()
    print("Safe items that would be removed:")
    if not safe:
        print("  None.")
    for item in safe:
        method = "permanently" if item["deletion"] == "permanent" else "to Trash"
        print(f"  {format_bytes(item['size_bytes'])}  {method}  {item['path']}")
    print()
    print("No files were changed.")


def main(argv: list[str] | None = None) -> int:
    assert_not_root()
    parser = argparse.ArgumentParser(
        description="Local macOS cache cleaner. It listens on 127.0.0.1 and does not delete anything until you confirm in the browser."
    )
    parser.add_argument("--scan", action="store_true", help="Print recoverable space and exit. Deletes nothing.")
    parser.add_argument("--dry-run", action="store_true", help="Same as --scan. Deletes nothing.")
    parser.add_argument(
        "--clean-chrome",
        metavar="JOB",
        help="Delete the Chrome caches from a command copied on the page. Refuses to run while Chrome or Google updater is open.",
    )
    parser.add_argument("--port", type=int, default=0, help="Local port. The default asks the system for a free one.")
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser window.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if args.port < 0 or args.port > 65535:
        print("Port must be between 0 and 65535.", file=sys.stderr)
        return 2

    if args.clean_chrome:
        return clean_chrome_job(args.clean_chrome, project_root=Path(__file__).resolve().parent.parent)

    if args.scan or args.dry_run:
        def progress(message: str) -> None:
            print(message, flush=True)

        result = perform_scan(progress=progress)
        print()
        print_report(result, dry_run=True)
        return 0

    serve(args.port, open_browser=not args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
