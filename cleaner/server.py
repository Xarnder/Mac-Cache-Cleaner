"""Local web UI. The server listens on 127.0.0.1 and nowhere else."""

from __future__ import annotations

import json
import secrets
import socket
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .chrome_job import chrome_command, chrome_items_waiting, save_chrome_job
from .delete import delete_item
from .rules import CATEGORIES
from .scan import normalize_root, perform_scan, processes_running, read_icloud_flags
from .util import append_log

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
TOKEN = secrets.token_urlsafe(32)
HIDDEN_FIELDS = {"dev", "ino", "prefix", "relative", "processes"}


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.status = "idle"
        self.progress = "Ready"
        self.scan_id = ""
        self.items: list[dict] = []
        self.warnings: list[str] = []
        self.error = ""
        self.scanning = False
        self.cleaning = False


STATE = State()


class LocalServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        super().server_bind()
        host = self.server_address[0]
        if host != "127.0.0.1":
            raise RuntimeError("refusing to listen on anything except 127.0.0.1")


def public_item(item: dict) -> dict:
    return {key: value for key, value in item.items() if key not in HIDDEN_FIELDS}


def totals(items: list[dict]) -> dict:
    def summed(risk: str, selectable: bool | None = None) -> int:
        total = 0
        for item in items:
            if item["risk"] != risk:
                continue
            if selectable is not None and item["selectable"] != selectable:
                continue
            total += int(item["size_bytes"])
        return total

    safe = summed("safe", True)
    review = summed("review", True)
    manual = summed("manual", True)
    return {
        "safe": safe,
        "review": review,
        "manual": manual,
        "recoverable": safe + review,
    }


def payload() -> dict:
    with STATE.lock:
        items = [public_item(item) for item in STATE.items]
        return {
            "status": STATE.status,
            "progress": STATE.progress,
            "scan_id": STATE.scan_id,
            "error": STATE.error,
            "warnings": list(STATE.warnings),
            "totals": totals(STATE.items),
            "categories": [
                {"id": category_id, "label": label, "note": note}
                for category_id, label, note in CATEGORIES
            ],
            "items": items,
        }


def start_scan() -> None:
    with STATE.lock:
        if STATE.scanning or STATE.cleaning:
            return
        STATE.scanning = True
        STATE.status = "running"
        STATE.progress = "Starting scan"
        STATE.error = ""

    def run() -> None:
        def progress(message: str) -> None:
            print(message, flush=True)
            with STATE.lock:
                STATE.progress = message

        try:
            result = perform_scan(progress=progress)
            with STATE.lock:
                STATE.items = result.items
                STATE.warnings = result.warnings
                STATE.scan_id = secrets.token_hex(8)
                STATE.status = "done"
                STATE.progress = "Scan finished"
            append_log(
                ROOT,
                {
                    "event": "scan",
                    "items": len(result.items),
                    "warnings": result.warnings,
                },
            )
        except Exception:
            append_log(ROOT, {"event": "scan-error", "detail": traceback.format_exc()})
            with STATE.lock:
                STATE.status = "error"
                STATE.error = "Scan failed. Details are in logs/cleanup.log."
                STATE.progress = "Scan failed"
        finally:
            with STATE.lock:
                STATE.scanning = False

    threading.Thread(target=run, name="cache-scan", daemon=True).start()


def refresh_running() -> None:
    with STATE.lock:
        items = list(STATE.items)
    groups = {tuple(item.get("processes") or ()) for item in items if item.get("requires_app_closed")}
    running = {group: bool(processes_running(group)) for group in groups if group}
    with STATE.lock:
        for item in STATE.items:
            processes = tuple(item.get("processes") or ())
            item["app_running"] = bool(item.get("requires_app_closed") and running.get(processes, False))


def _selected(body: dict, *, claim: bool = False) -> tuple[list[dict] | None, str | None]:
    scan_id = body.get("scan_id")
    raw_ids = body.get("ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        return None, "Choose at least one item."
    if not all(isinstance(item_id, str) for item_id in raw_ids):
        return None, "The selection was not valid."
    with STATE.lock:
        if STATE.scanning or STATE.cleaning:
            return None, "A scan or cleanup is already running."
        if scan_id != STATE.scan_id or not STATE.scan_id:
            return None, "The scan changed. Rescan, then choose the items again."
        by_id = {item["id"]: item for item in STATE.items}
        if any(item_id not in by_id for item_id in raw_ids):
            return None, "The selection does not match this scan. Rescan and choose again."
        selected = [dict(by_id[item_id]) for item_id in raw_ids]
        if any(not item["selectable"] or item["deletion"] == "none" for item in selected):
            return None, "One of the chosen items cannot be deleted."
        if claim:
            STATE.cleaning = True
    return selected, None


def preview(body: dict) -> tuple[int, dict]:
    refresh_running()
    selected, error = _selected(body)
    if error:
        status = 409 if "Rescan" in error or "already running" in error else 400
        return status, {"error": error}
    # Running flags were refreshed on the live items; copy them onto the selection.
    with STATE.lock:
        live = {item["id"]: item for item in STATE.items}
    for item in selected:
        item["app_running"] = bool(live[item["id"]].get("app_running"))
    running_messages = []
    seen = set()
    for item in selected:
        message = item.get("close_message") or ""
        if item.get("app_running") and message and message not in seen:
            seen.add(message)
            running_messages.append(message)
    permanent = [item for item in selected if item["deletion"] == "permanent"]
    trash = [item for item in selected if item["deletion"] == "trash"]
    waiting = chrome_items_waiting(selected)
    chrome_terminal = chrome_command(ROOT, save_chrome_job(ROOT, waiting)) if waiting else None
    return 200, {
        "count": len(selected),
        "size_bytes": sum(int(item["size_bytes"]) for item in selected),
        "permanent_count": len(permanent),
        "permanent_bytes": sum(int(item["size_bytes"]) for item in permanent),
        "trash_count": len(trash),
        "trash_bytes": sum(int(item["size_bytes"]) for item in trash),
        "running_messages": running_messages,
        "locations": [
            {
                "id": item["id"],
                "name": item["name"],
                "app": item["app"],
                "path": item["path"],
                "size_bytes": item["size_bytes"],
                "deletion": item["deletion"],
                "deletion_label": item["deletion_label"],
                "kind": item["kind"],
                "category": item.get("category"),
                "app_running": bool(item.get("app_running")),
            }
            for item in selected
        ],
        "chrome_command": chrome_terminal,
        "chrome_count": len(waiting),
        "chrome_bytes": sum(int(item["size_bytes"]) for item in waiting),
    }


def clean(body: dict) -> tuple[int, dict]:
    if body.get("confirm") is not True:
        return 400, {"error": "Cleanup was not confirmed. Nothing was deleted."}
    refresh_running()
    selected, error = _selected(body, claim=True)
    if error:
        status = 409 if "Rescan" in error or "already running" in error else 400
        return status, {"error": error}
    assert selected is not None
    running = sorted(
        {
            item["close_message"]
            for item in selected
            if item.get("app_running") and item.get("close_message")
        }
    )
    chrome_open = chrome_items_waiting(selected)
    if chrome_open:
        with STATE.lock:
            STATE.cleaning = False
        return 409, {
            "error": "Chrome is still open. Quit Google Chrome and Google updater, then run the Terminal command shown on the page. Nothing was deleted.",
        }
    if running and body.get("allow_running") is not True:
        with STATE.lock:
            STATE.cleaning = False
        return 409, {
            "error": "An app is still open. Close it and rescan, or confirm that you want to clean while it is open.",
            "running_messages": running,
        }

    try:
        try:
            home = normalize_root(Path.home())
            trash_root = Path.home() / ".Trash"
            icloud_desktop, icloud_documents = read_icloud_flags()
            results = [
                delete_item(
                    item,
                    home=home,
                    project_root=ROOT,
                    icloud_desktop=icloud_desktop,
                    icloud_documents=icloud_documents,
                    trash_root=trash_root,
                )
                for item in selected
            ]
        except Exception:
            append_log(ROOT, {"event": "clean-error", "detail": traceback.format_exc()})
            return 500, {
                "error": "Cleanup failed. Details are in logs/cleanup.log. Check the paths before trying again.",
            }
    finally:
        with STATE.lock:
            STATE.cleaning = False

    removed = [item for item in results if item.get("status") == "removed"]
    skipped = [item for item in results if item.get("status") == "skipped"]
    errors = [item for item in results if item.get("status") == "error"]
    freed = sum(int(item.get("freed_bytes") or 0) for item in results)
    trashed = sum(int(item.get("trashed_bytes") or 0) for item in removed if item.get("deletion") == "trash")
    summary = {
        "removed": removed,
        "skipped": skipped,
        "errors": errors,
        "freed_bytes": freed,
        "trashed_bytes": trashed,
        "removed_count": len(removed),
        "skipped_count": len(skipped),
        "error_count": len(errors),
    }
    append_log(
        ROOT,
        {
            "event": "clean",
            "freed_bytes": freed,
            "trashed_bytes": trashed,
            "removed": [item.get("path") for item in removed],
            "skipped": [{item.get("path"): item.get("error")} for item in skipped],
            "errors": [{item.get("path"): item.get("error")} for item in errors],
        },
    )
    return 200, summary


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MacCacheCleaner"

    def log_message(self, fmt: str, *args) -> None:
        if self.command == "POST":
            print(f"{self.command} {urlparse(self.path).path}", flush=True)

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in {"127.0.0.1", "localhost"}

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        port = self.server.server_address[1]
        allowed = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
        return origin in allowed

    def _token_ok(self) -> bool:
        return self.headers.get("X-Cleaner-Token") == TOKEN

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'",
        )
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def _read_json(self) -> dict | None:
        if not self._host_ok() or not self._origin_ok() or not self._token_ok():
            self._json(403, {"error": "This request was refused."})
            return None
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self._json(415, {"error": "Expected JSON."})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > 1_000_000:
            self._json(413, {"error": "Request is too large."})
            return None
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "Request was not valid JSON."})
            return None
        if not isinstance(data, dict):
            self._json(400, {"error": "Request was not valid JSON."})
            return None
        return data

    def do_GET(self) -> None:
        if not self._host_ok():
            self._json(403, {"error": "This request was refused."})
            return
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            page = (WEB / "index.html").read_text(encoding="utf-8")
            page = page.replace("__CLEANER_TOKEN__", TOKEN)
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/app.js":
            self._send(200, (WEB / "app.js").read_bytes(), "text/javascript; charset=utf-8")
            return
        if path == "/style.css":
            self._send(200, (WEB / "style.css").read_bytes(), "text/css; charset=utf-8")
            return
        if path == "/api/scan":
            if not self._token_ok():
                self._json(403, {"error": "This request was refused."})
                return
            self._json(200, payload())
            return
        if path == "/api/apps":
            if not self._token_ok():
                self._json(403, {"error": "This request was refused."})
                return
            refresh_running()
            self._json(200, payload())
            return
        self._json(404, {"error": "Not found."})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/scan":
            if not self._host_ok() or not self._origin_ok() or not self._token_ok():
                self._json(403, {"error": "This request was refused."})
                return
            start_scan()
            self._json(202, payload())
            return
        data = self._read_json()
        if data is None:
            return
        if path == "/api/preview":
            status, body = preview(data)
            self._json(status, body)
            return
        if path == "/api/clean":
            status, body = clean(data)
            self._json(status, body)
            return
        self._json(404, {"error": "Not found."})


def create_server(port: int = 0) -> LocalServer:
    server = LocalServer(("127.0.0.1", port), Handler)
    if server.server_address[0] != "127.0.0.1":
        server.server_close()
        raise RuntimeError("refusing to listen on anything except 127.0.0.1")
    return server


def serve(port: int = 0, *, open_browser: bool = True) -> None:
    server = create_server(port)
    bound = server.server_address[1]
    url = f"http://127.0.0.1:{bound}/"
    print("Mac Cache Cleaner", flush=True)
    print(f"Listening on {url}", flush=True)
    print("This server is local only. Press Control-C to stop.", flush=True)
    if open_browser:
        import subprocess

        subprocess.run(["/usr/bin/open", url], check=False)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)
    finally:
        server.server_close()


