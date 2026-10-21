"""Safety tests. These use a fake home directory and must not touch the real one."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cleaner.chrome_job import chrome_command, clean_chrome_job, save_chrome_job
from cleaner.delete import delete_item, permanent_delete
from cleaner.main import assert_not_root
from cleaner.rules import (
    CHROME_PROFILE_RULES,
    DENIED_COMPONENTS,
    ELECTRON_APPS,
    FIXED_RULES,
)
from cleaner.safety import UnsafePath, is_denied, validate_item
from cleaner.scan import perform_scan
from cleaner.server import create_server


def _write(path: Path, size: int = 64, text: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if text is not None:
        path.write_text(text, encoding="utf-8")
    else:
        path.write_bytes(b"x" * size)


class SafetyTests(unittest.TestCase):
    def test_refuses_root(self) -> None:
        with self.assertRaises(SystemExit):
            assert_not_root(0)

    def test_rules_do_not_point_at_protected_data(self) -> None:
        home = Path("/Users/example")
        for rule in FIXED_RULES:
            path = home.joinpath(*rule.relative_path.split("/"))
            self.assertIsNone(is_denied(path, home), rule.relative_path)
            self.assertNotIn("..", Path(rule.relative_path).parts)
        for spec in CHROME_PROFILE_RULES:
            self.assertFalse(set(Path(spec["subpath"]).parts) & DENIED_COMPONENTS)
        for app in ELECTRON_APPS:
            for child in app["children"]:
                self.assertFalse(set(Path(child["subpath"]).parts) & DENIED_COMPONENTS)
                self.assertFalse(child["subpath"].startswith("User"))
        home = Path("/Users/example")
        partition = home / "Library/Application Support/Cursor/Partitions/cursor-browser"
        self.assertIsNone(is_denied(partition / "Cache", home))
        self.assertIsNone(is_denied(partition / "Code Cache", home))
        self.assertIsNotNone(is_denied(partition, home))
        self.assertIsNotNone(is_denied(partition / "Cookies", home))
        self.assertIsNotNone(is_denied(partition / "Local Storage", home))
        self.assertIsNotNone(is_denied(partition / "IndexedDB", home))
        self.assertIsNotNone(is_denied(home / "Library/Application Support/Cursor/User/globalStorage/state.vscdb", home))

    def test_purge_does_not_follow_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            outside = root / "outside"
            outside.mkdir()
            keep = outside / "keep.txt"
            keep.write_text("keep", encoding="utf-8")
            cache = root / "cache"
            nested = cache / "sub" / "deep"
            nested.mkdir(parents=True)
            (nested / "a.txt").write_text("gone", encoding="utf-8")
            (cache / "gone.txt").write_text("gone", encoding="utf-8")
            (cache / "$(echo owned).txt").write_text("weird", encoding="utf-8")
            (cache / "link").symlink_to(keep)
            (cache / "linkdir").symlink_to(outside)
            info = cache.lstat()
            permanent_delete(cache, info.st_dev, info.st_ino)
            self.assertFalse(cache.exists())
            self.assertEqual(keep.read_text(encoding="utf-8"), "keep")
            self.assertTrue(outside.is_dir())

    def test_refuses_to_delete_a_symlink_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep.txt").write_text("keep", encoding="utf-8")
            link = root / "link"
            link.symlink_to(outside)
            info = link.lstat()
            with self.assertRaises(UnsafePath):
                permanent_delete(link, info.st_dev, info.st_ino)
            self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "keep")
            self.assertTrue(stat.S_ISLNK(link.lstat().st_mode))

    def test_purge_keeps_going_when_one_file_is_locked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            cache = root / "cache"
            nested = cache / "Cache_Data"
            nested.mkdir(parents=True)
            gone = nested / "data_0"
            gone.write_bytes(b"x" * 4096)
            locked = nested / "data_1"
            locked.write_bytes(b"y" * 2048)
            (cache / "index").write_text("index", encoding="utf-8")
            os.chflags(locked, stat.UF_IMMUTABLE)
            try:
                info = cache.lstat()
                blocked, freed = permanent_delete(cache, info.st_dev, info.st_ino)
                self.assertGreater(blocked, 0)
                self.assertGreater(freed, 0)
                self.assertFalse(gone.exists())
                self.assertFalse((cache / "index").exists())
                self.assertTrue(locked.is_file())
                self.assertTrue(cache.is_dir())
            finally:
                os.chflags(locked, 0)


class ScanTests(unittest.TestCase):
    def _fixture(self, home: Path) -> None:
        _write(home / "Library/Caches/Homebrew/pkg.tar")
        _write(home / "Library/Caches/Homebrew/link-target.txt", text="secret-homebrew")
        secret = home / "Documents/secret.txt"
        _write(secret, text="secret-doc")
        (home / "Library/Caches/Homebrew/link").symlink_to(secret)
        (home / "Library/Caches/EvilLink").symlink_to(home / "Documents")
        _write(home / "Library/Caches/com.apple.akd/data")
        _write(home / "Library/Caches/com.apple.Safari/cache")
        _write(home / "Library/Caches/PassKit/data")
        _write(home / "Library/Caches/RandomApp/data")
        _write(home / "Library/Caches/ms-playwright/chromium")
        _write(home / "Library/Caches/com.todesktop.230313mzl4w4u92.ShipIt/update")
        _write(home / "Library/Caches/Google/Chrome/Default/Cache/data")
        _write(home / "Library/Caches/Google/Chrome/Default/Cookies", text="cookie-secret")
        _write(home / "Library/Application Support/Google/Chrome/Default/Cookies", text="cookie-secret")
        _write(home / "Library/Application Support/Google/Chrome/Default/GPUCache/data")
        _write(home / "Library/Application Support/Google/Chrome/Default/Local Storage/leveldb/data", text="storage-secret")
        _write(home / "Library/Application Support/Cursor/Cache/data")
        _write(home / "Library/Application Support/Cursor/Partitions/cursor-browser/Cache/Cache_Data/data_0", size=5000)
        _write(home / "Library/Application Support/Cursor/Partitions/cursor-browser/Code Cache/js/code", size=2000)
        _write(
            home / "Library/Application Support/Cursor/Partitions/cursor-browser/Service Worker/CacheStorage/data",
            size=1500,
        )
        _write(home / "Library/Application Support/Cursor/Partitions/cursor-browser/Cookies", text="partition-cookie")
        _write(
            home / "Library/Application Support/Cursor/Partitions/cursor-browser/Local Storage/leveldb/data",
            text="partition-storage",
        )
        _write(home / "Library/Application Support/Cursor/Partitions/cursor-browser/IndexedDB/db", text="partition-db")
        _write(home / "Library/Application Support/Cursor/User/settings.json", text="settings-secret")
        _write(home / "Library/Application Support/Cursor/User/globalStorage/state.vscdb", text="chat-secret")
        _write(home / "Library/Application Support/Cursor/AgentStores/secret", text="agent-secret")
        _write(
            home / "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Message/Media/chat/photo.jpg",
            text="photo-secret",
        )
        _write(home / "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Logs/log.txt")
        _write(home / "Library/Containers/net.whatsapp.WhatsApp/Data/Library/Caches/thumb")
        _write(home / "Library/Logs/DiagnosticReports/crash.ips")
        _write(home / "Library/Logs/SomeApp/app.log")
        _write(home / "Downloads/GoogleChrome.dmg", size=200)
        _write(home / "Downloads/WhatsAppSetup.zip", size=200)
        _write(home / "Downloads/WhatsApp Chat - export.zip", size=200, text="chat-export")
        _write(home / "Downloads/holiday.zip", size=20)
        _write(home / "Downloads/notes.txt", size=10)
        _write(home / "Downloads/OldApp.app/Contents/MacOS/bin", size=200)
        _write(home / "Desktop/Old/Helper.app/Contents/MacOS/bin", size=200)
        _write(home / "Documents/OldApp.app/Contents/MacOS/bin", size=200)
        _write(home / "Downloads/Stuff/keep.txt", text="keep-folder")
        (home / "Downloads" / "Linked.app").symlink_to(home / "Downloads" / "OldApp.app")
        _write(home / "Documents/video.mp4", size=2000)
        _write(home / "Pictures/family.jpg", size=5000, text="picture-secret")
        _write(home / "Library/Application Support/ExampleApp/Cache/data")
        _write(home / "Library/Application Support/ExampleApp/Local Storage/data", text="example-storage")

    def _scan(self, home: Path):
        return perform_scan(
            home,
            min_dir_bytes=1,
            min_installer_bytes=100,
            min_large_file_bytes=1000,
            aggregate_blocked_below=0,
            include_system_caches=False,
            include_temp=False,
            icloud_desktop=False,
            icloud_documents=False,
            process_check=lambda _names: [],
        )

    def test_scan_and_delete_leave_protected_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            home.mkdir()
            self._fixture(home)
            project = Path(raw) / "project"
            project.mkdir()
            trash = Path(raw) / "trash"
            trash.mkdir()
            result = self._scan(home)
            root = Path(result.home)
            paths = [item["path"] for item in result.items]

            def find(suffix: str, risk: str | None = None):
                matches = [
                    item
                    for item in result.items
                    if item["path"].endswith(suffix) and (risk is None or item["risk"] == risk)
                ]
                self.assertEqual(len(matches), 1, suffix)
                return matches[0]

            self.assertTrue(any(path.endswith("/Library/Caches/Homebrew") for path in paths))
            self.assertEqual(find("/Library/Caches/Homebrew")["risk"], "review")
            self.assertEqual(find("/Library/Caches/ms-playwright")["risk"], "review")
            self.assertIn("download the browsers again", find("/Library/Caches/ms-playwright")["description"])
            self.assertFalse(find("/Library/Caches/com.apple.akd")["selectable"])
            self.assertFalse(find("/Library/Caches/PassKit")["selectable"])
            self.assertEqual(find("/Library/Caches/RandomApp")["risk"], "manual")
            self.assertEqual(find("/com.todesktop.230313mzl4w4u92.ShipIt")["risk"], "safe")
            self.assertEqual(find("/Google/Chrome/Default/Cache")["risk"], "safe")
            self.assertEqual(find("/Default/GPUCache")["risk"], "safe")
            self.assertEqual(find("/Cursor/Cache")["risk"], "safe")
            browser_cache = find("/Partitions/cursor-browser/Cache")
            self.assertEqual(browser_cache["risk"], "safe")
            self.assertEqual(browser_cache["rule_id"], "cursor-partition")
            self.assertIn("20 GB", browser_cache["description"])
            self.assertEqual(find("/Partitions/cursor-browser/Code Cache")["risk"], "safe")
            self.assertEqual(find("/Partitions/cursor-browser/Service Worker/CacheStorage")["risk"], "review")
            stolen = dict(browser_cache)
            stolen["relative"] = "cursor-browser/Cookies"
            stolen["path"] = str(root / "Library/Application Support/Cursor/Partitions/cursor-browser/Cookies")
            cookie_info = Path(stolen["path"]).lstat()
            stolen["dev"] = cookie_info.st_dev
            stolen["ino"] = cookie_info.st_ino
            refused = delete_item(
                stolen,
                home=root,
                project_root=project,
                icloud_desktop=False,
                icloud_documents=False,
                trash_root=trash,
            )
            self.assertEqual(refused["status"], "skipped")
            self.assertEqual(Path(stolen["path"]).read_text(encoding="utf-8"), "partition-cookie")
            self.assertEqual(find("/net.whatsapp.WhatsApp/Data/Library/Caches")["risk"], "safe")
            self.assertEqual(find("WhatsApp.shared/Logs")["risk"], "safe")
            self.assertEqual(find("/Logs/DiagnosticReports")["risk"], "safe")
            self.assertEqual(find("/Logs/SomeApp")["risk"], "review")
            self.assertEqual(find("/Downloads/GoogleChrome.dmg")["deletion"], "trash")
            self.assertEqual(find("/Downloads/WhatsAppSetup.zip")["deletion"], "trash")
            self.assertEqual(find("/Downloads/OldApp.app")["deletion"], "trash")
            self.assertEqual(find("/Downloads/OldApp.app")["risk"], "manual")
            self.assertEqual(find("/Desktop/Old/Helper.app")["deletion"], "trash")
            self.assertTrue(find("/Downloads/OldApp.app")["selectable"])
            self.assertEqual(find("/Documents/video.mp4")["risk"], "manual")
            self.assertEqual(find("/ExampleApp/Cache")["risk"], "manual")

            for path in paths:
                self.assertNotIn("Message/Media", path)
                self.assertNotIn("Cookies", path)
                self.assertNotIn("Local Storage", path)
                self.assertNotIn("AgentStores", path)
                self.assertNotIn("settings.json", path)
                self.assertNotIn("globalStorage", path)
                self.assertNotIn("EvilLink", path)
                self.assertNotIn("Pictures", path)
                self.assertNotIn("holiday.zip", path)
                self.assertNotIn("Chat - export.zip", path)
                self.assertNotIn("notes.txt", path)
                self.assertNotIn("Documents/OldApp.app", path)
                self.assertNotIn("Linked.app", path)
                self.assertNotIn("/Downloads/Stuff", path)

            def wipe(risks: set[str]) -> None:
                fresh = self._scan(root)
                for item in fresh.items:
                    if item["selectable"] and item["risk"] in risks:
                        delete_item(
                            item,
                            home=root,
                            project_root=project,
                            icloud_desktop=False,
                            icloud_documents=False,
                            trash_root=trash,
                        )

            wipe({"safe"})
            self.assertFalse((root / "Library/Caches/Google/Chrome/Default/Cache").exists())
            self.assertFalse((root / "Library/Application Support/Cursor/Cache").exists())
            self.assertFalse((root / "Library/Application Support/Cursor/Partitions/cursor-browser/Cache").exists())
            self.assertFalse((root / "Library/Application Support/Cursor/Partitions/cursor-browser/Code Cache").exists())
            self.assertTrue(
                (root / "Library/Application Support/Cursor/Partitions/cursor-browser/Service Worker/CacheStorage").is_dir()
            )
            self.assertFalse((root / "Library/Containers/net.whatsapp.WhatsApp/Data/Library/Caches").exists())
            self.assertTrue((root / "Library/Caches/Homebrew").exists())
            self.assertTrue((root / "Downloads/GoogleChrome.dmg").exists())
            self.assertTrue((root / "Documents/video.mp4").exists())
            self.assertTrue((root / "Library/Caches/com.apple.akd").exists())

            wipe({"review", "manual"})
            self.assertFalse((root / "Library/Caches/Homebrew").exists())
            self.assertFalse((root / "Downloads/GoogleChrome.dmg").exists())
            self.assertTrue(any(trash.iterdir()))
            self.assertFalse((root / "Documents/video.mp4").exists())
            self.assertEqual((root / "Documents/secret.txt").read_text(encoding="utf-8"), "secret-doc")
            self.assertEqual(
                (root / "Library/Application Support/Google/Chrome/Default/Cookies").read_text(encoding="utf-8"),
                "cookie-secret",
            )
            self.assertEqual(
                (root / "Library/Application Support/Cursor/User/settings.json").read_text(encoding="utf-8"),
                "settings-secret",
            )
            self.assertEqual(
                (root / "Library/Application Support/Cursor/AgentStores/secret").read_text(encoding="utf-8"),
                "agent-secret",
            )
            self.assertIn("chat-secret", (root / "Library/Application Support/Cursor/User/globalStorage/state.vscdb").read_text(encoding="utf-8"))
            partition = root / "Library/Application Support/Cursor/Partitions/cursor-browser"
            self.assertEqual((partition / "Cookies").read_text(encoding="utf-8"), "partition-cookie")
            self.assertEqual((partition / "Local Storage/leveldb/data").read_text(encoding="utf-8"), "partition-storage")
            self.assertEqual((partition / "IndexedDB/db").read_text(encoding="utf-8"), "partition-db")
            self.assertFalse((partition / "Service Worker/CacheStorage").exists())
            self.assertEqual(
                (
                    root / "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Message/Media/chat/photo.jpg"
                ).read_text(encoding="utf-8"),
                "photo-secret",
            )
            self.assertTrue((root / "Library/Caches/com.apple.akd").is_dir())
            self.assertTrue((root / "Library/Caches/PassKit").is_dir())
            self.assertEqual((root / "Pictures/family.jpg").read_text(encoding="utf-8"), "picture-secret")
            self.assertTrue((root / "Downloads/notes.txt").exists())
            self.assertTrue((root / "Downloads/holiday.zip").exists())
            self.assertEqual((root / "Downloads/WhatsApp Chat - export.zip").read_text(encoding="utf-8"), "chat-export")
            self.assertFalse((root / "Downloads/WhatsAppSetup.zip").exists())
            self.assertFalse((root / "Downloads/OldApp.app").exists())
            self.assertFalse((root / "Desktop/Old/Helper.app").exists())
            self.assertTrue((root / "Documents/OldApp.app/Contents/MacOS/bin").is_file())
            self.assertEqual((root / "Downloads/Stuff/keep.txt").read_text(encoding="utf-8"), "keep-folder")
            self.assertIn(
                "example-storage",
                (root / "Library/Application Support/ExampleApp/Local Storage/data").read_text(encoding="utf-8"),
            )
            self.assertTrue((root / "Documents").is_dir())

            blocked = next(item for item in result.items if item["path"].endswith("/com.apple.akd"))
            blocked["selectable"] = True
            blocked["rule_id"] = "cache-dir"
            blocked["deletion"] = "permanent"
            outcome = delete_item(
                blocked,
                home=root,
                project_root=project,
                icloud_desktop=False,
                icloud_documents=False,
                trash_root=trash,
            )
            self.assertNotEqual(outcome["status"], "removed")
            self.assertTrue((root / "Library/Caches/com.apple.akd").is_dir())

    def test_relative_escape_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            caches = home / "Library" / "Caches"
            target = caches / "Homebrew"
            _write(target / "file")
            secret = home / "Documents" / "secret.txt"
            _write(secret, text="stay")
            item = {
                "selectable": True,
                "kind": "dir",
                "deletion": "permanent",
                "prefix": str(caches),
                "relative": "Homebrew/../../Documents",
                "path": str(home / "Documents"),
                "rule_id": "cache-dir",
                "dev": target.lstat().st_dev,
                "ino": target.lstat().st_ino,
            }
            with self.assertRaises(UnsafePath):
                validate_item(
                    item,
                    home=home,
                    project_root=home / "project",
                    icloud_desktop=False,
                    icloud_documents=False,
                )
            self.assertEqual(secret.read_text(encoding="utf-8"), "stay")

    def test_plain_download_folder_and_documents_app_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            folder = home / "Downloads" / "Stuff"
            _write(folder / "keep.txt", text="keep")
            documents_app = home / "Documents" / "OldApp.app" / "Contents"
            _write(documents_app / "Info.plist", text="plist")
            project = home / "project"
            project.mkdir()
            info = folder.lstat()
            plain = {
                "selectable": True,
                "kind": "dir",
                "deletion": "trash",
                "prefix": str(home / "Downloads"),
                "relative": "Stuff",
                "path": str(folder),
                "rule_id": "installer",
                "dev": info.st_dev,
                "ino": info.st_ino,
            }
            with self.assertRaises(UnsafePath):
                validate_item(
                    plain,
                    home=home,
                    project_root=project,
                    icloud_desktop=False,
                    icloud_documents=False,
                )
            bundle = documents_app.parent
            bundle_info = bundle.lstat()
            crafted = {
                "selectable": True,
                "kind": "dir",
                "deletion": "trash",
                "prefix": str(home / "Documents"),
                "relative": "OldApp.app",
                "path": str(bundle),
                "rule_id": "installer",
                "dev": bundle_info.st_dev,
                "ino": bundle_info.st_ino,
            }
            with self.assertRaises(UnsafePath):
                validate_item(
                    crafted,
                    home=home,
                    project_root=project,
                    icloud_desktop=False,
                    icloud_documents=False,
                )
            self.assertEqual((folder / "keep.txt").read_text(encoding="utf-8"), "keep")
            self.assertTrue(bundle.is_dir())

    def test_chrome_command_waits_until_chrome_and_google_quit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            home.mkdir()
            self._fixture(home)
            project = Path(raw) / "project"
            project.mkdir()
            trash = Path(raw) / "trash"
            trash.mkdir()
            result = self._scan(home)
            root = Path(result.home)
            chrome = next(item for item in result.items if item["path"].endswith("/Google/Chrome/Default/Cache"))
            secret = root / "Documents" / "secret.txt"
            job_id = save_chrome_job(project, [chrome])
            command = chrome_command(project, job_id)
            self.assertIn(f"--clean-chrome {job_id}", command)
            self.assertNotIn(";", command)

            blocked = clean_chrome_job(
                job_id,
                project_root=project,
                home=root,
                trash_root=trash,
                process_check=lambda _names: ["Google Chrome", "GoogleUpdater"],
                icloud_desktop=False,
                icloud_documents=False,
            )
            self.assertEqual(blocked, 1)
            self.assertTrue(Path(chrome["path"]).is_dir())

            saved = json.loads((project / "logs" / f"chrome-clean-{job_id}.json").read_text(encoding="utf-8"))
            saved["items"][0]["prefix"] = str(root / "Documents")
            saved["items"][0]["relative"] = "secret.txt"
            saved["items"][0]["path"] = str(secret)
            saved["items"][0]["rule_id"] = "installer"
            saved["items"][0]["kind"] = "file"
            saved["items"][0]["deletion"] = "trash"
            (project / "logs" / f"chrome-clean-{job_id}.json").write_text(json.dumps(saved), encoding="utf-8")
            refused = clean_chrome_job(
                job_id,
                project_root=project,
                home=root,
                trash_root=trash,
                process_check=lambda _names: [],
                icloud_desktop=False,
                icloud_documents=False,
            )
            self.assertEqual(refused, 1)
            self.assertEqual(secret.read_text(encoding="utf-8"), "secret-doc")
            self.assertTrue(Path(chrome["path"]).is_dir())

            fresh = save_chrome_job(project, [chrome])
            self.assertEqual(clean_chrome_job("not a job", project_root=project, home=root, trash_root=trash, process_check=lambda _names: [], icloud_desktop=False, icloud_documents=False), 2)
            cleaned = clean_chrome_job(
                fresh,
                project_root=project,
                home=root,
                trash_root=trash,
                process_check=lambda _names: [],
                icloud_desktop=False,
                icloud_documents=False,
            )
            self.assertEqual(cleaned, 0)
            self.assertFalse(Path(chrome["path"]).exists())
            self.assertEqual(secret.read_text(encoding="utf-8"), "secret-doc")


class ServerTests(unittest.TestCase):
    def test_binds_localhost_and_requires_token(self) -> None:
        server = create_server(0)
        self.assertEqual(server.server_address[0], "127.0.0.1")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
            body = page.read().decode("utf-8")
            self.assertNotIn("__CLEANER_TOKEN__", body)
            self.assertIn('name="cleaner-token"', body)
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/clean",
                data=json.dumps({"confirm": True, "ids": ["abcd"]}).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(caught.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
