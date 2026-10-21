"""Cleanup definitions.

Add an application by appending to these tables. Scanning code should not grow
a new hardcoded path for every app. Risk levels:

- safe: regenerated cache or crash data. "Select Safe Items" checks these.
- review: usually disposable, with a consequence. "Review Recommended" checks these.
- manual: shown, never checked by either shortcut.
- blocked: shown only. The deleter refuses them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


CATEGORIES: tuple[tuple[str, str, str], ...] = (
    (
        "whatsapp",
        "WhatsApp",
        "Caches and logs only. Message databases, downloaded photos, videos, and account data are never included.",
    ),
    (
        "chrome",
        "Chrome",
        "Browser caches and crash dumps. Profiles, bookmarks, cookies, passwords, extensions, and history are never included.",
    ),
    (
        "cursor",
        "Cursor",
        "Regenerated caches and logs, including the embedded browser cache, which can grow past 20 GB. Projects, settings, extensions, and chat history are never included.",
    ),
    (
        "caches",
        "Application caches",
        "Folders in ~/Library/Caches, one application at a time. Unknown folders stay unchecked.",
    ),
    (
        "logs",
        "Logs",
        "Application logs and crash reports. Removing them drops troubleshooting history, not documents.",
    ),
    (
        "installers",
        "Old installations",
        "Disk images, installer packages, and application copies left in Downloads or on the Desktop. Nothing here is checked until you check it. They go to the Trash. Apps in /Applications are never removed.",
    ),
    (
        "developer",
        "Developer tools",
        "Caches that can be rebuilt. They are not selected just because they are large. The note on each item says what will be downloaded again.",
    ),
    (
        "large",
        "Large files",
        "Unusually large files in Downloads, Desktop, Documents, and Movies. Review only. Never checked automatically. Moved to the Trash.",
    ),
)

PROFILE_NAME = re.compile(r"^(Default|Guest Profile|System Profile|Profile [0-9]+)$")
INSTALLER_NAME = re.compile(
    r"(chrome|googlechrome|cursor|whatsapp|installer|setup|update|discord|zoom|docker|firefox|edge|slack|vlc|obs)",
    re.IGNORECASE,
)
# Chat exports and backups mention an app name but are not installers.
EXPORT_NAME = re.compile(r"(chat|chats|backup|messages)", re.IGNORECASE)
PROCESS_NAME = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")

# Directory names that must never be deletion targets, at any depth.
DENIED_COMPONENTS = {
    "Cookies",
    "Cookies-journal",
    "Login Data",
    "Login Data-journal",
    "Login Data For Account",
    "History",
    "Archived History",
    "Bookmarks",
    "Web Data",
    "Web Data-journal",
    "Local Storage",
    "IndexedDB",
    "Session Storage",
    "Sessions",
    "Extensions",
    "Local Extension Settings",
    "Sync Extension Settings",
    "Secure Preferences",
    "AgentStores",
    "workspaceStorage",
    "globalStorage",
    "LocalKeyValue-locks",
}

# Exact home-relative prefixes that are never deletable, including their children.
DENIED_HOME_PREFIXES = (
    "Library/Mobile Documents",
    "Library/CloudStorage",
    "Library/Keychains",
    "Library/Mail",
    "Library/Messages",
    "Library/Photos",
    "Library/Safari",
    "Library/Accounts",
    "Library/Cookies",
    "Library/IdentityServices",
    "Library/HomeKit",
    "Library/Application Support/MobileSync",
    "Library/Application Support/AddressBook",
    "Library/Application Support/CallHistoryDB",
    "Library/Application Support/Knowledge",
    "Library/Application Support/com.apple.TCC",
    "Library/Application Support/Cursor/User",
    "Library/Application Support/Cursor/AgentStores",
    "Library/Application Support/Cursor/Backups",
    "Library/Application Support/Cursor/blob_storage",
    "Library/Application Support/Cursor/snapshots",
    "Library/Application Support/Cursor/Partitions",
    "Library/Application Support/Cursor/Local Storage",
    "Library/Application Support/Cursor/IndexedDB",
    "Library/Application Support/Cursor/Session Storage",
    "Library/Application Support/Code/User",
    "Library/Application Support/Code/Backups",
    "Library/Application Support/Code/blob_storage",
    "Library/Application Support/Code/Local Storage",
    "Library/Application Support/Code/IndexedDB",
    "Library/Application Support/Code/Session Storage",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Message",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Media",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Documents",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/stickers",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/AppState",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/LocalStorageDB",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/MessagingInfraDB_v2",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ExtChatDB",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/statusDB",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/BackedUpStorageDB",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Biz",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/fts",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/channels-fts",
    "Library/Group Containers/group.net.whatsapp.WhatsApp.private",
    "Pictures",
    "Music",
    ".cursor",
    ".vscode",
    ".Trash",
)

USER_FILE_ROOTS = ("Downloads", "Desktop", "Documents", "Movies")
INSTALLER_SUFFIXES = {".dmg", ".pkg", ".mpkg"}
PRUNE_DIR_NAMES = {
    "Cache",
    "Caches",
    "Code Cache",
    "GPUCache",
    "CacheStorage",
    "ScriptCache",
    "CachedData",
    "node_modules",
    ".git",
    ".Trash",
    "Library",
}


@dataclass(frozen=True)
class FixedRule:
    id: str
    app: str
    category: str
    name: str
    relative_path: str
    risk: str
    deletion: str
    description: str
    requires_app_closed: bool = False
    processes: tuple[str, ...] = ()
    close_message: str = ""
    kind: str = "dir"


@dataclass(frozen=True)
class CacheVerdict:
    app: str
    category: str
    name: str
    risk: str
    risk_label: str
    deletion: str
    description: str
    selectable: bool
    requires_app_closed: bool = False
    processes: tuple[str, ...] = ()
    close_message: str = ""


def category_label(category_id: str) -> str:
    for identifier, label, _note in CATEGORIES:
        if identifier == category_id:
            return label
    return category_id


def category_note(category_id: str) -> str:
    for identifier, _label, note in CATEGORIES:
        if identifier == category_id:
            return note
    return ""


def _fixed(
    rule_id: str,
    app: str,
    category: str,
    name: str,
    relative_path: str,
    risk: str,
    deletion: str,
    description: str,
    *,
    requires_app_closed: bool = False,
    processes: tuple[str, ...] = (),
    kind: str = "dir",
) -> FixedRule:
    close = f"Close {app} before cleaning these files." if requires_app_closed else ""
    return FixedRule(
        id=rule_id,
        app=app,
        category=category,
        name=name,
        relative_path=relative_path,
        risk=risk,
        deletion=deletion,
        description=description,
        requires_app_closed=requires_app_closed,
        processes=processes,
        close_message=close,
        kind=kind,
    )


def whatsapp_rules() -> list[FixedRule]:
    containers = (
        "net.whatsapp.WhatsApp",
        "net.whatsapp.WhatsApp.ServiceExtension",
        "net.whatsapp.WhatsApp.Intents",
        "net.whatsapp.WhatsApp.WAAppKitBridgeService",
    )
    pieces = (
        (
            "caches",
            "Data/Library/Caches",
            "Container cache",
            "safe",
            "Sandbox cache for temporary files and regenerated thumbnails. Messages, downloaded media, and account data are not in this folder.",
        ),
        (
            "crash",
            "Data/Library/Application Support/CrashReporter",
            "Crash reports",
            "safe",
            "Crash reports from this WhatsApp container. WhatsApp creates new ones if it crashes again.",
        ),
        (
            "resolver",
            "Data/Library/Application Support/MNSResolverCache",
            "Resolver cache",
            "safe",
            "Network resolver cache. WhatsApp recreates it. This is not the message database.",
        ),
    )
    rules: list[FixedRule] = []
    for container in containers:
        short = container.removeprefix("net.whatsapp.")
        for kind, relative, name, risk, description in pieces:
            rules.append(
                _fixed(
                    f"whatsapp-{container}-{kind}",
                    "WhatsApp",
                    "whatsapp",
                    f"{name} ({short})",
                    f"Library/Containers/{container}/{relative}",
                    risk,
                    "permanent",
                    description,
                    requires_app_closed=True,
                    processes=("WhatsApp",),
                )
            )
    rules.append(
        _fixed(
            "whatsapp-shared-logs",
            "WhatsApp",
            "whatsapp",
            "Shared logs",
            "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Logs",
            "safe",
            "permanent",
            "Diagnostic logs from the WhatsApp group container. Conversations stay in the message database, which is not here.",
            requires_app_closed=True,
            processes=("WhatsApp",),
        )
    )
    return rules


WHATSAPP_GROUP_CACHE = "Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Library/Caches"
WHATSAPP_GROUP_CACHE_SKIP = {"LocalKeyValue-locks"}


CHROME_PROFILE_RULES: tuple[dict, ...] = (
    {
        "id": "chrome-browser-cache",
        "root": "Library/Caches/Google/Chrome",
        "subpath": "Cache",
        "name": "Browser cache",
        "risk": "safe",
        "description": "On-disk network cache for this Chrome profile. Chrome rebuilds it as you browse. Bookmarks, passwords, cookies, and history are not in this folder.",
    },
    {
        "id": "chrome-code-cache",
        "root": "Library/Caches/Google/Chrome",
        "subpath": "Code Cache",
        "name": "Code cache",
        "risk": "safe",
        "description": "Cached compiled scripts for this profile. Chrome regenerates them. Site settings are not stored here.",
    },
    {
        "id": "chrome-image-cache",
        "root": "Library/Caches/Google/Chrome",
        "subpath": "image_cache",
        "name": "Image cache",
        "risk": "safe",
        "description": "Decoded image cache for this profile. Chrome downloads images again when you revisit a page.",
    },
    {
        "id": "chrome-gpu-cache",
        "root": "Library/Application Support/Google/Chrome",
        "subpath": "GPUCache",
        "name": "GPU cache",
        "risk": "safe",
        "description": "GPU process cache for this profile. Regenerated automatically. This is not your profile.",
    },
    {
        "id": "chrome-dawn-graphite",
        "root": "Library/Application Support/Google/Chrome",
        "subpath": "DawnGraphiteCache",
        "name": "Graphics cache",
        "risk": "safe",
        "description": "Graphite graphics cache. Chrome recreates it. Safe to remove while Chrome is closed.",
    },
    {
        "id": "chrome-dawn-webgpu",
        "root": "Library/Application Support/Google/Chrome",
        "subpath": "DawnWebGPUCache",
        "name": "WebGPU cache",
        "risk": "safe",
        "description": "WebGPU cache. Chrome recreates it.",
    },
    {
        "id": "chrome-sw-cache",
        "root": "Library/Application Support/Google/Chrome",
        "subpath": "Service Worker/CacheStorage",
        "name": "Service worker cache",
        "risk": "review",
        "description": "Cached responses for sites that use service workers. Pages still work; offline copies are fetched again. Cookies and logins are not in this folder.",
    },
    {
        "id": "chrome-sw-scripts",
        "root": "Library/Application Support/Google/Chrome",
        "subpath": "Service Worker/ScriptCache",
        "name": "Service worker scripts",
        "risk": "review",
        "description": "Cached service-worker scripts. Chrome fetches them again. The service-worker database and your profile are left alone.",
    },
    {
        "id": "chrome-hint-cache",
        "root": "Library/Application Support/Google/Chrome",
        "subpath": "optimization_guide_hint_cache_store",
        "name": "Optimization hint cache",
        "risk": "review",
        "description": "Chrome's optimization-guide cache. It is redownloaded. This is not browsing history.",
    },
    {
        "id": "chrome-autofill-model",
        "root": "Library/Application Support/Google/Chrome",
        "subpath": "AutofillAiModelCache",
        "name": "Autofill model cache",
        "risk": "review",
        "description": "Downloaded model used for autofill suggestions. Your saved addresses and cards stay in Web Data, which is not touched.",
    },
)

CHROME_SHARED_RULES: tuple[FixedRule, ...] = (
    _fixed(
        "chrome-crashpad",
        "Google Chrome",
        "chrome",
        "Crash reports",
        "Library/Application Support/Google/Chrome/Crashpad",
        "safe",
        "permanent",
        "Chrome crash dumps. Your profile is not in this folder.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-shader-cache",
        "Google Chrome",
        "chrome",
        "Shader cache",
        "Library/Application Support/Google/Chrome/ShaderCache",
        "safe",
        "permanent",
        "Shared shader cache. Chrome rebuilds it.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-graphite-cache",
        "Google Chrome",
        "chrome",
        "Shared graphics cache",
        "Library/Application Support/Google/Chrome/GraphiteDawnCache",
        "safe",
        "permanent",
        "Shared Graphite cache. Chrome rebuilds it.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-gr-shader",
        "Google Chrome",
        "chrome",
        "Ganesh shader cache",
        "Library/Application Support/Google/Chrome/GrShaderCache",
        "safe",
        "permanent",
        "Shared Ganesh shader cache. Chrome rebuilds it.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-gpu-persistent",
        "Google Chrome",
        "chrome",
        "Persistent GPU cache",
        "Library/Application Support/Google/Chrome/GPUPersistentCache",
        "safe",
        "permanent",
        "Persistent GPU cache outside the profiles. Chrome rebuilds it.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-component-crx",
        "Google Chrome",
        "chrome",
        "Component download cache",
        "Library/Application Support/Google/Chrome/component_crx_cache",
        "review",
        "permanent",
        "Cached Chrome components. Chrome downloads them again. Installed extensions are not removed.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-extension-crx",
        "Google Chrome",
        "chrome",
        "Extension package cache",
        "Library/Application Support/Google/Chrome/extensions_crx_cache",
        "review",
        "permanent",
        "Cached copies of extension packages. The installed extensions, in each profile's Extensions folder, are not removed.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-local-traces",
        "Google Chrome",
        "chrome",
        "Local traces",
        "Library/Application Support/Google/Chrome/Local Traces",
        "review",
        "permanent",
        "Local performance traces. Diagnostic data only.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-opt-models",
        "Google Chrome",
        "chrome",
        "Optimization models",
        "Library/Application Support/Google/Chrome/optimization_guide_model_store",
        "review",
        "permanent",
        "Downloaded optimization models. Chrome fetches them again. This can be a large download.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
    _fixed(
        "chrome-headless-cache",
        "Google Chrome",
        "chrome",
        "Headless Chrome cache",
        "Library/Caches/Google/Chrome-headless",
        "safe",
        "permanent",
        "Cache for headless Chrome. It is not a user profile.",
        requires_app_closed=True,
        processes=("Google Chrome",),
    ),
)


def _electron_children(default_risk: str) -> tuple[dict, ...]:
    return (
        {
            "id": "cache",
            "subpath": "Cache",
            "name": "Application cache",
            "risk": default_risk,
            "description": "Chromium application cache. It is rebuilt on next launch, even when the folder is many gigabytes. Settings and history are not in this folder.",
        },
        {
            "id": "cached-data",
            "subpath": "CachedData",
            "name": "Cached application data",
            "risk": default_risk,
            "description": "Cached files for the installed app version. They are extracted again on next launch. The User folder is not touched.",
        },
        {
            "id": "code-cache",
            "subpath": "Code Cache",
            "name": "Code cache",
            "risk": default_risk,
            "description": "Cached compiled interface code. Regenerated on next launch.",
        },
        {
            "id": "gpu-cache",
            "subpath": "GPUCache",
            "name": "GPU cache",
            "risk": default_risk,
            "description": "GPU cache. Regenerated on next launch.",
        },
        {
            "id": "dawn-graphite",
            "subpath": "DawnGraphiteCache",
            "name": "Graphics cache",
            "risk": default_risk,
            "description": "Graphite graphics cache. Regenerated on next launch.",
        },
        {
            "id": "dawn-webgpu",
            "subpath": "DawnWebGPUCache",
            "name": "WebGPU cache",
            "risk": default_risk,
            "description": "WebGPU cache. Regenerated on next launch.",
        },
        {
            "id": "crashpad",
            "subpath": "Crashpad",
            "name": "Crash reports",
            "risk": default_risk,
            "description": "Crash dumps. The app creates new ones if it crashes again. Projects and settings are not here.",
        },
        {
            "id": "logs",
            "subpath": "logs",
            "name": "Logs",
            "risk": default_risk,
            "description": "Application logs. They can mention local file paths from recent sessions. Chat history and settings are not in this folder.",
        },
        {
            "id": "vsix-cache",
            "subpath": "CachedExtensionVSIXs",
            "name": "Extension download cache",
            "risk": default_risk,
            "description": "Cached extension installer packages. Installed extensions stay where they are and can be downloaded again.",
        },
        {
            "id": "sentry",
            "subpath": "sentry",
            "name": "Diagnostic queue",
            "risk": default_risk,
            "description": "Queued diagnostic reports. Not chats, projects, or account data.",
        },
        {
            "id": "update-supervisor",
            "subpath": "update-supervisor",
            "name": "Updater files",
            "risk": "review",
            "description": "Working files left by the updater. Close the app first so an update is not in progress. Your projects are not here.",
        },
        {
            "id": "sw-cache",
            "subpath": "Service Worker/CacheStorage",
            "name": "Window resource cache",
            "risk": "review",
            "description": "Cached resources for the app window. Rebuilt on launch. Session data is stored elsewhere and is not deleted.",
        },
        {
            "id": "sw-scripts",
            "subpath": "Service Worker/ScriptCache",
            "name": "Window script cache",
            "risk": "review",
            "description": "Cached scripts for the app window. Rebuilt on launch.",
        },
        {
            "id": "cached-profiles",
            "subpath": "CachedProfilesData",
            "name": "Profile metadata cache",
            "risk": "review",
            "description": "Cached profile metadata. Actual settings stay in the User folder, which is not deleted.",
        },
    )


ELECTRON_APPS: tuple[dict, ...] = (
    {
        "id": "cursor",
        "app": "Cursor",
        "category": "cursor",
        "support": "Library/Application Support/Cursor",
        "processes": ("Cursor",),
        "children": _electron_children("safe"),
    },
    {
        "id": "vscode",
        "app": "Visual Studio Code",
        "category": "developer",
        "support": "Library/Application Support/Code",
        "processes": ("Code",),
        "children": _electron_children("review"),
    },
)


# Caches inside ~/Library/Application Support/Cursor/Partitions/<window>/.
# The rest of a partition (cookies, storage, databases) stays denied.
CURSOR_PARTITION_CACHES: tuple[dict, ...] = (
    {
        "subpath": "Cache",
        "name": "Browser cache",
        "risk": "safe",
        "description": "Cache for Cursor's embedded browser. This is the folder that grows past 20 GB. Cursor rebuilds it. Cookies, chats, and settings are not in this folder.",
    },
    {
        "subpath": "Code Cache",
        "name": "Browser code cache",
        "risk": "safe",
        "description": "Compiled scripts for Cursor's embedded browser. Regenerated on next launch. It can be large. Settings are not stored here.",
    },
    {
        "subpath": "GPUCache",
        "name": "Browser GPU cache",
        "risk": "safe",
        "description": "GPU cache for Cursor's embedded browser. Regenerated on next launch.",
    },
    {
        "subpath": "DawnGraphiteCache",
        "name": "Browser graphics cache",
        "risk": "safe",
        "description": "Graphite graphics cache for Cursor's embedded browser. Regenerated on next launch.",
    },
    {
        "subpath": "DawnWebGPUCache",
        "name": "Browser WebGPU cache",
        "risk": "safe",
        "description": "WebGPU cache for Cursor's embedded browser. Regenerated on next launch.",
    },
    {
        "subpath": "GrShaderCache",
        "name": "Browser shader cache",
        "risk": "safe",
        "description": "Shader cache for Cursor's embedded browser. Regenerated on next launch.",
    },
    {
        "subpath": "ShaderCache",
        "name": "Browser shader cache",
        "risk": "safe",
        "description": "Shader cache for Cursor's embedded browser. Regenerated on next launch.",
    },
    {
        "subpath": "Service Worker/CacheStorage",
        "name": "Browser window cache",
        "risk": "review",
        "description": "Cached resources for Cursor's embedded browser window. Rebuilt on launch. Session data is stored elsewhere and is not deleted.",
    },
    {
        "subpath": "Service Worker/ScriptCache",
        "name": "Browser script cache",
        "risk": "review",
        "description": "Cached scripts for Cursor's embedded browser window. Rebuilt on launch.",
    },
)


def _partition_name_ok(name: str) -> bool:
    return bool(
        name
        and name not in {".", ".."}
        and not name.startswith(".")
        and "/" not in name
        and "\x00" not in name
        and name not in DENIED_COMPONENTS
    )


def cursor_partition_spec(parts: tuple[str, ...]) -> dict | None:
    """Match Partitions/<window>/<cache>. Returns nothing for cookies or the partition itself."""
    if len(parts) < 2 or not _partition_name_ok(parts[0]):
        return None
    tail = parts[1:]
    for spec in CURSOR_PARTITION_CACHES:
        if tuple(spec["subpath"].split("/")) == tail:
            return spec
    return None


def cursor_partition_relative(relative: str) -> tuple[str, ...] | None:
    prefix = "Library/Application Support/Cursor/Partitions/"
    if not relative.startswith(prefix) or relative.endswith("/") or "//" in relative:
        return None
    parts = tuple(relative[len(prefix) :].split("/"))
    if cursor_partition_spec(parts) is None:
        return None
    return parts


def developer_fixed_rules() -> tuple[FixedRule, ...]:
    closed = False
    return (
        _fixed(
            "npm-cacache",
            "npm",
            "developer",
            "Download cache",
            ".npm/_cacache",
            "review",
            "permanent",
            "npm's download cache. Packages are fetched again the next time you install. Project node_modules folders are not touched.",
            requires_app_closed=closed,
        ),
        _fixed(
            "npm-logs",
            "npm",
            "logs",
            "npm logs",
            ".npm/_logs",
            "review",
            "permanent",
            "npm debug logs. Install history in these files is removed. Installed packages are not.",
        ),
        _fixed(
            "pnpm-store",
            "pnpm",
            "developer",
            "Content store",
            "Library/pnpm/store",
            "review",
            "permanent",
            "pnpm's content-addressed store. The next install downloads packages again. Project files are not in this store.",
        ),
        _fixed(
            "bun-cache",
            "Bun",
            "developer",
            "Install cache",
            ".bun/install/cache",
            "review",
            "permanent",
            "Bun's package cache. The next install downloads packages again.",
        ),
        _fixed(
            "cargo-registry",
            "Rust cargo",
            "developer",
            "Registry cache",
            ".cargo/registry/cache",
            "review",
            "permanent",
            "Cached crate downloads. Cargo downloads them again on the next build. Installed cargo binaries in ~/.cargo/bin are not removed.",
        ),
        _fixed(
            "cargo-git",
            "Rust cargo",
            "developer",
            "Git dependency cache",
            ".cargo/git",
            "review",
            "permanent",
            "Cloned git dependencies for Cargo. The next build fetches them again. Your own repositories are not inside this folder.",
        ),
        _fixed(
            "gradle-caches",
            "Gradle",
            "developer",
            "Build cache",
            ".gradle/caches",
            "review",
            "permanent",
            "Gradle dependency and build caches. The next build downloads them again. Project directories are not touched.",
        ),
        _fixed(
            "m2-repository",
            "Maven",
            "developer",
            "Local repository",
            ".m2/repository",
            "review",
            "permanent",
            "Maven's cached artifacts. The next build downloads them again. This is a cache, but it is also the local repository Maven resolves from.",
        ),
        _fixed(
            "nuget-packages",
            "NuGet",
            "developer",
            "Package cache",
            ".nuget/packages",
            "review",
            "permanent",
            "Cached NuGet packages. The next restore downloads them again.",
        ),
        _fixed(
            "go-mod",
            "Go modules",
            "developer",
            "Module cache",
            "go/pkg/mod",
            "review",
            "permanent",
            "Downloaded Go modules. The next build fetches them again. Your source checkouts are not this folder.",
        ),
        _fixed(
            "xcode-derived",
            "Xcode",
            "developer",
            "DerivedData",
            "Library/Developer/Xcode/DerivedData",
            "review",
            "permanent",
            "Intermediate build products. The next build recreates them, and that build will be slower. Source code is not stored in DerivedData.",
        ),
        _fixed(
            "xcode-archives",
            "Xcode",
            "developer",
            "Archives",
            "Library/Developer/Xcode/Archives",
            "manual",
            "trash",
            "Signed archives kept for distribution. This is not a cache. It is moved to the Trash, and only if you check it yourself.",
        ),
        _fixed(
            "xcode-ios-symbols",
            "Xcode",
            "developer",
            "iOS device symbols",
            "Library/Developer/Xcode/iOS DeviceSupport",
            "review",
            "permanent",
            "Symbol files copied from connected devices. Xcode copies them again the next time a device connects. This is often several gigabytes.",
        ),
        _fixed(
            "xcode-watch-symbols",
            "Xcode",
            "developer",
            "watchOS device symbols",
            "Library/Developer/Xcode/watchOS DeviceSupport",
            "review",
            "permanent",
            "watchOS symbol files. Xcode copies them again the next time a watch connects.",
        ),
        _fixed(
            "xcode-tv-symbols",
            "Xcode",
            "developer",
            "tvOS device symbols",
            "Library/Developer/Xcode/tvOS DeviceSupport",
            "review",
            "permanent",
            "tvOS symbol files. Xcode copies them again the next time a device connects.",
        ),
        _fixed(
            "simulator-caches",
            "Simulator",
            "developer",
            "Simulator caches",
            "Library/Developer/CoreSimulator/Caches",
            "review",
            "permanent",
            "CoreSimulator caches. Simulators rebuild them. Installed simulator runtimes and device data are not in this folder.",
        ),
        _fixed(
            "docker-raw",
            "Docker",
            "developer",
            "Virtual disk",
            "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
            "manual",
            "trash",
            "Docker's virtual disk. Moving it to the Trash removes images, containers, and volumes after you empty the Trash. Never checked automatically.",
            kind="file",
        ),
        _fixed(
            "docker-raw-legacy",
            "Docker",
            "developer",
            "Virtual disk (older layout)",
            "Library/Containers/com.docker.docker/Data/docker.raw",
            "manual",
            "trash",
            "Older location of Docker's virtual disk. Moving it to the Trash removes Docker's images, containers, and volumes after you empty the Trash.",
            kind="file",
        ),
        _fixed(
            "iphone-updates",
            "Apple devices",
            "installers",
            "iPhone software updates",
            "Library/iTunes/iPhone Software Updates",
            "manual",
            "trash",
            "Downloaded iPhone restore images. Move these to the Trash only if you do not need an offline restore. The folder goes to the Trash.",
        ),
        _fixed(
            "ipad-updates",
            "Apple devices",
            "installers",
            "iPad software updates",
            "Library/iTunes/iPad Software Updates",
            "manual",
            "trash",
            "Downloaded iPad restore images. Move these to the Trash only if you do not need an offline restore.",
        ),
    )


FIXED_RULES: tuple[FixedRule, ...] = tuple(whatsapp_rules()) + CHROME_SHARED_RULES + developer_fixed_rules()
FIXED_BY_ID = {rule.id: rule for rule in FIXED_RULES}


# Exact ~/Library/Caches child names. Prefix and suffix rules below cover the rest.
CACHE_DIR_RULES: dict[str, dict] = {
    "Homebrew": {
        "app": "Homebrew",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "Downloaded Homebrew bottles and source archives. The next install or upgrade downloads them again. Installed packages are not removed.",
    },
    "pip": {
        "app": "pip",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "pip's download cache. Packages are downloaded again when you install them. Virtual environments are not in this folder.",
    },
    "pypoetry": {
        "app": "Poetry",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "Poetry's download cache. Packages are fetched again on the next install.",
    },
    "pipx": {
        "app": "pipx",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "pipx download cache. Reinstalled tools download their packages again.",
    },
    "uv": {
        "app": "uv",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "uv's download cache. Packages are fetched again when needed.",
    },
    "yarn": {
        "app": "Yarn",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "Yarn's download cache. The next install downloads packages again. Project folders are not touched.",
    },
    "pnpm": {
        "app": "pnpm",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "pnpm's cache under ~/Library/Caches. Packages are fetched again. This is separate from a project folder.",
    },
    "node-gyp": {
        "app": "node-gyp",
        "category": "developer",
        "name": "Header cache",
        "risk": "review",
        "description": "Cached Node.js headers used to compile native modules. node-gyp downloads them again when needed.",
    },
    "typescript": {
        "app": "TypeScript",
        "category": "developer",
        "name": "Compiler cache",
        "risk": "review",
        "description": "TypeScript incremental cache. The next typecheck rebuilds it.",
    },
    "deno": {
        "app": "Deno",
        "category": "developer",
        "name": "Cache",
        "risk": "review",
        "description": "Deno's downloaded dependencies and generated cache. Deno fetches them again when you run a program.",
    },
    "go-build": {
        "app": "Go",
        "category": "developer",
        "name": "Build cache",
        "risk": "review",
        "description": "The Go build cache. The next build recompiles. Source code is not stored here.",
    },
    "CocoaPods": {
        "app": "CocoaPods",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "Cached CocoaPods downloads. The next pod install downloads them again.",
    },
    "org.swift.swiftpm": {
        "app": "Swift Package Manager",
        "category": "developer",
        "name": "Package cache",
        "risk": "review",
        "description": "Cached Swift packages. The next build may download them again. Your projects are not in this folder.",
    },
    "composer": {
        "app": "Composer",
        "category": "developer",
        "name": "Download cache",
        "risk": "review",
        "description": "Composer's package cache. The next install downloads packages again.",
    },
    "ms-playwright": {
        "app": "Playwright",
        "category": "developer",
        "name": "Browsers",
        "risk": "review",
        "description": "Safe to remove, but Playwright will need to download the browsers again the next time tests run.",
    },
    "ms-playwright-go": {
        "app": "Playwright for Go",
        "category": "developer",
        "name": "Browsers",
        "risk": "review",
        "description": "Safe to remove, but Playwright will need to download the browsers again the next time tests run.",
    },
    "com.google.GoogleUpdater": {
        "app": "Google Chrome",
        "category": "chrome",
        "name": "Updater cache",
        "risk": "safe",
        "description": "Download cache used by Google's updater. Chrome profiles are not stored here. Stale update payloads are recreated when Chrome updates.",
        "requires_app_closed": False,
    },
    "com.todesktop.230313mzl4w4u92": {
        "app": "Cursor",
        "category": "cursor",
        "name": "Application cache",
        "risk": "safe",
        "description": "Cursor's Electron cache outside Application Support. Cursor rebuilds it. Settings and chats are not here.",
        "requires_app_closed": True,
        "processes": ("Cursor",),
    },
    "cursor-compile-cache": {
        "app": "Cursor",
        "category": "cursor",
        "name": "Compile cache",
        "risk": "safe",
        "description": "Cursor compile cache. It is regenerated. Projects and chats are not in this folder.",
        "requires_app_closed": True,
        "processes": ("Cursor",),
    },
    "com.microsoft.VSCode": {
        "app": "Visual Studio Code",
        "category": "developer",
        "name": "Application cache",
        "risk": "review",
        "description": "VS Code's Electron cache. It is rebuilt on next launch. Settings and extensions stay installed.",
        "requires_app_closed": True,
        "processes": ("Code",),
    },
}

APPLE_REVIEW_CACHES = {
    "com.apple.Safari": "Safari's web cache. Pages load again on the next visit. Bookmarks and saved passwords are not in this folder.",
    "com.apple.Safari.SafeBrowsing": "Safe Browsing data. Safari downloads a fresh copy. This is not your history.",
    "com.apple.dt.Xcode": "Xcode's cache under ~/Library/Caches. The next build recreates what it needs. Source code and archives are not here.",
}

HARD_BLOCK_NAMES = {
    "PassKit",
    "CloudKit",
    "FamilyCircle",
    "familycircled",
    "GeoServices",
    "Accounts",
    "HomeKit",
}

FRIENDLY_NAMES = {
    "com.hnc.Discord": "Discord",
    "com.spotify.client": "Spotify",
    "us.zoom.xos": "Zoom",
    "com.figma.agent": "Figma",
    "com.microsoft.teams": "Microsoft Teams",
    "com.tinyspeck.slackmacgap": "Slack",
    "com.docker.docker": "Docker",
    "org.videolan.vlc": "VLC",
    "com.obsproject.obs-studio": "OBS",
    "com.adobe.Photoshop": "Photoshop",
    "com.openai.chat": "ChatGPT",
    "com.anthropic.claudefordesktop": "Claude",
    "Steam": "Steam",
    "Adobe": "Adobe",
    "Blender": "Blender",
    "minecraft": "Minecraft",
}

SENSITIVE_PARTS = {
    "keychain",
    "password",
    "passwords",
    "cookie",
    "cookies",
    "wallet",
    "secret",
    "secrets",
    "token",
    "tokens",
}

APP_SUPPORT_SKIP = {
    "Google",
    "Cursor",
    "Code",
    "WhatsApp",
    "AddressBook",
    "CallHistoryDB",
    "MobileSync",
    "Knowledge",
    "CloudDocs",
    "FileProvider",
    "HomeKit",
    "IdentityServices",
    "AuthKit",
    "com.apple.TCC",
    "CrashReporter",
}

APP_SUPPORT_MANUAL = {
    "Cache",
    "Caches",
    "Code Cache",
    "GPUCache",
    "CachedData",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "ShaderCache",
    "GrShaderCache",
    "GPUPersistentCache",
}

APP_SUPPORT_REVIEW = {"Crashpad", "logs"}

INSTALLER_SEARCH_ROOTS: tuple[tuple[str, int], ...] = (
    ("Downloads", 2),
    ("Desktop", 2),
    ("Library/Caches", 2),
    ("Library/Google", 4),
    ("Library/Application Support/Google/GoogleUpdater", 3),
)

LARGE_FILE_ROOTS: tuple[tuple[str, int], ...] = (
    ("Downloads", 2),
    ("Desktop", 2),
    ("Documents", 2),
    ("Movies", 2),
)


def risk_label(risk: str, *, manual_label: str = "Review manually") -> str:
    return {
        "safe": "Safe to delete",
        "review": "Review recommended",
        "manual": manual_label,
        "blocked": "Not deleted by this tool",
    }.get(risk, manual_label)


def sensitive_name(name: str) -> bool:
    return _sensitive(name)


def _sensitive(name: str) -> bool:
    if name in HARD_BLOCK_NAMES:
        return True
    parts = [part for part in re.split(r"[.\-_]", name.lower()) if part]
    return any(part in SENSITIVE_PARTS for part in parts)


def _verdict(
    app: str,
    category: str,
    name: str,
    risk: str,
    description: str,
    *,
    selectable: bool,
    deletion: str = "permanent",
    requires_app_closed: bool = False,
    processes: tuple[str, ...] = (),
    manual_label: str = "Review manually",
) -> CacheVerdict:
    close = f"Close {app} before cleaning these files." if requires_app_closed else ""
    return CacheVerdict(
        app=app,
        category=category,
        name=name,
        risk=risk,
        risk_label=risk_label(risk, manual_label=manual_label),
        deletion=deletion if selectable else "none",
        description=description,
        selectable=selectable,
        requires_app_closed=requires_app_closed,
        processes=processes,
        close_message=close,
    )


def app_name_from_cache_dir(name: str) -> str:
    base = name[: -len(".ShipIt")] if name.endswith(".ShipIt") else name
    if base in FRIENDLY_NAMES:
        return FRIENDLY_NAMES[base]
    if base in CACHE_DIR_RULES:
        return str(CACHE_DIR_RULES[base]["app"])
    parts = [
        part
        for part in base.split(".")
        if part and part not in {"com", "org", "net", "io", "app", "mac", "osx", "desktop"}
    ]
    label = parts[-1] if parts else base
    return label.replace("-", " ").replace("_", " ")


def classify_cache_dir(name: str) -> CacheVerdict:
    """Classify one direct child of ~/Library/Caches. Never walk its contents to decide."""
    if name in ("", ".", "..") or "/" in name or "\x00" in name or _sensitive(name):
        return _verdict(
            "macOS",
            "caches",
            name or "cache",
            "blocked",
            "The name looks like credentials, account data, or a private store. It is listed so you can see it, and it cannot be deleted here.",
            selectable=False,
        )

    if name.endswith(".ShipIt"):
        base = name[: -len(".ShipIt")]
        if base.startswith("com.apple.") or _sensitive(base):
            return _verdict(
                "macOS",
                "caches",
                "Update leftover",
                "blocked",
                "This updater leftover belongs to macOS or to a sensitive store, so it is not deleted.",
                selectable=False,
            )
        inner_app = app_name_from_cache_dir(base)
        processes: tuple[str, ...] = ()
        requires = False
        if base.startswith("com.todesktop."):
            inner_app = "Cursor"
            processes = ("Cursor",)
            requires = True
        elif base.startswith("com.microsoft.VSCode"):
            inner_app = "Visual Studio Code"
            processes = ("Code",)
            requires = True
        return _verdict(
            inner_app,
            "caches",
            "Update leftover",
            "safe",
            "Leftover updater files (ShipIt). The app recreates them when it updates. Safe to remove.",
            selectable=True,
            requires_app_closed=requires,
            processes=processes,
        )

    if name in CACHE_DIR_RULES:
        rule = CACHE_DIR_RULES[name]
        return _verdict(
            str(rule["app"]),
            str(rule["category"]),
            str(rule["name"]),
            str(rule["risk"]),
            str(rule["description"]),
            selectable=True,
            requires_app_closed=bool(rule.get("requires_app_closed", False)),
            processes=tuple(rule.get("processes", ())),
        )

    if name in APPLE_REVIEW_CACHES:
        app = "Safari" if name.startswith("com.apple.Safari") else "Xcode"
        return _verdict(
            app,
            "caches" if app == "Safari" else "developer",
            "Cache",
            "review",
            APPLE_REVIEW_CACHES[name],
            selectable=True,
            requires_app_closed=True,
            processes=("Safari",) if app == "Safari" else (),
        )

    if name.startswith("com.apple."):
        return _verdict(
            "macOS",
            "caches",
            app_name_from_cache_dir(name),
            "blocked",
            "macOS system cache. Removing these can disturb iCloud, accounts, or system services, so this tool never deletes them.",
            selectable=False,
        )

    if name.startswith("com.todesktop."):
        return _verdict(
            "Cursor",
            "cursor",
            "Application cache",
            "safe",
            "Cursor cache under ~/Library/Caches. Cursor rebuilds it. Settings and chats are stored elsewhere.",
            selectable=True,
            requires_app_closed=True,
            processes=("Cursor",),
        )

    if name.startswith("com.microsoft.VSCode"):
        return _verdict(
            "Visual Studio Code",
            "developer",
            "Application cache",
            "review",
            "VS Code cache under ~/Library/Caches. It is rebuilt on next launch. Settings stay in the User folder.",
            selectable=True,
            requires_app_closed=True,
            processes=("Code",),
        )

    if name.startswith(("com.google.Keystone", "com.google.SoftwareUpdate")):
        return _verdict(
            "Google Chrome",
            "chrome",
            "Updater cache",
            "review",
            "Older Google updater cache. Profiles are not stored here. The updater can download it again.",
            selectable=True,
        )

    pretty = app_name_from_cache_dir(name)
    return _verdict(
        pretty,
        "caches",
        "Cache",
        "manual",
        "This folder is in ~/Library/Caches, so it is probably disposable, but it is not on the known-safe list. Check the path. It is never selected for you.",
        selectable=True,
        manual_label="Review manually",
    )
