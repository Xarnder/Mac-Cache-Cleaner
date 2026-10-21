# Mac Cache Cleaner

A small disk-space cleaner for this Mac. It measures known caches, logs, old installers, and large files, then waits. Nothing is deleted until you check the paths and confirm in the browser.

It is local only. The server listens on `127.0.0.1`, there is no account, and it does not phone home.

## Safety

Every cleanup target comes from a rule in `cleaner/rules.py`. A folder is not chosen just because its name contains "Cache".

Three levels:

| Level | Meaning | How it gets checked |
| --- | --- | --- |
| Safe to delete | Regenerated cache, crash dumps, or updater leftovers | **Select Safe Items** |
| Review recommended | Usually disposable, with a consequence (a rebuild, a redownload, lost log history) | **Review Recommended** |
| Review manually / Not selected automatically | Unknown caches, installers, large files, Xcode archives, Docker's disk | Only if you check that row yourself |

A fourth group is shown and cannot be deleted: macOS system caches, iCloud files, and anything whose safety is not clear enough.

The deleter checks the path again at the moment of deletion:

- The path has to match the rule that found it. A checkbox cannot be pointed at a different folder.
- Symlinks are not followed. A link inside a cache is removed; the thing it points at is not.
- The file identity (device and inode) has to match the scan. If something replaced the folder, it is skipped.
- The cleaner refuses `/`, your home folder, library roots, and its own project folder.
- Paths that hold messages, profiles, cookies, passwords, or project data are on a denylist even if a rule is wrong.
- The program refuses to run as root.

Caches and logs are deleted permanently, because moving hundreds of thousands of cache files to the Trash is slow and easy to get wrong. Installers, large files, Xcode archives, and Docker's disk are renamed into the Trash. Empty the Trash to actually free that space. The confirmation screen lists every path and which method applies.

## What this tool will not delete

- Documents, Desktop, Pictures, Music, or iCloud Drive (Desktop and Documents are blocked when iCloud sync is on)
- Photos, source checkouts, and anything under `~/.cursor` or `~/.vscode`
- WhatsApp message databases, `Message/Media`, documents, and stickers
- Chrome profiles: cookies, passwords, history, bookmarks, extensions, Local Storage, IndexedDB
- Cursor and VS Code settings, chat history, Agent Stores, installed extensions, and the `User` folder
- Keychains, Mail, Messages, accounts, and iPhone backups in MobileSync
- macOS caches in `~/Library/Caches/com.apple.*` (Safari's web cache and Xcode's cache are the exceptions) and everything in `/Library/Caches`

Unknown caches under `~/Library/Caches` are listed so you can see them. They stay unchecked.

## Requirements

- macOS, running as your user. Do not use `sudo`.
- Python 3.9 or newer. `/usr/bin/python3` is enough. There are no packages to install.

## Start it

In Terminal:

```bash
cd /Users/xanderwiles/Documents/Work/Code/Mac-Cache-Cleaner
chmod +x cleanup.command
./cleanup.command
```

Or double-click `Start.command` in Finder. It opens `http://127.0.0.1:<port>/` in the browser. Leave the Terminal window open while you use it. Control-C stops the server.

The page is a dry run. **Select Safe Items**, **Review Recommended**, **Select Old Installations**, and **Deselect All** only change checkboxes. Each app also has **Select these caches**. **Clean Selected** shows the paths, the total, and whether each one is permanent or moved to the Trash. Permanent cache deletes need an extra confirmation. If Cursor, WhatsApp, Safari, or VS Code is open, those caches stay held until you check the box that says to remove them anyway. It will not quit the app for you. Chrome is different: while Google Chrome is open, Clean Selected shows a Terminal command. Quit Google Chrome and Google updater, paste the command, and it removes only the Chrome caches you selected. The command does nothing if either is still open.

Afterward you get:

- space freed immediately
- space moved to the Trash
- how many locations were removed, skipped, or failed
- a fresh scan of what is still recoverable

A log of what was removed is appended to `logs/cleanup.log` inside this folder.

### Command line

Both of these only print a report. They do not delete.

```bash
./cleanup.command --scan
./cleanup.command --dry-run
```

There is no command that deletes without the confirmation page.

Folders under 1 MB are left out of the list. Installers under 1 MB are left out. Large files are files of at least 200 MB in Downloads, Desktop, Documents, and Movies, two folders deep. The whole disk is not walked.

## Add another app

Edit `cleaner/rules.py`.

A known folder outside `~/Library/Caches` is a `FixedRule` (`_fixed(...)`): app, category, path relative to your home, risk, and whether to delete it or move it to the Trash.

A direct child of `~/Library/Caches` is an entry in `CACHE_DIR_RULES`. Names ending in `.ShipIt` are treated as updater leftovers. Anything else in that folder is shown as "Review manually" and is not selected for you.

Chrome profile caches and the Cursor / VS Code folders are tables (`CHROME_PROFILE_RULES`, `ELECTRON_APPS`). Copy a row to add another cache subfolder. Do not add `Cookies`, `Login Data`, `Local Storage`, `IndexedDB`, or `User`.

## Locations it can delete

Only when the folder exists, is large enough to list, and you confirm it. `<profile>` is `Default`, `System Profile`, `Guest Profile`, or `Profile` plus a number.

### WhatsApp

Permanent, and only after WhatsApp is closed (unless you override that on the confirmation screen):

- `~/Library/Containers/net.whatsapp.WhatsApp/Data/Library/Caches`
- `~/Library/Containers/net.whatsapp.WhatsApp.ServiceExtension/Data/Library/Caches`
- `~/Library/Containers/net.whatsapp.WhatsApp.Intents/Data/Library/Caches`
- `~/Library/Containers/net.whatsapp.WhatsApp.WAAppKitBridgeService/Data/Library/Caches`
- `~/Library/Containers/<those same containers>/Data/Library/Application Support/CrashReporter`
- `~/Library/Containers/<those same containers>/Data/Library/Application Support/MNSResolverCache`
- `~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Logs`
- Other folders directly inside `~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Library/Caches`, except `LocalKeyValue-locks`

Not included: `Message`, `Media`, `Documents`, stickers, and the message databases (`LocalStorageDB`, `MessagingInfraDB_v2`, `ExtChatDB`, `statusDB`, `BackedUpStorageDB`).

### Google Chrome

Permanent. Close Chrome first.

Safe:

- `~/Library/Caches/Google/Chrome/<profile>/Cache`
- `~/Library/Caches/Google/Chrome/<profile>/Code Cache`
- `~/Library/Caches/Google/Chrome/<profile>/image_cache`
- `~/Library/Application Support/Google/Chrome/<profile>/GPUCache`
- `~/Library/Application Support/Google/Chrome/<profile>/DawnGraphiteCache`
- `~/Library/Application Support/Google/Chrome/<profile>/DawnWebGPUCache`
- `~/Library/Application Support/Google/Chrome/Crashpad`
- `~/Library/Application Support/Google/Chrome/ShaderCache`
- `~/Library/Application Support/Google/Chrome/GraphiteDawnCache`
- `~/Library/Application Support/Google/Chrome/GrShaderCache`
- `~/Library/Application Support/Google/Chrome/GPUPersistentCache`
- `~/Library/Caches/Google/Chrome-headless`
- `~/Library/Caches/com.google.GoogleUpdater`

Review recommended:

- `~/Library/Application Support/Google/Chrome/<profile>/Service Worker/CacheStorage`
- `~/Library/Application Support/Google/Chrome/<profile>/Service Worker/ScriptCache`
- `~/Library/Application Support/Google/Chrome/<profile>/optimization_guide_hint_cache_store`
- `~/Library/Application Support/Google/Chrome/<profile>/AutofillAiModelCache`
- `~/Library/Application Support/Google/Chrome/component_crx_cache`
- `~/Library/Application Support/Google/Chrome/extensions_crx_cache`
- `~/Library/Application Support/Google/Chrome/Local Traces`
- `~/Library/Application Support/Google/Chrome/optimization_guide_model_store`
- `~/Library/Caches/com.google.Keystone*` and `com.google.SoftwareUpdate*`

The service-worker database, `Cookies`, `Login Data`, `History`, `Bookmarks`, `Extensions`, `Local Storage`, and `IndexedDB` are not targets.

### Cursor

Permanent. Close Cursor first. Safe, except where noted:

- `~/Library/Application Support/Cursor/Cache`
- `~/Library/Application Support/Cursor/CachedData`
- `~/Library/Application Support/Cursor/Code Cache`
- `~/Library/Application Support/Cursor/GPUCache`
- `~/Library/Application Support/Cursor/DawnGraphiteCache`
- `~/Library/Application Support/Cursor/DawnWebGPUCache`
- `~/Library/Application Support/Cursor/Crashpad`
- `~/Library/Application Support/Cursor/logs`
- `~/Library/Application Support/Cursor/CachedExtensionVSIXs`
- `~/Library/Application Support/Cursor/sentry`
- `~/Library/Caches/com.todesktop.230313mzl4w4u92` and other `com.todesktop.*` caches
- `~/Library/Caches/cursor-compile-cache`
- `~/Library/Caches/*.ShipIt` updater leftovers for Cursor
- `~/Library/Application Support/Cursor/Partitions/<window>/Cache`
- `~/Library/Application Support/Cursor/Partitions/<window>/Code Cache`
- `~/Library/Application Support/Cursor/Partitions/<window>/GPUCache`
- `~/Library/Application Support/Cursor/Partitions/<window>/DawnGraphiteCache`
- `~/Library/Application Support/Cursor/Partitions/<window>/DawnWebGPUCache`

The partition `Cache` folder is Cursor's embedded browser cache. It is separate from the application `Cache` folder and is the one that grows past 20 GB. A locked file inside a cache does not stop the rest of that cache from being removed.

Review recommended:

- `~/Library/Application Support/Cursor/update-supervisor`
- `~/Library/Application Support/Cursor/Service Worker/CacheStorage`
- `~/Library/Application Support/Cursor/Service Worker/ScriptCache`
- `~/Library/Application Support/Cursor/Partitions/<window>/Service Worker/CacheStorage`
- `~/Library/Application Support/Cursor/Partitions/<window>/Service Worker/ScriptCache`
- `~/Library/Application Support/Cursor/CachedProfilesData`

Not included: `User` (settings, workspace storage, chat history, including `state.vscdb`), `AgentStores`, `Backups`, `blob_storage`, `snapshots`, cookies and storage inside a partition, and `~/.cursor`.

### Visual Studio Code

Same cache folders as Cursor, under `~/Library/Application Support/Code` and `~/Library/Caches/com.microsoft.VSCode` (including `.ShipIt`). These are review recommended, not selected with Safe Items. The `User` folder is not touched.

### Application caches

Each direct child of `~/Library/Caches` is listed on its own, with its size and date.

Known download caches (review recommended, not selected just because they are large): Homebrew, pip, pipx, Poetry, uv, Yarn, pnpm, node-gyp, TypeScript, Deno, Go's build cache, CocoaPods, Swift Package Manager (`org.swift.swiftpm`), Composer.

`com.apple.Safari`, `com.apple.Safari.SafeBrowsing`, and `com.apple.dt.Xcode` are review recommended. Other `com.apple.*` caches, plus CloudKit, PassKit, HomeKit, FamilyCircle, GeoServices, and names that look like passwords or tokens, are shown and cannot be deleted.

Other names are "Review manually". `~/Library/Caches/Google` is not deleted as one folder; Chrome's caches are the entries above.

For other apps, only these names directly inside `~/Library/Application Support/<App>/` are offered, and only as review or manual, never for Google, Cursor, VS Code, WhatsApp, or Apple:

`Cache`, `Caches`, `Code Cache`, `GPUCache`, `CachedData`, `DawnGraphiteCache`, `DawnWebGPUCache`, `ShaderCache`, `GrShaderCache`, `GPUPersistentCache`, `Crashpad`, `logs`.

`/Library/Caches` is measured and shown. It is not deleted, and the tool will not ask for an administrator password.

### Logs

Each folder directly inside `~/Library/Logs`.

- `DiagnosticReports` and `CrashReporter`: safe
- Other logs: review recommended
- `~/.npm/_logs`: review recommended

### Developer tools

Review recommended, permanent, not selected with Safe Items:

- `~/.npm/_cacache` — npm will download packages again. `node_modules` is not touched.
- `~/Library/pnpm/store`
- `~/.bun/install/cache`
- `~/.cargo/registry/cache` and `~/.cargo/git` — not `~/.cargo/bin`
- `~/.gradle/caches`
- `~/.m2/repository` — Maven's local repository; the next build downloads artifacts again
- `~/.nuget/packages`
- `~/go/pkg/mod`
- `~/Library/Developer/Xcode/DerivedData` — the next build is slower. Source is not in here.
- `~/Library/Developer/Xcode/iOS DeviceSupport`
- `~/Library/Developer/Xcode/watchOS DeviceSupport`
- `~/Library/Developer/Xcode/tvOS DeviceSupport`
- `~/Library/Developer/CoreSimulator/Caches` — simulator devices themselves are not deleted

Not selected automatically. Moved to the Trash:

- `~/Library/Developer/Xcode/Archives` — distribution archives, not a cache
- `~/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw`
- `~/Library/Containers/com.docker.docker/Data/docker.raw`

Playwright (`~/Library/Caches/ms-playwright` and `ms-playwright-go`): safe to remove, but Playwright will need to download the browsers again the next time tests run.

### Old installations

Moved to the Trash, and only if you check the file. The Downloads folder is never deleted as a folder.

Looked for `.dmg`, `.pkg`, and `.mpkg`, plus `.zip` whose name looks like an installer or a known app. In `~/Downloads` and `~/Desktop` it also lists application copies (folders ending in `.app`), two levels deep. Those copies are moved to the Trash only if you check them. Apps installed in `/Applications` are never removed.

Looked for installer files in:

- `~/Downloads` and `~/Desktop` (two levels)
- `~/Library/Caches` (two levels, and it does not walk into folders named `Cache`, `Code Cache`, `GPUCache`, or `CachedData`)
- `~/Library/Google`
- `~/Library/Application Support/Google/GoogleUpdater`
- your temporary directory, only for installer files that have not been touched in the last day

Also, if present, the whole folder (Trash, manual):

- `~/Library/iTunes/iPhone Software Updates`
- `~/Library/iTunes/iPad Software Updates`

### Large files

Files of at least 200 MB in `~/Downloads`, `~/Desktop`, `~/Documents`, and `~/Movies`, two folders deep. Review only. Moved to the Trash. Never checked automatically. Pictures and Music are not scanned. iCloud placeholders are not deleted.

## Permissions

The cleaner uses your account. If a system folder is not writable, it is shown as not deleted. It will not ask for a password and it will not run as root.

## Uninstall

1. Stop it with Control-C, or quit the Terminal window that is running it.
2. Delete this project folder.
3. Empty the Trash if you want the space from files that were moved there.

Nothing is installed in LaunchAgents, `/Applications`, or `/Library`. The only files it writes are `logs/cleanup.log` in this folder, plus whatever you sent to the Trash.

## Tests

```bash
python3 -m unittest tests.test_cleaner -v
```

The tests use a fake home directory. They check that a cleanup of every selectable item still leaves WhatsApp media, Chrome cookies, Cursor settings, and a file reached through a symlink.
