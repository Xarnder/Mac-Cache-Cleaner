const token = document.querySelector('meta[name="cleaner-token"]').content;
const statusNode = document.getElementById("status");
const totalNode = document.getElementById("total");
const detailNode = document.getElementById("total-detail");
const bannersNode = document.getElementById("banners");
const resultsNode = document.getElementById("results");
const warningsNode = document.getElementById("warnings");
const categoriesNode = document.getElementById("categories");
const navList = document.getElementById("nav-list");
const cleanButton = document.getElementById("clean");
const modal = document.getElementById("modal");
const modalBody = document.getElementById("modal-body");
const modalConfirm = document.getElementById("modal-confirm");
const hideSmallInput = document.getElementById("hide-small");
const queryInput = document.getElementById("query");
const progressNode = document.getElementById("progress");
const progressBar = document.getElementById("progress-bar");
const progressLabel = document.getElementById("progress-label");

const SCAN_STAGES = [
  "Starting scan",
  "Checking known app folders",
  "Measuring Chrome caches",
  "Measuring Cursor and VS Code",
  "Measuring application caches",
  "Measuring logs",
  "Checking application support caches",
  "Looking for old installers",
  "Looking for large files",
  "Checking system caches",
  "Scan finished",
];

let scan = null;
const selected = new Set();
const forceOpen = new Set();
let previewPayload = null;
let notice = "";
let loopToken = 0;
let awaitingOwnScan = false;
let activeSection = null;
let scrollWatching = false;
let scrollScheduled = false;

function formatBytes(size) {
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let value = Number(size) || 0;
  for (const unit of units) {
    if (value < 1000 || unit === "TB") {
      if (unit === "bytes") return `${Math.round(value)} bytes`;
      return `${value.toFixed(1)} ${unit}`;
    }
    value /= 1000;
  }
  return `${value.toFixed(1)} TB`;
}

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([key, value]) => {
    if (value == null || value === false) return;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "checked") node.checked = Boolean(value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, value);
  });
  (children || []).filter(Boolean).forEach((child) => node.append(child));
  return node;
}

async function api(path, options) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "X-Cleaner-Token": token,
      ...(options && options.body ? { "Content-Type": "application/json" } : {}),
      ...(options && options.headers ? options.headers : {}),
    },
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.error || "Request failed");
    error.payload = data;
    error.status = response.status;
    throw error;
  }
  return data;
}

function selectableItems() {
  return (scan && scan.items ? scan.items : []).filter((item) => item.selectable);
}

function categoryLabel(id) {
  const category = (scan.categories || []).find((entry) => entry.id === id);
  return category ? category.label.toLowerCase() : "";
}

function visible(item) {
  const query = queryInput.value.trim().toLowerCase();
  if (query && !`${item.app} ${item.name} ${item.path} ${categoryLabel(item.category)}`.toLowerCase().includes(query)) return false;
  if (item.risk === "manual") return true;
  if (!hideSmallInput.checked) return true;
  const categoryItems = (scan.items || []).filter((candidate) => candidate.category === item.category && candidate.kind !== "info");
  const hasLarge = categoryItems.some((candidate) => candidate.size_bytes >= 10_000_000);
  if (!hasLarge) return true;
  return item.size_bytes >= 10_000_000 || item.kind === "info";
}

function selectedItems() {
  const byId = new Map(selectableItems().map((item) => [item.id, item]));
  return [...selected].map((id) => byId.get(id)).filter(Boolean);
}

function updateCleanButton() {
  const items = selectedItems();
  const bytes = items.reduce((sum, item) => sum + item.size_bytes, 0);
  cleanButton.disabled = items.length === 0 || (scan && scan.status === "running");
  cleanButton.textContent = items.length ? `Clean Selected · ${formatBytes(bytes)}` : "Clean Selected";
}

function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function scanPercent() {
  const index = SCAN_STAGES.indexOf(scan && scan.progress);
  if (index < 0) return 8;
  return Math.round((index / (SCAN_STAGES.length - 1)) * 100);
}

function renderProgress() {
  const running = Boolean(scan && scan.status === "running");
  progressNode.classList.toggle("hidden", !running);
  progressLabel.classList.toggle("hidden", !running);
  if (!running) return;
  const percent = scanPercent();
  progressNode.setAttribute("aria-valuenow", String(percent));
  progressBar.style.width = `${Math.max(percent, 6)}%`;
  progressLabel.textContent = scan.progress || "Scanning";
}

function renderBanners() {
  bannersNode.replaceChildren();
  if (notice) bannersNode.append(el("div", { class: "banner", text: notice }));
  if (scan && scan.status === "running") return;
  const messages = [];
  selectedItems().forEach((item) => {
    if (item.app_running && item.close_message && !messages.includes(item.close_message)) {
      messages.push(item.close_message);
    }
  });
  (scan.items || []).forEach((item) => {
    if (item.app_running && item.close_message && item.selectable && !messages.includes(item.close_message)) {
      messages.push(item.close_message);
    }
  });
  messages.forEach((message) => {
    bannersNode.append(el("div", { class: "banner", text: `${message} Then press Rescan.` }));
  });
}

function renderItem(item) {
  const box = item.selectable
    ? el("input", {
        type: "checkbox",
        checked: selected.has(item.id),
        "aria-label": `${item.app} ${item.name}`,
        onchange: (event) => {
          if (event.target.checked) selected.add(item.id);
          else selected.delete(item.id);
          updateCleanButton();
          renderBanners();
        },
      })
    : el("span");
  const badges = el("div", { class: "badges" }, [
    el("span", { class: `badge ${item.risk}`, text: item.risk_label }),
    el("span", { class: "badge", text: item.deletion_label }),
    item.modified ? el("span", { class: "badge", text: item.modified }) : null,
  ]);
  return el(item.selectable ? "label" : "article", { class: "item" }, [
    box,
    el("div", {}, [
      el("h3", { text: `${item.app} — ${item.name}` }),
      el("p", { class: "meta", text: formatBytes(item.size_bytes) }),
      el("p", { class: "path", text: item.path }),
      el("p", { class: "desc", text: item.description }),
      item.requires_app_closed ? el("p", { class: "warn-line", text: item.close_message }) : null,
      badges,
    ]),
  ]);
}

function render() {
  if (!scan) return;
  statusNode.textContent = scan.status === "running" ? "Scanning" : scan.status === "error" ? "Scan failed" : "Ready";
  renderProgress();
  const recoverable = scan.totals ? scan.totals.recoverable : 0;
  totalNode.textContent = scan.status === "done" ? formatBytes(recoverable) : scan.status === "running" ? "Scanning" : "…";
  if (scan.status === "running") {
    detailNode.textContent = "Looking through known cache folders. Nothing is deleted during a scan.";
  } else if (scan.status === "done" && scan.totals) {
    const parts = [
      `${formatBytes(scan.totals.safe)} safe to delete`,
      `${formatBytes(scan.totals.review)} worth reviewing`,
    ];
    if (scan.totals.manual) parts.push(`${formatBytes(scan.totals.manual)} left unchecked until you choose it`);
    detailNode.textContent = parts.join(" · ");
  }

  warningsNode.replaceChildren();
  (scan.warnings || []).forEach((warning) => {
    warningsNode.append(el("p", { class: "warning", text: warning }));
  });
  renderBanners();
  updateCleanButton();

  const previouslyOpen = categoriesNode.querySelector("details.category")
    ? new Set(
        [...categoriesNode.querySelectorAll("details.category")]
          .filter((node) => node.open)
          .map((node) => node.dataset.id)
      )
    : null;
  categoriesNode.replaceChildren();
  if (scan.status !== "done") {
    renderNav([]);
    return;
  }
  const query = queryInput.value.trim().toLowerCase();
  const navEntries = [];
  (scan.categories || []).forEach((category) => {
    const items = (scan.items || []).filter((item) => item.category === category.id);
    const normal = items.filter((item) => item.group !== "system" && item.kind !== "info");
    const system = items.filter((item) => item.group === "system" || item.kind === "info");
    const shown = normal.filter(visible);
    const headline = normal.filter((item) => item.selectable).reduce((sum, item) => sum + item.size_bytes, 0);
    const body = [el("p", { class: "note", text: category.note })];
    const inCategory = selectableItems().filter((item) => item.category === category.id);
    const actions = categoryActions(category, inCategory);
    if (actions.length) body.push(el("div", { class: "category-actions" }, actions));
    if (!shown.length) {
      body.push(el("p", { class: "empty", text: normal.length ? "Nothing matches this filter." : "Nothing large enough to list. Checked locations are in the README." }));
    }
    shown.forEach((item) => body.push(renderItem(item)));
    const hiddenCount = normal.length - shown.length;
    if (hiddenCount > 0) {
      body.push(el("p", { class: "empty", text: `${hiddenCount} smaller recommended item${hiddenCount === 1 ? "" : "s"} hidden. Items you choose yourself stay listed. Select these caches still includes the hidden ones, and the confirmation list shows every path.` }));
    }
    if (system.length) {
      const systemBody = system.map(renderItem);
      body.push(el("details", { class: "system" }, [
        el("summary", { text: `Not deleted by this tool · ${formatBytes(system.reduce((sum, item) => sum + item.size_bytes, 0))}` }),
        ...systemBody,
      ]));
    }
    if (query && !shown.length && !category.label.toLowerCase().includes(query)) return;
    navEntries.push({ id: category.id, label: category.label, bytes: headline });
    const defaultOpen = category.id === "installers" || shown.some((item) => item.risk === "safe" || item.risk === "review");
    const isOpen = Boolean(query) || forceOpen.has(category.id) || (previouslyOpen ? previouslyOpen.has(category.id) : defaultOpen);
    categoriesNode.append(el("details", { class: "category", open: isOpen || undefined, "data-id": category.id }, [
      el("summary", {}, [
        el("span", { text: category.label }),
        el("span", { text: formatBytes(headline) }),
      ]),
      ...body,
    ]));
  });
  const previousSection = activeSection;
  if (!navEntries.some((entry) => entry.id === activeSection)) activeSection = navEntries.length ? navEntries[0].id : null;
  renderNav(navEntries);
  if (query && activeSection && activeSection !== previousSection) {
    const match = categoriesNode.querySelector(`details.category[data-id="${activeSection}"]`);
    if (match) {
      match.open = true;
      match.scrollIntoView({ block: "start" });
    }
  }
  watchSections();
  forceOpen.clear();
}

function renderNav(entries) {
  navList.replaceChildren();
  if (!scan || scan.status !== "done") {
    navList.append(el("p", { class: "nav-empty", text: "Sections show up when the scan finishes." }));
    return;
  }
  if (!entries.length) {
    navList.append(el("p", { class: "nav-empty", text: "No sections match that search." }));
    return;
  }
  entries.forEach((entry) => {
    const active = entry.id === activeSection;
    navList.append(el("button", {
      type: "button",
      class: active ? "nav-link active" : "nav-link",
      "data-id": entry.id,
      "aria-current": active ? "true" : null,
      onclick: () => showSection(entry.id),
    }, [
      el("span", { class: "nav-label", text: entry.label }),
      el("span", { class: "nav-size", text: formatBytes(entry.bytes) }),
    ]));
  });
}

function updateNavActive() {
  navList.querySelectorAll(".nav-link").forEach((button) => {
    const active = button.dataset.id === activeSection;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "true");
    else button.removeAttribute("aria-current");
  });
}

function showSection(id) {
  activeSection = id;
  updateNavActive();
  const node = categoriesNode.querySelector(`details.category[data-id="${id}"]`);
  if (!node) return;
  node.open = true;
  node.scrollIntoView({ behavior: "smooth", block: "start" });
}

function sectionAtToolbar() {
  const toolbar = document.querySelector(".toolbar");
  const line = (toolbar ? toolbar.getBoundingClientRect().bottom : 80) + 28;
  let current = null;
  categoriesNode.querySelectorAll("details.category").forEach((node) => {
    if (node.getBoundingClientRect().top <= line) current = node.dataset.id;
  });
  return current;
}

function watchSections() {
  if (scrollWatching) return;
  scrollWatching = true;
  const sync = () => {
    scrollScheduled = false;
    const id = sectionAtToolbar();
    if (!id || id === activeSection) return;
    if (!navList.querySelector(`.nav-link[data-id="${id}"]`)) return;
    activeSection = id;
    updateNavActive();
  };
  window.addEventListener("scroll", () => {
    if (scrollScheduled) return;
    scrollScheduled = true;
    window.requestAnimationFrame(sync);
  }, { passive: true });
}

function categoryActions(category, inCategory) {
  const actions = [];
  if (inCategory.some((item) => item.risk === "safe" || item.risk === "review")) {
    actions.push(el("button", {
      type: "button",
      text: "Select these caches",
      onclick: (event) => {
        event.preventDefault();
        selectCategory(category.id, ["safe", "review"]);
      },
    }));
  }
  if (category.id !== "large" && inCategory.some((item) => item.risk === "manual")) {
    actions.push(el("button", {
      type: "button",
      text: category.id === "installers" ? "Select old installations" : "Select remaining",
      onclick: (event) => {
        event.preventDefault();
        selectCategory(category.id, ["manual"]);
      },
    }));
  }
  if (inCategory.some((item) => selected.has(item.id))) {
    actions.push(el("button", {
      type: "button",
      text: "Clear",
      onclick: (event) => {
        event.preventDefault();
        clearCategory(category.id);
      },
    }));
  }
  return actions;
}

function selectCategory(categoryId, risks) {
  forceOpen.add(categoryId);
  selectableItems().forEach((item) => {
    if (item.category === categoryId && risks.includes(item.risk)) selected.add(item.id);
  });
  render();
}

function clearCategory(categoryId) {
  forceOpen.add(categoryId);
  selectableItems().forEach((item) => {
    if (item.category === categoryId) selected.delete(item.id);
  });
  render();
}

function setSelection(risk) {
  selectableItems().forEach((item) => {
    if (item.risk === risk) selected.add(item.id);
  });
  render();
}

async function followScan() {
  const token = ++loopToken;
  while (token === loopToken) {
    let latest;
    try {
      latest = await api("/api/scan");
    } catch (error) {
      if (token !== loopToken) return;
      statusNode.textContent = "Reconnecting";
      detailNode.textContent = error.message;
      await sleep(1000);
      continue;
    }
    if (token !== loopToken) return;
    const replaced = Boolean(scan && scan.scan_id && latest.scan_id && latest.scan_id !== scan.scan_id);
    const same = scan && latest.status === scan.status && latest.scan_id === scan.scan_id && latest.progress === scan.progress;
    if (replaced && !awaitingOwnScan) {
      selected.clear();
      closeModal();
      notice = latest.status === "running"
        ? "Scanning again. Choose items after the bar finishes."
        : "A newer scan replaced this list. Choose the items again.";
    }
    if (latest.status === "done") awaitingOwnScan = false;
    if (!same || replaced) {
      scan = latest;
      if (latest.status === "done") {
        const ids = new Set((latest.items || []).map((item) => item.id));
        [...selected].forEach((id) => {
          if (!ids.has(id)) selected.delete(id);
        });
      }
      render();
    }
    await sleep(latest.status === "running" ? 400 : 2000);
  }
}

async function rescan(keepResults) {
  selected.clear();
  notice = "";
  awaitingOwnScan = true;
  if (keepResults !== true) resultsNode.classList.add("hidden");
  loopToken += 1;
  const token = loopToken;
  scan = await api("/api/scan", { method: "POST" });
  if (token !== loopToken) return;
  render();
  followScan();
}

async function recoverStaleScan() {
  closeModal();
  selected.clear();
  const latest = await api("/api/scan");
  notice = latest.status === "running"
    ? "Scanning again. Choose items after the bar finishes."
    : "That scan is out of date. The list is updated. Choose the items again.";
  scan = latest;
  render();
  if (latest.status !== "running" && !latest.scan_id) {
    await rescan(true);
    return;
  }
  followScan();
}

function closeModal() {
  modal.classList.add("hidden");
  previewPayload = null;
  modalConfirm.disabled = true;
}

function chromeWaiting() {
  if (!previewPayload || !previewPayload.chrome_command) return [];
  return previewPayload.locations.filter((location) => location.category === "chrome" && location.app_running);
}

function chosenLocations() {
  if (!previewPayload) return [];
  const running = document.getElementById("ack-running");
  const includeOpen = Boolean(running && running.checked);
  return previewPayload.locations.filter((location) => {
    if (location.category === "chrome" && location.app_running) return false;
    return includeOpen || !location.app_running;
  });
}

function copyChromeCommand(event) {
  const command = document.getElementById("chrome-command");
  const button = event.currentTarget;
  const text = previewPayload && previewPayload.chrome_command;
  if (!command || !text) return;
  const range = document.createRange();
  range.selectNodeContents(command);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
  const done = () => {
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = "Copy command";
    }, 2000);
  };
  done();
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).catch(() => {});
}

function confirmReady() {
  if (!previewPayload) {
    modalConfirm.disabled = true;
    return;
  }
  const chosen = chosenLocations();
  const needsPermanent = chosen.some((location) => location.deletion === "permanent");
  const permanent = document.getElementById("ack-permanent");
  const permanentOk = !needsPermanent || Boolean(permanent && permanent.checked);
  const running = document.getElementById("ack-running");
  const otherBlocked = previewPayload.locations.filter((location) => location.app_running && location.category !== "chrome").length;
  const ready = previewPayload.locations.filter((location) => !location.app_running).length;
  if (running && running.checked) modalConfirm.textContent = "Remove all selected";
  else if (otherBlocked && ready) modalConfirm.textContent = `Remove ${ready} ready item${ready === 1 ? "" : "s"}`;
  else if (otherBlocked) modalConfirm.textContent = "Remove caches for open apps";
  else if (chromeWaiting().length && !chosen.length) modalConfirm.textContent = "Use the Terminal command";
  else modalConfirm.textContent = "Remove selected";
  modalConfirm.disabled = !(permanentOk && chosen.length > 0);
}

async function openConfirm() {
  const ids = selectedItems().map((item) => item.id);
  if (!ids.length) return;
  modalBody.replaceChildren(el("p", { text: "Checking the current scan…" }));
  modal.classList.remove("hidden");
  modalConfirm.disabled = true;
  try {
    previewPayload = await api("/api/preview", {
      method: "POST",
      body: JSON.stringify({ scan_id: scan.scan_id, ids }),
    });
  } catch (error) {
    if (/scan changed|already running|does not match this scan/i.test(error.message)) {
      await recoverStaleScan();
      return;
    }
    modalBody.replaceChildren(el("p", { text: error.message }));
    return;
  }
  const preview = previewPayload;
  const chromeHeld = chromeWaiting();
  const otherBlocked = preview.locations.filter((location) => location.app_running && location.category !== "chrome");
  const ready = preview.locations.filter((location) => !location.app_running);
  const onlyChrome = Boolean(preview.chrome_command) && chromeHeld.length === preview.locations.length;
  const nodes = onlyChrome
    ? [el("p", { text: `${chromeHeld.length} Chrome cache${chromeHeld.length === 1 ? "" : "s"} · ${formatBytes(preview.chrome_bytes)}. Nothing is removed until you run the command below.` })]
    : [
        el("p", { text: `${preview.count} location${preview.count === 1 ? "" : "s"} · ${formatBytes(preview.size_bytes)}` }),
        el("p", { text: `${preview.permanent_count} deleted permanently (${formatBytes(preview.permanent_bytes)}). Space is freed now.` }),
        el("p", { text: `${preview.trash_count} moved to the Trash (${formatBytes(preview.trash_bytes)}). Empty the Trash to free that space.` }),
      ];
  if (preview.chrome_command) {
    nodes.push(el("p", {
      class: "warn-line",
      text: `Google Chrome is open, so ${chromeHeld.length} Chrome cache${chromeHeld.length === 1 ? "" : "s"} (${formatBytes(preview.chrome_bytes)}) cannot be removed yet. Quit Google Chrome from the Chrome menu, and quit Google updater if it is open. Then paste this into Terminal:`,
    }));
    nodes.push(el("pre", { class: "command", id: "chrome-command", text: preview.chrome_command }));
    nodes.push(el("div", { class: "command-actions" }, [
      el("button", { type: "button", text: "Copy command", onclick: copyChromeCommand }),
    ]));
    nodes.push(el("p", { class: "note", text: "The command checks that Chrome and Google updater have quit. It then removes only the Chrome caches you selected. It does nothing if either is still open." }));
  }
  if (otherBlocked.length) {
    const summary = ready.length
      ? `${ready.length} can be removed now. ${otherBlocked.length} belong to other apps that are still open and stay put unless you check the box.`
      : "These caches belong to apps that are still open. Check the box if you still want them removed.";
    nodes.push(el("p", { class: "warn-line", text: summary }));
    preview.running_messages
      .filter((message) => !message.includes("Google Chrome"))
      .forEach((message) => nodes.push(el("p", { class: "warn-line", text: message })));
    nodes.push(el("label", { class: "check" }, [
      el("input", { type: "checkbox", id: "ack-running", onchange: confirmReady }),
      el("span", { text: "Also remove caches while those other apps are still open." }),
    ]));
  }
  const inAppPermanent = preview.locations.some(
    (location) => location.deletion === "permanent" && !(location.category === "chrome" && location.app_running)
  );
  if (inAppPermanent) {
    nodes.push(el("label", { class: "check" }, [
      el("input", { type: "checkbox", id: "ack-permanent", onchange: confirmReady }),
      el("span", { text: "I understand the cache and log deletions are permanent." }),
    ]));
  }
  const list = el("ol", { class: "paths" });
  preview.locations.forEach((location) => {
    const held = location.category === "chrome" && location.app_running
      ? "Quit Chrome, then run the command above. "
      : location.app_running
        ? "Held while the app is open. "
        : "";
    list.append(el("li", { text: `${held}${location.deletion_label}: ${location.path}` }));
  });
  nodes.push(list);
  modalBody.replaceChildren(...nodes);
  confirmReady();
  const commandNode = document.getElementById("chrome-command");
  if (commandNode) commandNode.scrollIntoView({ block: "center" });
  else document.getElementById("modal-cancel").focus();
}

function renderResults(summary) {
  const lines = [
    `Freed now: ${formatBytes(summary.freed_bytes)}`,
    `Moved to Trash: ${formatBytes(summary.trashed_bytes)} — empty the Trash to release it`,
    `Removed: ${summary.removed_count}`,
    `Skipped: ${summary.skipped_count}`,
    `Errors: ${summary.error_count}`,
  ];
  const block = el("div", {}, lines.map((line) => el("p", { text: line })));
  (summary.errors || []).forEach((item) => block.append(el("p", { text: `${item.path}: ${item.error}` })));
  (summary.skipped || []).forEach((item) => block.append(el("p", { text: `Skipped ${item.path}: ${item.error}` })));
  resultsNode.replaceChildren(block);
  resultsNode.classList.remove("hidden");
}

async function cleanSelected() {
  const ids = chosenLocations().map((location) => location.id);
  const running = document.getElementById("ack-running");
  if (!ids.length) return;
  modalConfirm.disabled = true;
  try {
    const summary = await api("/api/clean", {
      method: "POST",
      body: JSON.stringify({
        scan_id: scan.scan_id,
        ids,
        confirm: true,
        allow_running: Boolean(running && running.checked),
      }),
    });
    closeModal();
    renderResults(summary);
    selected.clear();
    await rescan(true);
  } catch (error) {
    if (/scan changed|already running|does not match this scan/i.test(error.message)) {
      await recoverStaleScan();
      return;
    }
    modalBody.append(el("p", { text: error.message }));
    modalConfirm.disabled = false;
  }
}

document.getElementById("select-safe").addEventListener("click", () => setSelection("safe"));
document.getElementById("select-review").addEventListener("click", () => setSelection("review"));
document.getElementById("select-installers").addEventListener("click", () => selectCategory("installers", ["manual"]));
document.getElementById("select-none").addEventListener("click", () => {
  selected.clear();
  render();
});
document.getElementById("rescan").addEventListener("click", () => rescan(false));
cleanButton.addEventListener("click", openConfirm);
document.getElementById("modal-cancel").addEventListener("click", closeModal);
modalConfirm.addEventListener("click", cleanSelected);
hideSmallInput.addEventListener("change", render);
queryInput.addEventListener("input", render);
modal.addEventListener("click", (event) => {
  if (event.target === modal) closeModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeModal();
});

async function boot() {
  try {
    scan = await api("/api/scan");
  } catch (error) {
    statusNode.textContent = "Could not reach the cleaner";
    detailNode.textContent = error.message;
    return;
  }
  render();
  if (scan.status === "running" || (scan.status === "done" && scan.scan_id)) {
    followScan();
    return;
  }
  await rescan(false);
}

boot();
