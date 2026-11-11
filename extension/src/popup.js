import "./shared.js";
import "./popup-core.js";

// spec/05 §2.12 action popup: yw-app status (as last observed by the background) and the
// compatibility mode selector. Text is set with textContent only.
//
// It renders at once (2026-11-11): everything below up to the first `await` runs before the
// page's load event, so Chrome opens the popup already showing the modes and status it showed
// last time (popup-core MODES_CACHE_KEY/STATUS_CACHE_KEY, this page's own localStorage). The
// chrome.storage.local read and the background's answer (which may first have to start the
// service worker) then refresh it in place.
const shared = globalThis.__YOUR_WALLET_SHARED__;
const popup = globalThis.__YOUR_WALLET_POPUP_CORE__;

const byId = (id) => document.getElementById(id);

function setText(id, text) {
  byId(id).textContent = text;
}

// localStorage can be missing or throw (blocked site data); the popup then renders live only.
function cacheGet(key) {
  try {
    return globalThis.localStorage.getItem(key);
  } catch (_error) {
    return null;
  }
}

function cacheSet(key, value) {
  try {
    globalThis.localStorage.setItem(key, value);
  } catch (_error) {
    // Only the next popup's first paint is affected.
  }
}

// `stale`: the status shown last time, until the background answers again.
function renderStatus(status, stale = false) {
  const view = popup.statusView(status);
  const value = byId("status-value");
  value.textContent = view.text;
  value.dataset.tone = view.tone;
  setText("status-detail", stale ? popup.TEXT.statusStale : view.detail);
}

function requestStatus() {
  let answered = false;
  let port = null;
  const finish = (status, observed) => {
    if (answered) {
      return;
    }
    answered = true;
    clearTimeout(timer);
    renderStatus(status);
    // Only what the background reported is remembered (not a timeout or a closed port).
    if (observed) {
      cacheSet(popup.STATUS_CACHE_KEY, status);
    }
    if (port !== null) {
      try {
        port.disconnect();
      } catch (_error) {
        // Already closed.
      }
    }
  };
  const timer = setTimeout(() => finish("unknown", false), popup.STATUS_TIMEOUT_MS);
  try {
    port = chrome.runtime.connect({ name: shared.POPUP_PORT_NAME });
    port.onMessage.addListener((message) => {
      const status = popup.parseStatusMessage(message);
      finish(status ?? "unknown", status !== null);
    });
    port.onDisconnect.addListener(() => {
      void chrome.runtime.lastError;
      finish("unknown", false);
    });
  } catch (_error) {
    finish("unknown", false);
  }
}

// One selectable card per mode: radio, label and its one-line explanation. `kind` is the group
// (evm, sol, btc), each with its own storage key and radio name.
function renderModes(selected, kind = "evm", containerId = "modes") {
  const group = byId(containerId);
  group.replaceChildren();
  for (const option of popup.GROUPS[kind].options) {
    const card = document.createElement("label");
    card.className = "mode";
    const input = document.createElement("input");
    input.type = "radio";
    input.name = kind === "evm" ? "compat-mode" : `${kind}-compat-mode`;
    input.value = option.value;
    input.checked = option.value === selected;
    input.addEventListener("change", () => {
      if (input.checked) {
        void saveMode(option.value, kind);
      }
    });
    const text = document.createElement("span");
    text.className = "mode-text";
    const name = document.createElement("span");
    name.className = "mode-label";
    name.textContent = option.label;
    const explanation = document.createElement("span");
    explanation.className = "mode-explanation";
    explanation.textContent = option.explanation;
    text.append(name, explanation);
    card.append(input, text);
    group.append(card);
  }
}

// Per group: where its cards and "saved" line go and which look-alike warning it has. The
// warning matters only while that group's look-alike mode is on, so it is hidden for "off".
const GROUP_IDS = Object.freeze({
  evm: Object.freeze({ modes: "modes", saved: "mode-saved", warning: "warning", explain: "mode-explain" }),
  sol: Object.freeze({ modes: "sol-modes", saved: "sol-saved", warning: "sol-warning", explain: "sol-explain" }),
  btc: Object.freeze({ modes: "btc-modes", saved: "btc-saved", warning: "btc-warning", explain: "btc-explain" })
});
const KINDS = Object.freeze(["evm", "sol", "btc"]);

// The modes sit side by side (2026-11-11, a short popup); the chosen one's sentence is shown once
// under them instead of on every card.
function showWarning(kind, mode) {
  const option = popup.GROUPS[kind].options.find((candidate) => candidate.value === mode);
  byId(GROUP_IDS[kind].explain).textContent = option?.explanation ?? "";
  byId(GROUP_IDS[kind].warning).hidden = !popup.warningShown(mode);
  if (kind === "evm") {
    byId("metamask-note").hidden = !popup.metamaskNoteShown(mode);
  }
}

function renderGroup(kind, mode) {
  renderModes(mode, kind, GROUP_IDS[kind].modes);
  showWarning(kind, mode);
}

// What the cards show now, and which groups the user changed in this popup (a late storage read
// never overwrites a choice made meanwhile).
const shown = { evm: null, sol: null, btc: null };
const touched = new Set();

function rememberModes() {
  if (KINDS.every((kind) => shown[kind] !== null)) {
    cacheSet(popup.MODES_CACHE_KEY, popup.serializeModes(shown));
  }
}

async function saveMode(mode, kind = "evm") {
  const update = popup.storageUpdateFor(kind, mode);
  if (update === null) {
    return;
  }
  touched.add(kind);
  shown[kind] = mode;
  showWarning(kind, mode);
  try {
    await chrome.storage.local.set(update);
    setText(GROUP_IDS[kind].saved, popup.TEXT.saved);
    rememberModes();
  } catch (_error) {
    setText(GROUP_IDS[kind].saved, popup.TEXT.saveFailed);
  }
}

async function loadModes() {
  try {
    const stored = await chrome.storage.local.get([
      shared.COMPAT_MODE_STORAGE_KEY,
      shared.SOL_COMPAT_MODE_STORAGE_KEY,
      shared.BTC_COMPAT_MODE_STORAGE_KEY
    ]);
    return {
      modes: {
        evm: shared.normalizeCompatMode(stored?.[shared.COMPAT_MODE_STORAGE_KEY]),
        sol: shared.normalizeSolCompatMode(stored?.[shared.SOL_COMPAT_MODE_STORAGE_KEY]),
        btc: shared.normalizeBtcCompatMode(stored?.[shared.BTC_COMPAT_MODE_STORAGE_KEY])
      },
      failed: false
    };
  } catch (_error) {
    return { modes: { evm: "off", sol: "off", btc: "off" }, failed: true };
  }
}

async function main() {
  setText("title", popup.TEXT.title);
  setText("status-heading", popup.TEXT.statusHeading);
  setText("mode-heading", popup.TEXT.modeHeading);
  setText("apply-note", popup.TEXT.applyNote);
  setText("warning", popup.TEXT.warning);
  setText("metamask-note", popup.TEXT.metamaskConnectNote);
  setText("sol-heading", popup.TEXT.solHeading);
  setText("btc-heading", popup.TEXT.btcHeading);
  setText("sol-warning", popup.TEXT.solWarning);
  setText("btc-warning", popup.TEXT.btcWarning);
  setText("chain-note", popup.TEXT.chainNote);

  // First paint: last time's state (or the loading text), with no round trip.
  const cachedStatus = popup.parseCachedStatus(cacheGet(popup.STATUS_CACHE_KEY));
  if (cachedStatus === null) {
    setText("status-value", popup.TEXT.statusLoading);
  } else {
    renderStatus(cachedStatus, true);
  }
  const cachedModes = popup.parseCachedModes(cacheGet(popup.MODES_CACHE_KEY));
  if (cachedModes !== null) {
    for (const kind of KINDS) {
      shown[kind] = cachedModes[kind];
      renderGroup(kind, cachedModes[kind]);
    }
  }

  // Live state, filled in as it arrives.
  requestStatus();
  const { modes, failed } = await loadModes();
  for (const kind of KINDS) {
    if (!touched.has(kind) && shown[kind] !== modes[kind]) {
      shown[kind] = modes[kind];
      renderGroup(kind, modes[kind]);
    }
  }
  if (failed) {
    setText("mode-saved", popup.TEXT.loadFailed);
  } else {
    rememberModes();
  }
}

void main();
