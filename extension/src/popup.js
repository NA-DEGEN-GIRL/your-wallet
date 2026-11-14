import "./shared.js";
import "./popup-core.js";

// spec/05 §2.12 action popup: yw-app status (as last observed by the background), the
// compatibility mode selector and (2026-11-14) the 한국어 | English toggle. Text is set with
// textContent only.
//
// It renders at once (2026-11-11): everything below up to the first `await` runs before the
// page's load event, so Chrome opens the popup already showing the language, modes and status it
// showed last time (popup-core LANGUAGE_CACHE_KEY/MODES_CACHE_KEY/STATUS_CACHE_KEY, this page's own
// localStorage). The chrome.storage.local read and the background's answer (which may first have
// to start the service worker) then refresh it in place.
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

// The language everything is drawn in, and the language-dependent state to redraw on a switch:
// the status shown (null while loading) and each group's last "saved" line (a TEXT key or null).
let lang = "ko";
let languageTouched = false;
const statusShown = { status: null, stale: false };
const savedShown = { evm: null, sol: null, btc: null };

const text = () => popup.texts(lang);

// `stale`: the status shown last time, until the background answers again.
function renderStatus(status, stale = false) {
  statusShown.status = status;
  statusShown.stale = stale;
  const view = popup.statusView(status, lang);
  const value = byId("status-value");
  value.textContent = view.text;
  value.dataset.tone = view.tone;
  setText("status-detail", stale ? text().statusStale : view.detail);
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
  for (const option of popup.groupOptions(kind, lang)) {
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
    const label = document.createElement("span");
    label.className = "mode-text";
    const name = document.createElement("span");
    name.className = "mode-label";
    name.textContent = option.label;
    const explanation = document.createElement("span");
    explanation.className = "mode-explanation";
    explanation.textContent = option.explanation;
    label.append(name, explanation);
    card.append(input, label);
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
  const option = popup.groupOptions(kind, lang).find((candidate) => candidate.value === mode);
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

function showSaved(kind, key) {
  savedShown[kind] = key;
  setText(GROUP_IDS[kind].saved, key === null ? "" : text()[key]);
}

// What the cards show now, and which groups the user changed in this popup (a late storage read
// never overwrites a choice made meanwhile).
const shown = { evm: null, sol: null, btc: null };
const touched = new Set();

// Every fixed text, the cards, the status and the saved lines in the current language.
function applyLanguage() {
  document.documentElement.lang = lang;
  for (const code of popup.LANGUAGES) {
    byId(`lang-${code}`).setAttribute("aria-pressed", code === lang ? "true" : "false");
  }
  const t = text();
  setText("title", t.title);
  setText("status-heading", t.statusHeading);
  setText("mode-heading", t.modeHeading);
  setText("apply-note", t.applyNote);
  setText("warning", t.warning);
  setText("metamask-note", t.metamaskConnectNote);
  setText("sol-heading", t.solHeading);
  setText("btc-heading", t.btcHeading);
  setText("sol-warning", t.solWarning);
  setText("btc-warning", t.btcWarning);
  setText("chain-note", t.chainNote);
  if (statusShown.status === null) {
    setText("status-value", t.statusLoading);
  } else {
    renderStatus(statusShown.status, statusShown.stale);
  }
  for (const kind of KINDS) {
    if (shown[kind] !== null) {
      renderGroup(kind, shown[kind]);
    }
    showSaved(kind, savedShown[kind]);
  }
}

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
    showSaved(kind, "saved");
    rememberModes();
  } catch (_error) {
    showSaved(kind, "saveFailed");
  }
}

// The toggle applies at once; chrome.storage.local is where the next popup reads it from.
async function saveLanguage(code) {
  const update = popup.languageUpdate(code);
  if (update === null) {
    return;
  }
  languageTouched = true;
  if (code !== lang) {
    lang = code;
    applyLanguage();
  }
  try {
    await chrome.storage.local.set(update);
    cacheSet(popup.LANGUAGE_CACHE_KEY, code);
  } catch (_error) {
    showSaved("evm", "saveFailed");
  }
}

async function loadStored() {
  try {
    const stored = await chrome.storage.local.get([
      shared.COMPAT_MODE_STORAGE_KEY,
      shared.SOL_COMPAT_MODE_STORAGE_KEY,
      shared.BTC_COMPAT_MODE_STORAGE_KEY,
      shared.LANGUAGE_STORAGE_KEY
    ]);
    return {
      modes: {
        evm: shared.normalizeCompatMode(stored?.[shared.COMPAT_MODE_STORAGE_KEY]),
        sol: shared.normalizeSolCompatMode(stored?.[shared.SOL_COMPAT_MODE_STORAGE_KEY]),
        btc: shared.normalizeBtcCompatMode(stored?.[shared.BTC_COMPAT_MODE_STORAGE_KEY])
      },
      language: shared.normalizeLanguage(stored?.[shared.LANGUAGE_STORAGE_KEY]),
      failed: false
    };
  } catch (_error) {
    return { modes: { evm: "off", sol: "off", btc: "off" }, language: lang, failed: true };
  }
}

async function main() {
  for (const code of popup.LANGUAGES) {
    byId(`lang-${code}`).addEventListener("click", () => {
      void saveLanguage(code);
    });
  }

  // First paint: last time's language, modes and status (or the loading text), with no round trip.
  lang = popup.parseCachedLanguage(cacheGet(popup.LANGUAGE_CACHE_KEY)) ?? "ko";
  const cachedStatus = popup.parseCachedStatus(cacheGet(popup.STATUS_CACHE_KEY));
  if (cachedStatus !== null) {
    statusShown.status = cachedStatus;
    statusShown.stale = true;
  }
  const cachedModes = popup.parseCachedModes(cacheGet(popup.MODES_CACHE_KEY));
  if (cachedModes !== null) {
    for (const kind of KINDS) {
      shown[kind] = cachedModes[kind];
    }
  }
  applyLanguage();

  // Live state, filled in as it arrives.
  requestStatus();
  const { modes, language, failed } = await loadStored();
  if (!languageTouched && language !== lang) {
    lang = language;
    applyLanguage();
  }
  for (const kind of KINDS) {
    if (!touched.has(kind) && shown[kind] !== modes[kind]) {
      shown[kind] = modes[kind];
      renderGroup(kind, modes[kind]);
    }
  }
  if (failed) {
    showSaved("evm", "loadFailed");
  } else {
    rememberModes();
    if (!languageTouched) {
      cacheSet(popup.LANGUAGE_CACHE_KEY, lang);
    }
  }
}

void main();
