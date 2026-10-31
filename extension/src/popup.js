import "./shared.js";
import "./popup-core.js";

// spec/05 §2.12 action popup: yw-app status (as last observed by the background) and the
// compatibility mode selector. Text is set with textContent only.
const shared = globalThis.__YOUR_WALLET_SHARED__;
const popup = globalThis.__YOUR_WALLET_POPUP_CORE__;

const byId = (id) => document.getElementById(id);

function setText(id, text) {
  byId(id).textContent = text;
}

function renderStatus(status) {
  const view = popup.statusView(status);
  const value = byId("status-value");
  value.textContent = view.text;
  value.dataset.tone = view.tone;
  setText("status-detail", view.detail);
}

function requestStatus() {
  let answered = false;
  let port = null;
  const finish = (status) => {
    if (answered) {
      return;
    }
    answered = true;
    clearTimeout(timer);
    renderStatus(status);
    if (port !== null) {
      try {
        port.disconnect();
      } catch (_error) {
        // Already closed.
      }
    }
  };
  const timer = setTimeout(() => finish("unknown"), popup.STATUS_TIMEOUT_MS);
  try {
    port = chrome.runtime.connect({ name: shared.POPUP_PORT_NAME });
    port.onMessage.addListener((message) => finish(popup.parseStatusMessage(message) ?? "unknown"));
    port.onDisconnect.addListener(() => {
      void chrome.runtime.lastError;
      finish("unknown");
    });
  } catch (_error) {
    finish("unknown");
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

// Per group: where its "saved" line goes and which look-alike warning it has. The warning
// matters only while that group's look-alike mode is on, so it is hidden for "off".
const GROUP_IDS = Object.freeze({
  evm: Object.freeze({ saved: "mode-saved", warning: "warning" }),
  sol: Object.freeze({ saved: "sol-saved", warning: "sol-warning" }),
  btc: Object.freeze({ saved: "btc-saved", warning: "btc-warning" })
});

function showWarning(kind, mode) {
  byId(GROUP_IDS[kind].warning).hidden = !popup.warningShown(mode);
}

async function saveMode(mode, kind = "evm") {
  const update = popup.storageUpdateFor(kind, mode);
  if (update === null) {
    return;
  }
  showWarning(kind, mode);
  try {
    await chrome.storage.local.set(update);
    setText(GROUP_IDS[kind].saved, popup.TEXT.saved);
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
      mode: shared.normalizeCompatMode(stored?.[shared.COMPAT_MODE_STORAGE_KEY]),
      sol: shared.normalizeSolCompatMode(stored?.[shared.SOL_COMPAT_MODE_STORAGE_KEY]),
      btc: shared.normalizeBtcCompatMode(stored?.[shared.BTC_COMPAT_MODE_STORAGE_KEY]),
      failed: false
    };
  } catch (_error) {
    return { mode: "off", sol: "off", btc: "off", failed: true };
  }
}

async function main() {
  setText("title", popup.TEXT.title);
  setText("status-heading", popup.TEXT.statusHeading);
  setText("mode-heading", popup.TEXT.modeHeading);
  setText("apply-note", popup.TEXT.applyNote);
  setText("warning", popup.TEXT.warning);
  setText("sol-heading", popup.TEXT.solHeading);
  setText("btc-heading", popup.TEXT.btcHeading);
  setText("sol-warning", popup.TEXT.solWarning);
  setText("btc-warning", popup.TEXT.btcWarning);
  setText("chain-note", popup.TEXT.chainNote);
  setText("status-value", popup.TEXT.statusLoading);
  requestStatus();
  const { mode, sol, btc, failed } = await loadModes();
  renderModes(mode);
  renderModes(sol, "sol", "sol-modes");
  renderModes(btc, "btc", "btc-modes");
  showWarning("evm", mode);
  showWarning("sol", sol);
  showWarning("btc", btc);
  if (failed) {
    setText("mode-saved", popup.TEXT.loadFailed);
  }
}

void main();
