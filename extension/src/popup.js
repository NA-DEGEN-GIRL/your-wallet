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

function renderModes(selected) {
  const group = byId("modes");
  group.replaceChildren();
  for (const option of popup.MODE_OPTIONS) {
    const label = document.createElement("label");
    label.className = "mode";
    const input = document.createElement("input");
    input.type = "radio";
    input.name = "compat-mode";
    input.value = option.value;
    input.checked = option.value === selected;
    input.addEventListener("change", () => {
      if (input.checked) {
        void saveMode(option.value);
      }
    });
    const text = document.createElement("span");
    text.textContent = option.label;
    label.append(input, text);
    group.append(label);
  }
  setText("mode-explanation", popup.modeOption(selected).explanation);
}

async function saveMode(mode) {
  const update = popup.storageUpdate(mode);
  setText("mode-explanation", popup.modeOption(mode).explanation);
  if (update === null) {
    return;
  }
  try {
    await chrome.storage.local.set(update);
    setText("mode-saved", popup.TEXT.saved);
  } catch (_error) {
    setText("mode-saved", popup.TEXT.saveFailed);
  }
}

async function loadMode() {
  try {
    const stored = await chrome.storage.local.get(shared.COMPAT_MODE_STORAGE_KEY);
    return { mode: shared.normalizeCompatMode(stored?.[shared.COMPAT_MODE_STORAGE_KEY]), failed: false };
  } catch (_error) {
    return { mode: "off", failed: true };
  }
}

async function main() {
  setText("title", popup.TEXT.title);
  setText("status-heading", popup.TEXT.statusHeading);
  setText("mode-heading", popup.TEXT.modeHeading);
  setText("apply-note", popup.TEXT.applyNote);
  setText("warning", popup.TEXT.warning);
  setText("status-value", popup.TEXT.statusLoading);
  requestStatus();
  const { mode, failed } = await loadMode();
  renderModes(mode);
  if (failed) {
    setText("mode-saved", popup.TEXT.loadFailed);
  }
}

void main();
