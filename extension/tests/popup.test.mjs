// spec/05 §10.1 PO1–PO3: the compatibility-mode action popup (pure text/parsing, page structure,
// and popup.js wired to a fake DOM and fake chrome APIs).
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import "../src/shared.js";
import "../src/popup-core.js";

const shared = globalThis.__YOUR_WALLET_SHARED__;
const popup = globalThis.__YOUR_WALLET_POPUP_CORE__;
const POPUP_HTML = await readFile(new URL("../popup/popup.html", import.meta.url), "utf8");
const POPUP_JS = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");
const POPUP_CSS = await readFile(new URL("../popup/popup.css", import.meta.url), "utf8");

const settle = async (turns = 4) => {
  for (let turn = 0; turn < turns; turn += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

test("PO1 popup text: the three mode labels, the warning and the next-load note", () => {
  assert.deepEqual(popup.MODE_OPTIONS.map((option) => [option.value, option.label]), [
    ["off", "기본 (Your Wallet)"],
    ["metamask", "MetaMask처럼 보이기"],
    ["rabby", "Rabby처럼 보이기"]
  ]);
  assert.deepEqual(popup.MODE_OPTIONS.map((option) => option.value), [...shared.COMPAT_MODES]);
  for (const option of popup.MODE_OPTIONS) {
    // One line each.
    assert.equal(typeof option.explanation, "string");
    assert.ok(option.explanation.length > 10 && option.explanation.length < 120, option.value);
    assert.doesNotMatch(option.explanation, /\n/u);
  }
  assert.equal(popup.TEXT.warning, "실제 MetaMask/Rabby가 켜져 있으면 가로채기가 완벽하지 않을 수 있습니다. 함께 쓰지 않을 때 가장 확실합니다.");
  assert.match(popup.TEXT.applyNote, /다음 페이지 로드부터 적용/u);
  assert.match(popup.TEXT.saved, /다음 페이지 로드부터 적용/u);
  assert.equal(popup.modeOption("rabby").label, "Rabby처럼 보이기");
  assert.equal(popup.modeOption("garbage").value, "off");
  assert.equal(popup.modeOption(undefined).value, "off");
});

test("PO1 popup status: observed states map to Korean text; anything else is 확인 불가", () => {
  assert.deepEqual(Object.fromEntries(Object.entries(popup.STATUS_VIEWS).map(([key, view]) => [key, view.text])), {
    connected: "연결됨",
    checking: "확인 중",
    unavailable: "연결 안 됨",
    unknown: "확인 불가"
  });
  assert.equal(popup.statusView("connected").tone, "ok");
  assert.equal(popup.statusView("unavailable").tone, "bad");
  for (const value of ["bogus", undefined, null, "toString", "__proto__"]) {
    assert.equal(popup.statusView(value).text, "확인 불가", String(value));
  }
  const message = { namespace: "your-wallet", version: 1, kind: "status", native: "connected" };
  assert.equal(popup.parseStatusMessage(message), "connected");
  for (const bad of [
    { ...message, extra: 1 },
    { ...message, native: "bogus" },
    { ...message, native: "toString" },
    { ...message, kind: "response" },
    { ...message, version: 2 },
    { namespace: "your-wallet", version: 1, kind: "status" },
    "connected",
    null
  ]) {
    assert.equal(popup.parseStatusMessage(bad), null, JSON.stringify(bad));
  }
  assert.deepEqual(popup.storageUpdate("metamask"), { compatMode: "metamask" });
  assert.deepEqual(popup.storageUpdate("off"), { compatMode: "off" });
  assert.equal(popup.storageUpdate("MetaMask"), null);
  assert.equal(popup.storageUpdate(undefined), null);
});

test("PO2 popup page: local module script only, no inline code, every id popup.js uses exists", () => {
  assert.match(POPUP_HTML, /<html lang="ko">/u);
  assert.deepEqual([...POPUP_HTML.matchAll(/<script\b[^>]*>/gu)].map((match) => match[0]), ['<script type="module" src="../src/popup.js">']);
  assert.match(POPUP_HTML, /<script type="module" src="\.\.\/src\/popup\.js"><\/script>/u);
  assert.doesNotMatch(POPUP_HTML, /\son[a-z]+=|style=|<style|https?:|javascript:/iu);
  assert.doesNotMatch(POPUP_CSS, /url\(|@import|https?:/iu);
  const ids = new Set([...POPUP_HTML.matchAll(/\sid="([a-z-]+)"/gu)].map((match) => match[1]));
  const used = new Set([...POPUP_JS.matchAll(/(?:byId|setText)\("([a-z-]+)"/gu)].map((match) => match[1]));
  assert.ok(used.size >= 9);
  for (const id of used) {
    assert.ok(ids.has(id), id);
  }
  assert.doesNotMatch(POPUP_JS, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/u);
});

class FakeElement {
  constructor(tagName, id = null) {
    this.tagName = tagName;
    this.id = id;
    this.textContent = "";
    this.className = "";
    this.dataset = {};
    this.children = [];
    this.listeners = new Map();
  }

  replaceChildren(...children) {
    this.children = children;
  }

  append(...children) {
    this.children.push(...children);
  }

  addEventListener(type, listener) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }
}

test("PO3 popup.js: shows the stored mode, saves a new one to chrome.storage.local and renders status", async () => {
  const elements = new Map([...POPUP_HTML.matchAll(/\sid="([a-z-]+)"/gu)].map((match) => [match[1], new FakeElement("x", match[1])]));
  const writes = [];
  const ports = [];
  globalThis.document = {
    getElementById: (id) => elements.get(id) ?? null,
    createElement: (tagName) => new FakeElement(tagName)
  };
  globalThis.chrome = {
    runtime: {
      lastError: undefined,
      connect({ name }) {
        const port = { name, messageListeners: [], disconnected: false };
        ports.push(port);
        return {
          onMessage: { addListener: (listener) => port.messageListeners.push(listener) },
          onDisconnect: { addListener() {} },
          disconnect: () => {
            port.disconnected = true;
          }
        };
      }
    },
    storage: {
      local: {
        async get(key) {
          assert.equal(key, "compatMode");
          return { compatMode: "rabby" };
        },
        async set(values) {
          writes.push(values);
        }
      }
    }
  };
  try {
    await import("../src/popup.js");
    await settle();
    const text = (id) => elements.get(id).textContent;
    assert.equal(text("warning"), popup.TEXT.warning);
    assert.equal(text("apply-note"), popup.TEXT.applyNote);
    assert.equal(text("status-heading"), "yw-app 연결 상태");

    // The stored mode is preselected.
    const labels = elements.get("modes").children;
    assert.deepEqual(labels.map((label) => label.children[1].textContent), ["기본 (Your Wallet)", "MetaMask처럼 보이기", "Rabby처럼 보이기"]);
    const inputs = labels.map((label) => label.children[0]);
    assert.deepEqual(inputs.map((input) => [input.type, input.name, input.value, input.checked]), [
      ["radio", "compat-mode", "off", false],
      ["radio", "compat-mode", "metamask", false],
      ["radio", "compat-mode", "rabby", true]
    ]);
    assert.equal(text("mode-explanation"), popup.modeOption("rabby").explanation);

    // Choosing MetaMask writes exactly { compatMode: "metamask" }.
    inputs[1].checked = true;
    for (const listener of inputs[1].listeners.get("change")) {
      listener();
    }
    await settle();
    assert.deepEqual(writes, [{ compatMode: "metamask" }]);
    assert.equal(text("mode-saved"), popup.TEXT.saved);
    assert.equal(text("mode-explanation"), popup.modeOption("metamask").explanation);

    // Status over the popup port.
    assert.equal(ports.length, 1);
    assert.equal(ports[0].name, "your-wallet-popup-v1");
    assert.equal(text("status-value"), popup.TEXT.statusLoading);
    for (const listener of ports[0].messageListeners) {
      listener({ namespace: "your-wallet", version: 1, kind: "status", native: "connected" });
    }
    assert.equal(text("status-value"), "연결됨");
    assert.equal(elements.get("status-value").dataset.tone, "ok");
    assert.equal(ports[0].disconnected, true);
  } finally {
    delete globalThis.document;
    delete globalThis.chrome;
  }
});
