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
  assert.deepEqual(popup.MODE_OPTIONS.ko.map((option) => [option.value, option.label]), [
    ["off", "기본 (Your Wallet EVM)"],
    ["metamask", "MetaMask처럼 보이기"],
    ["rabby", "Rabby처럼 보이기"]
  ]);
  assert.deepEqual(popup.MODE_OPTIONS.ko.map((option) => option.value), [...shared.COMPAT_MODES]);
  for (const option of popup.MODE_OPTIONS.ko) {
    // One short sentence each (shown on the mode card).
    assert.equal(typeof option.explanation, "string");
    assert.ok(option.explanation.length > 10 && option.explanation.length < 80, option.value);
    assert.doesNotMatch(option.explanation, /\n/u);
  }
  assert.equal(popup.modeOption("off").explanation, "dApp에 Your Wallet (EVM) 이름으로 보이며, 다른 지갑 확장은 건드리지 않습니다.");
  assert.equal(popup.modeOption("metamask").explanation, "MetaMask만 지원하는 dApp에서 쓰며, 승인 창은 그대로 Your Wallet 앱에 뜹니다.");
  assert.equal(popup.modeOption("rabby").explanation, "Rabby만 지원하는 dApp에서 쓰며, 승인 창은 그대로 Your Wallet 앱에 뜹니다.");
  assert.equal(popup.TEXT.ko.warning, "호환 모드를 쓸 때는 실제 MetaMask·Rabby 확장을 꺼 두세요. 켜져 있으면 dApp이 그 지갑에 연결될 수 있습니다.");
  assert.equal(popup.TEXT.ko.applyNote, "모드 변경은 다음 페이지 로드부터 적용됩니다(열린 dApp 탭은 새로고침).");
  assert.match(popup.TEXT.ko.saved, /다음 페이지 로드부터 적용/u);
  // spec/05 §2.13 (2026-11-12): Solana dApp transactions are supported, Bitcoin stays message-only.
  assert.equal(popup.TEXT.ko.chainNote, "Bitcoin은 연결과 메시지 서명만 됩니다. Solana는 거래 서명·전송도 됩니다.");
  assert.equal(popup.TEXT.ko.statusHeading, "Your Wallet 앱 연결 상태");
  // Plain words: no internal binary names in user-facing text (either language).
  for (const lang of popup.LANGUAGES) {
    for (const text of [...Object.values(popup.TEXT[lang]), ...Object.values(popup.STATUS_VIEWS[lang]).map((view) => view.detail)]) {
      assert.doesNotMatch(text, /yw-app/u, text);
    }
  }
  assert.equal(popup.modeOption("rabby").label, "Rabby처럼 보이기");
  assert.equal(popup.modeOption("garbage").value, "off");
  assert.equal(popup.modeOption(undefined).value, "off");
});

test("PO1 popup status: observed states map to Korean text; anything else is 확인 불가", () => {
  assert.deepEqual(Object.fromEntries(Object.entries(popup.STATUS_VIEWS.ko).map(([key, view]) => [key, view.text])), {
    connected: "연결됨",
    checking: "확인 중",
    unavailable: "연결 안 됨",
    unknown: "확인 불가"
  });
  assert.deepEqual(Object.fromEntries(Object.entries(popup.STATUS_VIEWS.ko).map(([key, view]) => [key, view.tone])), {
    connected: "ok",
    checking: "neutral",
    unavailable: "bad",
    unknown: "neutral"
  });
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
  // shared.js and popup-core.js are listed too so all three load in parallel (2026-11-11); popup.js
  // still imports them (one module instance each).
  assert.deepEqual([...POPUP_HTML.matchAll(/<script\b[^>]*>/gu)].map((match) => match[0]), [
    '<script type="module" src="../src/shared.js">',
    '<script type="module" src="../src/popup-core.js">',
    '<script type="module" src="../src/popup.js">'
  ]);
  assert.match(POPUP_HTML, /<script type="module" src="\.\.\/src\/popup\.js"><\/script>/u);
  assert.doesNotMatch(POPUP_HTML, /\son[a-z]+=|style=|<style|https?:|javascript:/iu);
  assert.doesNotMatch(POPUP_CSS, /url\(|@import|https?:/iu);
  const ids = new Set([...POPUP_HTML.matchAll(/\sid="([a-z-]+)"/gu)].map((match) => match[1]));
  const used = new Set([...POPUP_JS.matchAll(/(?:byId|setText)\("([a-z-]+)"/gu)].map((match) => match[1]));
  assert.ok(used.size >= 9);
  for (const id of [...used, "lang-ko", "lang-en"]) {
    assert.ok(ids.has(id), id);
  }
  // 2026-11-14: the header's 한국어 | English toggle, the same words in both languages.
  assert.match(POPUP_HTML, /<div class="lang-toggle" role="group" aria-label="언어 · Language">/u);
  assert.match(POPUP_HTML, /<button type="button" id="lang-ko" class="lang-option" lang="ko" aria-pressed="true">한국어<\/button>/u);
  assert.match(POPUP_HTML, /<button type="button" id="lang-en" class="lang-option" lang="en" aria-pressed="false">English<\/button>/u);
  assert.doesNotMatch(POPUP_JS, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/u);
});

test("PO2 popup style: light-only desktop-app tokens, local fonts, status/warning colors", () => {
  // Light theme only, like the desktop app (spec/04): no dark variant.
  assert.match(POPUP_CSS, /color-scheme:\s*light;/u);
  assert.doesNotMatch(POPUP_CSS, /prefers-color-scheme|@font-face/u);
  assert.match(POPUP_CSS, /font-family:\s*"Malgun Gothic", "Segoe UI", system-ui/u);
  for (const token of [
    "--page-bg: #F3F4F6", "--card-bg: #FFFFFF", "--card-border: #E1E4E8", "--radius: 8px", "--text: #1F1F1F",
    "--muted: #5F6368", "--primary: #0F6CBD", "--info-bg: #E8F1FB", "--info-text: #0F4C81", "--caution-bg: #FFF4CE",
    "--caution-text: #7A5C00", "--danger-bg: #FDE7E9", "--danger-text: #A4262C", "--success-bg: #DFF6DD", "--success-text: #0E700E"
  ]) {
    assert.ok(POPUP_CSS.includes(`${token};`), token);
  }
  // ok → 성공, bad → 고위험, the warning → 주의.
  assert.match(POPUP_CSS, /\.status-pill\[data-tone="ok"\] \{\s*background: var\(--success-bg\);\s*color: var\(--success-text\);/u);
  assert.match(POPUP_CSS, /\.status-pill\[data-tone="bad"\] \{\s*background: var\(--danger-bg\);\s*color: var\(--danger-text\);/u);
  assert.match(POPUP_CSS, /\.notice-warning \{[^}]*background: var\(--caution-bg\);\s*color: var\(--caution-text\);/u);
  assert.match(POPUP_HTML, /<p id="warning" class="notice-warning">/u);
  assert.match(POPUP_HTML, /<p id="status-value" class="status-pill" data-tone="neutral">/u);
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
    this.attributes = new Map();
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
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
    documentElement: { lang: "ko" },
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
        async get(keys) {
          assert.equal(JSON.stringify(keys), JSON.stringify(["compatMode", "solCompatMode", "btcCompatMode", "yourWalletLanguage"]));
          return { compatMode: "rabby", solCompatMode: "phantom", btcCompatMode: "garbage" };
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
    assert.equal(text("warning"), popup.TEXT.ko.warning);
    assert.equal(text("apply-note"), popup.TEXT.ko.applyNote);
    assert.equal(text("status-heading"), "Your Wallet 앱 연결 상태");

    // One card per mode (label > radio + [name, one-line explanation]); the stored mode is preselected.
    const cards = elements.get("modes").children;
    assert.deepEqual(cards.map((card) => [card.tagName, card.className]), [["label", "mode"], ["label", "mode"], ["label", "mode"]]);
    assert.deepEqual(cards.map((card) => card.children[1].children.map((part) => [part.className, part.textContent])), popup.MODE_OPTIONS.ko.map((option) => [
      ["mode-label", option.label],
      ["mode-explanation", option.explanation]
    ]));
    assert.deepEqual(cards.map((card) => card.children[1].children[0].textContent), ["기본 (Your Wallet EVM)", "MetaMask처럼 보이기", "Rabby처럼 보이기"]);
    const inputs = cards.map((card) => card.children[0]);
    assert.deepEqual(inputs.map((input) => [input.type, input.name, input.value, input.checked]), [
      ["radio", "compat-mode", "off", false],
      ["radio", "compat-mode", "metamask", false],
      ["radio", "compat-mode", "rabby", true]
    ]);

    // Choosing MetaMask writes exactly { compatMode: "metamask" }.
    inputs[1].checked = true;
    for (const listener of inputs[1].listeners.get("change")) {
      listener();
    }
    await settle();
    assert.deepEqual(writes, [{ compatMode: "metamask" }]);
    assert.equal(text("mode-saved"), popup.TEXT.ko.saved);

    // spec/05 §2.13: Solana and Bitcoin groups with their own keys; bad stored values show off.
    assert.equal(text("sol-warning"), popup.TEXT.ko.solWarning);
    assert.equal(text("chain-note"), popup.TEXT.ko.chainNote);
    // A group's "turn off the real wallet" warning shows only while its look-alike mode is on.
    assert.equal(elements.get("warning").hidden, false);
    assert.equal(elements.get("sol-warning").hidden, false);
    assert.equal(elements.get("btc-warning").hidden, true);
    assert.equal(popup.warningShown("off"), false);
    assert.equal(popup.warningShown("unisat"), true);
    const solInputs = elements.get("sol-modes").children.map((card) => card.children[0]);
    assert.deepEqual(solInputs.map((input) => [input.name, input.value, input.checked]), [
      ["sol-compat-mode", "off", false],
      ["sol-compat-mode", "phantom", true]
    ]);
    const btcInputs = elements.get("btc-modes").children.map((card) => card.children[0]);
    assert.deepEqual(btcInputs.map((input) => [input.name, input.value, input.checked]), [
      ["btc-compat-mode", "off", true],
      ["btc-compat-mode", "unisat", false],
      ["btc-compat-mode", "xverse", false]
    ]);
    btcInputs[2].checked = true;
    for (const listener of btcInputs[2].listeners.get("change")) {
      listener();
    }
    await settle();
    assert.deepEqual(writes, [{ compatMode: "metamask" }, { btcCompatMode: "xverse" }]);
    assert.equal(elements.get("btc-warning").hidden, false);
    assert.equal(text("btc-saved"), popup.TEXT.ko.saved);
    assert.equal(text("sol-saved"), "");
    assert.equal(popup.storageUpdateFor("sol", "unisat"), null);
    assert.deepEqual(popup.storageUpdateFor("sol", "phantom"), { solCompatMode: "phantom" });

    // Status over the popup port.
    assert.equal(ports.length, 1);
    assert.equal(ports[0].name, "your-wallet-popup-v1");
    assert.equal(text("status-value"), popup.TEXT.ko.statusLoading);
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

test("PO4 popup.js renders at once from the last known modes and status, then refreshes live", async () => {
  // The cached values are validated: wrong keys, unknown modes or statuses are ignored.
  assert.deepEqual(popup.parseCachedModes('{"evm":"metamask","sol":"off","btc":"unisat"}'), { evm: "metamask", sol: "off", btc: "unisat" });
  for (const bad of [null, "", "{bad", '{"evm":"metamask","sol":"off"}', '{"evm":"MetaMask","sol":"off","btc":"off"}',
    '{"evm":"off","sol":"unisat","btc":"off"}', '{"evm":"off","sol":"off","btc":"off","x":1}', '["off","off","off"]']) {
    assert.equal(popup.parseCachedModes(bad), null, String(bad));
  }
  assert.equal(popup.parseCachedStatus("connected"), "connected");
  for (const bad of [null, "bogus", "toString", "__proto__"]) {
    assert.equal(popup.parseCachedStatus(bad), null, String(bad));
  }
  assert.ok(popup.TEXT.ko.metamaskConnectNote.includes("기본이나 Rabby처럼 보이기"));
  assert.equal(popup.metamaskNoteShown("metamask"), true);
  assert.equal(popup.metamaskNoteShown("rabby"), false);

  const elements = new Map([...POPUP_HTML.matchAll(/\sid="([a-z-]+)"/gu)].map((match) => [match[1], new FakeElement("x", match[1])]));
  const store = new Map([
    [popup.MODES_CACHE_KEY, JSON.stringify({ evm: "metamask", sol: "off", btc: "unisat" })],
    [popup.STATUS_CACHE_KEY, "connected"]
  ]);
  const writes = [];
  const ports = [];
  let resolveStorage = null;
  globalThis.document = {
    documentElement: { lang: "ko" },
    getElementById: (id) => elements.get(id) ?? null,
    createElement: (tagName) => new FakeElement(tagName)
  };
  globalThis.localStorage = {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => store.set(key, String(value))
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
        // The storage read and the background stay unanswered until the test says so.
        get: () => new Promise((resolve) => {
          resolveStorage = resolve;
        }),
        async set(values) {
          writes.push(values);
        }
      }
    }
  };
  const text = (id) => elements.get(id).textContent;
  const checked = (id) => elements.get(id).children.map((card) => card.children[0]).find((input) => input.checked)?.value;
  try {
    // A fresh module instance (PO3 already ran popup.js once in this process).
    await import("../src/popup.js?po4");
    // First paint, before any answer: last time's modes, warnings and status.
    assert.equal(typeof resolveStorage, "function");
    assert.equal(ports.length, 1);
    assert.deepEqual(["modes", "sol-modes", "btc-modes"].map(checked), ["metamask", "off", "unisat"]);
    assert.equal(elements.get("warning").hidden, false);
    assert.equal(elements.get("metamask-note").hidden, false);
    assert.equal(text("metamask-note"), popup.TEXT.ko.metamaskConnectNote);
    assert.equal(elements.get("sol-warning").hidden, true);
    assert.equal(elements.get("btc-warning").hidden, false);
    assert.equal(text("status-value"), "연결됨");
    assert.equal(elements.get("status-value").dataset.tone, "ok");
    assert.equal(text("status-detail"), popup.TEXT.ko.statusStale);

    // The user picks Phantom before the storage read answers; the read must not undo it.
    const solInputs = elements.get("sol-modes").children.map((card) => card.children[0]);
    // A radio group: checking one unchecks the others.
    solInputs[0].checked = false;
    solInputs[1].checked = true;
    for (const listener of solInputs[1].listeners.get("change")) {
      listener();
    }
    resolveStorage({ compatMode: "rabby", solCompatMode: "off", btcCompatMode: "unisat" });
    await settle();
    assert.deepEqual(writes, [{ solCompatMode: "phantom" }]);
    assert.deepEqual(["modes", "sol-modes", "btc-modes"].map(checked), ["rabby", "phantom", "unisat"]);
    assert.equal(elements.get("metamask-note").hidden, true);
    assert.equal(elements.get("sol-warning").hidden, false);
    assert.deepEqual(JSON.parse(store.get(popup.MODES_CACHE_KEY)), { evm: "rabby", sol: "phantom", btc: "unisat" });

    // The live status replaces last time's and is remembered for the next popup.
    for (const listener of ports[0].messageListeners) {
      listener({ namespace: "your-wallet", version: 1, kind: "status", native: "unavailable" });
    }
    assert.equal(text("status-value"), "연결 안 됨");
    assert.equal(text("status-detail"), popup.STATUS_VIEWS.ko.unavailable.detail);
    assert.equal(store.get(popup.STATUS_CACHE_KEY), "unavailable");
    assert.equal(ports[0].disconnected, true);
  } finally {
    delete globalThis.document;
    delete globalThis.chrome;
    delete globalThis.localStorage;
  }
});

// spec/14 §4 (the app's catalogue rule, applied to the popup): English text has no Hangul.
const HANGUL = /[ᄀ-ᇿ㄰-㆏가-힯]/u;

test("PO5 popup languages: every text, mode and status exists in Korean and English; English has no Hangul", () => {
  assert.deepEqual([...popup.LANGUAGES], ["ko", "en"]);
  assert.deepEqual(Object.keys(popup.TEXT), ["ko", "en"]);
  assert.deepEqual(Object.keys(popup.TEXT.en), Object.keys(popup.TEXT.ko));
  assert.deepEqual(Object.keys(popup.TEXT.ko), [
    "title", "statusHeading", "statusLoading", "statusStale", "metamaskConnectNote", "modeHeading", "warning", "applyNote",
    "saved", "saveFailed", "loadFailed", "solHeading", "btcHeading", "solWarning", "btcWarning", "chainNote"
  ]);
  for (const lang of popup.LANGUAGES) {
    for (const [key, text] of Object.entries(popup.TEXT[lang])) {
      assert.equal(typeof text, "string", `${lang}.${key}`);
      assert.ok(text.trim().length > 0, `${lang}.${key}`);
      assert.doesNotMatch(text, /\n/u, `${lang}.${key}`);
    }
    assert.deepEqual(Object.keys(popup.STATUS_VIEWS[lang]), [...popup.STATUS_WORDS]);
    for (const [word, view] of Object.entries(popup.STATUS_VIEWS[lang])) {
      assert.deepEqual(Object.keys(view), ["text", "tone", "detail"], `${lang}.${word}`);
      assert.ok(view.text.length > 0 && view.detail.length > 0, `${lang}.${word}`);
      assert.equal(view.tone, popup.STATUS_VIEWS.ko[word].tone);
    }
    for (const kind of Object.keys(popup.GROUPS)) {
      const options = popup.groupOptions(kind, lang);
      assert.deepEqual(options.map((option) => option.value), popup.groupOptions(kind, "ko").map((option) => option.value), `${lang}.${kind}`);
      for (const option of options) {
        assert.deepEqual(Object.keys(option), ["value", "label", "explanation"]);
        assert.ok(option.label.length > 0 && option.explanation.length > 10 && option.explanation.length < 80, `${lang}.${kind}.${option.value}`);
      }
    }
  }
  assert.equal(popup.GROUPS.sol.options.en, popup.SOL_MODE_OPTIONS.en);
  assert.equal(popup.GROUPS.btc.options.ko, popup.BTC_MODE_OPTIONS.ko);
  const english = [
    ...Object.values(popup.TEXT.en),
    ...Object.values(popup.STATUS_VIEWS.en).flatMap((view) => [view.text, view.detail]),
    ...[popup.MODE_OPTIONS.en, popup.SOL_MODE_OPTIONS.en, popup.BTC_MODE_OPTIONS.en].flat().flatMap((option) => [option.label, option.explanation])
  ];
  for (const text of english) {
    assert.doesNotMatch(text, HANGUL, text);
  }
  // Korean really is Korean (the tables were not swapped).
  assert.match(popup.TEXT.ko.statusHeading, HANGUL);
  assert.equal(popup.TEXT.en.statusHeading, "Your Wallet app connection");
  assert.equal(popup.TEXT.en.chainNote, "Bitcoin supports connecting and message signing only. Solana also signs and sends transactions.");
  assert.deepEqual(popup.MODE_OPTIONS.en.map((option) => option.label), ["Default (Your Wallet EVM)", "Look like MetaMask", "Look like Rabby"]);
  assert.deepEqual(Object.values(popup.STATUS_VIEWS.en).map((view) => view.text), ["Connected", "Checking", "Not connected", "Unknown"]);

  // Lookups: anything but "en" is Korean.
  assert.equal(popup.texts("en"), popup.TEXT.en);
  for (const value of ["ko", "EN", "", undefined, null, "fr"]) {
    assert.equal(popup.texts(value), popup.TEXT.ko, String(value));
  }
  assert.equal(popup.statusView("connected", "en").text, "Connected");
  assert.equal(popup.statusView("bogus", "en").text, "Unknown");
  assert.equal(popup.modeOption("rabby", "en").label, "Look like Rabby");
  assert.equal(popup.modeOption("rabby").label, "Rabby처럼 보이기");

  // What the toggle writes, and the render cache's language.
  assert.deepEqual(popup.languageUpdate("en"), { yourWalletLanguage: "en" });
  assert.deepEqual(popup.languageUpdate("ko"), { yourWalletLanguage: "ko" });
  for (const bad of ["EN", "en-US", "", null, undefined, 1]) {
    assert.equal(popup.languageUpdate(bad), null, String(bad));
  }
  assert.equal(popup.LANGUAGE_CACHE_KEY, "yourWalletPopupLanguageV1");
  assert.equal(popup.parseCachedLanguage("en"), "en");
  assert.equal(popup.parseCachedLanguage("ko"), "ko");
  for (const bad of [null, "", "EN", "english", "toString"]) {
    assert.equal(popup.parseCachedLanguage(bad), null, String(bad));
  }
});

test("PO6 popup.js language: first paint from the cached language, stored language wins, the toggle switches at once and is saved", async () => {
  const elements = new Map([...POPUP_HTML.matchAll(/\sid="([a-z-]+)"/gu)].map((match) => [match[1], new FakeElement("x", match[1])]));
  const store = new Map([
    [popup.LANGUAGE_CACHE_KEY, "en"],
    [popup.MODES_CACHE_KEY, JSON.stringify({ evm: "off", sol: "phantom", btc: "off" })],
    [popup.STATUS_CACHE_KEY, "connected"]
  ]);
  const writes = [];
  const ports = [];
  let resolveStorage = null;
  const root = { lang: "ko" };
  globalThis.document = {
    documentElement: root,
    getElementById: (id) => elements.get(id) ?? null,
    createElement: (tagName) => new FakeElement(tagName)
  };
  globalThis.localStorage = {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => store.set(key, String(value))
  };
  globalThis.chrome = {
    runtime: {
      lastError: undefined,
      connect({ name }) {
        const port = { name, messageListeners: [] };
        ports.push(port);
        return {
          onMessage: { addListener: (listener) => port.messageListeners.push(listener) },
          onDisconnect: { addListener() {} },
          disconnect() {}
        };
      }
    },
    storage: {
      local: {
        get: (keys) => {
          assert.deepEqual(keys, ["compatMode", "solCompatMode", "btcCompatMode", "yourWalletLanguage"]);
          return new Promise((resolve) => {
            resolveStorage = resolve;
          });
        },
        async set(values) {
          writes.push(values);
        }
      }
    }
  };
  const text = (id) => elements.get(id).textContent;
  const pressed = () => ["lang-ko", "lang-en"].map((id) => elements.get(id).attributes.get("aria-pressed"));
  const labels = (id) => elements.get(id).children.map((card) => card.children[1].children[0].textContent);
  const click = (id) => {
    for (const listener of elements.get(id).listeners.get("click")) {
      listener();
    }
  };
  try {
    await import("../src/popup.js?po6");
    // First paint in English (cached), before any answer.
    assert.equal(root.lang, "en");
    assert.deepEqual(pressed(), ["false", "true"]);
    assert.equal(text("status-heading"), popup.TEXT.en.statusHeading);
    assert.equal(text("chain-note"), popup.TEXT.en.chainNote);
    assert.equal(text("status-value"), "Connected");
    assert.equal(text("status-detail"), popup.TEXT.en.statusStale);
    assert.deepEqual(labels("sol-modes"), popup.SOL_MODE_OPTIONS.en.map((option) => option.label));
    assert.equal(text("sol-explain"), popup.SOL_MODE_OPTIONS.en[1].explanation);

    // chrome.storage.local says Korean: it is the source of truth, so the popup switches back.
    resolveStorage({ compatMode: "off", solCompatMode: "phantom", btcCompatMode: "off", yourWalletLanguage: "ko" });
    await settle();
    assert.equal(root.lang, "ko");
    assert.deepEqual(pressed(), ["true", "false"]);
    assert.equal(text("status-heading"), popup.TEXT.ko.statusHeading);
    assert.deepEqual(labels("modes"), popup.MODE_OPTIONS.ko.map((option) => option.label));
    assert.equal(store.get(popup.LANGUAGE_CACHE_KEY), "ko");
    assert.deepEqual(writes, []);

    // A saved line and the live status follow a later switch.
    const btcInputs = elements.get("btc-modes").children.map((card) => card.children[0]);
    btcInputs[1].checked = true;
    for (const listener of btcInputs[1].listeners.get("change")) {
      listener();
    }
    await settle();
    assert.equal(text("btc-saved"), popup.TEXT.ko.saved);
    for (const listener of ports[0].messageListeners) {
      listener({ namespace: "your-wallet", version: 1, kind: "status", native: "unavailable" });
    }
    assert.equal(text("status-value"), "연결 안 됨");

    // The toggle: English at once, written to chrome.storage.local and the render cache.
    click("lang-en");
    assert.equal(root.lang, "en");
    assert.deepEqual(pressed(), ["false", "true"]);
    assert.equal(text("warning"), popup.TEXT.en.warning);
    assert.equal(text("btc-warning"), popup.TEXT.en.btcWarning);
    assert.equal(text("btc-saved"), popup.TEXT.en.saved);
    assert.equal(text("status-value"), "Not connected");
    assert.equal(text("status-detail"), popup.STATUS_VIEWS.en.unavailable.detail);
    assert.deepEqual(labels("btc-modes"), popup.BTC_MODE_OPTIONS.en.map((option) => option.label));
    assert.equal(text("btc-explain"), popup.BTC_MODE_OPTIONS.en[1].explanation);
    // The radios keep their selection across the redraw.
    assert.equal(elements.get("btc-modes").children.map((card) => card.children[0]).find((input) => input.checked)?.value, "unisat");
    await settle();
    assert.deepEqual(writes, [{ btcCompatMode: "unisat" }, { yourWalletLanguage: "en" }]);
    assert.equal(store.get(popup.LANGUAGE_CACHE_KEY), "en");

    // And back to Korean.
    click("lang-ko");
    await settle();
    assert.equal(root.lang, "ko");
    assert.equal(text("warning"), popup.TEXT.ko.warning);
    assert.deepEqual(writes.at(-1), { yourWalletLanguage: "ko" });
    assert.equal(store.get(popup.LANGUAGE_CACHE_KEY), "ko");
  } finally {
    delete globalThis.document;
    delete globalThis.chrome;
    delete globalThis.localStorage;
  }
});
