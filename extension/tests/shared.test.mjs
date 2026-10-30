import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import "../src/shared.js";

const shared = globalThis.__YOUR_WALLET_SHARED__;

async function golden(name) {
  return JSON.parse(await readFile(new URL(`../native-host/${name}`, import.meta.url), "utf8"));
}

function nestedArrays(levels) {
  let value = [];
  for (let level = 1; level < levels; level += 1) {
    value = [value];
  }
  return value;
}

// spec/05 §10.3 v1-limits shapes.
function buildCase(shape, n) {
  switch (shape) {
    case "depth":
      return { v: n === 1 ? null : nestedArrays(n - 1) };
    case "array":
      return { v: new Array(n).fill(0) };
    case "object": {
      const value = {};
      for (let index = 0; index < n; index += 1) {
        value[`k${index}`] = 0;
      }
      return value;
    }
    case "bytes":
      return { v: "a".repeat(n - 8) };
    default:
      throw new Error(`unknown shape ${shape}`);
  }
}

test("S1 METHOD_ROUTE equals v1-methods.golden.json and contains no rejected method", async () => {
  const methods = await golden("v1-methods.golden.json");
  const byRoute = { permission: [], read: [], signing: [] };
  for (const [method, route] of Object.entries(shared.METHOD_ROUTE)) {
    byRoute[route].push(method);
  }
  assert.deepEqual(byRoute.permission, methods.permission);
  assert.deepEqual(byRoute.read, methods.read);
  assert.deepEqual(byRoute.signing, methods.signing);
  assert.deepEqual(
    Object.keys(shared.METHOD_ROUTE),
    [...methods.permission, ...methods.read, ...methods.signing]
  );
  assert.equal(Object.keys(shared.METHOD_ROUTE).length, 37);
  assert.equal(Object.isFrozen(shared.METHOD_ROUTE), true);
  for (const [route, list] of Object.entries({ permission: methods.permission, read: methods.read, signing: methods.signing })) {
    for (const method of list) {
      assert.equal(shared.methodRoute(method), route, method);
    }
  }
  assert.equal(methods.rejected.length, 38);
  for (const method of methods.rejected) {
    assert.equal(Object.hasOwn(shared.METHOD_ROUTE, method), false, method);
    assert.equal(shared.methodRoute(method), null, method);
  }
  for (const method of ["Eth_chainId", "eth_chainId ", "toString", "__proto__", "constructor", "", 7, null]) {
    assert.equal(shared.methodRoute(method), null, String(method));
  }
});

test("S2 checkJson matches every v1-limits.golden.json case and rejects lone surrogates", async () => {
  const limits = await golden("v1-limits.golden.json");
  assert.deepEqual({ ...shared.REQUEST_LIMITS }, limits.limits.request);
  assert.deepEqual({ ...shared.RESPONSE_LIMITS }, limits.limits.response);
  const profiles = { request: shared.REQUEST_LIMITS, response: shared.RESPONSE_LIMITS };
  assert.ok(limits.cases.length >= 14);
  for (const { profile, shape, n, ok } of limits.cases) {
    const value = buildCase(shape, n);
    if (shape === "bytes") {
      assert.equal(Buffer.byteLength(JSON.stringify(value), "utf8"), n);
    }
    assert.equal(shared.checkJson(value, profiles[profile]), ok, `${profile}/${shape}/${n}`);
  }

  for (const limitsProfile of [shared.REQUEST_LIMITS, shared.RESPONSE_LIMITS]) {
    assert.equal(shared.checkJson({ v: "ok" }, limitsProfile), true);
    assert.equal(shared.checkJson({ v: "\uD800" }, limitsProfile), false);
    assert.equal(shared.checkJson({ v: "a\uDC00b" }, limitsProfile), false);
    assert.equal(shared.checkJson({ "\uD83D": 1 }, limitsProfile), false);
    assert.equal(shared.checkJson({ v: "\uD83D\uDE00" }, limitsProfile), true);
    assert.equal(shared.checkJson({ v: Number.NaN }, limitsProfile), false);
    assert.equal(shared.checkJson({ v: Infinity }, limitsProfile), false);
    assert.equal(shared.checkJson({ v: undefined }, limitsProfile), false);
    assert.equal(shared.checkJson({ v: 1n }, limitsProfile), false);
    assert.equal(shared.checkJson({ v: new Date(0) }, limitsProfile), false);
    assert.equal(shared.checkJson(Object.assign(Object.create(null), { v: 1 }), limitsProfile), true);
  }
  // A root object alone has depth 1; a scalar root has depth 0.
  assert.equal(shared.checkJson("scalar", { maxBytes: 100, maxDepth: 0, maxNodes: 1, maxItems: 0 }), true);
  assert.equal(shared.checkJson({}, { maxBytes: 100, maxDepth: 0, maxNodes: 1, maxItems: 0 }), false);
  assert.equal(shared.checkJson({}, { maxBytes: 100, maxDepth: 1, maxNodes: 1, maxItems: 0 }), true);
  // nodes count keys: {"a":1} = root + key + value = 3 nodes, 1 item.
  assert.equal(shared.checkJson({ a: 1 }, { maxBytes: 100, maxDepth: 1, maxNodes: 3, maxItems: 1 }), true);
  assert.equal(shared.checkJson({ a: 1 }, { maxBytes: 100, maxDepth: 1, maxNodes: 2, maxItems: 1 }), false);
  assert.equal(shared.checkJson({ a: 1 }, { maxBytes: 100, maxDepth: 1, maxNodes: 3, maxItems: 0 }), false);
});

test("S3 isSupportedPageUrl follows the spec/05 §2.4 table", () => {
  for (const url of [
    "https://dapp.example/",
    "https://dapp.example:8443/path?q=1#f",
    "https://xn--80ak6aa92e.com/",
    "http://localhost:5173/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://127.0.0.1:8545/app"
  ]) {
    assert.equal(shared.isSupportedPageUrl(url), true, url);
  }
  for (const url of [
    "http://example.com/",
    "http://localhost.example.com/",
    "http://127.0.0.2/",
    "http://[::1]:5173/",
    "https://[::1]/",
    "file:///C:/index.html",
    "data:text/html,hi",
    "about:blank",
    "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
    "ftp://dapp.example/",
    "https://user:pass@dapp.example/",
    "https://user@dapp.example/",
    "not a url",
    ""
  ]) {
    assert.equal(shared.isSupportedPageUrl(url), false, url);
  }
});

test("message parsers enforce the spec/05 §2.6 exact key sets", () => {
  const channel = "d".repeat(64);
  const activation = "c".repeat(64);
  const id = "01".repeat(16);
  const base = { namespace: "your-wallet", version: 1 };
  const pageRequest = { ...base, kind: "request", channel, id, method: "eth_chainId", params: [] };
  assert.deepEqual({ ...shared.parsePageMessage(pageRequest, channel) }, { kind: "request", id, method: "eth_chainId", params: [] });
  assert.equal(shared.parsePageMessage({ ...pageRequest, extra: 1 }, channel), null);
  assert.equal(shared.parsePageMessage({ ...pageRequest, channel: "e".repeat(64) }, channel), null);
  assert.equal(shared.parsePageMessage({ ...pageRequest, id: "0".repeat(32) }, channel), null);
  assert.equal(shared.parsePageMessage({ ...pageRequest, params: "x" }, channel), null);
  assert.equal(shared.parsePageMessage({ ...pageRequest, version: 2 }, channel), null);
  assert.equal(shared.parsePageMessage({ ...base, kind: "bridge-request" }, channel)?.kind, "bridge-request");
  assert.equal(shared.parsePageMessage({ ...base, kind: "bridge-request", channel }, channel), null);
  assert.equal(shared.parsePageMessage({ ...base, kind: "cancel", channel, id }, channel)?.kind, "cancel");
  assert.equal(shared.parsePageMessage({ ...base, kind: "cancel", channel, id, reason: "x" }, channel), null);
  assert.equal(shared.parsePageMessage({ ...base, kind: "bridge-init", channel }, channel), null);

  const contentRequest = { ...base, kind: "request", activationNonce: activation, id, method: "eth_chainId", params: {} };
  assert.equal(shared.parseContentMessage(contentRequest, activation)?.kind, "request");
  assert.equal(shared.parseContentMessage({ ...contentRequest, context: {} }, activation), null);
  assert.equal(shared.parseContentMessage(contentRequest, "f".repeat(64)), null);
  assert.equal(shared.parseContentMessage({ ...base, kind: "cancel", activationNonce: activation, id, reason: "page-cancel" }, activation)?.reason, "page-cancel");
  assert.equal(shared.parseContentMessage({ ...base, kind: "cancel", activationNonce: activation, id, reason: "has space" }, activation), null);
  assert.equal(shared.parseContentMessage({ ...base, kind: "disconnect", activationNonce: activation, reason: "document-pagehide" }, activation)?.kind, "disconnect");
  assert.equal(shared.parseContentMessage({ ...base, kind: "fatal", activationNonce: activation, error: { code: 1, message: "x" } }, activation), null);

  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "activated", activationNonce: activation })?.kind, "activated");
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "response", activationNonce: activation, id, result: null })?.kind, "response");
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "response", activationNonce: activation, id, result: 1, error: { code: 1, message: "x" } }), null);
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "response", activationNonce: activation, id, error: { code: 1, message: "" } }), null);
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "response", activationNonce: activation, id, error: { code: 1.5, message: "x" } }), null);
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "response", activationNonce: activation, id, error: { code: 1, message: "x".repeat(513) } }), null);
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "response", activationNonce: activation, id, error: { code: 1, message: "x".repeat(512), data: "0x" } })?.kind, "response");
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "event", activationNonce: activation, event: "chainChanged", payload: "0x1" })?.kind, "event");
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "event", activationNonce: activation, event: "chainChanged", payload: "0x01" }), null);
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "event", activationNonce: activation, event: "connect", payload: {} }), null);
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "disconnect", activationNonce: activation, error: { code: 4900, message: "x" } }), null);
  assert.equal(shared.parseBackgroundMessage({ ...base, kind: "fatal", activationNonce: activation, error: { code: 4900, message: "x" } }), null);

  const address = `0x${"ab".repeat(20)}`;
  assert.equal(shared.validEvent("accountsChanged", []), true);
  assert.equal(shared.validEvent("accountsChanged", new Array(16).fill(address)), true);
  assert.equal(shared.validEvent("accountsChanged", new Array(17).fill(address)), false);
  assert.equal(shared.validEvent("accountsChanged", [address.toUpperCase().replace("0X", "0x")]), false);
  assert.equal(shared.validEvent("chainChanged", "0xaa36a7"), true);
  assert.equal(shared.validEvent("chainChanged", "0x0"), false);
  assert.equal(shared.validEvent("chainChanged", 1), false);
});

test("shared error strings are exactly the spec/05 §5 messages", () => {
  const expected = {
    UNSUPPORTED_METHOD: [4200, "Unsupported method."],
    UNAVAILABLE: [4900, "Wallet is unavailable."],
    CONNECTION_CLOSED: [4900, "Wallet connection closed."],
    EXTENSION_RELOADED: [4900, "Wallet extension was reloaded."],
    RATE_LIMITED: [-32005, "Rate limit exceeded."],
    TOO_MANY_PENDING: [-32005, "Too many pending requests."],
    REQUEST_TOO_LARGE: [-32600, "Request too large."],
    INTERNAL: [-32603, "Internal error."],
    TIMED_OUT: [-32603, "Request timed out."],
    RESPONSE_TOO_LARGE: [-32603, "Response too large."]
  };
  assert.deepEqual(Object.keys(shared.ERRORS).sort(), Object.keys(expected).sort());
  for (const [name, [code, message]] of Object.entries(expected)) {
    assert.deepEqual({ ...shared.ERRORS[name] }, { code, message }, name);
  }
});

test("S4 compatibility mode values, normalization and the optional content→background compatMode", () => {
  assert.deepEqual([...shared.COMPAT_MODES], ["off", "metamask", "rabby"]);
  assert.equal(shared.COMPAT_MODE_STORAGE_KEY, "compatMode");
  assert.equal(shared.POPUP_PORT_NAME, "your-wallet-popup-v1");
  for (const mode of ["off", "metamask", "rabby"]) {
    assert.equal(shared.isCompatMode(mode), true, mode);
    assert.equal(shared.normalizeCompatMode(mode), mode, mode);
  }
  for (const value of ["MetaMask", "RABBY", "on", "", " metamask", null, undefined, 1, {}, ["metamask"]]) {
    assert.equal(shared.isCompatMode(value), false, String(value));
    assert.equal(shared.normalizeCompatMode(value), "off", String(value));
  }
  const activation = "c".repeat(64);
  const request = { namespace: "your-wallet", version: 1, kind: "request", activationNonce: activation, id: "01".repeat(16), method: "eth_chainId", params: [] };
  assert.equal(shared.parseContentMessage(request, activation).compatMode, "off");
  assert.equal(shared.parseContentMessage({ ...request, compatMode: "metamask" }, activation).compatMode, "metamask");
  assert.equal(shared.parseContentMessage({ ...request, compatMode: "rabby" }, activation).compatMode, "rabby");
  for (const compatMode of ["off", "MetaMask", "x", null, 1, true]) {
    assert.equal(shared.parseContentMessage({ ...request, compatMode }, activation), null, String(compatMode));
  }
  // Page messages never carry a mode (the page cannot choose it).
  const channel = "d".repeat(64);
  assert.equal(shared.parsePageMessage({ namespace: "your-wallet", version: 1, kind: "request", channel, id: "01".repeat(16), method: "eth_chainId", params: [], compatMode: "metamask" }, channel), null);
});

test("S9 Solana/Bitcoin: method families, wire compat modes and account events", () => {
  assert.equal(shared.methodFamily("sol_connect"), "sol");
  assert.equal(shared.methodFamily("btc_signMessage"), "btc");
  assert.equal(shared.methodFamily("eth_chainId"), "evm");
  for (const method of ["sol_signTransaction", "sol_signAndSendTransaction", "btc_signPsbt", "btc_sendBitcoin"]) {
    assert.equal(shared.methodRoute(method), null, method);
  }
  assert.equal(shared.normalizeSolCompatMode("phantom"), "phantom");
  assert.equal(shared.normalizeSolCompatMode("metamask"), "off");
  assert.equal(shared.normalizeBtcCompatMode("xverse"), "xverse");
  assert.equal(shared.normalizeBtcCompatMode("Xverse"), "off");
  const key = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";
  assert.equal(shared.validEvent("solAccountsChanged", [key]), true);
  assert.equal(shared.validEvent("solAccountsChanged", []), true);
  assert.equal(shared.validEvent("solAccountsChanged", [key, key]), false);
  assert.equal(shared.validEvent("solAccountsChanged", ["0OIl"]), false);
  assert.equal(shared.validEvent("btcAccountsChanged", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]), true);
  assert.equal(shared.validEvent("btcAccountsChanged", ["a", "b", "c"]), false);
  assert.equal(shared.validEvent("btcAccountsChanged", ["bc1q w508"]), false);
});
