import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import "../src/shared.js";
import "../src/background-core.js";
import { validateNativeManifest } from "../native-host/validate-manifest.mjs";

const { BackgroundRouter } = globalThis.__YOUR_WALLET_BACKGROUND_CORE__;
const nativeHostDir = new URL("../native-host/", import.meta.url);
const validatorPath = fileURLToPath(new URL("validate-manifest.mjs", nativeHostDir));
const EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop";
// v1-request.golden.json keeps deadlineUnixMs 1700000120000; eth_chainId is route
// `permission` (600 s), so the issue time is 1700000120000 - 600000.
const ISSUED_AT = 1_700_000_120_000 - 600_000;

async function golden(name) {
  return JSON.parse(await readFile(new URL(name, nativeHostDir), "utf8"));
}

function goldenRouter() {
  const scripted = ["c".padStart(64, "0"), "d".padStart(64, "0"), "b".repeat(64)];
  let fallback = 0x100;
  const timers = [];
  const sent = [];
  const delivered = [];
  let receiveNative = null;
  let now = ISSUED_AT;
  const router = new BackgroundRouter({
    profileInstallId: "a".repeat(64),
    extensionId: EXTENSION_ID,
    randomHex: () => scripted.shift() ?? (fallback++).toString(16).padStart(64, "0"),
    now: () => now,
    setTimer: (callback, milliseconds) => {
      const timer = { callback, due: now + milliseconds, active: true };
      timers.push(timer);
      return timer;
    },
    clearTimer: (timer) => {
      timer.active = false;
    },
    nativeFactory: ({ hostName, onMessage }) => {
      assert.equal(hostName, "com.your_wallet.native");
      receiveNative = onMessage;
      return { send: (message) => sent.push(structuredClone(message)), disconnect: () => {} };
    }
  });
  const handle = router.attachContent({
    sender: {
      tab: { id: 17, incognito: false },
      frameId: 0,
      documentId: "document-17",
      documentLifecycle: "active",
      origin: "https://dapp.example",
      url: "https://dapp.example/private/path?not-forwarded=true"
    },
    postMessage: (message) => delivered.push(structuredClone(message)),
    disconnect: () => {}
  });
  const request = () => handle.receive({
    namespace: "your-wallet",
    version: 1,
    kind: "request",
    activationNonce: handle.activationNonce,
    id: "01".repeat(16),
    method: "eth_chainId",
    params: []
  });
  const advance = (milliseconds) => {
    now += milliseconds;
    for (const timer of timers) {
      if (timer.active && timer.due <= now) {
        timer.active = false;
        timer.callback();
      }
    }
  };
  return { advance, delivered, handle, receive: (message) => receiveNative(message), request, sent };
}

test("N1 request and cancel envelopes match the v1 goldens byte-for-field", async () => {
  const requestGolden = await golden("v1-request.golden.json");
  const cancelGolden = await golden("v1-cancel.golden.json");
  const harness = goldenRouter();
  assert.equal(harness.handle.activationNonce, requestGolden.activationNonce);
  assert.equal(harness.request(), true);
  assert.equal(harness.sent.length, 1);
  assert.equal(JSON.stringify(harness.sent[0]), JSON.stringify(requestGolden));
  harness.advance(599_999);
  assert.equal(harness.sent.length, 1);
  harness.advance(1);
  assert.equal(JSON.stringify(harness.sent[1]), JSON.stringify(cancelGolden));
  assert.deepEqual(harness.delivered.at(-1).error, { code: -32603, message: "Request timed out." });
});

test("N1 response, event and unavailable goldens are delivered to the content script", async () => {
  const resultGolden = await golden("v1-response-result.golden.json");
  const eventGolden = await golden("v1-event.golden.json");
  const unavailableGolden = await golden("v1-unavailable-response.golden.json");
  const activationNonce = resultGolden.activationNonce;

  const harness = goldenRouter();
  harness.request();
  harness.receive(resultGolden);
  assert.deepEqual(harness.delivered.at(-1), {
    namespace: "your-wallet", version: 1, kind: "response", activationNonce, id: "01".repeat(16), result: "0xaa36a7"
  });
  harness.receive(eventGolden);
  assert.deepEqual(harness.delivered.at(-1), {
    namespace: "your-wallet", version: 1, kind: "event", activationNonce, event: "chainChanged", payload: "0x1"
  });

  const unavailable = goldenRouter();
  unavailable.request();
  unavailable.receive(unavailableGolden);
  assert.deepEqual(unavailable.delivered.at(-1), {
    namespace: "your-wallet", version: 1, kind: "response", activationNonce, id: "01".repeat(16),
    error: { code: 4900, message: "Wallet is unavailable." }
  });
  assert.deepEqual(unavailableGolden.error, { code: 4900, message: "Wallet is unavailable." });
});

test("N1 validateNativeManifest accepts only concrete yw-host.exe manifests; the template is never valid", async () => {
  const template = JSON.parse(await readFile(new URL("com.your_wallet.native.json.template", nativeHostDir), "utf8"));
  assert.equal(template.description, "Your Wallet native messaging host");
  assert.deepEqual(validateNativeManifest(template), { valid: false, extensionId: null });
  const concrete = {
    ...template,
    path: "C:\\Users\\Test User\\AppData\\Local\\YourWallet\\bin\\yw-host.exe",
    allowed_origins: [`chrome-extension://${EXTENSION_ID}/`]
  };
  assert.deepEqual(validateNativeManifest(concrete), { valid: true, extensionId: EXTENSION_ID });
  assert.equal(validateNativeManifest({ ...concrete, path: "D:\\bin\\YW-HOST.EXE" }).valid, true);
  for (const [name, value] of Object.entries({
    "other executable": { ...concrete, path: "C:\\bin\\native-host.exe" },
    "suffix match only": { ...concrete, path: "C:\\bin\\my-yw-host.exe" },
    "dot segment": { ...concrete, path: "C:\\bin\\..\\yw-host.exe" },
    "relative": { ...concrete, path: "bin\\yw-host.exe" },
    "percent": { ...concrete, path: "C:\\%USERNAME%\\yw-host.exe" },
    "ampersand": { ...concrete, path: "C:\\a&b\\yw-host.exe" },
    "caret": { ...concrete, path: "C:\\a^b\\yw-host.exe" },
    "bang": { ...concrete, path: "C:\\a!b\\yw-host.exe" },
    "quote": { ...concrete, path: "C:\\a\"b\\yw-host.exe" },
    "two origins": { ...concrete, allowed_origins: [`chrome-extension://${EXTENSION_ID}/`, `chrome-extension://${EXTENSION_ID}/`] },
    "wildcard origin": { ...concrete, allowed_origins: ["chrome-extension://*/"] },
    "uppercase id": { ...concrete, allowed_origins: [`chrome-extension://${EXTENSION_ID.toUpperCase()}/`] },
    "missing slash": { ...concrete, allowed_origins: [`chrome-extension://${EXTENSION_ID}`] },
    "extra key": { ...concrete, extra: true },
    "wrong name": { ...concrete, name: "com.other" },
    "wrong type": { ...concrete, type: "pipe" }
  })) {
    assert.equal(validateNativeManifest(value).valid, false, name);
  }
});

test("N1 validate-manifest CLI prints OK <id> or INVALID and rejects a BOM", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "your-wallet-native-manifest-"));
  try {
    const manifest = {
      name: "com.your_wallet.native",
      description: "Your Wallet native messaging host",
      path: "C:\\Users\\Test\\AppData\\Local\\YourWallet\\bin\\yw-host.exe",
      type: "stdio",
      allowed_origins: [`chrome-extension://${EXTENSION_ID}/`]
    };
    const file = path.join(directory, "com.your_wallet.native.json");
    await writeFile(file, JSON.stringify(manifest, null, 2));
    const bomFile = path.join(directory, "bom.json");
    await writeFile(bomFile, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(manifest))]));
    const run = (...args) => spawnSync(process.execPath, [validatorPath, ...args], { encoding: "utf8" });

    let result = run(file);
    assert.equal(result.status, 0);
    assert.equal(result.stdout, `OK ${EXTENSION_ID}\n`);
    result = run(file, "--expect-id", EXTENSION_ID);
    assert.equal(result.status, 0);
    assert.equal(result.stdout, `OK ${EXTENSION_ID}\n`);
    for (const args of [
      [file, "--expect-id", "ponmlkjihgfedcbaponmlkjihgfedcba"],
      [bomFile],
      [fileURLToPath(new URL("com.your_wallet.native.json.template", nativeHostDir))],
      [path.join(directory, "missing.json")],
      [file, "--expect-id"],
      []
    ]) {
      result = run(...args);
      assert.equal(result.status, 1, args.join(" "));
      assert.equal(result.stdout, "INVALID\n", args.join(" "));
    }
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});
