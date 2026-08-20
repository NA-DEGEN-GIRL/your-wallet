import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import "../src/shared.js";
import "../src/background-core.js";
import { validateReleaseNativeManifest } from "../native-host/validate-manifest.mjs";

const shared = globalThis.__YOUR_WALLET_SHARED__;
const { BackgroundRouter } = globalThis.__YOUR_WALLET_BACKGROUND_CORE__;
const fixtureUrl = new URL("../native-host/v1-request.golden.json", import.meta.url);
const responseFixtureUrl = new URL(
  "../native-host/v1-unavailable-response.golden.json",
  import.meta.url
);
const templateUrl = new URL(
  "../native-host/com.your_wallet.native.json.template",
  import.meta.url
);

test("extension output is byte-for-field compatible with the Rust v1 golden request", async () => {
  const golden = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const goldenResponse = JSON.parse(await readFile(responseFixtureUrl, "utf8"));
  const sent = [];
  const delivered = [];
  let receiveNative = null;
  let nonce = 12;
  const router = new BackgroundRouter({
    profileInstallId: "a".repeat(64),
    sessionId: "b".repeat(64),
    extensionId: "abcdefghijklmnopabcdefghijklmnop",
    randomHex: () => (nonce++).toString(16).padStart(64, "0"),
    now: () => 1_700_000_000_000,
    nativeFactory: ({ onMessage }) => {
      receiveNative = onMessage;
      return { send: (message) => sent.push(message), disconnect: () => {} };
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
    postMessage: (message) => delivered.push(message)
  });
  assert.equal(handle.receive({
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    kind: "request",
    activationNonce: handle.activationNonce,
    id: "01".repeat(16),
    method: "eth_chainId",
    params: []
  }), true);
  assert.deepEqual(sent, [golden]);
  assert.equal(typeof receiveNative, "function");
  receiveNative(goldenResponse);
  assert.equal(delivered.at(-1).kind, "response");
  assert.equal(delivered.at(-1).error.code, 4900);
});

test("native manifest template is never release-valid", async () => {
  const template = JSON.parse(await readFile(templateUrl, "utf8"));
  assert.deepEqual(
    validateReleaseNativeManifest(template),
    { valid: false, extensionId: null }
  );
  assert.deepEqual(
    validateReleaseNativeManifest({
      ...template,
      path: "C:\\Program Files\\Your Wallet\\native-host.exe",
      allowed_origins: [
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
      ]
    }),
    { valid: true, extensionId: "abcdefghijklmnopabcdefghijklmnop" }
  );
  assert.equal(validateReleaseNativeManifest({
    ...template,
    path: "C:\\Program Files\\..\\native-host.exe",
    allowed_origins: ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]
  }).valid, false);
});

test("manifest declares incognito denial without host permissions", async () => {
  const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));
  assert.equal(manifest.incognito, "not_allowed");
  assert.deepEqual(manifest.permissions, ["nativeMessaging", "storage"]);
  assert.equal(Object.hasOwn(manifest, "host_permissions"), false);
});
