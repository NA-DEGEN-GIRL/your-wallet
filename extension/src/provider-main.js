(function installYourWalletProvider(root) {
  "use strict";

  if (root.top !== root || !isSupportedPage(root.location)) {
    return;
  }

  const NAMESPACE = "your-wallet";
  const VERSION = 1;
  // Background's longest route deadline (600 s) + 5 s; the provider has no method table (spec/05 §6.4).
  const REQUEST_TIMEOUT_MS = 605_000;
  const MAX_PENDING = 64;
  const BRIDGE_WAIT_MS = 10_000;
  // The compatibility mode arrives with `bridge-init` (spec/05 §2.12). If the content script
  // never answers, the default identity is announced after this long.
  const MODE_WAIT_MS = 10_000;
  const MAX_MESSAGE_BYTES = 1_048_576;
  const EIP6963_ANNOUNCE_EVENT = "eip6963:announceProvider";
  const EIP6963_REQUEST_EVENT = "eip6963:requestProvider";
  const PROVIDER_RDNS = "io.github.na-degen-girl.yourwallet";
  // spec/05 §2.12. Names and rdns only; the icon is always ours (no third-party logos).
  const IDENTITIES = Object.freeze({
    off: Object.freeze({ name: "Your Wallet", rdns: PROVIDER_RDNS }),
    metamask: Object.freeze({ name: "MetaMask", rdns: "io.metamask" }),
    rabby: Object.freeze({ name: "Rabby Wallet", rdns: "io.rabby" })
  });
  // Foreign EIP-6963 announcements hidden from the page in the two compatibility modes.
  const INTERCEPTED_RDNS = new Set(["io.metamask", "io.metamask.flask", "io.rabby"]);
  // The app icon as a 96 px PNG, written by scripts/make-icons.mjs (do not edit by hand).
  const PROVIDER_ICON = "data:image/png;base64,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";
  const EVENT_NAMES = new Set(["connect", "disconnect", "accountsChanged", "chainChanged", "message"]);
  const METHOD_PATTERN = /^[A-Za-z0-9_]{1,96}$/u;
  const CHANNEL_PATTERN = /^[0-9a-f]{64}$/u;
  const REQUEST_ID_PATTERN = /^[0-9a-f]{32}$/u;
  const HEX_CHAIN_ID_PATTERN = /^0x[0-9A-Fa-f]{1,64}$/u;
  const SYNC_SEND_UNSUPPORTED = "send(payload) without a callback supports only eth_accounts, eth_coinbase and net_version. Use request() or pass a callback.";
  const targetOrigin = root.location.origin;
  // Captured before any page script runs. Reports a throwing legacy callback like an uncaught
  // page error without letting it reach provider state (spec/05 §2.5 레거시 API).
  const nativeReportError = typeof root.reportError === "function" ? root.reportError : null;

  class ProviderRpcError extends Error {
    constructor(code, message, data) {
      super(message);
      this.name = "ProviderRpcError";
      this.code = code;
      if (data !== undefined) {
        this.data = data;
      }
    }
  }

  const listeners = new Map();
  const pending = new Map();
  const bridgeWaiters = new Set();
  let channel = null;
  let dead = false;
  let activeChainId = null;
  let selectedAddress = null;
  let connectEmitted = false;
  let announcingProvider = false;
  // `off` until the mode is settled (bridge-init or MODE_WAIT_MS), then fixed for the document.
  let compatMode = "off";
  let modeSettled = false;
  let modeTimer = null;

  // Extensible plain object: legacy dApps may assign their own properties. The
  // members below cannot be overwritten or reconfigured. Identity flags are getters
  // that read the current mode.
  const provider = {};
  const metamaskApi = Object.freeze({ isUnlocked });
  defineMember("isYourWallet", { value: true });
  defineMember("isMetaMask", { get: () => compatMode !== "off" });
  defineMember("isRabby", { get: () => compatMode === "rabby" });
  defineMember("_metamask", { get: () => (compatMode === "off" ? undefined : metamaskApi) });
  defineMember("chainId", { get: () => activeChainId });
  defineMember("selectedAddress", { get: () => selectedAddress });
  defineMember("isConnected", { value: () => channel !== null && !dead });
  defineMember("request", { value: request });
  // Legacy MetaMask API in every mode (spec/05 §2.5 레거시 API). Each one only calls `request`,
  // so the method table, permissions, limits and error codes are exactly those of `request`.
  defineMember("enable", { value: () => request({ method: "eth_requestAccounts" }) });
  defineMember("send", { value: send });
  defineMember("sendAsync", { value: sendAsync });
  defineMember("on", { value: addListener });
  defineMember("addListener", { value: addListener });
  defineMember("once", { value: once });
  defineMember("off", { value: removeListener });
  defineMember("removeListener", { value: removeListener });
  defineMember("removeAllListeners", { value: removeAllListeners });
  defineMember("listenerCount", { value: listenerCount });

  // One UUID per page for whichever identity the settled mode selects (only one is ever announced).
  const providerUuid = randomUuid();
  const providerDetails = Object.freeze(Object.fromEntries(Object.entries(IDENTITIES).map(([mode, identity]) => [
    mode,
    Object.freeze({
      info: Object.freeze({ uuid: providerUuid, name: identity.name, icon: PROVIDER_ICON, rdns: identity.rdns }),
      provider
    })
  ])));

  // Capture phase, registered at document_start before any page script: at the window target,
  // capture listeners run before the page's own (non-capture) announcement listeners.
  root.addEventListener(EIP6963_ANNOUNCE_EVENT, interceptAnnouncement, true);
  root.addEventListener("message", receiveBridgeMessage);
  root.addEventListener(EIP6963_REQUEST_EVENT, receiveProviderRequest);
  root.addEventListener("DOMContentLoaded", reclaimWindowEthereum);
  root.addEventListener("load", reclaimWindowEthereum);
  installWindowEthereum();
  modeTimer = root.setTimeout(() => settleMode("off"), MODE_WAIT_MS);
  postToBridge({ kind: "bridge-request" });

  function defineMember(name, descriptor) {
    Object.defineProperty(provider, name, {
      ...descriptor,
      enumerable: true,
      configurable: false,
      ...(Object.prototype.hasOwnProperty.call(descriptor, "value") ? { writable: false } : {})
    });
  }

  function installWindowEthereum() {
    // Default mode (and before the mode is known): only claim window.ethereum when no other
    // wallet has; never overwrite. Later assignments by other wallets replace it.
    try {
      if ("ethereum" in root) {
        return;
      }
      Object.defineProperty(root, "ethereum", {
        value: provider,
        configurable: true,
        enumerable: true,
        writable: true
      });
      root.dispatchEvent(new Event("ethereum#initialized"));
    } catch (_error) {
      // A page-defined accessor or proxy must not break EIP-6963 discovery.
    }
  }

  // Compatibility modes (spec/05 §2.12): window.ethereum is an accessor that always returns our
  // provider. Its setter accepts and ignores assignments (`window.ethereum = other` neither
  // throws nor wins). It stays configurable so another wallet's Object.defineProperty does not
  // throw and crash that wallet's script; such a redefinition is taken back at the next
  // checkpoint (mode settled, eip6963:requestProvider, DOMContentLoaded, load). A
  // non-configurable redefinition cannot be undone; then only the incumbent's own setter
  // (assignment) is tried.
  function ethereumGetter() {
    return provider;
  }

  function ethereumSetter(_ignored) {
    // Intentionally ignored: our provider keeps precedence for the document's lifetime.
  }

  function claimWindowEthereum() {
    let descriptor;
    let before;
    try {
      descriptor = Object.getOwnPropertyDescriptor(root, "ethereum");
      if (descriptor !== undefined && descriptor.get === ethereumGetter) {
        return true;
      }
      before = root.ethereum;
    } catch (_error) {
      return false;
    }
    let claimed = false;
    if (descriptor === undefined || descriptor.configurable === true) {
      try {
        Object.defineProperty(root, "ethereum", {
          get: ethereumGetter,
          set: ethereumSetter,
          configurable: true,
          enumerable: true
        });
        claimed = true;
      } catch (_error) {
        claimed = false;
      }
    }
    if (!claimed) {
      try {
        root.ethereum = provider;
      } catch (_error) {
        // Non-configurable and not assignable: another wallet holds window.ethereum.
      }
    }
    let after;
    try {
      after = root.ethereum;
    } catch (_error) {
      return false;
    }
    if (after === provider && before !== provider) {
      try {
        root.dispatchEvent(new Event("ethereum#initialized"));
      } catch (_error) {
        // A hostile listener cannot undo the claim.
      }
    }
    return after === provider;
  }

  function reclaimWindowEthereum() {
    if (compatMode !== "off") {
      claimWindowEthereum();
    }
  }

  // Foreign MetaMask/Rabby announcements never reach the page in a compatibility mode. Off (and
  // before the mode is settled) nothing is intercepted. Hostile `detail` getters let the event pass.
  function interceptAnnouncement(event) {
    if (compatMode === "off") {
      return;
    }
    try {
      const detail = event.detail;
      if (detail === providerDetails[compatMode]) {
        return;
      }
      const info = detail !== null && typeof detail === "object" ? detail.info : undefined;
      const rdns = info !== null && typeof info === "object" ? info.rdns : undefined;
      if (typeof rdns === "string" && INTERCEPTED_RDNS.has(rdns.toLowerCase())) {
        event.stopImmediatePropagation();
      }
    } catch (_error) {
      // Leave events we cannot inspect alone.
    }
  }

  function settleMode(mode) {
    if (modeSettled) {
      return;
    }
    modeSettled = true;
    root.clearTimeout(modeTimer);
    modeTimer = null;
    compatMode = Object.prototype.hasOwnProperty.call(IDENTITIES, mode) ? mode : "off";
    if (compatMode !== "off") {
      claimWindowEthereum();
    }
    // The first announcement waits for the mode so the page never sees two identities; any
    // eip6963:requestProvider received before this point is answered here.
    announceProvider();
  }

  function receiveProviderRequest() {
    if (!modeSettled) {
      return;
    }
    reclaimWindowEthereum();
    announceProvider();
  }

  function announceProvider() {
    // A hostile listener can synchronously dispatch another request while an
    // announcement is being delivered. Suppress only that recursive cycle;
    // every later discovery request receives the same immutable page identity.
    if (announcingProvider || !modeSettled) {
      return;
    }
    announcingProvider = true;
    try {
      root.dispatchEvent(new CustomEvent(EIP6963_ANNOUNCE_EVENT, { detail: providerDetails[compatMode] }));
    } finally {
      announcingProvider = false;
    }
  }

  // MetaMask's `_metamask.isUnlocked()`: whether accounts are exposed to this origin now
  // (eth_accounts non-empty = connected and yw-app unlocked). Never rejects.
  async function isUnlocked() {
    try {
      const accounts = await request({ method: "eth_accounts" });
      return Array.isArray(accounts) && accounts.length > 0;
    } catch (_error) {
      return false;
    }
  }

  async function request(args) {
    const method = isPlainObject(args) ? args.method : undefined;
    if (typeof method !== "string" || !METHOD_PATTERN.test(method)) {
      throw new ProviderRpcError(4200, "Unsupported method.");
    }
    const suppliedParams = args.params;
    const params = suppliedParams === undefined ? [] : suppliedParams;
    if (!Array.isArray(params) && !isPlainObject(params)) {
      throw new ProviderRpcError(-32602, "Invalid params.");
    }
    if (channel === null && !dead) {
      await waitForBridge();
    }
    if (dead) {
      throw reloadedError();
    }
    if (channel === null) {
      throw new ProviderRpcError(4900, "Wallet connection closed.");
    }
    if (pending.size >= MAX_PENDING) {
      throw new ProviderRpcError(-32005, "Too many pending requests.");
    }
    let id = randomHex(16);
    while (pending.has(id) || /^0+$/u.test(id)) {
      id = randomHex(16);
    }
    const requestChannel = channel;
    let text;
    try {
      text = JSON.stringify({
        namespace: NAMESPACE,
        version: VERSION,
        kind: "request",
        channel: requestChannel,
        id,
        method,
        params
      });
    } catch (_error) {
      text = undefined;
    }
    if (typeof text !== "string" || new TextEncoder().encode(text).byteLength > MAX_MESSAGE_BYTES) {
      throw new ProviderRpcError(-32600, "Request too large.");
    }
    // Send the JSON form so toJSON/undefined members reach the extension as plain JSON.
    const message = JSON.parse(text);
    if (!Array.isArray(message.params) && !isPlainObject(message.params)) {
      throw new ProviderRpcError(-32602, "Invalid params.");
    }
    return new Promise((resolve, reject) => {
      const entry = { method, resolve, reject, timer: null };
      entry.timer = root.setTimeout(() => {
        if (pending.get(id) !== entry) {
          return;
        }
        pending.delete(id);
        postToBridge({ kind: "cancel", channel: requestChannel, id });
        reject(new ProviderRpcError(-32603, "Request timed out."));
      }, REQUEST_TIMEOUT_MS);
      pending.set(id, entry);
      try {
        root.postMessage(message, targetOrigin);
      } catch (_error) {
        root.clearTimeout(entry.timer);
        pending.delete(id);
        reject(new ProviderRpcError(4900, "Wallet connection closed."));
      }
    });
  }

  function waitForBridge() {
    return new Promise((resolve) => {
      const waiter = { resolve, timer: null };
      waiter.timer = root.setTimeout(() => {
        bridgeWaiters.delete(waiter);
        resolve();
      }, BRIDGE_WAIT_MS);
      bridgeWaiters.add(waiter);
    });
  }

  function releaseBridgeWaiters() {
    for (const waiter of [...bridgeWaiters]) {
      root.clearTimeout(waiter.timer);
      waiter.resolve();
    }
    bridgeWaiters.clear();
  }

  // MetaMask legacy `send`, three signatures:
  //   send(method: string, params?)  → request({ method, params }) (Promise of the raw result)
  //   send(payload, callback)        → sendAsync(payload, callback), returns undefined
  //   send(payload)                  → synchronous JSON-RPC response from cached state (no I/O)
  function send(methodOrPayload, paramsOrCallback) {
    if (typeof methodOrPayload === "string") {
      return request({ method: methodOrPayload, params: paramsOrCallback });
    }
    if (typeof paramsOrCallback === "function") {
      return sendAsync(methodOrPayload, paramsOrCallback);
    }
    return sendSync(methodOrPayload);
  }

  // Only what the provider already exposes as properties (selectedAddress, chainId); anything
  // else would need I/O, so it throws instead.
  function sendSync(payload) {
    const { id, method } = legacyCall(payload);
    let result;
    if (method === "eth_accounts") {
      result = selectedAddress === null ? [] : [selectedAddress];
    } else if (method === "eth_coinbase") {
      result = selectedAddress;
    } else if (method === "net_version") {
      result = cachedNetVersion();
    } else {
      throw new Error(SYNC_SEND_UNSUPPORTED);
    }
    return { id, jsonrpc: "2.0", result };
  }

  // callback(null, { id, jsonrpc, result }) or callback(error, { id, jsonrpc, error }), always
  // after the call returns. An array payload is a batch: every element is validated first, then
  // each runs through `request` and the callback gets callback(null, [responses in order]).
  function sendAsync(payload, callback) {
    if (typeof callback !== "function") {
      throw new TypeError("Legacy JSON-RPC callback must be a function.");
    }
    if (Array.isArray(payload)) {
      const calls = [];
      for (let index = 0; index < payload.length; index += 1) {
        calls.push(legacyCall(payload[index]));
      }
      Promise.all(calls.map((call) => legacyResponse(call))).then((outcomes) => {
        invokeLegacyCallback(callback, null, outcomes.map((outcome) => outcome.response));
      });
      return undefined;
    }
    const call = legacyCall(payload);
    legacyResponse(call).then((outcome) => invokeLegacyCallback(callback, outcome.error, outcome.response));
    return undefined;
  }

  // Reads `id`, `method` and `params` once. Other payload keys (`jsonrpc` etc.) are ignored.
  function legacyCall(payload) {
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      throw new TypeError("Legacy JSON-RPC payload must be an object with a string method.");
    }
    const method = payload.method;
    if (typeof method !== "string") {
      throw new TypeError("Legacy JSON-RPC payload must be an object with a string method.");
    }
    return { id: payload.id, method, params: payload.params };
  }

  // Never rejects.
  function legacyResponse(call) {
    return request({ method: call.method, params: call.params }).then(
      (result) => ({ error: null, response: { id: call.id, jsonrpc: "2.0", result } }),
      (error) => ({ error, response: { id: call.id, jsonrpc: "2.0", error: legacyErrorObject(error) } })
    );
  }

  function legacyErrorObject(error) {
    if (!(error instanceof ProviderRpcError)) {
      return { code: -32603, message: "Internal error." };
    }
    return error.data === undefined
      ? { code: error.code, message: error.message }
      : { code: error.code, message: error.message, data: error.data };
  }

  // A throwing dApp callback is reported (window.reportError) and otherwise ignored.
  function invokeLegacyCallback(callback, error, response) {
    try {
      callback(error, response);
    } catch (callbackError) {
      if (nativeReportError !== null) {
        try {
          nativeReportError.call(root, callbackError);
        } catch (_error) {
          // Reporting is best effort.
        }
      }
    }
  }

  function cachedNetVersion() {
    return typeof activeChainId === "string" && HEX_CHAIN_ID_PATTERN.test(activeChainId)
      ? BigInt(activeChainId).toString(10)
      : null;
  }

  function addListener(eventName, listener) {
    return register(eventName, listener, false);
  }

  function once(eventName, listener) {
    return register(eventName, listener, true);
  }

  function register(eventName, listener, onlyOnce) {
    if (typeof listener !== "function") {
      throw new TypeError("Provider listener must be a function.");
    }
    if (!EVENT_NAMES.has(eventName)) {
      return provider;
    }
    const entries = listeners.get(eventName) || [];
    entries.push({ listener, once: onlyOnce });
    listeners.set(eventName, entries);
    return provider;
  }

  function removeListener(eventName, listener) {
    const entries = listeners.get(eventName);
    if (entries) {
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        if (entries[index].listener === listener) {
          entries.splice(index, 1);
          break;
        }
      }
      if (entries.length === 0) {
        listeners.delete(eventName);
      }
    }
    return provider;
  }

  function removeAllListeners(eventName) {
    if (eventName === undefined) {
      listeners.clear();
    } else {
      listeners.delete(eventName);
    }
    return provider;
  }

  function listenerCount(eventName) {
    const entries = listeners.get(eventName);
    return entries ? entries.length : 0;
  }

  function emit(eventName, payload) {
    const entries = listeners.get(eventName);
    if (!entries) {
      return;
    }
    for (const entry of [...entries]) {
      if (entry.once) {
        const index = entries.indexOf(entry);
        if (index === -1) {
          continue;
        }
        entries.splice(index, 1);
        if (entries.length === 0 && listeners.get(eventName) === entries) {
          listeners.delete(eventName);
        }
      }
      try {
        entry.listener(payload);
      } catch (_error) {
        // A dApp listener must not interrupt provider message processing.
      }
    }
  }

  function receiveBridgeMessage(event) {
    if (event.source !== root || event.origin !== targetOrigin) {
      return;
    }
    const message = event.data;
    if (!isPlainObject(message) || message.namespace !== NAMESPACE || message.version !== VERSION) {
      return;
    }
    if (message.kind === "bridge-init") {
      if (hasExactKeys(message, ["namespace", "version", "kind", "channel", "compatMode"])
        && typeof message.channel === "string"
        && CHANNEL_PATTERN.test(message.channel)
        && typeof message.compatMode === "string"
        && Object.prototype.hasOwnProperty.call(IDENTITIES, message.compatMode)
        && channel === null
        && !dead) {
        channel = message.channel;
        settleMode(message.compatMode);
        releaseBridgeWaiters();
      }
      return;
    }
    if (channel === null || message.channel !== channel) {
      return;
    }
    if (message.kind === "response") {
      receiveResponse(message);
    } else if (message.kind === "event") {
      receiveEvent(message);
    } else if (message.kind === "disconnect") {
      if (hasExactKeys(message, ["namespace", "version", "kind", "channel", "error"])
        && validRpcError(message.error)) {
        enterDead();
      }
    }
  }

  function receiveResponse(message) {
    const base = ["namespace", "version", "kind", "channel", "id"];
    const isResult = hasExactKeys(message, [...base, "result"]);
    const isError = hasExactKeys(message, [...base, "error"]) && validRpcError(message.error);
    if ((!isResult && !isError) || typeof message.id !== "string" || !REQUEST_ID_PATTERN.test(message.id)) {
      return;
    }
    const entry = pending.get(message.id);
    if (!entry) {
      return;
    }
    pending.delete(message.id);
    root.clearTimeout(entry.timer);
    if (isResult) {
      updateProviderView(entry.method, message.result);
      entry.resolve(message.result);
    } else {
      entry.reject(new ProviderRpcError(message.error.code, message.error.message, message.error.data));
    }
  }

  function receiveEvent(message) {
    if (!hasExactKeys(message, ["namespace", "version", "kind", "channel", "event", "payload"])) {
      return;
    }
    const { event: eventName, payload } = message;
    if (eventName === "accountsChanged" && Array.isArray(payload)
      && payload.every((account) => typeof account === "string")) {
      selectedAddress = payload.length > 0 ? payload[0] : null;
      emit("accountsChanged", payload);
    } else if (eventName === "chainChanged" && typeof payload === "string") {
      learnChainId(payload);
      emit("chainChanged", payload);
    }
  }

  function updateProviderView(method, result) {
    if ((method === "eth_accounts" || method === "eth_requestAccounts") && Array.isArray(result)) {
      selectedAddress = typeof result[0] === "string" ? result[0] : null;
    } else if (method === "eth_chainId" && typeof result === "string") {
      learnChainId(result);
    }
  }

  function learnChainId(chainId) {
    activeChainId = chainId;
    if (!connectEmitted && !dead) {
      connectEmitted = true;
      emit("connect", { chainId });
    }
  }

  // DEAD: the extension context was invalidated (reload/update). Transient
  // connection losses never reach this path; they are per-request 4900 errors.
  function enterDead() {
    if (dead) {
      return;
    }
    dead = true;
    releaseBridgeWaiters();
    const entries = [...pending.values()];
    pending.clear();
    for (const entry of entries) {
      root.clearTimeout(entry.timer);
      entry.reject(reloadedError());
    }
    emit("disconnect", reloadedError());
  }

  function reloadedError() {
    return new ProviderRpcError(4900, "Wallet extension was reloaded.");
  }

  function postToBridge(fields) {
    try {
      root.postMessage({ namespace: NAMESPACE, version: VERSION, ...fields }, targetOrigin);
    } catch (_error) {
      // The window is closing.
    }
  }

  function validRpcError(value) {
    return hasExactKeys(value, ["code", "message"], ["data"])
      && Number.isSafeInteger(value.code)
      && typeof value.message === "string"
      && value.message.length >= 1
      && value.message.length <= 512;
  }

  function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  }

  function hasExactKeys(value, required, optional = []) {
    if (!isPlainObject(value)) {
      return false;
    }
    const keys = Object.keys(value);
    const allowed = new Set([...required, ...optional]);
    return keys.length >= required.length
      && keys.length <= required.length + optional.length
      && required.every((key) => Object.prototype.hasOwnProperty.call(value, key))
      && keys.every((key) => allowed.has(key));
  }

  // Own copy of spec/05 §2.4 (this script runs in the page world without shared.js).
  function isSupportedPage(location) {
    let url;
    try {
      url = new URL(location.href);
    } catch (_error) {
      return false;
    }
    if (url.username !== "" || url.password !== "" || url.origin === "null"
      || url.hostname === "" || url.hostname.startsWith("[")) {
      return false;
    }
    if (url.protocol === "https:") {
      return true;
    }
    return url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  }

  function randomHex(byteLength) {
    const bytes = new Uint8Array(byteLength);
    root.crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function randomUuid() {
    const bytes = new Uint8Array(16);
    root.crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
}(globalThis));
