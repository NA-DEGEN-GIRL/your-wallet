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
