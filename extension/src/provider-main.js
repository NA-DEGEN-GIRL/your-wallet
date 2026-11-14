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
    off: Object.freeze({ name: "Your Wallet (EVM)", rdns: PROVIDER_RDNS }),
    metamask: Object.freeze({ name: "MetaMask", rdns: "io.metamask" }),
    rabby: Object.freeze({ name: "Rabby Wallet", rdns: "io.rabby" })
  });
  // Foreign EIP-6963 announcements hidden from the page in the two compatibility modes.
  const INTERCEPTED_RDNS = new Set(["io.metamask", "io.metamask.flask", "io.rabby"]);
  // spec/05 §2.12 MetaMask Connect (2026-11-11). MetaMask Connect (`@metamask/connect-evm`, the
  // wagmi `metaMask()` connector Uniswap uses) never calls window.ethereum: once an EIP-6963
  // `io.metamask` announcement is seen it talks to MetaMask's own content script over
  // window.postMessage (CAIP-25 `wallet_getSession`/`wallet_createSession` on this substream)
  // and, with no answer, waits 60 s ("clicking MetaMask does nothing"). In metamask mode, while no
  // real MetaMask has announced itself on the page, such requests are refused at once (4200) so
  // the dApp reports an error. Nothing is forwarded to the wallet.
  const MM_RDNS = new Set(["io.metamask", "io.metamask.flask", "io.metamask.mobile"]);
  const MM_CONTENT_SCRIPT = "metamask-contentscript";
  const MM_INPAGE = "metamask-inpage";
  const MM_MULTICHAIN_STREAM = "metamask-multichain-provider";
  const MM_CONNECT_UNSUPPORTED = "Your Wallet's MetaMask look-alike mode cannot answer MetaMask Connect, which talks to the MetaMask extension directly. Choose the default or Rabby mode in the Your Wallet extension popup and reload this page.";
  // The app icon as a 96 px PNG, written by scripts/make-icons.mjs (do not edit by hand).
  const PROVIDER_ICON = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAYAAADimHc4AAAJTklEQVR42u2dD1AU1x3HvwsYSARjbDSIJ4jBSBT1IEPVTAwiSYxpTUisxk6J0U4zZJymkyY46XQA+yc106ptTJgkMmmbPzSkRc0fp5GklUC1jVQdKQyNCOhpQK0YhPNO7hTZztvbO1jY/3+89Xi/GQb32Hdv9/P2vd/v931vfQA1atSohc0Yo1+QlVkeBwaLWQY5AOsEgzQADpZB3GANLFhGWCPLf84dCz5TWYb/XGsZwd+1lfGBQQfAtoFBA8ugDkBt+85nfWFpgKzMcieAQjAoYBnES95kZMAPnT+sXg+ACpbB9uNVzzZckwbIcpangcFmAPmDFzMq4Q8v8yGADcf/8uM2LTyjNMIvAoMmCl+0TD7LoCn18d8Vmd4Dspzl8QCqwOBBIQQKX6JMNctgpavyOY/hBshylicC2AMGTgpfXRn+uAEMlrnee+6s7gbgn/x9FL5m+MF6iWNe5PqTdE9Q8gFVFL5u+MScLIMqOcDRCg53PYWvG36wTNr4eUu9vY2f/Uv1EMSHmiTaiaPwDcEPHvtYBnNOvfN8m7ohKBDnU/jmwAevCmxW1QP4DPcIhW8a/KFlMk+9XdSg1AMKKXxL4JPjQtkewAtrXaNY27ESPjEPGEz86o9FPvEeEFA1KXxr4JNjklctlhyCeEmZwrcGfvB3jowP4PR8Ct86+OQzp3QDBCZTKHzr4HOJmVwU5KDwLYVP/u2Q8wFxFL6l8MEluLJ5AIVvJfzBcyR8AIV/DeGLRUEUvtXw5XoAhX8t4LNQ4QMofKvgq/ABFP61gk8sZvgHZsBPSIjFquWzsSDLgeQpN6tcoMGat2aPGfFtqs19yY8j7WewY18z99t0+IxMA5gBf8W37kRR4d1IiI/F9WqzUibie0vm4pODrXjhD59xjWIFfJEeYAz+M9+fj8KCuxAp9lD2DMx0fAMrfvVnXPBcMgW+sg/QCT9nYUpEwQ/a7ZMnYOtTS02Ez6p1wurhR8dE4YX19yBSLW/edCxMn2oOfEZhUl5PtJPtTNLgbK9PW33vHHPgq0/E1Ieac++8DZFuC9IdpsPXL8YNi/Mj/eknNvmWBHMXKugW40STrNFi5sLXLsZJZLijxkybrpXINzPufY2l8gLMi3Ykypx99SeMNjGOwjcNvnYxjsK3DL5MHkDhW70+SlmM0wB/0/N5ePT+9Ij3wY7CzabCF42CdD35oyUINW3GUMEHaB52RlMuYMaklbQcrW/Mt3sv8Pqu4IKnTxXYoffDWgFfzgcYcrg2s/+e6sL7dU2oa3LBda4nrA5XCr6EE76+4Xdf7MPGd2vwcX2LLaIdscBGcQjSHjbaw9rPdGP1piqcc3ttC59VGoJ0xfk2aATX/3pk4U9IuBE3xY0R770MK/5QcZP7gft29/nR2+czFT7E5oT1JFnhtv6rA1hftnsE/NuTJuCZ5Qu4Ga1xNxlfJEC+v7qxFWV/q8dX3b2mqMcxquNcpQw3jLZjfzOaT3UJ4H9n0WxsWnMfYsfEmFbPpHFjseYeJ1Zkz8IP3/krqpuOGVaPVYtxdoVPrHzPYcEN5sxNxa/XPSCA3z8wgJbO8+j42m24vrGxN+CNtcsxNzlRv4Ym7QO0azvhHIRaOs5zzjd4XdHRUfhFwRLERA0+WwdbO/Gj33+Cjq97uePsGVOw/emHMXHcWN31ksbdmJ+Lx8oqdcNXJcapEdbC6YQPtZ4WXFf2HVMwbdL40N+7er144uWdIfjknH+3deLJsl2G6747LRnTJt6iS0MTbQD9qmb47FyvV3Bdc1KFCwR2HfgS3suXR9xP48mz3I9RuyslSTd8WTFOk6RsI5FsbOwYoQzhvywZNnr9VwzXHRPN6NDQVE3IaNPzw2WxY6IF1xWQHQYta/pkUShkDJ+ZdKvh+k/3XjSkHssvzLI5fGIzHbcKnsDaZhcX8QRtcUYqHs5OH3EvP1+ViwnxNxqqu7fPj/oTHToFTKU8QEtWHMaGWJA+lesF/v6r3LV0ey6hovY/WLskM3TOa099G0udadh/9CR37mPzZyErNclw3a/X1sPf32+eGKcLfpiNjPmPLpyFyv1NoWt7adc/MDt5ErLTpoTOeyQ7nfsxy3Y3tuCVmgOGBcwow/Bt0AjrH/pmwBfw1+K9fAUF23bgrc+PCIYjM4w88a/WHEDhux+hnx0wrB4bF+NsEAWRuL94ZQ5KKveGro00QvH7f0fZp/XIzUhF4vh44cPCjOz5rAiLoccnzl9ATcsJdHsvGVuoYJoYF1QKyRskYTYy5ru6evDm3sMCKGd6LuK9fzZaIynrXiUim4hpXzrS3tltC03oZ4/n4sXv5nHDkZ1fuTUuxg1bt/P54RO4enXAFo2wNjcTezeuw6qFGYi9IcZ28Fm5taF3LH+Fhc5FU5uezsOqvAzYyUimu++oCy1nzuN0z0X4r/SP8APsCBJD7pv/nMT7e5qPmQb/wovFjGQYqnfF2ksV+zB/tgMpieNt0wAkRH1w3gzux4gVVnxk3pOvW4xTWC5IHPEPfvMx2k93I1KMhLAbdn6KDxq+tAS+ejFO5VpNAj//p5XYtuOALSIjI1Zz9DgeePktvP3FEQvWxMrmAcYWypJxd9vOL/D67oOYM/02TEu8OTSWinkeVmTslR6fh0ygK34nK1JWecx3+/w4dLIT5zxe04cdVSvjzFqlTBzeoWOdONTaqbrM8EmeSP7PY1XkAZG/RDzc8MXyAB+Fb/l7ED45Ma6DwofVL6F0yEVBbRS+5W8Atcn1gAYK31L45KhBzgnXUfiWv/tWJ+eEa/nt+Sh8a+B7WAa1kg3Ab0xZQeHDqrc+K9wlpT5ZOZpsTEnhW/bK7XalPADcrqCBjSkpfHPhf+guKW1QbADeNoQSBgrfDPgkwd0gBlq0AfgtWUsofNPe9C9xF5eKbnMru6gkdfVv97BDdlCl8HXBr3YXly6TYiy7lyTZkpXfFZTC1wefjPkr5RjLNgC3Hy6DZfwXUfja4S9zF5d6dDcA1wiB/XAXsQyqKXz1ww5h5i4uVXwBQdPCwpQntpLtun+ptNXJKI92iMPdopap5pWdyWu2pnEbUzLIp/CFcT4JNaWiHdMaINQQT25x8nsjFvA7xI1WbaeCZLhiSZalDRC0qeu2xHHb8zHICWxSxqbxWzXFReBMVkdAz2dJZFhHhLXh2g41atSoXUf2f2Kh5Blo3K20AAAAAElFTkSuQmCC";
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
  const nativeWarn = root.console !== null && typeof root.console === "object" && typeof root.console.warn === "function"
    ? root.console.warn.bind(root.console)
    : null;

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
  // spec/05 §2.5: `channel` is claimed by the content script's synchronous `bridge-claim` (queued
  // before any page script can post) or, failing that, by the first valid `bridge-init`; requests
  // flow only once `bridge-init` on that channel opened the bridge.
  let channel = null;
  let bridgeOpen = false;
  let dead = false;
  let activeChainId = null;
  let selectedAddress = null;
  let connectEmitted = false;
  let announcingProvider = false;
  // `off` until the mode is settled (bridge-init or MODE_WAIT_MS), then fixed for the document.
  let compatMode = "off";
  let modeSettled = false;
  let modeTimer = null;
  // A real MetaMask announced itself (EIP-6963) on this page: its content script answers the
  // MetaMask Connect substream, so ours stays silent (spec/05 §2.12).
  let foreignMetaMaskSeen = false;
  let metaMaskConnectWarned = false;

  // ----- Solana and Bitcoin (spec/05 §2.13) --------------------------------------------------
  // The wire methods are sol_* / btc_* (shared.js METHOD_ROUTE). Solana: connect, messages and
  // the site's own transactions (sol_signTransaction, sol_signAllTransactions,
  // sol_signAndSendTransaction, spec.md D38). Bitcoin: connect and messages only; its PSBT and
  // send methods exist only where dApps need them to detect a wallet and always reject locally
  // with 4200.
  const SOL_CHAINS = Object.freeze(["solana:mainnet", "solana:devnet"]);
  // Any other Phantom `request` method (neutral: Solana transactions are supported).
  const SOL_REQUEST_UNSUPPORTED = "Unsupported method.";
  // spec/05 §2.9: one transaction ≤ 1,232 bytes, ≤ 32 per approval.
  const MAX_SOL_TX_BYTES = 1232;
  const MAX_SOL_TX_BATCH = 32;
  const SOL_TX_VERSIONS = Object.freeze(["legacy", 0]);
  // web3.js commitments and their deprecated aliases (spec/05 §2.13); any other value is dropped.
  const SOL_COMMITMENTS = Object.freeze({
    processed: "processed",
    confirmed: "confirmed",
    finalized: "finalized",
    recent: "processed",
    single: "confirmed",
    singleGossip: "confirmed",
    root: "finalized",
    max: "finalized"
  });
  // spec/05 §2.13, §5: fixed English like every other dApp-facing message (2026-11-14: Korean
  // before — "이 지갑은 Bitcoin에서 메시지 서명(소유 증명)만 지원합니다" and "Bitcoin 네트워크는
  // Your Wallet 앱 설정에서만 바꿀 수 있습니다").
  const BTC_TX_UNSUPPORTED = "This wallet supports only message signing (proof of ownership) on Bitcoin.";
  const BTC_NETWORK_FIXED = "The Bitcoin network can only be changed in the Your Wallet app settings.";
  const SOL_MODES = new Set(["off", "phantom"]);
  // spec/05 §2.13 (2026-11-11): the default-mode names say which chain they are — the EIP-6963
  // announcement is "Your Wallet (EVM)" and the Wallet Standard wallet "Your Wallet (Solana)". Multi-chain dApps merge wallets of the same name into one entry
  // (Uniswap: lower-cased, a trailing " wallet" dropped, then EVM connect followed by a Solana
  // connect), so a shared name turned "Your Wallet" into a Solana connection as well.
  const SOL_WALLET_NAME = "Your Wallet (Solana)";
  const BTC_MODES = new Set(["off", "unisat", "xverse"]);
  const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const XVERSE_PROVIDER_ID = "XverseProviders.BitcoinProvider";
  const XVERSE_ACCOUNT_ID = "your-wallet";
  const XVERSE_METHODS = Object.freeze([
    "getInfo", "getAccounts", "signMessage", "wallet_connect", "wallet_disconnect",
    "wallet_getAccount", "wallet_getNetwork", "wallet_renouncePermissions"
  ]);
  const SOL_ACCOUNT_FEATURES = Object.freeze([
    "solana:signMessage", "solana:signIn", "solana:signTransaction", "solana:signAndSendTransaction"
  ]);
  const HEX_PATTERN = /^(?:[0-9a-f]{2})*$/u;
  let solCompatMode = "off";
  let btcCompatMode = "off";
  let solKey = null;
  let solAccount = null;
  let btcAccounts = [];
  let solRegistered = false;
  const solChangeListeners = new Set();
  const phantomListeners = new Map();
  const unisatListeners = new Map();
  const xverseListeners = new Map();
  const appReadyApis = [];

  function base58Encode(bytes) {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) {
      zeros += 1;
    }
    const digits = [];
    for (let index = zeros; index < bytes.length; index += 1) {
      let carry = bytes[index];
      for (let digit = 0; digit < digits.length; digit += 1) {
        carry += digits[digit] * 256;
        digits[digit] = carry % 58;
        carry = Math.floor(carry / 58);
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = Math.floor(carry / 58);
      }
    }
    return "1".repeat(zeros) + digits.reverse().map((digit) => BASE58_ALPHABET[digit]).join("");
  }

  function base58Decode32(text) {
    if (typeof text !== "string" || text.length < 32 || text.length > 44) {
      return null;
    }
    const bytes = [];
    for (const character of text) {
      const value = BASE58_ALPHABET.indexOf(character);
      if (value < 0) {
        return null;
      }
      let carry = value;
      for (let index = 0; index < bytes.length; index += 1) {
        carry += bytes[index] * 58;
        bytes[index] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }
    for (const character of text) {
      if (character !== "1") {
        break;
      }
      bytes.push(0);
    }
    const out = Uint8Array.from(bytes.reverse());
    return out.length === 32 ? out : null;
  }

  // Any base58 text of at most MAX_SOL_TX_BYTES bytes (the Phantom `message` form); else null.
  function base58Decode(text) {
    // 1,232 bytes are at most 1,683 base58 characters.
    if (typeof text !== "string" || text.length < 1 || text.length > 1683) {
      return null;
    }
    let zeros = 0;
    while (zeros < text.length && text[zeros] === "1") {
      zeros += 1;
    }
    const bytes = [];
    for (const character of text) {
      const value = BASE58_ALPHABET.indexOf(character);
      if (value < 0) {
        return null;
      }
      let carry = value;
      for (let index = 0; index < bytes.length; index += 1) {
        carry += bytes[index] * 58;
        bytes[index] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }
    const out = new Uint8Array(zeros + bytes.length);
    out.set(bytes.reverse(), zeros);
    return out.length <= MAX_SOL_TX_BYTES ? out : null;
  }

  function toHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function fromHex(text, length) {
    if (typeof text !== "string" || !HEX_PATTERN.test(text) || (length !== undefined && text.length !== length * 2)) {
      throw internalError();
    }
    const out = new Uint8Array(text.length / 2);
    for (let index = 0; index < out.length; index += 1) {
      out[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
    }
    return out;
  }

  function internalError() {
    return new ProviderRpcError(-32603, "Internal error.");
  }

  function invalidParams() {
    return new ProviderRpcError(-32602, "Invalid params.");
  }

  function unauthorized() {
    return new ProviderRpcError(4100, "Unauthorized.");
  }

  // Uint8Array (or any byte view) → a copy; anything else is -32602.
  function messageBytes(value) {
    if (value instanceof Uint8Array) {
      return Uint8Array.from(value);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    throw invalidParams();
  }

  function emitTo(map, eventName, ...args) {
    for (const listener of [...(map.get(eventName) ?? [])]) {
      try {
        listener(...args);
      } catch (_error) {
        // A dApp listener must not break the provider.
      }
    }
  }

  function addTo(map, names, eventName, listener) {
    if (typeof listener !== "function") {
      throw new TypeError("Provider listener must be a function.");
    }
    if (names.has(eventName)) {
      const list = map.get(eventName) ?? [];
      list.push(listener);
      map.set(eventName, list);
    }
  }

  function removeFrom(map, eventName, listener) {
    const list = map.get(eventName);
    if (list) {
      const index = list.lastIndexOf(listener);
      if (index >= 0) {
        list.splice(index, 1);
      }
    }
  }

  function defineOn(target, name, descriptor) {
    Object.defineProperty(target, name, {
      ...descriptor,
      enumerable: true,
      configurable: false,
      ...(Object.prototype.hasOwnProperty.call(descriptor, "value") ? { writable: false } : {})
    });
  }

  // A minimal web3.js `PublicKey`-like value (no class from the page realm is needed).
  function makePublicKey(bytes) {
    const key = Uint8Array.from(bytes);
    const text = base58Encode(key);
    return Object.freeze({
      toBase58: () => text,
      toString: () => text,
      toJSON: () => text,
      toBytes: () => Uint8Array.from(key),
      toBuffer: () => Uint8Array.from(key),
      equals: (other) => {
        try {
          const value = other !== null && typeof other === "object" && typeof other.toBase58 === "function"
            ? other.toBase58()
            : String(other);
          return value === text;
        } catch (_error) {
          return false;
        }
      }
    });
  }

  function makeSolAccount(bytes) {
    const key = Uint8Array.from(bytes);
    const account = {};
    Object.defineProperties(account, {
      address: { value: base58Encode(key), enumerable: true },
      publicKey: { get: () => key.slice(), enumerable: true },
      chains: { get: () => SOL_CHAINS.slice(), enumerable: true },
      features: { get: () => SOL_ACCOUNT_FEATURES.slice(), enumerable: true }
    });
    return Object.freeze(account);
  }

  // One place for every Solana account change (connect, disconnect, wire events).
  function setSolKey(bytes) {
    const before = solKey === null ? null : base58Encode(solKey);
    solKey = bytes === null ? null : Uint8Array.from(bytes);
    const after = solKey === null ? null : base58Encode(solKey);
    if (before === after) {
      return;
    }
    solAccount = solKey === null ? null : makeSolAccount(solKey);
    const accounts = solAccount === null ? [] : [solAccount];
    for (const listener of [...solChangeListeners]) {
      try {
        listener({ accounts });
      } catch (_error) {
        // Ignored like every other dApp listener.
      }
    }
    if (after === null) {
      emitTo(phantomListeners, "disconnect");
    } else if (before === null) {
      emitTo(phantomListeners, "connect", makePublicKey(solKey));
    } else {
      emitTo(phantomListeners, "accountChanged", makePublicKey(solKey));
    }
  }

  async function solConnect(onlyIfTrusted) {
    const result = await request({ method: "sol_connect", params: onlyIfTrusted ? [{ onlyIfTrusted: true }] : [] });
    const key = isPlainObject(result) ? base58Decode32(result.publicKey) : null;
    if (key === null) {
      throw internalError();
    }
    setSolKey(key);
    return key;
  }

  async function solDisconnect() {
    try {
      await request({ method: "sol_disconnect" });
    } catch (_error) {
      // The page forgets the account either way.
    }
    setSolKey(null);
  }

  async function solSignBytes(message) {
    if (solKey === null) {
      throw unauthorized();
    }
    const result = await request({
      method: "sol_signMessage",
      params: [{ publicKey: base58Encode(solKey), message: toHex(message) }]
    });
    return fromHex(isPlainObject(result) ? result.signature : undefined, 64);
  }

  // Sign-In-With-Solana: connects first when needed (its own window), then the app builds the
  // message from the validated input and the dApp gets exactly the signed bytes back.
  async function solSignIn(input) {
    const value = input === undefined || input === null ? {} : input;
    if (!isPlainObject(value)) {
      throw invalidParams();
    }
    if (solKey === null) {
      await solConnect(false);
    }
    const result = await request({ method: "sol_signIn", params: [{ publicKey: base58Encode(solKey), input: value }] });
    if (!isPlainObject(result)) {
      throw internalError();
    }
    return { signature: fromHex(result.signature, 64), signedMessage: fromHex(result.signedMessage) };
  }

  // ----- Solana dApp transactions (spec/05 §2.13, spec/07 §20) -------------------------------
  // The page's bytes go to the app as they are; the app parses, shows and signs them. The
  // provider only checks the signature layout and, on the way back, that the app changed
  // nothing but one 64-byte signature slot (spec/07 §20.10 step 4).

  // `shortvec(count) ‖ 64·count signatures ‖ message`: the layout of a wire transaction, or null
  // (count ≥ 1, compact-u16 of at most 3 bytes, a non-empty message after the signatures).
  function solSigLayout(bytes) {
    let count = 0;
    let prefix = 0;
    for (;;) {
      if (prefix >= 3 || prefix >= bytes.length) {
        return null;
      }
      const byte = bytes[prefix];
      count |= (byte & 0x7f) << (7 * prefix);
      prefix += 1;
      if ((byte & 0x80) === 0) {
        break;
      }
    }
    const end = prefix + 64 * count;
    return count >= 1 && end < bytes.length ? { prefix, count, end } : null;
  }

  // A page transaction as bytes (a copy): ≤ 1,232 bytes with a valid signature layout, else
  // -32602.
  function solTxBytes(value) {
    const bytes = messageBytes(value);
    if (bytes.length > MAX_SOL_TX_BYTES || solSigLayout(bytes) === null) {
      throw invalidParams();
    }
    return bytes;
  }

  // The app's signed copy of `sent`: the same length and layout, the same bytes outside the
  // signatures, and every changed byte inside one slot. Returns `{ bytes, slot }` (`slot` -1 when
  // nothing changed); anything else is -32603.
  function solSigned(sent, hex) {
    const bytes = fromHex(hex);
    const layout = solSigLayout(sent);
    const back = bytes.length === sent.length ? solSigLayout(bytes) : null;
    if (layout === null || back === null || back.prefix !== layout.prefix || back.count !== layout.count) {
      throw internalError();
    }
    let slot = -1;
    for (let index = 0; index < bytes.length; index += 1) {
      if (bytes[index] === sent[index]) {
        continue;
      }
      if (index < layout.prefix || index >= layout.end) {
        throw internalError();
      }
      const changed = Math.floor((index - layout.prefix) / 64);
      if (slot !== -1 && slot !== changed) {
        throw internalError();
      }
      slot = changed;
    }
    return { bytes, slot };
  }

  // Wallet Standard / Phantom `chain`: absent (`undefined`, `null`) or one of SOL_CHAINS.
  function solChain(value) {
    if (value === undefined || value === null) {
      return undefined;
    }
    if (!SOL_CHAINS.includes(value)) {
      throw invalidParams();
    }
    return value;
  }

  // One chain for a batch: every given chain must be the same.
  function solBatchChain(chains) {
    const given = [...new Set(chains.filter((chain) => chain !== undefined))];
    if (given.length > 1) {
      throw invalidParams();
    }
    return given[0];
  }

  // Send options: only the three known keys are read; `undefined`/`null` is absent, every other
  // key (maxRetries, commitment, mode, …) is ignored and never reaches the wire.
  function solSendOptions(value) {
    if (value === undefined || value === null) {
      return {};
    }
    if (typeof value !== "object") {
      throw invalidParams();
    }
    let skipPreflight;
    let preflightCommitment;
    let minContextSlot;
    try {
      ({ skipPreflight, preflightCommitment, minContextSlot } = value);
    } catch (_error) {
      throw invalidParams();
    }
    const options = {};
    if (skipPreflight !== undefined && skipPreflight !== null) {
      if (typeof skipPreflight !== "boolean") {
        throw invalidParams();
      }
      options.skipPreflight = skipPreflight;
    }
    if (typeof preflightCommitment === "string" && Object.prototype.hasOwnProperty.call(SOL_COMMITMENTS, preflightCommitment)) {
      options.preflightCommitment = SOL_COMMITMENTS[preflightCommitment];
    }
    if (minContextSlot !== undefined && minContextSlot !== null) {
      if (!Number.isSafeInteger(minContextSlot) || minContextSlot < 0) {
        throw invalidParams();
      }
      options.minContextSlot = minContextSlot;
    }
    return options;
  }

  // One approval for 1..=32 transactions: `sol_signTransaction` for one, `sol_signAllTransactions`
  // for more. Returns `[{ bytes, slot }]` in input order.
  async function solSignTransactions(list, chain) {
    if (solKey === null) {
      throw unauthorized();
    }
    if (list.length < 1 || list.length > MAX_SOL_TX_BATCH) {
      throw invalidParams();
    }
    const publicKey = base58Encode(solKey);
    const target = chain === undefined ? {} : { chain };
    if (list.length === 1) {
      const result = await request({
        method: "sol_signTransaction",
        params: [{ publicKey, transaction: toHex(list[0]), ...target }]
      });
      return [solSigned(list[0], isPlainObject(result) ? result.signedTransaction : undefined)];
    }
    const result = await request({
      method: "sol_signAllTransactions",
      params: [{ publicKey, transactions: list.map((bytes) => toHex(bytes)), ...target }]
    });
    const signed = isPlainObject(result) ? result.signedTransactions : undefined;
    if (!Array.isArray(signed) || signed.length !== list.length) {
      throw internalError();
    }
    return list.map((bytes, index) => solSigned(bytes, signed[index]));
  }

  // `sol_signAndSendTransaction`: the app signs, journals and sends; the answer is signature 0
  // (the transaction id). `publicKey` is the account the call was checked against (base58): when
  // the current account is no longer that one (changed or disconnected while an earlier send's
  // window was open), 4100 and nothing posted, never the bytes under another key.
  async function solSignAndSend(bytes, chain, options, publicKey) {
    if (solKey === null || base58Encode(solKey) !== publicKey) {
      throw unauthorized();
    }
    const params = { publicKey, transaction: toHex(bytes) };
    if (chain !== undefined) {
      params.chain = chain;
    }
    if (Object.keys(options).length > 0) {
      params.options = options;
    }
    const result = await request({ method: "sol_signAndSendTransaction", params: [params] });
    return fromHex(isPlainObject(result) ? result.signature : undefined, 64);
  }

  // Sends one after another (no multi-send wire method), all for the one account `publicKey`
  // (base58) the inputs were checked against. A failure after the first, an account change
  // included (4100), rejects with the error of that send and `data: { signatures: [base58…] }` of
  // those already sent.
  async function solSendSerially(items, publicKey) {
    const signatures = [];
    for (const item of items) {
      try {
        signatures.push(await solSignAndSend(item.bytes, item.chain, item.options, publicKey));
      } catch (error) {
        if (signatures.length === 0) {
          throw error;
        }
        const code = error instanceof ProviderRpcError ? error.code : -32603;
        const message = error instanceof ProviderRpcError ? error.message : "Internal error.";
        throw new ProviderRpcError(code, message, { signatures: signatures.map((signature) => base58Encode(signature)) });
      }
    }
    return signatures;
  }

  // A Wallet Standard transaction input `{ account, chain?, transaction, options? }`: the
  // current account (4100 otherwise, nothing posted), its chain and bytes. Getters are read once.
  function solStandardInput(input) {
    if (input === null || typeof input !== "object") {
      throw invalidParams();
    }
    let account;
    let chain;
    let transaction;
    let options;
    try {
      ({ account, chain, transaction, options } = input);
    } catch (_error) {
      throw invalidParams();
    }
    checkSolAccount(account);
    return { chain: solChain(chain), bytes: solTxBytes(transaction), options };
  }

  function solStandardInputs(inputs) {
    if (inputs.length > MAX_SOL_TX_BATCH) {
      throw invalidParams();
    }
    return inputs.map((input) => solStandardInput(input));
  }

  // The `required` zero signatures in front of a bare message (the deprecated Phantom
  // `params.message` form): `required` = msg[0], or msg[1] after the v0 prefix 0x80, ≤ 127.
  function solWrapMessage(message) {
    const versioned = message.length > 0 && (message[0] & 0x80) !== 0;
    if (versioned && message[0] !== 0x80) {
      throw invalidParams();
    }
    const required = versioned ? message[1] : message[0];
    if (!Number.isInteger(required) || required < 1 || required > 127) {
      throw invalidParams();
    }
    const out = new Uint8Array(1 + 64 * required + message.length);
    out[0] = required;
    out.set(message, 1 + 64 * required);
    return solTxBytes(out);
  }

  // A Phantom page transaction (a web3.js `Transaction`/`VersionedTransaction` or bytes) as
  // `{ bytes, rebuild }`: `rebuild(signed)` gives the page's own class again through its
  // constructor's `deserialize` (versioned) or `from` (legacy). Legacy transactions serialize
  // without requiring or verifying signatures (the wallet's slot is still empty). The provider
  // never calls `addSignature` (our PublicKey look-alike is not web3.js's class).
  function solPageTx(tx) {
    if (ArrayBuffer.isView(tx)) {
      return { bytes: solTxBytes(tx), rebuild: (signed) => signed };
    }
    if (tx === null || typeof tx !== "object") {
      throw invalidParams();
    }
    let serialized;
    let factory;
    let owner;
    try {
      const versioned = "version" in tx;
      serialized = versioned ? tx.serialize() : tx.serialize({ requireAllSignatures: false, verifySignatures: false });
      owner = tx.constructor;
      factory = owner === null || owner === undefined ? undefined : owner[versioned ? "deserialize" : "from"];
    } catch (_error) {
      throw invalidParams();
    }
    const bytes = solTxBytes(serialized);
    if (typeof factory !== "function") {
      throw internalError();
    }
    return {
      bytes,
      rebuild: (signed) => {
        try {
          return factory.call(owner, signed);
        } catch (_error) {
          throw internalError();
        }
      }
    };
  }

  function solPageTxs(txs) {
    if (!Array.isArray(txs)) {
      throw invalidParams();
    }
    return txs.map((tx) => solPageTx(tx));
  }

  async function phantomSignAll(txs) {
    if (solKey === null) {
      throw unauthorized();
    }
    const pageTxs = solPageTxs(txs);
    if (pageTxs.length === 0) {
      return [];
    }
    const signed = await solSignTransactions(pageTxs.map((entry) => entry.bytes), undefined);
    return signed.map((entry, index) => pageTxs[index].rebuild(entry.bytes));
  }

  async function phantomSendAll(txs, opts) {
    if (solKey === null) {
      throw unauthorized();
    }
    const pageTxs = solPageTxs(txs);
    if (pageTxs.length > MAX_SOL_TX_BATCH) {
      throw invalidParams();
    }
    const options = solSendOptions(opts);
    const publicKey = base58Encode(solKey);
    const signatures = await solSendSerially(pageTxs.map((entry) => ({ bytes: entry.bytes, chain: undefined, options })), publicKey);
    return { signatures: signatures.map((signature) => base58Encode(signature)), publicKey };
  }

  // Our signature out of a signed `message`-form transaction.
  function ownSignature(signed) {
    if (signed.slot < 0) {
      throw internalError();
    }
    const start = solSigLayout(signed.bytes).prefix + 64 * signed.slot;
    return base58Encode(signed.bytes.slice(start, start + 64));
  }

  function solMessageArgument(value) {
    const message = base58Decode(value);
    if (message === null) {
      throw invalidParams();
    }
    return solWrapMessage(message);
  }

  // The deprecated `request({ method, params: { message(s): base58 } })` form (spec/05 §2.13).
  async function phantomMessageRequest(method, params) {
    if (solKey === null) {
      throw unauthorized();
    }
    const publicKey = base58Encode(solKey);
    if (method === "signTransaction") {
      const [signed] = await solSignTransactions([solMessageArgument(params.message)], undefined);
      return { publicKey, signature: ownSignature(signed) };
    }
    if (method === "signAllTransactions") {
      if (!Array.isArray(params.messages)) {
        throw invalidParams();
      }
      const list = params.messages.map((message) => solMessageArgument(message));
      if (list.length === 0) {
        return { publicKey, signatures: [] };
      }
      const signed = await solSignTransactions(list, undefined);
      return { publicKey, signatures: signed.map((entry) => ownSignature(entry)) };
    }
    const options = solSendOptions(params.options);
    const signature = await solSignAndSend(solMessageArgument(params.message), undefined, options, publicKey);
    return { publicKey, signature: base58Encode(signature) };
  }

  function checkSolAccount(account) {
    let address;
    try {
      address = account.address;
    } catch (_error) {
      address = undefined;
    }
    if (solKey === null || address !== base58Encode(solKey)) {
      throw unauthorized();
    }
  }

  // Wallet Standard features (`@wallet-standard/features`, `@solana/wallet-standard-features`).
  // Transactions (spec.md D38): `solana:signTransaction` signs 1..=32 inputs in one approval,
  // `solana:signAndSendTransaction` checks every input first and then sends them one by one.
  const solFeatures = Object.freeze({
    "standard:connect": Object.freeze({
      version: "1.0.0",
      connect: async (input) => {
        const silent = isPlainObject(input) && input.silent === true;
        if (solKey === null) {
          try {
            await solConnect(silent);
          } catch (error) {
            if (!silent) {
              throw error;
            }
          }
        }
        return { accounts: solAccount === null ? [] : [solAccount] };
      }
    }),
    "standard:disconnect": Object.freeze({ version: "1.0.0", disconnect: () => solDisconnect() }),
    "standard:events": Object.freeze({
      version: "1.0.0",
      on: (eventName, listener) => {
        if (eventName !== "change" || typeof listener !== "function") {
          return () => {};
        }
        const entry = (properties) => listener(properties);
        solChangeListeners.add(entry);
        return () => solChangeListeners.delete(entry);
      }
    }),
    "solana:signMessage": Object.freeze({
      version: "1.0.0",
      signMessage: async (...inputs) => {
        const outputs = [];
        for (const input of inputs) {
          if (!input || typeof input !== "object") {
            throw invalidParams();
          }
          checkSolAccount(input.account);
          const message = messageBytes(input.message);
          const signature = await solSignBytes(message);
          outputs.push({ signedMessage: message, signature, signatureType: "ed25519" });
        }
        return outputs;
      }
    }),
    "solana:signIn": Object.freeze({
      version: "1.0.0",
      signIn: async (...inputs) => {
        const outputs = [];
        for (const input of inputs.length === 0 ? [{}] : inputs) {
          const signed = await solSignIn(input);
          outputs.push({
            account: solAccount,
            signedMessage: signed.signedMessage,
            signature: signed.signature,
            signatureType: "ed25519"
          });
        }
        return outputs;
      }
    }),
    "solana:signTransaction": Object.freeze({
      version: "1.0.0",
      supportedTransactionVersions: SOL_TX_VERSIONS,
      // `options` (preflightCommitment, minContextSlot) has no meaning for signing only and is
      // never put on the wire.
      signTransaction: async (...inputs) => {
        const items = solStandardInputs(inputs);
        if (items.length === 0) {
          return [];
        }
        const chain = solBatchChain(items.map((item) => item.chain));
        const signed = await solSignTransactions(items.map((item) => item.bytes), chain);
        return signed.map((entry) => ({ signedTransaction: entry.bytes }));
      }
    }),
    "solana:signAndSendTransaction": Object.freeze({
      version: "1.0.0",
      supportedTransactionVersions: SOL_TX_VERSIONS,
      signAndSendTransaction: async (...inputs) => {
        const items = solStandardInputs(inputs).map((item) => ({ ...item, options: solSendOptions(item.options) }));
        solBatchChain(items.map((item) => item.chain));
        // Every input named this account (checked above); later sends stay on it.
        const signatures = await solSendSerially(items, solKey === null ? null : base58Encode(solKey));
        return signatures.map((signature) => ({ signature }));
      }
    })
  });

  // Phantom mode names the wallet "Phantom" (our icon, never Phantom's logo).
  const solWallet = Object.freeze(Object.defineProperties({}, {
    version: { value: "1.0.0", enumerable: true },
    name: { get: () => (solCompatMode === "phantom" ? "Phantom" : SOL_WALLET_NAME), enumerable: true },
    icon: { value: PROVIDER_ICON, enumerable: true },
    chains: { get: () => SOL_CHAINS.slice(), enumerable: true },
    features: { value: solFeatures, enumerable: true },
    accounts: { get: () => (solAccount === null ? [] : [solAccount]), enumerable: true }
  }));

  function registerWith(api) {
    try {
      if (api !== null && typeof api === "object" && typeof api.register === "function") {
        api.register(solWallet);
      }
    } catch (_error) {
      // A hostile registry cannot break the provider.
    }
  }

  // Wallet Standard registration: announce once the mode (the name) is known, and answer every
  // app-ready event (an app that started before us got its api queued).
  function registerSolanaWallet() {
    if (solRegistered) {
      return;
    }
    solRegistered = true;
    try {
      root.dispatchEvent(new CustomEvent("wallet-standard:register-wallet", { detail: registerWith }));
    } catch (_error) {
      // Nothing listens yet; app-ready will ask.
    }
    for (const api of appReadyApis.splice(0)) {
      registerWith(api);
    }
  }

  function receiveAppReady(event) {
    let api;
    try {
      api = event.detail;
    } catch (_error) {
      return;
    }
    if (solRegistered) {
      registerWith(api);
    } else if (appReadyApis.length < 16) {
      appReadyApis.push(api);
    }
  }

  // window.phantom.solana (phantom mode only).
  const phantomSolana = {};
  const PHANTOM_EVENTS = new Set(["connect", "disconnect", "accountChanged"]);
  defineOn(phantomSolana, "isPhantom", { value: true });
  defineOn(phantomSolana, "isYourWallet", { value: true });
  defineOn(phantomSolana, "publicKey", { get: () => (solKey === null ? null : makePublicKey(solKey)) });
  defineOn(phantomSolana, "isConnected", { get: () => solKey !== null });
  defineOn(phantomSolana, "connect", {
    value: async (options) => {
      const key = await solConnect(isPlainObject(options) && options.onlyIfTrusted === true);
      return { publicKey: makePublicKey(key) };
    }
  });
  defineOn(phantomSolana, "disconnect", { value: () => solDisconnect() });
  defineOn(phantomSolana, "signMessage", {
    value: async (message, _display) => {
      const signature = await solSignBytes(messageBytes(message));
      return { signature, publicKey: makePublicKey(solKey) };
    }
  });
  defineOn(phantomSolana, "signIn", {
    value: async (input) => {
      const signed = await solSignIn(input);
      return { address: makePublicKey(solKey), signedMessage: signed.signedMessage, signature: signed.signature };
    }
  });
  // Transactions (spec/05 §2.13): the page's own class comes back for a class instance.
  defineOn(phantomSolana, "signTransaction", {
    value: async (tx) => {
      const [signed] = await phantomSignAll([tx]);
      return signed;
    }
  });
  defineOn(phantomSolana, "signAllTransactions", { value: (txs) => phantomSignAll(txs) });
  defineOn(phantomSolana, "signAndSendTransaction", {
    value: async (tx, opts) => {
      const { signatures, publicKey } = await phantomSendAll([tx], opts);
      return { signature: signatures[0], publicKey };
    }
  });
  defineOn(phantomSolana, "signAndSendAllTransactions", { value: (txs, opts) => phantomSendAll(txs, opts) });
  const PHANTOM_TX_METHODS = new Set(["signTransaction", "signAllTransactions", "signAndSendTransaction", "signAndSendAllTransactions"]);
  defineOn(phantomSolana, "request", {
    value: async (args) => {
      const method = isPlainObject(args) ? args.method : undefined;
      const params = isPlainObject(args) && isPlainObject(args.params) ? args.params : {};
      if (method === "connect") {
        return phantomSolana.connect(params);
      }
      if (method === "disconnect") {
        return phantomSolana.disconnect();
      }
      if (method === "signMessage") {
        return phantomSolana.signMessage(params.message, params.display);
      }
      if (method === "signIn") {
        return phantomSolana.signIn(params);
      }
      if (PHANTOM_TX_METHODS.has(method)) {
        // The deprecated base58 `message(s)` form, else the transaction object(s).
        if (method !== "signAndSendAllTransactions" && (params.message !== undefined || params.messages !== undefined)) {
          return phantomMessageRequest(method, params);
        }
        if (method === "signTransaction") {
          return phantomSolana.signTransaction(params.transaction);
        }
        if (method === "signAllTransactions") {
          return phantomSolana.signAllTransactions(params.transactions);
        }
        if (method === "signAndSendTransaction") {
          return phantomSolana.signAndSendTransaction(params.transaction, params.options);
        }
        return phantomSolana.signAndSendAllTransactions(params.transactions, params.options);
      }
      throw new ProviderRpcError(4200, SOL_REQUEST_UNSUPPORTED);
    }
  });
  for (const name of ["on", "addListener"]) {
    defineOn(phantomSolana, name, {
      value: (eventName, listener) => {
        addTo(phantomListeners, PHANTOM_EVENTS, eventName, listener);
        return phantomSolana;
      }
    });
  }
  for (const name of ["off", "removeListener"]) {
    defineOn(phantomSolana, name, {
      value: (eventName, listener) => {
        removeFrom(phantomListeners, eventName, listener);
        return phantomSolana;
      }
    });
  }
  defineOn(phantomSolana, "removeAllListeners", {
    value: (eventName) => {
      if (eventName === undefined) {
        phantomListeners.clear();
      } else {
        phantomListeners.delete(eventName);
      }
      return phantomSolana;
    }
  });
  const phantomNamespace = Object.freeze({ solana: phantomSolana });

  function phantomGetter() {
    return phantomNamespace;
  }

  // ----- Bitcoin ------------------------------------------------------------------------------

  function setBtcAccounts(value) {
    if (!Array.isArray(value) || !value.every((entry) => isPlainObject(entry) && typeof entry.address === "string")) {
      throw internalError();
    }
    btcAccounts = value.map((entry) => Object.freeze({ ...entry }));
    return btcAccounts;
  }

  async function btcConnect(purposes) {
    return setBtcAccounts(await request({ method: "btc_requestAccounts", params: [{ purposes }] }));
  }

  async function btcGetAccounts() {
    return setBtcAccounts(await request({ method: "btc_getAccounts" }));
  }

  async function btcDisconnect() {
    try {
      await request({ method: "btc_disconnect" });
    } catch (_error) {
      // Forgotten locally either way.
    }
    receiveBtcAddresses([]);
  }

  async function btcNetwork() {
    const network = await request({ method: "btc_getNetwork" });
    if (network !== "mainnet" && network !== "testnet4") {
      throw internalError();
    }
    return network;
  }

  function btcTxRejected() {
    return Promise.reject(new ProviderRpcError(4200, BTC_TX_UNSUPPORTED));
  }

  // A wire `btcAccountsChanged` (or a local disconnect).
  function receiveBtcAddresses(addresses) {
    btcAccounts = btcAccounts.filter((entry) => addresses.includes(entry.address));
    emitTo(unisatListeners, "accountsChanged", addresses.slice());
    if (addresses.length === 0) {
      emitTo(xverseListeners, "disconnect", { type: "disconnect" });
    } else {
      emitTo(xverseListeners, "accountChange", { type: "accountChange", addresses: xverseAddresses(btcAccounts) });
    }
  }

  function unisatChain(network) {
    return network === "mainnet"
      ? { enum: "BITCOIN_MAINNET", name: "Bitcoin Mainnet", network: "livenet" }
      : { enum: "BITCOIN_TESTNET4", name: "Bitcoin Testnet4", network: "testnet" };
  }

  // window.unisat (unisat mode only).
  const unisat = {};
  const UNISAT_EVENTS = new Set(["accountsChanged", "networkChanged"]);
  defineOn(unisat, "isYourWallet", { value: true });
  defineOn(unisat, "requestAccounts", { value: async () => (await btcConnect(["any"])).map((entry) => entry.address) });
  defineOn(unisat, "getAccounts", { value: async () => (await btcGetAccounts()).map((entry) => entry.address) });
  defineOn(unisat, "getNetwork", { value: async () => unisatChain(await btcNetwork()).network });
  defineOn(unisat, "switchNetwork", {
    value: async (network) => {
      const current = unisatChain(await btcNetwork()).network;
      if (network === current) {
        return current;
      }
      throw new ProviderRpcError(4200, BTC_NETWORK_FIXED);
    }
  });
  defineOn(unisat, "getChain", { value: async () => unisatChain(await btcNetwork()) });
  defineOn(unisat, "switchChain", {
    value: async (chain) => {
      const current = unisatChain(await btcNetwork());
      if (chain === current.enum) {
        return current;
      }
      throw new ProviderRpcError(4200, BTC_NETWORK_FIXED);
    }
  });
  defineOn(unisat, "getPublicKey", {
    value: async () => {
      const accounts = btcAccounts.length > 0 ? btcAccounts : await btcGetAccounts();
      if (accounts.length === 0) {
        throw unauthorized();
      }
      return accounts[0].publicKey;
    }
  });
  defineOn(unisat, "signMessage", {
    value: async (message, type = "ecdsa") => {
      const protocol = type === "ecdsa" ? "ecdsa" : type === "bip322-simple" ? "bip322" : null;
      if (typeof message !== "string" || protocol === null) {
        throw invalidParams();
      }
      const accounts = btcAccounts.length > 0 ? btcAccounts : await btcGetAccounts();
      if (accounts.length === 0) {
        throw unauthorized();
      }
      const result = await request({
        method: "btc_signMessage",
        params: [{ address: accounts[0].address, message, protocol }]
      });
      if (!isPlainObject(result) || typeof result.signature !== "string") {
        throw internalError();
      }
      return result.signature;
    }
  });
  for (const name of [
    "getBalance", "getInscriptions", "sendBitcoin", "sendInscription", "inscribeTransfer",
    "signPsbt", "signPsbts", "pushPsbt", "pushTx", "sendRunes"
  ]) {
    defineOn(unisat, name, { value: () => btcTxRejected() });
  }
  defineOn(unisat, "on", {
    value: (eventName, listener) => {
      addTo(unisatListeners, UNISAT_EVENTS, eventName, listener);
      return unisat;
    }
  });
  defineOn(unisat, "removeListener", {
    value: (eventName, listener) => {
      removeFrom(unisatListeners, eventName, listener);
      return unisat;
    }
  });

  function unisatGetter() {
    return unisat;
  }

  // sats-connect (Xverse) shapes: addresses carry walletType, Taproot keys are x-only.
  function xverseAddresses(accounts) {
    return accounts.map((entry) => ({
      address: entry.address,
      publicKey: entry.addressType === "p2tr" && typeof entry.publicKey === "string" && entry.publicKey.length === 66
        ? entry.publicKey.slice(2)
        : entry.publicKey,
      purpose: entry.purpose === "any" ? "payment" : entry.purpose,
      addressType: entry.addressType,
      walletType: "software"
    }));
  }

  function xversePurposes(value) {
    if (!Array.isArray(value)) {
      throw invalidParams();
    }
    const purposes = ["payment", "ordinals"].filter((purpose) => value.includes(purpose));
    if (purposes.length === 0) {
      throw invalidParams();
    }
    return purposes;
  }

  async function xverseNetwork() {
    const network = await btcNetwork();
    return {
      bitcoin: { name: network === "mainnet" ? "Mainnet" : "Testnet4" },
      stacks: { name: "mainnet" },
      spark: { name: "mainnet" }
    };
  }

  async function xverseCall(method, params) {
    switch (method) {
      case "getInfo":
        return { version: "1.0.0", methods: XVERSE_METHODS.slice(), supports: [] };
      case "getAccounts":
        return xverseAddresses(await btcConnect(xversePurposes(isPlainObject(params) ? params.purposes : undefined)));
      case "wallet_connect": {
        const wanted = isPlainObject(params) && Array.isArray(params.addresses) ? params.addresses : ["payment", "ordinals"];
        const accounts = await btcConnect(xversePurposes(wanted));
        return { id: XVERSE_ACCOUNT_ID, addresses: xverseAddresses(accounts), walletType: "software", network: await xverseNetwork() };
      }
      case "wallet_getAccount": {
        const accounts = await btcGetAccounts();
        if (accounts.length === 0) {
          throw unauthorized();
        }
        return { id: XVERSE_ACCOUNT_ID, addresses: xverseAddresses(accounts), walletType: "software", network: await xverseNetwork() };
      }
      case "wallet_disconnect":
      case "wallet_renouncePermissions":
        await btcDisconnect();
        return null;
      case "wallet_getNetwork":
        return xverseNetwork();
      case "signMessage": {
        if (!isPlainObject(params) || typeof params.address !== "string" || typeof params.message !== "string"
          || (params.protocol !== undefined && params.protocol !== "ECDSA" && params.protocol !== "BIP322")) {
          throw invalidParams();
        }
        const result = await request({
          method: "btc_signMessage",
          params: [{
            address: params.address,
            message: params.message,
            ...(params.protocol === undefined ? {} : { protocol: params.protocol === "BIP322" ? "bip322" : "ecdsa" })
          }]
        });
        if (!isPlainObject(result)) {
          throw internalError();
        }
        return {
          signature: result.signature,
          messageHash: result.messageHash,
          address: result.address,
          protocol: result.protocol === "bip322" ? "BIP322" : "ECDSA"
        };
      }
      default:
        throw new ProviderRpcError(4200, BTC_TX_UNSUPPORTED);
    }
  }

  // sats-connect RpcErrorCode: USER_REJECTION -32000, METHOD_NOT_SUPPORTED -32001,
  // ACCESS_DENIED -32002, INVALID_PARAMS -32602, INTERNAL_ERROR -32603.
  function xverseError(error) {
    const code = error instanceof ProviderRpcError ? error.code : -32603;
    const mapped = code === 4001 ? -32000
      : code === 4200 ? -32001
        : code === 4100 ? -32002
          : code === -32602 || code === -32600 ? code
            : -32603;
    const message = error instanceof ProviderRpcError ? error.message : "Internal error.";
    return { code: mapped, message };
  }

  // window.XverseProviders.BitcoinProvider (xverse mode only): sats-connect `request(method,
  // params)` answers a JSON-RPC 2.0 response object, success or error.
  const xverseProvider = {};
  const XVERSE_EVENTS = new Set(["accountChange", "networkChange", "disconnect"]);
  defineOn(xverseProvider, "isYourWallet", { value: true });
  defineOn(xverseProvider, "request", {
    value: async (method, params) => {
      const id = randomHex(8);
      try {
        const result = await xverseCall(method, params);
        return { jsonrpc: "2.0", id, result };
      } catch (error) {
        return { jsonrpc: "2.0", id, error: xverseError(error) };
      }
    }
  });
  defineOn(xverseProvider, "addListener", {
    value: (eventNameOrInfo, maybeListener) => {
      const info = isPlainObject(eventNameOrInfo) ? eventNameOrInfo : { eventName: eventNameOrInfo, cb: maybeListener };
      addTo(xverseListeners, XVERSE_EVENTS, info.eventName, info.cb);
      return () => removeFrom(xverseListeners, info.eventName, info.cb);
    }
  });
  // The pre-RPC sats-connect API (JWT strings): not supported.
  for (const name of [
    "connect", "signMessage", "signTransaction", "sendBtcTransaction", "createInscription",
    "createRepeatInscriptions", "signMultipleTransactions"
  ]) {
    defineOn(xverseProvider, name, { value: () => btcTxRejected() });
  }
  const xverseNamespace = Object.freeze({ BitcoinProvider: xverseProvider });

  function xverseGetter() {
    return xverseNamespace;
  }

  // WBIP004 provider list entry (xverse mode): sats-connect's default provider id, our icon.
  function ensureBtcProviders() {
    const entry = Object.freeze({
      id: XVERSE_PROVIDER_ID,
      name: "Xverse Wallet",
      icon: PROVIDER_ICON,
      methods: Object.freeze(XVERSE_METHODS.slice())
    });
    try {
      if (!Array.isArray(root.btc_providers)) {
        Object.defineProperty(root, "btc_providers", { value: [], configurable: true, enumerable: true, writable: true });
      }
      const list = root.btc_providers;
      const index = list.findIndex((provider) => provider !== null && typeof provider === "object" && provider.id === XVERSE_PROVIDER_ID);
      if (index >= 0) {
        list.splice(index, 1, entry);
      } else {
        list.push(entry);
      }
    } catch (_error) {
      // A frozen or hostile list stays as it is.
    }
  }

  function ignoreAssignment(_ignored) {
    // Assignments by other wallets are accepted and ignored (like window.ethereum).
  }

  // window.phantom / window.unisat / window.XverseProviders in their modes: the same precedence
  // rules as window.ethereum in a compatibility mode (spec/05 §2.12).
  function claimGlobal(name, getter) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(root, name);
      if (descriptor !== undefined && descriptor.get === getter) {
        return true;
      }
    } catch (_error) {
      return false;
    }
    if (descriptor === undefined || descriptor.configurable === true) {
      try {
        Object.defineProperty(root, name, { get: getter, set: ignoreAssignment, configurable: true, enumerable: true });
        return true;
      } catch (_error) {
        // Fall through to assignment.
      }
    }
    try {
      root[name] = getter();
    } catch (_error) {
      // Not assignable: another wallet keeps it.
    }
    try {
      return root[name] === getter();
    } catch (_error) {
      return false;
    }
  }

  function defineIfAbsent(name, value) {
    try {
      if (!(name in root)) {
        Object.defineProperty(root, name, { value, configurable: true, enumerable: true, writable: true });
      }
    } catch (_error) {
      // A page-defined accessor or proxy stays.
    }
  }

  function claimChainGlobals() {
    if (solCompatMode === "phantom") {
      claimGlobal("phantom", phantomGetter);
    }
    if (btcCompatMode === "unisat") {
      claimGlobal("unisat", unisatGetter);
    }
    if (btcCompatMode === "xverse") {
      claimGlobal("XverseProviders", xverseGetter);
      ensureBtcProviders();
    }
  }

  function settleChainModes(sol, btc) {
    solCompatMode = SOL_MODES.has(sol) ? sol : "off";
    btcCompatMode = BTC_MODES.has(btc) ? btc : "off";
    claimChainGlobals();
    if (solCompatMode === "phantom") {
      defineIfAbsent("solana", phantomSolana);
    }
    if (btcCompatMode === "xverse") {
      defineIfAbsent("BitcoinProvider", xverseProvider);
    }
    registerSolanaWallet();
  }

  function receiveChainEvent(eventName, payload) {
    if (eventName === "solAccountsChanged" && Array.isArray(payload) && payload.length <= 1) {
      const key = payload.length === 1 ? base58Decode32(payload[0]) : null;
      if (payload.length === 0 || key !== null) {
        setSolKey(key);
      }
      return true;
    }
    if (eventName === "btcAccountsChanged" && Array.isArray(payload)
      && payload.every((address) => typeof address === "string")) {
      receiveBtcAddresses(payload);
      return true;
    }
    return false;
  }

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
  defineMember("isConnected", { value: () => bridgeOpen && !dead });
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
  root.addEventListener("message", receiveMetaMaskConnect);
  root.addEventListener(EIP6963_REQUEST_EVENT, receiveProviderRequest);
  root.addEventListener("DOMContentLoaded", reclaimWindowEthereum);
  root.addEventListener("load", reclaimWindowEthereum);
  root.addEventListener("DOMContentLoaded", claimChainGlobals);
  root.addEventListener("load", claimChainGlobals);
  root.addEventListener("wallet-standard:app-ready", receiveAppReady);
  installWindowEthereum();
  modeTimer = root.setTimeout(() => settleMode("off", "off", "off"), MODE_WAIT_MS);
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
  // In every mode a foreign MetaMask announcement is remembered (see receiveMetaMaskConnect).
  function interceptAnnouncement(event) {
    try {
      const detail = event.detail;
      if (detail === providerDetails[compatMode]) {
        return;
      }
      const info = detail !== null && typeof detail === "object" ? detail.info : undefined;
      const rdns = info !== null && typeof info === "object" ? info.rdns : undefined;
      if (typeof rdns !== "string") {
        return;
      }
      const normalized = rdns.toLowerCase();
      if (MM_RDNS.has(normalized)) {
        foreignMetaMaskSeen = true;
      }
      if (compatMode !== "off" && INTERCEPTED_RDNS.has(normalized)) {
        event.stopImmediatePropagation();
      }
    } catch (_error) {
      // Leave events we cannot inspect alone.
    }
  }

  // MetaMask Connect's request to MetaMask's content script (spec/05 §2.12): in metamask mode,
  // with no real MetaMask on the page, every request on the multichain substream is answered with
  // 4200 at once (notifications, without an id, get nothing). Only the page's own messages count.
  function receiveMetaMaskConnect(event) {
    if (compatMode !== "metamask" || foreignMetaMaskSeen || event.source !== root || event.origin !== targetOrigin) {
      return;
    }
    let id;
    try {
      const message = event.data;
      if (!isPlainObject(message) || message.target !== MM_CONTENT_SCRIPT) {
        return;
      }
      const envelope = message.data;
      if (!isPlainObject(envelope) || envelope.name !== MM_MULTICHAIN_STREAM) {
        return;
      }
      const body = envelope.data;
      if (!isPlainObject(body) || typeof body.method !== "string") {
        return;
      }
      id = body.id;
    } catch (_error) {
      return;
    }
    if (!Number.isSafeInteger(id) && !(typeof id === "string" && id.length >= 1 && id.length <= 128)) {
      return;
    }
    if (!metaMaskConnectWarned && nativeWarn !== null) {
      metaMaskConnectWarned = true;
      try {
        nativeWarn(`[Your Wallet] ${MM_CONNECT_UNSUPPORTED}`);
      } catch (_error) {
        // Logging is best effort.
      }
    }
    try {
      root.postMessage({
        target: MM_INPAGE,
        data: {
          name: MM_MULTICHAIN_STREAM,
          data: { jsonrpc: "2.0", id, error: { code: 4200, message: MM_CONNECT_UNSUPPORTED } }
        }
      }, targetOrigin);
    } catch (_error) {
      // The window is closing.
    }
  }

  function settleMode(mode, sol, btc) {
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
    settleChainModes(sol, btc);
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

  // MetaMask's `metamask_getProviderState` in the compatibility modes (spec/05 §2.12): answered
  // in the page from three ordinary requests (no wire method of its own, no extensionId).
  // `isUnlocked` follows `_metamask.isUnlocked()`: accounts exposed to this origin now.
  async function providerState() {
    const [accounts, chainId, networkVersion] = await Promise.all([
      request({ method: "eth_accounts" }),
      request({ method: "eth_chainId" }),
      request({ method: "net_version" })
    ]);
    const list = Array.isArray(accounts) ? accounts.filter((account) => typeof account === "string") : [];
    return { accounts: list, chainId, isUnlocked: list.length > 0, networkVersion };
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
    if (method === "metamask_getProviderState" && compatMode !== "off") {
      return providerState();
    }
    if (!bridgeOpen && !dead) {
      await waitForBridge();
    }
    if (dead) {
      throw reloadedError();
    }
    if (!bridgeOpen) {
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
    if (message.kind === "bridge-claim") {
      // The content script posts this synchronously at document_start, before any page script
      // runs; window messages are delivered in posting order, so a page's forged bridge-init or
      // bridge-claim always arrives after it and finds the channel taken.
      if (hasExactKeys(message, ["namespace", "version", "kind", "channel"])
        && typeof message.channel === "string"
        && CHANNEL_PATTERN.test(message.channel)
        && channel === null
        && !dead) {
        channel = message.channel;
      }
      return;
    }
    if (message.kind === "bridge-init") {
      if (hasExactKeys(message, ["namespace", "version", "kind", "channel", "compatMode", "solCompatMode", "btcCompatMode"])
        && typeof message.channel === "string"
        && CHANNEL_PATTERN.test(message.channel)
        && typeof message.compatMode === "string"
        && Object.prototype.hasOwnProperty.call(IDENTITIES, message.compatMode)
        && SOL_MODES.has(message.solCompatMode)
        && BTC_MODES.has(message.btcCompatMode)
        && (channel === null || channel === message.channel)
        && !bridgeOpen
        && !dead) {
        channel = message.channel;
        bridgeOpen = true;
        settleMode(message.compatMode, message.solCompatMode, message.btcCompatMode);
        releaseBridgeWaiters();
      }
      return;
    }
    if (!bridgeOpen || message.channel !== channel) {
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
    if (receiveChainEvent(eventName, payload)) {
      return;
    }
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
  // Copy of shared.js isSupportedPageUrl (spec/05 §2.4/§4.7, native-host/v1-origins.golden.json).
  // Function declarations are hoisted, so the constants live inside: this runs before the
  // provider's top-level `const`s are initialized.
  function isSupportedPage(location) {
    let url;
    try {
      url = new URL(location.href);
    } catch (_error) {
      return false;
    }
    if (url.username !== "" || url.password !== "" || url.origin === "null"
      || url.hostname === "" || url.hostname.startsWith("[")
      || url.port === "0" || url.origin.length > 256) {
      return false;
    }
    if (url.protocol === "https:") {
      return url.hostname.length <= 253
        && url.hostname.split(".").every((label) => /^[a-z0-9_-]{1,63}$/u.test(label));
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
