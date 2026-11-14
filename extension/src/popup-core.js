(function installYourWalletPopupCore(root) {
  "use strict";

  if (Object.prototype.hasOwnProperty.call(root, "__YOUR_WALLET_POPUP_CORE__")) {
    return;
  }

  const shared = root.__YOUR_WALLET_SHARED__;
  if (!shared) {
    throw new Error("Your Wallet shared module was not loaded.");
  }

  // spec/05 §2.12: pure text and parsing for the action popup (no Chrome or DOM APIs here).
  // 2026-11-14: every text is a `{ ko, en }` pair (Korean before only); the per-language tables
  // below are derived from these, so a missing translation leaves a key out of one table and the
  // popup tests fail. `explanation` is the one-line description of each mode.
  const MODE_SOURCE = [
    {
      value: "off",
      label: { ko: "기본 (Your Wallet EVM)", en: "Default (Your Wallet EVM)" },
      explanation: {
        ko: "dApp에 Your Wallet (EVM) 이름으로 보이며, 다른 지갑 확장은 건드리지 않습니다.",
        en: "dApps see it as Your Wallet (EVM); other wallet extensions are left alone."
      }
    },
    {
      value: "metamask",
      label: { ko: "MetaMask처럼 보이기", en: "Look like MetaMask" },
      explanation: {
        ko: "MetaMask만 지원하는 dApp에서 쓰며, 승인 창은 그대로 Your Wallet 앱에 뜹니다.",
        en: "For MetaMask-only dApps; approvals still appear in the Your Wallet app."
      }
    },
    {
      value: "rabby",
      label: { ko: "Rabby처럼 보이기", en: "Look like Rabby" },
      explanation: {
        ko: "Rabby만 지원하는 dApp에서 쓰며, 승인 창은 그대로 Your Wallet 앱에 뜹니다.",
        en: "For Rabby-only dApps; approvals still appear in the Your Wallet app."
      }
    }
  ];

  // spec/05 §2.13: Solana and Bitcoin modes (Solana: connect, messages and transactions;
  // Bitcoin: connect and messages).
  const SOL_MODE_SOURCE = [
    {
      value: "off",
      label: { ko: "기본 (Your Wallet Solana)", en: "Default (Your Wallet Solana)" },
      explanation: {
        ko: "Solana dApp의 지갑 목록에 Your Wallet (Solana) 이름으로 보입니다.",
        en: "Listed as Your Wallet (Solana) in the wallet lists of Solana dApps."
      }
    },
    {
      value: "phantom",
      label: { ko: "Phantom처럼 보이기", en: "Look like Phantom" },
      explanation: {
        ko: "Phantom만 지원하는 dApp에서 쓰며, 아이콘은 Your Wallet 그대로입니다.",
        en: "For Phantom-only dApps; the icon stays the Your Wallet icon."
      }
    }
  ];

  const BTC_MODE_SOURCE = [
    {
      value: "off",
      label: { ko: "사용 안 함", en: "Off" },
      explanation: {
        ko: "dApp에 Bitcoin 지갑을 보이지 않습니다.",
        en: "No Bitcoin wallet is shown to dApps."
      }
    },
    {
      value: "unisat",
      label: { ko: "UniSat처럼 보이기", en: "Look like UniSat" },
      explanation: {
        ko: "UniSat 방식(window.unisat)을 쓰는 dApp에서 주소 연결과 메시지 서명을 합니다.",
        en: "Connect and sign messages in dApps that use UniSat (window.unisat)."
      }
    },
    {
      value: "xverse",
      label: { ko: "Xverse처럼 보이기", en: "Look like Xverse" },
      explanation: {
        ko: "sats-connect(Xverse) 방식 dApp에서 주소 연결과 메시지 서명을 합니다.",
        en: "Connect and sign messages in sats-connect (Xverse) dApps."
      }
    }
  ];

  const TEXT_SOURCE = {
    title: { ko: "Your Wallet", en: "Your Wallet" },
    statusHeading: { ko: "Your Wallet 앱 연결 상태", en: "Your Wallet app connection" },
    statusLoading: { ko: "확인하는 중…", en: "Checking…" },
    statusStale: {
      ko: "지난번에 확인한 상태입니다. 지금 다시 확인하는 중…",
      en: "This is the last known status. Checking again now…"
    },
    metamaskConnectNote: {
      ko: "Uniswap처럼 MetaMask Connect로 MetaMask 확장과 직접 통신하는 dApp에서는 이 모드로 연결되지 않습니다. 그런 dApp에서는 기본이나 Rabby처럼 보이기를 쓰세요.",
      en: "This mode cannot connect to dApps such as Uniswap that talk to the MetaMask extension directly through MetaMask Connect. On those dApps, use Default or Look like Rabby."
    },
    modeHeading: { ko: "EVM (이더리움 등) dApp에 보이는 지갑", en: "Wallet shown to EVM (Ethereum etc.) dApps" },
    warning: {
      ko: "호환 모드를 쓸 때는 실제 MetaMask·Rabby 확장을 꺼 두세요. 켜져 있으면 dApp이 그 지갑에 연결될 수 있습니다.",
      en: "When you use a compatibility mode, turn off the real MetaMask and Rabby extensions. If they are on, dApps may connect to them instead."
    },
    applyNote: {
      ko: "모드 변경은 다음 페이지 로드부터 적용됩니다(열린 dApp 탭은 새로고침).",
      en: "Mode changes apply from the next page load (reload open dApp tabs)."
    },
    saved: { ko: "저장했습니다. 다음 페이지 로드부터 적용됩니다.", en: "Saved. It applies from the next page load." },
    saveFailed: {
      ko: "저장하지 못했습니다. 팝업을 닫았다가 다시 열어 보세요.",
      en: "Could not save. Close the popup and open it again."
    },
    loadFailed: {
      ko: "저장된 모드를 읽지 못해 기본 모드로 표시합니다.",
      en: "Could not read the saved modes, so the default modes are shown."
    },
    solHeading: { ko: "Solana dApp에 보이는 지갑", en: "Wallet shown to Solana dApps" },
    btcHeading: { ko: "Bitcoin dApp에 보이는 지갑", en: "Wallet shown to Bitcoin dApps" },
    solWarning: {
      ko: "Phantom처럼 보이기를 쓸 때는 실제 Phantom 확장을 꺼 두세요. Solana 지갑 목록(Wallet Standard)에서는 실제 Phantom을 숨길 수 없어 두 지갑이 함께 보일 수 있습니다.",
      en: "When you use Look like Phantom, turn off the real Phantom extension. The Solana wallet list (Wallet Standard) cannot hide the real Phantom, so both wallets may appear."
    },
    btcWarning: {
      ko: "UniSat·Xverse처럼 보이기를 쓸 때는 실제 UniSat·Xverse 확장을 꺼 두세요. 켜져 있으면 dApp이 그 지갑에 연결될 수 있습니다.",
      en: "When you use Look like UniSat or Xverse, turn off the real UniSat and Xverse extensions. If they are on, dApps may connect to them instead."
    },
    chainNote: {
      ko: "Bitcoin은 연결과 메시지 서명만 됩니다. Solana는 거래 서명·전송도 됩니다.",
      en: "Bitcoin supports connecting and message signing only. Solana also signs and sends transactions."
    }
  };

  // tone: ok → 성공 colors, bad → 고위험 colors, neutral → 정보 colors (popup.css).
  const STATUS_SOURCE = {
    connected: {
      tone: "ok",
      text: { ko: "연결됨", en: "Connected" },
      detail: { ko: "Your Wallet 앱이 마지막 요청에 응답했습니다.", en: "The Your Wallet app answered the last request." }
    },
    checking: {
      tone: "neutral",
      text: { ko: "확인 중", en: "Checking" },
      detail: {
        ko: "Your Wallet 앱에 연결해 응답을 기다리는 중입니다.",
        en: "Connected to the Your Wallet app and waiting for its answer."
      }
    },
    unavailable: {
      tone: "bad",
      text: { ko: "연결 안 됨", en: "Not connected" },
      detail: {
        ko: "Your Wallet 앱에 연결하지 못했습니다. 앱이 실행 중인지, native host가 등록되어 있는지 확인하세요.",
        en: "Could not connect to the Your Wallet app. Check that the app is running and that the native host is registered."
      }
    },
    unknown: {
      tone: "neutral",
      text: { ko: "확인 불가", en: "Unknown" },
      detail: {
        ko: "아직 dApp 요청이 없었습니다(설치 직후 정상). 사이트에서 “지갑 연결”을 누르면 연결됨으로 바뀝니다. 설치 전에 연 탭은 새로고침하세요.",
        en: "No dApp request yet (normal right after installing). Press “Connect wallet” on a site and this changes to Connected. Reload tabs opened before the install."
      }
    }
  };

  const LANGUAGES = shared.LANGUAGES;

  function perLanguage(build) {
    return Object.freeze(Object.fromEntries(LANGUAGES.map((lang) => [lang, build(lang)])));
  }

  function optionsIn(source, lang) {
    return Object.freeze(source.map((option) => Object.freeze({
      value: option.value,
      label: option.label[lang],
      explanation: option.explanation[lang]
    })));
  }

  // `{ ko: [...], en: [...] }` / `{ ko: {...}, en: {...} }`: the same keys and values in both.
  const MODE_OPTIONS = perLanguage((lang) => optionsIn(MODE_SOURCE, lang));
  const SOL_MODE_OPTIONS = perLanguage((lang) => optionsIn(SOL_MODE_SOURCE, lang));
  const BTC_MODE_OPTIONS = perLanguage((lang) => optionsIn(BTC_MODE_SOURCE, lang));
  const TEXT = perLanguage((lang) => Object.freeze(Object.fromEntries(
    Object.entries(TEXT_SOURCE).map(([key, text]) => [key, text[lang]])
  )));
  const STATUS_VIEWS = perLanguage((lang) => Object.freeze(Object.fromEntries(
    Object.entries(STATUS_SOURCE).map(([key, view]) => [key, Object.freeze({ text: view.text[lang], tone: view.tone, detail: view.detail[lang] })])
  )));
  const STATUS_WORDS = Object.freeze(Object.keys(STATUS_SOURCE));

  // The popup's language table for `lang` (anything but "en" is Korean).
  function texts(lang) {
    return TEXT[shared.normalizeLanguage(lang)];
  }

  const GROUPS = Object.freeze({
    evm: Object.freeze({ key: shared.COMPAT_MODE_STORAGE_KEY, options: MODE_OPTIONS, normalize: shared.normalizeCompatMode }),
    sol: Object.freeze({ key: shared.SOL_COMPAT_MODE_STORAGE_KEY, options: SOL_MODE_OPTIONS, normalize: shared.normalizeSolCompatMode }),
    btc: Object.freeze({ key: shared.BTC_COMPAT_MODE_STORAGE_KEY, options: BTC_MODE_OPTIONS, normalize: shared.normalizeBtcCompatMode })
  });

  // Group `kind`'s mode cards in `lang`.
  function groupOptions(kind, lang) {
    return GROUPS[kind].options[shared.normalizeLanguage(lang)];
  }

  // What the popup writes for a selection in group `kind` (null for anything else).
  function storageUpdateFor(kind, mode) {
    const group = Object.prototype.hasOwnProperty.call(GROUPS, kind) ? GROUPS[kind] : null;
    return group !== null && group.normalize(mode) === mode ? { [group.key]: mode } : null;
  }

  // What the language toggle writes to chrome.storage.local (null for anything but "ko"/"en").
  function languageUpdate(lang) {
    return shared.normalizeLanguage(lang) === lang ? { [shared.LANGUAGE_STORAGE_KEY]: lang } : null;
  }

  function isStatusWord(status) {
    return typeof status === "string" && STATUS_WORDS.includes(status);
  }

  function modeOption(mode, lang = "ko") {
    const normalized = shared.normalizeCompatMode(mode);
    return groupOptions("evm", lang).find((option) => option.value === normalized);
  }

  function statusView(status, lang = "ko") {
    const views = STATUS_VIEWS[shared.normalizeLanguage(lang)];
    return isStatusWord(status) ? views[status] : views.unknown;
  }

  // background → popup `{ namespace, version, kind: "status", native }`, exact keys.
  function parseStatusMessage(value) {
    if (!shared.hasExactKeys(value, ["namespace", "version", "kind", "native"])
      || value.namespace !== shared.NAMESPACE
      || value.version !== shared.PROTOCOL_VERSION
      || value.kind !== "status"
      || !isStatusWord(value.native)) {
      return null;
    }
    return value.native;
  }

  // A group's "turn off the real wallet" warning is shown only while a look-alike mode is on.
  function warningShown(mode) {
    return mode !== "off";
  }

  // The MetaMask Connect limitation (spec/05 §2.12) concerns the MetaMask look-alike mode only.
  function metamaskNoteShown(mode) {
    return mode === "metamask";
  }

  // spec/05 §2.12 (2026-11-11): the popup renders at once from what it showed last time (the
  // modes, the last status the background reported and, since 2026-11-14, the language), then
  // refreshes from chrome.storage.local and the background. Kept in the popup page's own
  // localStorage: the extension origin only, never a page or a content script, and nothing secret
  // (mode names, a status word and a language code).
  const MODES_CACHE_KEY = "yourWalletPopupModesV1";
  const STATUS_CACHE_KEY = "yourWalletPopupStatusV1";
  const LANGUAGE_CACHE_KEY = "yourWalletPopupLanguageV1";

  // `{ evm, sol, btc }` exactly, each a valid mode of its group, or null.
  function parseCachedModes(text) {
    if (typeof text !== "string" || text.length > 256) {
      return null;
    }
    let value;
    try {
      value = JSON.parse(text);
    } catch (_error) {
      return null;
    }
    if (!shared.hasExactKeys(value, ["evm", "sol", "btc"])
      || Object.keys(GROUPS).some((kind) => typeof value[kind] !== "string" || GROUPS[kind].normalize(value[kind]) !== value[kind])) {
      return null;
    }
    return Object.freeze({ evm: value.evm, sol: value.sol, btc: value.btc });
  }

  function serializeModes(modes) {
    return JSON.stringify({ evm: modes.evm, sol: modes.sol, btc: modes.btc });
  }

  // A status word the background can report, or null.
  function parseCachedStatus(text) {
    return isStatusWord(text) ? text : null;
  }

  // "ko" or "en" exactly, or null.
  function parseCachedLanguage(text) {
    return typeof text === "string" && shared.normalizeLanguage(text) === text ? text : null;
  }

  // What the popup writes to chrome.storage.local for a selection (null for anything else).
  function storageUpdate(mode) {
    return shared.isCompatMode(mode) ? { [shared.COMPAT_MODE_STORAGE_KEY]: mode } : null;
  }

  Object.defineProperty(root, "__YOUR_WALLET_POPUP_CORE__", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({
      LANGUAGES,
      MODE_OPTIONS,
      SOL_MODE_OPTIONS,
      BTC_MODE_OPTIONS,
      GROUPS,
      TEXT,
      STATUS_VIEWS,
      STATUS_WORDS,
      STATUS_TIMEOUT_MS: 2_000,
      MODES_CACHE_KEY,
      STATUS_CACHE_KEY,
      LANGUAGE_CACHE_KEY,
      groupOptions,
      languageUpdate,
      metamaskNoteShown,
      modeOption,
      parseCachedLanguage,
      parseCachedModes,
      parseCachedStatus,
      parseStatusMessage,
      serializeModes,
      statusView,
      storageUpdate,
      storageUpdateFor,
      texts,
      warningShown
    })
  });
}(globalThis));
