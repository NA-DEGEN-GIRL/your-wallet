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
  const MODE_OPTIONS = Object.freeze([
    Object.freeze({
      value: "off",
      label: "기본 (Your Wallet)",
      explanation: "dApp에 Your Wallet로 표시됩니다. 다른 지갑 확장의 window.ethereum과 알림은 건드리지 않습니다."
    }),
    Object.freeze({
      value: "metamask",
      label: "MetaMask처럼 보이기",
      explanation: "MetaMask만 지원하는 dApp이 이 지갑을 MetaMask로 인식합니다. 연결·서명은 Your Wallet 승인 창에서 합니다."
    }),
    Object.freeze({
      value: "rabby",
      label: "Rabby처럼 보이기",
      explanation: "Rabby만 지원하는 dApp이 이 지갑을 Rabby Wallet로 인식합니다. 연결·서명은 Your Wallet 승인 창에서 합니다."
    })
  ]);

  const TEXT = Object.freeze({
    title: "Your Wallet",
    statusHeading: "yw-app 연결 상태",
    statusLoading: "조회 중…",
    modeHeading: "dApp에 보이는 지갑",
    warning: "실제 MetaMask/Rabby가 켜져 있으면 가로채기가 완벽하지 않을 수 있습니다. 함께 쓰지 않을 때 가장 확실합니다.",
    applyNote: "모드 변경은 다음 페이지 로드부터 적용됩니다. 열려 있는 dApp 탭은 새로고침하세요.",
    saved: "저장했습니다. 다음 페이지 로드부터 적용됩니다.",
    saveFailed: "저장하지 못했습니다. 확장을 다시 열어 보세요.",
    loadFailed: "저장된 모드를 읽지 못해 기본으로 표시합니다."
  });

  const STATUS_VIEWS = Object.freeze({
    connected: Object.freeze({ text: "연결됨", tone: "ok", detail: "yw-app이 이 브라우저의 마지막 요청에 응답했습니다." }),
    checking: Object.freeze({ text: "확인 중", tone: "neutral", detail: "yw-app에 연결하고 응답을 기다리는 중입니다." }),
    unavailable: Object.freeze({ text: "연결 안 됨", tone: "bad", detail: "마지막 연결 시도가 실패했습니다. yw-app 실행과 native host 등록을 확인하세요." }),
    unknown: Object.freeze({ text: "확인 불가", tone: "neutral", detail: "아직 확인할 정보가 없습니다. dApp에서 지갑 요청이 한 번 오가면 상태가 표시됩니다." })
  });

  function modeOption(mode) {
    const normalized = shared.normalizeCompatMode(mode);
    return MODE_OPTIONS.find((option) => option.value === normalized);
  }

  function statusView(status) {
    return Object.prototype.hasOwnProperty.call(STATUS_VIEWS, status) ? STATUS_VIEWS[status] : STATUS_VIEWS.unknown;
  }

  // background → popup `{ namespace, version, kind: "status", native }`, exact keys.
  function parseStatusMessage(value) {
    if (!shared.hasExactKeys(value, ["namespace", "version", "kind", "native"])
      || value.namespace !== shared.NAMESPACE
      || value.version !== shared.PROTOCOL_VERSION
      || value.kind !== "status"
      || typeof value.native !== "string"
      || !Object.prototype.hasOwnProperty.call(STATUS_VIEWS, value.native)) {
      return null;
    }
    return value.native;
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
      MODE_OPTIONS,
      TEXT,
      STATUS_VIEWS,
      STATUS_TIMEOUT_MS: 2_000,
      modeOption,
      parseStatusMessage,
      statusView,
      storageUpdate
    })
  });
}(globalThis));
