//! What S23 `Chrome 확장 설치` (spec/04 §2.21) says about the extension: whether one has talked to
//! this app ([`ExtensionStatus`], its texts) and the Chrome page that loads unpacked extensions
//! ([`CHROME_EXTENSIONS_URL`], which the screen shows and the shell copies).
//!
//! 2026-11-24 (spec/15 §11.4 S5-5, S5 plan critic C7): moved here unchanged from yw-app
//! `app_extension` with the screen builders; the extension folder, its checks and `폴더 열기`
//! stay the shell's (`app_extension`), which names [`CHROME_EXTENSIONS_URL`] here.
//!
//! 2026-11-24 (S5-5 review, spec/15 §18 31 (ㄷ)): [`ExtensionStatus`] and [`text`] are
//! crate-private (the screen builders draw them; no shell code names them); yw-app's tests reach
//! them through `crate::testkit::screen` (`extension_text`, `extension_status_texts`). At S5-5
//! itself they were `pub` for those tests only. The URL stays `pub`: the shell's `on_ext` copies it.

/// The Chrome page that loads unpacked extensions.
pub const CHROME_EXTENSIONS_URL: &str = "chrome://extensions";

/// Whether an extension has talked to this app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtensionStatus {
    /// A pipe connection is open now.
    Connected,
    /// Sites are connected (an extension has connected before).
    ConnectedBefore,
    /// Unlocked, no site and no connection.
    Never,
    /// Locked: the connection record (the sites) is not readable.
    Unknown,
}

impl ExtensionStatus {
    /// The status line in `lang`.
    #[must_use]
    pub const fn text_in(self, lang: yw_core::lang::Lang) -> &'static str {
        match self {
            Self::Connected => text::CONNECTED,
            Self::ConnectedBefore => text::CONNECTED_BEFORE,
            Self::Never => text::NEVER,
            Self::Unknown => text::UNKNOWN,
        }
        .get(lang)
    }
}

/// S23 texts (spec/04 §2.21; English spec/14 §5).
pub(crate) mod text {
    yw_core::texts! {
        CONNECTED = "확장이 지금 이 앱에 연결되어 있습니다." / "The extension is connected to this app now.";
        CONNECTED_BEFORE = "확장이 연결된 적 있음 (연결된 사이트가 있습니다)."
            / "The extension has connected before (there are connected sites).";
        NEVER = "아직 연결되지 않음 — 확장을 설치한 뒤 dApp 사이트에서 '지갑 연결'을 누르면 연결됩니다."
            / "Not connected yet — after installing the extension, press 'Connect wallet' on a dApp site.";
        UNKNOWN = "지금은 연결되어 있지 않습니다. 연결 기록(연결된 사이트)은 잠금을 해제하면 보입니다."
            / "Not connected now. The connection record (connected sites) shows after you unlock.";
    }
}
