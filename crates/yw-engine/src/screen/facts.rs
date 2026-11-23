//! What a screen asks the platform shell while it is built (spec/15 §3.2, §11.3): read-only
//! facts, asked at the point the screen needs them, and the platform flags.
//!
//! 2026-11-24 (spec/15 §11.3, §11.4 S5-2): created. Until S5-3 the Windows screens still read
//! these facts themselves (local time through `yw_win::time`, the data folder, the `rpc.json`
//! probe, the extension folder, the pipe state, the version line). 2026-11-24 (S5-3): they ask
//! [`ScreenFacts`] instead, at the same points (yw-app `screen_facts::WinFacts`, `App::facts`;
//! source check `render_asks_the_shell_only_through_facts`), and the Windows-only items they
//! draw are guarded by [`PlatformFlags`]. A fact never carries a secret or an RPC URL: the
//! folders are the display strings the screens show today. Windows answers each fact when asked
//! (so the number and timing of its file probes stay those of today); Android will answer from
//! values its shell pushed before the screen is built (no upward call, spec/15 §3.2).

use crate::errors::ErrorCode;

/// The named-pipe server's state for the S10 status line (spec/04 §2.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipeStatus {
    /// The pipe server runs.
    pub server: bool,
    /// Why it does not (E-PIPE-001, or E-PIPE-002 when another server holds the name); `None`
    /// reads as E-PIPE-001.
    pub error: Option<ErrorCode>,
}

/// Platform flags (spec/15 §11.3 last item, §9.3–§9.4). A flag only **narrows** what a screen or
/// window offers: an item it guards is drawn only when the flag is set **and** every condition
/// that guards it today holds (the user's settings, the secret window's kind, its input state).
/// No flag turns anything on that Windows does not offer today, and none is read by the approval
/// gate (critic C10 of the S5 plan). [`PlatformFlags::WINDOWS`] sets every flag but
/// [`PlatformFlags::seen_all`], so Windows draws what it draws today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent platform capabilities, each a yes/no the screens test on its own"
)]
pub struct PlatformFlags {
    /// The platform can copy a displayed secret (spec/15 §9.3): the `비밀 복사 허용` setting and
    /// W08/W09 `복사` exist. Copying still needs that setting (off by default, spec/04 §4.8).
    pub secret_copy: bool,
    /// The platform can paste recovery words into W05/W07 (spec/15 §9.4); a window whose kind
    /// forbids pasting still forbids it.
    pub secret_word_paste: bool,
    /// The `rpc.json` import card exists (a Windows developer file, spec/04 §2.10).
    pub rpc_json_import: bool,
    /// The Chrome extension parts exist: S23, its links and cards, the S10 pipe status line.
    pub browser_extension: bool,
    /// The platform opens folders: the data, log and extension folder buttons.
    pub open_folders: bool,
    /// The narrow-screen "모두 본 뒤 arm" rule (spec/15 §8.5, `seen_all`). Declared, not wired
    /// (2026-11-24 S5-2 review: plan O-9's recommended scope; the S5-2 commit left it out):
    /// nothing reads it, the approval gate included, and Windows leaves it off — whether Windows
    /// applies it is spec/15 §18 4, open, and turning it on there changes spec/04 §3.4. When it is
    /// wired it can only add a condition to approving, never remove one.
    pub seen_all: bool,
}

impl PlatformFlags {
    /// Windows: every flag set but `seen_all` (today's screens and approval window).
    pub const WINDOWS: Self = Self {
        secret_copy: true,
        secret_word_paste: true,
        rpc_json_import: true,
        browser_extension: true,
        open_folders: true,
        seen_all: false,
    };
}

/// The shell facts a screen asks while it is built (spec/15 §11.3). Read-only; `&self`.
pub trait ScreenFacts {
    /// `unix_ms` as local wall-clock milliseconds (`None`: the conversion failed, the screen shows
    /// UTC with a suffix).
    fn local_wall_ms(&self, unix_ms: u64) -> Option<u64>;
    /// The wallet's data folder as the settings screen shows it.
    fn data_dir(&self) -> String;
    /// Whether the developer `rpc.json` file is there now (asked only while the network section
    /// or the done screen is drawn).
    fn rpc_json_present(&self) -> bool;
    /// The Chrome extension folder found next to the app (`None`: none found).
    fn extension_dir(&self) -> Option<String>;
    /// Where the extension folder is expected (shown when none was found; `None`: not known,
    /// nothing is shown). 2026-11-24 (S5-3): an `Option`, as the Windows answer always was (S5-2
    /// declared a `String`).
    fn expected_extension_dir(&self) -> Option<String>;
    /// The named-pipe server's state.
    fn pipe(&self) -> PipeStatus;
    /// The version line of `정보` (version and install record) in `lang`.
    fn version_text(&self, lang: yw_core::lang::Lang) -> String;
    /// The platform flags.
    fn flags(&self) -> PlatformFlags;
}

#[cfg(test)]
mod tests {
    use super::{PipeStatus, PlatformFlags};

    #[test]
    fn windows_sets_every_flag_but_seen_all() {
        let PlatformFlags {
            secret_copy,
            secret_word_paste,
            rpc_json_import,
            browser_extension,
            open_folders,
            seen_all,
        } = PlatformFlags::WINDOWS;
        assert!(
            secret_copy
                && secret_word_paste
                && rpc_json_import
                && browser_extension
                && open_folders
        );
        assert!(
            !seen_all,
            "spec/15 §18 4 is open: Windows does not apply it"
        );
        assert_eq!(
            PipeStatus::default(),
            PipeStatus {
                server: false,
                error: None
            }
        );
    }
}
