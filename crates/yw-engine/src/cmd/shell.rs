//! The shell's own steps that the wallet takes as plain data (2026-11-24, spec/15 §11.4 S5-9,
//! S5 plan owner item O-11; spec/04 §1.3, §1.4, §4.8): before, the Windows shell called the
//! wallet's fns for them by name (`refresh`, `close_pickers`, `forget_copy_mark`, `banner`,
//! `error_banner`, `fill_template_gaps`, `wer_unprotected_noted`, `install_commit_read`,
//! `notice`, `drop_clip_notice`), each listed in the source check `SHELL_WALLET_CALLS` with
//! its reason. Each is now one [`crate::cmd::Cmd`] the wallet handles in the same order; none
//! carries a secret, a path or a URL.

use core::fmt;

/// A main-window step ([`crate::cmd::Cmd::Main`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainStep {
    /// Lay the screen out again: after `WM_SIZE`, at the first show, after Esc closed a
    /// drop-down and after a press that closed one (was `Wallet::refresh`).
    Relayout,
    /// Close an open network or account drop-down, nothing else (was `Wallet::close_pickers`,
    /// its answer unused): Esc and a press close one before they run (2026-11-12).
    ClosePickers,
    /// A click on the window itself, not on a control: an open drop-down closes and the screen
    /// is laid out again; with none open nothing happens (2026-11-12; was `close_pickers`, then
    /// `refresh` when it closed one).
    Clicked,
    /// An id that is no press reached the window (S3 D3): the copy mark goes, nothing else (was
    /// `Wallet::forget_copy_mark`).
    NotAPress,
}

/// What the shell found about its platform ([`crate::cmd::Cmd::Platform`]): the start's
/// findings (spec/04 §1.4 steps 4–5, in `main.rs`'s order) and a failed session registration
/// (§1.4-6). Never a path, a URL or a file's text: the refused settings are their key names.
#[derive(Clone, PartialEq, Eq)]
pub enum PlatformNote {
    /// `settings.json` values fell back to their defaults: the E-APP-001 banner names these keys
    /// (`"settings.json"` when the whole file was refused; `settings::SettingsLoad::banners`).
    SettingsRefused(Vec<String>),
    /// `apikeys.dpapi` was read (`readable`: the networks added since the addresses were made
    /// get the template's address) or could not be (the E-KEY-001 banner).
    ApiKeys {
        /// Whether the file was readable (a missing file is).
        readable: bool,
    },
    /// `WerAddExcludedApplication` failed (review L9): crash reports may be written.
    WerUnprotected,
    /// The commit of the installation record next to the executable, as read (`None`: a
    /// development build); the wallet keeps it only when it is a commit.
    InstallCommit(Option<String>),
    /// The session notifications could not be registered after the last retry (E-APP-004).
    SessionUnregistered,
}

/// Names and counts only (D28): never a key name or the commit.
impl fmt::Debug for PlatformNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SettingsRefused(keys) => formatter
                .debug_struct("SettingsRefused")
                .field("keys", &keys.len())
                .finish(),
            Self::ApiKeys { readable } => formatter
                .debug_struct("ApiKeys")
                .field("readable", readable)
                .finish(),
            Self::WerUnprotected => formatter.write_str("WerUnprotected"),
            Self::InstallCommit(commit) => formatter
                .debug_struct("InstallCommit")
                .field("some", &commit.is_some())
                .finish(),
            Self::SessionUnregistered => formatter.write_str("SessionUnregistered"),
        }
    }
}

/// What the shell's clipboard answered about a secret copy's automatic clear (spec/04 §4.8;
/// [`crate::cmd::Cmd::SecretClip`]): the wallet's notices follow it. The clipboard, the retry
/// timing and the copy itself stay the shell's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipNote {
    /// The copy whose clear was being retried and noticed (T-CLIP-NOT-CLEARED shown) is gone:
    /// cleared now (`cleared`: T-CLIP-CLEARED-LATE follows), or no longer ours (another program
    /// replaced it, or a new secret copy did); the warning goes and the screen is laid out again.
    NoticeEnds {
        /// The clear emptied the clipboard now.
        cleared: bool,
    },
    /// The clipboard stayed busy for the notice time, or the retries gave up before any notice:
    /// T-CLIP-NOT-CLEARED, and the screen is laid out again.
    NotCleared,
    /// At start a copy an earlier run left was cleared: T-CLIP-CLEARED-LATE (no layout: the main
    /// window was just made and is laid out when shown).
    EarlierRunCleared,
}
