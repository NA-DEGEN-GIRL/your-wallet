//! The open secret session: the wallet's record of the one secret window (spec/04 §4, D11;
//! spec/15 §11.4 S4, plan §3.6 with critique B-7).
//!
//! 2026-11-20 (S4 P7a1): created. Before, the purpose lived in the window record (`App::secret`,
//! `SecretWin.purpose`) and "a secret window is open" was "the window exists". Now the session
//! starts when the logic asks for a window (`App::open_input`, `App::open_display`) and ends on
//! every end of that window: refused or failed open, close, cancel, time-out, lock. The shell's
//! window record (`App::secret`: serial, window, form) holds no purpose. Every field is private;
//! these methods are the only writers. The struct stays in yw-app (it holds the yw-app
//! `Purpose`) until the wallet state moves to yw-engine (S4d).

use core::fmt;

use yw_engine::secret::SecretKind;

use crate::app::Purpose;

/// One secret window as the logic sees it: from the request until its end.
pub(crate) struct SecretSession {
    /// A fresh serial per window asked for (never reused); the window's messages and its open
    /// result carry it.
    serial: u64,
    kind: SecretKind,
    purpose: Purpose,
    /// Above every window (W11 and the dApp's W02).
    topmost: bool,
    /// The shell reported the window shown (`Cmd::SecretOpened` with `Shown`, or the direct
    /// opens of the display and card windows).
    shown: bool,
}

impl SecretSession {
    /// A session for window `kind` of `purpose`, not shown yet.
    pub(crate) const fn new(
        serial: u64,
        kind: SecretKind,
        purpose: Purpose,
        topmost: bool,
    ) -> Self {
        Self {
            serial,
            kind,
            purpose,
            topmost,
            shown: false,
        }
    }

    /// The session's serial.
    #[must_use]
    pub(crate) const fn serial(&self) -> u64 {
        self.serial
    }

    /// What the window is for.
    #[must_use]
    pub(crate) const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Whether the shell reported the window shown.
    #[must_use]
    pub(crate) const fn shown(&self) -> bool {
        self.shown
    }

    /// The shell reported the window shown.
    pub(crate) const fn mark_shown(&mut self) {
        self.shown = true;
    }
}

/// Serial, window id, purpose name and flags (D28; the purpose holds no secret).
impl fmt::Debug for SecretSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSession")
            .field("serial", &self.serial)
            .field("kind", &self.kind.id())
            .field("purpose", &self.purpose)
            .field("topmost", &self.topmost)
            .field("shown", &self.shown)
            .finish()
    }
}
