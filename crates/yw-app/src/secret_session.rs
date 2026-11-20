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
//!
//! 2026-11-20 (S4 P7a2): a session may carry one step the logic takes when the shell reports its
//! window shown ([`AfterShown`]): W12 reads the card's PIN counters then. Before, the handler
//! read the session right after the open returned (`App::yk_open_card_secret`).

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
    /// The shell reported the window shown (`Cmd::SecretOpened` with `Shown`, or the direct open
    /// of the display windows; 2026-11-20 S4 P7a2: the card windows open through the seam now).
    shown: bool,
    /// What the logic does once the window is shown (taken then; dropped with the session).
    after_shown: Option<AfterShown>,
}

/// A step the logic takes when the shell reports the session's window shown: never before, and
/// never for a window that was refused or failed (2026-11-20, S4 P7a2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AfterShown {
    /// W12: read the PIN counters of card `card` (`YkJob::Counters(CounterTarget::Card)`), which
    /// the window shows before the PIN is entered (spec/10 §9.1).
    CardCounters { card: u32 },
}

/// The step's name only (D28; the card serial is not printed).
impl fmt::Debug for AfterShown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CardCounters { .. } => "CardCounters",
        })
    }
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
            after_shown: None,
        }
    }

    /// The step to take once the window is shown (replaces one set before).
    pub(crate) const fn then_when_shown(&mut self, after: AfterShown) {
        self.after_shown = Some(after);
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

    /// The shell reported the window shown; returns the step to take now, if one was set (taken,
    /// so it runs once).
    #[must_use]
    pub(crate) const fn mark_shown(&mut self) -> Option<AfterShown> {
        self.shown = true;
        self.after_shown.take()
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
            .field("after_shown", &self.after_shown)
            .finish()
    }
}
