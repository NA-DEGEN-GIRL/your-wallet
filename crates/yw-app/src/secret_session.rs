//! The open secret session: the wallet's record of the one secret window (spec/04 §4, D11;
//! spec/15 §11.4 S4, plan §3.6 with critique B-7).
//!
//! 2026-11-20 (S4 P7a1): created. Before, the purpose lived in the window record (`App::secret`,
//! `SecretWin.purpose`) and "a secret window is open" was "the window exists". Now the session
//! starts when the logic asks for a window (`Wallet::open_input`, `Wallet::open_display`) and ends on
//! every end of that window: refused or failed open, close, cancel, time-out, lock. The shell's
//! window record (`App::secret`: serial, window, form) holds no purpose. Every field is private;
//! these methods are the only writers. The struct stays in yw-app (it holds the yw-app
//! `Purpose`) until the wallet state moves to yw-engine (S4d).
//!
//! 2026-11-20 (S4 P7a2): a session may carry one step the logic takes when the shell reports its
//! window shown ([`AfterShown`]): W12 reads the card's PIN counters then. Before, the handler
//! read the session right after the open returned (`App::yk_open_card_secret`).
//!
//! 2026-11-20 (S4 P7b): a display window's session holds the secret to display
//! ([`SecretSession::hold_display`]) from the request until the shell, having verified the new
//! window's capture exclusion, takes it ([`SecretSession::take_display`]); every other end of the
//! session drops it with the session (wiped: `DisplaySecret` holds a `SecretString`), so an ended
//! session can never fill a window (critique A-3). W08 of a new `YubiKey` wallet marks its words
//! shown once its window is shown ([`AfterShown::YkWordsShown`]); before, the handler read the
//! session right after the open (`App::on_yk_outcome`). Before P7b `App::open_display` made the
//! window and moved the secret into its form itself.
//!
//! 2026-11-20 (S4 P9, plan §4.4 S5): the form operations a handler made right after an open
//! (`Wallet::secret_form`, which reads the session to find the window: an error line, W11's card
//! lines, PIN tries, an information line) travel with the session too ([`AfterShown::Forms`])
//! and are made when the window is shown, in their order; a refused or failed window makes none,
//! as before (the session had ended when the handler's `secret_form` ran). Before, the handler
//! called `secret_form` after the open returned — the same point while the executor applies
//! effects at once.
//!
//! 2026-11-22 (S4c W12, preflight critic C12): what the window's form ends or asks for that is
//! the wallet's reaches it as a [`SecretAction`] through `Wallet::on_secret_action`; the shell's
//! `App::apply_form_action` keeps the window's own arms (repaint, paste, copy).

use core::fmt;

use yw_engine::secret::{DisplaySecret, SecretFormOp, SecretKind};

use crate::app::Purpose;
use crate::ui::secret::Submission;

/// What the open session's window ends or asks for that is the wallet's to handle: the typed,
/// in-process entry `Wallet::on_secret_action` (2026-11-22, S4c W12, preflight critic C12; plan
/// §3.6 `SecretAction`, §7.3). Before, the shell's `App::apply_form_action` held these arms
/// itself, mixed with its own (a repaint, the clipboard's paste and copy), which it keeps. Never
/// a `Cmd` or an `Effect`: a submission's values are secrets (`Zeroizing`, wiped when dropped,
/// so an action for a session that has ended is wiped where it is dropped, critique A-21). Plan
/// §3.6's `Gone` is not here: no window end reaches the wallet that way yet (no dead variant).
pub(crate) enum SecretAction {
    /// The primary button or Enter with valid input: the form's values, moved out of its fields.
    Submit(Submission),
    /// `취소`, Esc, `나중에` or the close box of an input window (the form already wiped).
    Cancel,
    /// The window's time ran out (the form already wiped).
    TimedOut,
    /// `닫기` (or the close box) of a display window with no hold.
    Close,
    /// W08's 2 s acknowledgement hold completed.
    HoldComplete,
}

/// The variant's name only; a submission prints its value count (D28, never a value).
impl fmt::Debug for SecretAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submit(submission) => formatter.debug_tuple("Submit").field(submission).finish(),
            Self::Cancel => formatter.write_str("Cancel"),
            Self::TimedOut => formatter.write_str("TimedOut"),
            Self::Close => formatter.write_str("Close"),
            Self::HoldComplete => formatter.write_str("HoldComplete"),
        }
    }
}

/// One secret window as the logic sees it: from the request until its end.
pub(crate) struct SecretSession {
    /// A fresh serial per window asked for (never reused); the window's messages and its open
    /// result carry it.
    serial: u64,
    kind: SecretKind,
    purpose: Purpose,
    /// Above every window (W11 and the dApp's W02).
    topmost: bool,
    /// The shell reported the window shown (`Cmd::SecretOpened` with `Shown`; 2026-11-20 S4
    /// P7a2: the card windows open through the seam now; S4 P7b: the display windows too, before
    /// their direct open marked it).
    shown: bool,
    /// What the logic does once the window is shown (taken then; dropped with the session).
    after_shown: Option<AfterShown>,
    /// W08/W09: the secret to display, until the shell takes it into its verified window
    /// (2026-11-20, S4 P7b); dropped (wiped) with the session.
    display: Option<DisplaySecret>,
}

/// A step the logic takes when the shell reports the session's window shown: never before, and
/// never for a window that was refused or failed (2026-11-20, S4 P7a2). 2026-11-20 (S4 P9): no
/// longer `Copy` (`Forms` holds texts).
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AfterShown {
    /// W12: read the PIN counters of card `card` (`YkJob::Counters(CounterTarget::Card)`), which
    /// the window shows before the PIN is entered (spec/10 §9.1).
    CardCounters { card: u32 },
    /// W08 of a new `YubiKey` wallet: its words count as shown (`App::yk_words`, unless they are
    /// already further on) — 2026-11-20, S4 P7b.
    YkWordsShown,
    /// The window's form operations, made in this order (`Wallet::secret_form`) — 2026-11-20, S4
    /// P9: the error line of a window opened again after a refused preview (W05, W07), W11's
    /// card, details and error lines, the PIN tries of a card secret window and of the connect
    /// PIN, the passphrase window's information line. Fixed, error and card texts, never a secret.
    Forms(Vec<SecretFormOp>),
}

/// The step's name only (D28; the card serial is not printed).
impl fmt::Debug for AfterShown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CardCounters { .. } => "CardCounters",
            Self::YkWordsShown => "YkWordsShown",
            // The operations' own `Debug` prints names and lengths only.
            Self::Forms(ops) => return formatter.debug_tuple("Forms").field(ops).finish(),
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
            display: None,
        }
    }

    /// Holds the secret a display window of this session shows, until the shell takes it
    /// (replaces one held before, which is dropped and wiped).
    pub(crate) fn hold_display(&mut self, display: DisplaySecret) {
        self.display = Some(display);
    }

    /// The held display secret, moved out once (the shell's verified window takes it; a
    /// refused or failed window drops it). `None` once the window is shown or when none is held.
    #[must_use]
    pub(crate) fn take_display(&mut self) -> Option<DisplaySecret> {
        if self.shown {
            return None;
        }
        self.display.take()
    }

    /// The step to take once the window is shown (replaces one set before). 2026-11-20 (S4 P9):
    /// no longer `const` (the step it replaces may hold texts to drop).
    pub(crate) fn then_when_shown(&mut self, after: AfterShown) {
        self.after_shown = Some(after);
    }

    /// The session's serial.
    #[must_use]
    pub(crate) const fn serial(&self) -> u64 {
        self.serial
    }

    /// The session's window kind (2026-11-22, S4c W3b: the idle clock's read of a shown W08/W09,
    /// `Wallet::idle_window`; before, it read the shell's window record).
    #[must_use]
    pub(crate) const fn kind(&self) -> SecretKind {
        self.kind
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

/// Serial, window id, purpose name and flags (D28; the purpose holds no secret, and a held
/// display secret prints as a flag only).
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
            .field("display", &self.display.is_some())
            .finish()
    }
}
