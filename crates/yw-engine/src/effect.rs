//! What the wallet logic asks the platform shell to do (spec/15 §3.2, §11.2, §11.4 S3): plain
//! data, never wallet-secret text, never a window handle, control id or pixel. Results come back
//! as [`crate::cmd::Cmd`]s, never as return values (no upcall, spec/15 §3.2).
//!
//! The shell applies an effect at once, inside the handler that emitted it (Windows: inside the
//! `App` borrow, so the `EN_CHANGE` a field write causes stays unseen, spec/01 §7.7). Nothing is
//! queued or coalesced in S3; an outbox, if S4 adds one, must drain inside the same borrow.
//!
//! 2026-11-18 (spec/15 §11.4 S3 B1): created. No yw-json codec yet (spec/15 §18 item 8).
//!
//! 2026-11-19 (spec/15 §11.4 S4 B5): [`Effect::Approval`], the approval window's open, close,
//! rebuilt view and bottom-bar repaint ([`ApprovalEffect`]); the open is answered with
//! `Cmd::ApprovalOpened`. Still applied at once (Windows: inside the `App` borrow).
//!
//! 2026-11-20 (spec/15 §11.4 S4 P3): [`Effect::OpenUrl`] (an explorer link; answered with
//! `Cmd::Opened`) and [`Effect::OpenFolder`] (a [`Folder`]; an extension folder the shell does not
//! find is answered with `Cmd::FolderMissing`). Before, the handlers started `explorer.exe`
//! themselves (`App::open_folder`, the launcher in `App::open_explorer`). Still applied at once.
//!
//! 2026-11-20 (spec/15 §11.4 S4 P4): what the logic asked of the main window directly before:
//! [`Effect::Reveal`] (scroll a control into view and focus it, [`RevealTarget`]),
//! [`Effect::RaiseMain`] (a second start's activation), the scroll memory of a screen entry
//! ([`Effect::ScreenLeaving`], [`Effect::ScreenEntered`], [`Effect::OverlayClosedInPlace`],
//! [`Effect::TabTop`], [`Effect::ScrollMemoryClear`]) and the end of a hold area's pointer
//! capture ([`Effect::ReleaseHold`]). None is answered. Still applied at once: the scroll ones
//! read the wallet's screen while they are applied (Windows: inside the handler that emitted
//! them), so an outbox must carry what they read. 2026-11-20 (spec/15 §11.4 S4 P10a): they do —
//! `ScreenLeaving` carries the place left (`left`), `ScreenEntered` where the entered screen opens
//! (`at`, a [`crate::screen::EnteredAt`]) and `TabTop` the place of the tab left (`left`), each
//! worked out by the logic when it emits them ([`crate::screen`]); the shell reads only its own
//! scroll state and memory. Before, they carried the flags `overlay_opens`/`changes`,
//! `back`/`overlay` and nothing, and the shell read the wallet's screen, previous screen and tab.
//!
//! 2026-11-20 (spec/15 §11.4 S4 P7a1): [`Effect::Secret`], a secret window's open (an input
//! window; answered with `Cmd::SecretOpened`) and close ([`SecretEffect`]): serials, kinds and
//! flags, never secret text. Before, the handlers created and closed the windows themselves
//! (`App::open_input`, `App::close_secret`). Still applied at once.
//!
//! 2026-11-20 (spec/15 §11.4 S4 P7b): `Effect::Secret` also opens the display windows, changes
//! an open window's form and clears a pending secret copy at the lock (`SecretEffect::{
//! OpenDisplay, Form, ClearClip}`); [`Effect::AwaitKeyLock`] is the lock's `Suspend` wait for the
//! key worker (critique A-2: an effect at the wait's place, so a later outbox keeps the order
//! secret close < clip clear < approval close < wait). Before, `App::lock` waited itself. Still
//! applied at once.
//!
//! 2026-11-20 (spec/15 §11.4 S4 P10b): effects go through an outbox — the Windows shell queues
//! each one when the logic emits it and applies the queue in order, never coalesced, inside the
//! `App` borrow before the shell entry that emitted them returns; an answer goes back to the logic
//! in the same drain (yw-app `App::emit`/`App::drain`/`App::dispatch`). A `SetField` is form
//! state when it is emitted (owner decision O-10). The second paragraph above describes S3 …
//! P10a (critique B-23).

use core::fmt;

use crate::approval::flow::ApprovalEffect;
use crate::cmd::{CopyMark, LinkTarget, Press};
use crate::form::{CredField, EditField};
use crate::screen::{EnteredAt, ScrollPlace};
use crate::secret::SecretEffect;

/// One request to the shell.
#[derive(Clone, PartialEq, Eq)]
pub enum Effect {
    /// Lay the main screen out again and repaint (Windows: today's `App::refresh` body after the
    /// dApp state sync).
    Render,
    /// Put text into a live plain edit on purpose (a picker fill, `최대`, a preset).
    SetField {
        /// The edit.
        field: EditField,
        /// Its new text.
        text: String,
    },
    /// Empty a plain edit.
    ClearField {
        /// The edit.
        field: EditField,
    },
    /// Empty a credential edit after its one-shot read.
    ClearCred {
        /// The edit.
        field: CredField,
    },
    /// Arm a one-shot timer; it fires as `Cmd::Timer(timer)`.
    StartTimer {
        /// Which timer.
        timer: TimerId,
        /// Delay in milliseconds.
        ms: u64,
    },
    /// Stop a timer armed with `StartTimer`.
    StopTimer {
        /// Which timer.
        timer: TimerId,
    },
    /// Copy non-secret text (an address, a hash, an explorer link); the shell answers with
    /// `Cmd::CopyDone` carrying the same `mark`.
    CopyText {
        /// The text.
        text: String,
        /// What the result applies to.
        mark: CopyMark,
    },
    /// The approval window (S4 B5): ids, flags and the language only, never request text.
    /// `ApprovalEffect::Open` is answered with `Cmd::ApprovalOpened`.
    Approval(ApprovalEffect),
    /// Open a link in the default browser (S4 P3): a block-explorer page built from a validated
    /// template (`explorer::build_url`). Answered with `Cmd::Opened` carrying the same `which`.
    /// `Debug` prints the URL's length only.
    OpenUrl {
        /// The URL.
        url: String,
        /// What the result applies to.
        which: LinkTarget,
    },
    /// Open one of the app's folders in the file manager (S4 P3; Windows only, spec/04 §2.14).
    /// The shell resolves the path; [`Folder::Extension`] not found is answered with
    /// `Cmd::FolderMissing`, the other folders with nothing.
    OpenFolder(Folder),
    /// Scroll a control of the main screen fully into view and give it the focus (S4 P4; was
    /// `App::reveal_id` in the handlers). Nothing when the screen laid out last does not show it.
    Reveal(RevealTarget),
    /// Show the main window and bring it to the foreground (S4 P4: a second start's
    /// `WM_YW_ACTIVATE`, spec/04 §1.1; was in `App::activate`). Not answered.
    RaiseMain,
    /// The screen shown now is being left (S4 P4; the first half of a screen entry, emitted
    /// before the logic changes its screen): the shell notes where it was scrolled when an
    /// overlay opens over it (`overlay_opens`) and, when another screen follows, where it was
    /// left for the ways back (spec/04 §1.7), under `left`. 2026-11-20 (S4 P10a): `left` is the
    /// place of the screen being left, worked out by the logic (`None`: no other screen follows,
    /// or the screen has no remembered place); before, the flag `changes`, and the shell read the
    /// screen being left.
    ScreenLeaving {
        /// A confirmation overlay opens over a screen that is not one.
        overlay_opens: bool,
        /// Where the offset of the screen being left is noted, when another screen follows.
        left: Option<ScrollPlace>,
    },
    /// A screen was entered (S4 P4; the second half, emitted after the logic changed its screen
    /// and before its render): it opens where `at` says. 2026-11-20 (S4 P10a): `at` is worked out
    /// by the logic from the screen entered and the one left; before, the flags `back` (a way
    /// back) and `overlay` (the screen left was a confirmation overlay), and the shell read the
    /// wallet's screen and previous screen.
    ScreenEntered {
        /// Where the screen opens.
        at: EnteredAt,
    },
    /// A confirmation overlay closed back onto the screen under it without a screen entry (S4
    /// P4; `App::close_overlay_in_place`): that screen is shown where it was, if that was noted.
    OverlayClosedInPlace,
    /// A chain tab is selected (S4 P4; emitted before the tab changes): the shell notes where the
    /// screen being left was, under `left`, and the new tab opens at its top. 2026-11-20 (S4
    /// P10a): `left` is that screen's place (S10: the tab being left), worked out by the logic;
    /// before, the shell read the wallet's screen and tab.
    TabTop {
        /// The place of the screen shown when the tab changes (`None`: none remembered).
        left: Option<ScrollPlace>,
    },
    /// Forget every remembered scroll offset (S4 P4: a lock; the next session opens at the top).
    ScrollMemoryClear,
    /// A press-and-hold area's hold ended: release its pointer capture (S4 P4; S22).
    ReleaseHold,
    /// A secret window (S4 P7a1): serials, kinds and flags only, never secret text.
    /// `SecretEffect::OpenInput` is answered with `Cmd::SecretOpened`.
    Secret(SecretEffect),
    /// Wait until the key worker has finished a lock queued after count `before` was read, at
    /// most `ms` milliseconds (S4 P7b, critique A-2: the lock's `Suspend` wait, spec/04 §5.3; was
    /// in `App::lock`). Blocks the shell's thread as the wait did; not answered.
    AwaitKeyLock {
        /// The completed-lock count read before the lock job was queued.
        before: u64,
        /// The longest wait in milliseconds (1 500 for `Suspend`).
        ms: u64,
    },
}

/// A control of the main screen [`Effect::Reveal`] names (S4 P4): a button by its press, a
/// masked credential edit by its field. Never a control id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevealTarget {
    /// The control that sends this press.
    Press(Press),
    /// The masked edit of this field (`ES_PASSWORD`).
    Cred(CredField),
}

/// Names, fields and lengths only (D28): never the text of a field or a copy.
impl fmt::Debug for Effect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Render => formatter.write_str("Render"),
            Self::SetField { field, text } => formatter
                .debug_struct("SetField")
                .field("field", field)
                .field("len", &text.len())
                .finish(),
            Self::ClearField { field } => formatter
                .debug_struct("ClearField")
                .field("field", field)
                .finish(),
            Self::ClearCred { field } => formatter
                .debug_struct("ClearCred")
                .field("field", field)
                .finish(),
            Self::StartTimer { timer, ms } => formatter
                .debug_struct("StartTimer")
                .field("timer", timer)
                .field("ms", ms)
                .finish(),
            Self::StopTimer { timer } => formatter
                .debug_struct("StopTimer")
                .field("timer", timer)
                .finish(),
            Self::CopyText { text, mark } => formatter
                .debug_struct("CopyText")
                .field("len", &text.len())
                .field("mark", mark)
                .finish(),
            Self::Approval(effect) => formatter.debug_tuple("Approval").field(effect).finish(),
            Self::OpenUrl { url, which } => formatter
                .debug_struct("OpenUrl")
                .field("len", &url.len())
                .field("which", which)
                .finish(),
            Self::OpenFolder(folder) => formatter.debug_tuple("OpenFolder").field(folder).finish(),
            Self::Reveal(target) => formatter.debug_tuple("Reveal").field(target).finish(),
            Self::RaiseMain => formatter.write_str("RaiseMain"),
            Self::ScreenLeaving {
                overlay_opens,
                left,
            } => formatter
                .debug_struct("ScreenLeaving")
                .field("overlay_opens", overlay_opens)
                .field("left", left)
                .finish(),
            Self::ScreenEntered { at } => formatter
                .debug_struct("ScreenEntered")
                .field("at", at)
                .finish(),
            Self::OverlayClosedInPlace => formatter.write_str("OverlayClosedInPlace"),
            Self::TabTop { left } => formatter
                .debug_struct("TabTop")
                .field("left", left)
                .finish(),
            Self::ScrollMemoryClear => formatter.write_str("ScrollMemoryClear"),
            Self::ReleaseHold => formatter.write_str("ReleaseHold"),
            Self::Secret(effect) => formatter.debug_tuple("Secret").field(effect).finish(),
            Self::AwaitKeyLock { before, ms } => formatter
                .debug_struct("AwaitKeyLock")
                .field("before", before)
                .field("ms", ms)
                .finish(),
        }
    }
}

/// A folder of the app the shell can open (S4 P3). Its path is the shell's, never in an effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Folder {
    /// The data folder (`데이터 폴더 열기`).
    Data,
    /// The log folder (`로그 폴더 열기`).
    Logs,
    /// The unpacked Chrome extension of this installation (S23 `탐색기에서 폴더 열기`); the
    /// shell may not find it.
    Extension,
}

/// A one-shot timer the logic arms through the shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerId {
    /// The EVM and Solana send forms' pause before the recipient and amount are checked.
    SendCheck,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::flow::ShownId;
    use crate::cmd::{EvmPress, Press};

    #[test]
    fn debug_prints_no_text() {
        let set = Effect::SetField {
            field: EditField::EvmSendTo,
            text: "0xsecretlookingtext".to_owned(),
        };
        let shown = format!("{set:?}");
        assert_eq!(shown, "SetField { field: EvmSendTo, len: 19 }");
        let copy = Effect::CopyText {
            text: "https://example.com/tx/abc".to_owned(),
            mark: CopyMark {
                anchor: Press::Evm(EvmPress::CopyAddress),
                address: true,
                band: None,
            },
        };
        let shown = format!("{copy:?}");
        assert!(!shown.contains("example"), "{shown}");
        assert_eq!(
            shown,
            "CopyText { len: 26, mark: CopyMark { anchor: Evm(CopyAddress), address: true, \
             band: None } }"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::StartTimer {
                    timer: TimerId::SendCheck,
                    ms: 700
                }
            ),
            "StartTimer { timer: SendCheck, ms: 700 }"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::ClearCred {
                    field: CredField::QnToken
                }
            ),
            "ClearCred { field: QnToken }"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::Approval(ApprovalEffect::Open {
                    shown: ShownId(4),
                    lang: yw_core::lang::Lang::Ko,
                    ai_reserved: true,
                    connect: false,
                })
            ),
            "Approval(Open { shown: ShownId(4), lang: Ko, ai_reserved: true, connect: false })"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::Approval(ApprovalEffect::Rebuilt {
                    shown: ShownId(4),
                    changed: true,
                })
            ),
            "Approval(Rebuilt { shown: ShownId(4), changed: true })"
        );
        // S4 P3: the URL's length only, never the URL or its host.
        let open = Effect::OpenUrl {
            url: "https://scan.example.org/tx/0xabc".to_owned(),
            which: LinkTarget::Explorer {
                net: crate::explorer::ExplorerNet::Evm(10),
                host: Some("scan.example.org".to_owned()),
            },
        };
        let shown = format!("{open:?}");
        assert!(!shown.contains("example"), "{shown}");
        assert_eq!(
            shown,
            "OpenUrl { len: 33, which: Explorer { net: Evm(10), host_len: Some(16) } }"
        );
        assert_eq!(
            format!("{:?}", Effect::OpenFolder(Folder::Extension)),
            "OpenFolder(Extension)"
        );
    }

    /// S4 P4: a reveal names a press or a field, never a control id; the scroll effects are
    /// flags.
    #[test]
    fn the_main_window_effects_debug_as_names_and_flags() {
        assert_eq!(
            format!(
                "{:?}",
                Effect::Reveal(RevealTarget::Press(Press::Evm(EvmPress::CopyAddress)))
            ),
            "Reveal(Press(Evm(CopyAddress)))"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::Reveal(RevealTarget::Cred(CredField::QnToken))
            ),
            "Reveal(Cred(QnToken))"
        );
        // 2026-11-20 (S4 P10a): the scroll effects carry the places they name (plain data).
        assert_eq!(
            format!(
                "{:?}",
                Effect::ScreenLeaving {
                    overlay_opens: true,
                    left: None
                }
            ),
            "ScreenLeaving { overlay_opens: true, left: None }"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::ScreenLeaving {
                    overlay_opens: false,
                    left: Some(ScrollPlace::Settings(
                        crate::screen::SettingsSection::Security
                    ))
                }
            ),
            "ScreenLeaving { overlay_opens: false, left: Some(Settings(Security)) }"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::ScreenEntered {
                    at: EnteredAt::LeftAt(Some(ScrollPlace::Sites))
                }
            ),
            "ScreenEntered { at: LeftAt(Some(Sites)) }"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::ScreenEntered {
                    at: EnteredAt::UnderOverlay { same: true }
                }
            ),
            "ScreenEntered { at: UnderOverlay { same: true } }"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::TabTop {
                    left: Some(ScrollPlace::Main(crate::meta::Tab::Evm))
                }
            ),
            "TabTop { left: Some(Main(Evm)) }"
        );
        for (effect, name) in [
            (Effect::RaiseMain, "RaiseMain"),
            (Effect::OverlayClosedInPlace, "OverlayClosedInPlace"),
            (Effect::ScrollMemoryClear, "ScrollMemoryClear"),
            (Effect::ReleaseHold, "ReleaseHold"),
        ] {
            assert_eq!(format!("{effect:?}"), name);
        }
    }

    /// S4 P7a1: a secret window effect is its serial, window id and flags.
    #[test]
    fn secret_window_effects_debug_as_ids_and_flags() {
        use crate::secret::SecretKind;
        assert_eq!(
            format!(
                "{:?}",
                Effect::Secret(SecretEffect::OpenInput {
                    serial: 3,
                    kind: SecretKind::Unlock,
                    step: None,
                    topmost: true,
                    lang: yw_core::lang::Lang::Ko,
                })
            ),
            "Secret(OpenInput { serial: 3, kind: \"W02\", step: false, topmost: true, lang: Ko })"
        );
        assert_eq!(
            format!("{:?}", Effect::Secret(SecretEffect::Close { serial: 3 })),
            "Secret(Close { serial: 3 })"
        );
        // S4 P7b: the form operation's text is a length; the clip clear and the lock wait are
        // flags and numbers.
        let form = Effect::Secret(SecretEffect::Form {
            serial: 3,
            op: crate::secret::SecretFormOp::Error(Some("wrong password".to_owned())),
        });
        let shown = format!("{form:?}");
        assert!(!shown.contains("wrong"), "{shown}");
        assert_eq!(
            shown,
            "Secret(Form { serial: 3, op: Error { len: Some(14) } })"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::Secret(SecretEffect::ClearClip { at_exit: false })
            ),
            "Secret(ClearClip { at_exit: false })"
        );
        assert_eq!(
            format!(
                "{:?}",
                Effect::AwaitKeyLock {
                    before: 2,
                    ms: 1_500
                }
            ),
            "AwaitKeyLock { before: 2, ms: 1500 }"
        );
    }
}
