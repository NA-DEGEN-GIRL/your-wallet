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

use core::fmt;

use crate::approval::flow::ApprovalEffect;
use crate::cmd::{CopyMark, LinkTarget};
use crate::form::{CredField, EditField};

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
            },
        };
        let shown = format!("{copy:?}");
        assert!(!shown.contains("example"), "{shown}");
        assert_eq!(
            shown,
            "CopyText { len: 26, mark: CopyMark { anchor: Evm(CopyAddress), address: true } }"
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
}
