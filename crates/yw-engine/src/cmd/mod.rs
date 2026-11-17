//! Inputs to the wallet logic (spec/15 §3.2, §11.4 S3): plain data, never a platform control id,
//! window handle, focus index or pixel, and never wallet-secret text (spec/15 §3.1). The shell
//! turns a click, a key or a field change into one [`Cmd`]; the logic answers with
//! [`crate::effect::Effect`]s and state.
//!
//! 2026-11-18 (S3 B1): created with `Press::{Back, Enter, Legacy}` only; one sub-enum per handler
//! family follows in the family's own commit. Windows-transitional (they go in S5 or earlier):
//! `Press::Legacy` (a control id whose handler is not converted yet), `Press::Enter` (the shell
//! still resolves the focus), `Cmd::Form` (the edits' text read back from the window) and the
//! positional [`Row`].
//!
//! 2026-11-18 (S3 C1): the received-history, hidden-account, side-file and drop-down/recipient
//! families (`Press::{Received, Hidden, Sidecar, Links}`) and the two press facts the shell's
//! dispatcher checks before a family handler ([`Press::is_receive_gated`],
//! [`Press::refresh_chain`]).
//!
//! 2026-11-18 (S3 C2): S13's sites and `WalletConnect` panel (`Press::{Sites, Wc}`).
//!
//! 2026-11-18 (S3 C3): the block-explorer card and links and the AI-explanation settings
//! (`Press::{Explorer, Llm}`).
//!
//! 2026-11-18 (S3 C4): the address book, its favorite chips, picker and save prompt
//! (`Press::Book`).
//!
//! 2026-11-18 (S3 C5): S22 and T-WAIT-STALLED, S23, the imported-key screens and the `rpc.json`
//! import (`Press::{Reset, Ext, Keys, RpcImport}`).
//!
//! 2026-11-18 (S3 C6): the recovery phrases (`Press::Mn`).
//!
//! 2026-11-18 (S3 C7): `HyperCore` and Zcash (`Press::{Hc, Zec}`); the two chains' `새로고침`
//! and Zcash's two `주소 복사` are the first presses with a received-history read and a receive
//! gate.
//!
//! 2026-11-18 (S3 C8): Solana (`Press::Sol`).

use core::fmt;

use yw_core::secret::Zeroizing;

use crate::effect::TimerId;
use crate::form::{EditField, FormSnapshot, PressInput};
use crate::received::RecvChain;

mod book;
mod explorer;
mod ext;
mod hc;
mod hidden;
mod keys;
mod links;
mod llm;
mod mn;
mod received;
mod reset;
mod rpc_import;
mod sidecar;
mod sites;
mod sol;
mod wc;
mod zec;

pub use book::{BookPress, BookRowAction};
pub use explorer::{ExplorerLinkAction, ExplorerPress, ExplorerRowAction};
pub use ext::ExtPress;
pub use hc::HcPress;
pub use hidden::HiddenPress;
pub use keys::KeysPress;
pub use links::LinksPress;
pub use llm::LlmPress;
pub use mn::MnPress;
pub use received::ReceivedPress;
pub use reset::ResetPress;
pub use rpc_import::RpcImportPress;
pub use sidecar::SidecarPress;
pub use sites::SitesPress;
pub use sol::{SolPress, SolScanAction};
pub use wc::WcPress;
pub use zec::ZecPress;

/// A list row as the screen drew it (positional: resolved against the list rebuilt when the
/// press is handled; S5 → stable keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Row(pub u16);

/// One input. Not `Clone`: a press may carry credential units (wiped on drop).
pub enum Cmd {
    /// A button, link, check box, radio or row action (Windows: `WM_COMMAND` code 0).
    Press {
        /// What was pressed.
        press: Press,
        /// Platform input captured with the press (credential units).
        input: PressInput,
    },
    /// A plain field's text changed (Windows `EN_CHANGE`). The logic cuts it to `field.cap()`
    /// UTF-16 units with [`EditField::clamp`].
    Edit {
        /// The field.
        field: EditField,
        /// Its text now.
        text: Zeroizing<String>,
    },
    /// Windows-transitional (goes in S5): what the plain edits show now.
    Form(FormSnapshot),
    /// A one-shot timer asked for by `Effect::StartTimer` fired.
    Timer(TimerId),
    /// Result of `Effect::CopyText`, echoing its mark (it may arrive later on Android).
    CopyDone {
        /// Whether the text reached the clipboard.
        ok: bool,
        /// The mark of the copy effect.
        mark: CopyMark,
    },
}

/// Variant, field names and lengths only (D28): never a field's text or a credential unit.
impl fmt::Debug for Cmd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Press { press, input } => formatter
                .debug_struct("Press")
                .field("press", press)
                .field("input", input)
                .finish(),
            Self::Edit { field, text } => formatter
                .debug_struct("Edit")
                .field("field", field)
                .field("len", &text.len())
                .finish(),
            Self::Form(snapshot) => formatter.debug_tuple("Form").field(snapshot).finish(),
            Self::Timer(timer) => formatter.debug_tuple("Timer").field(timer).finish(),
            Self::CopyDone { ok, mark } => formatter
                .debug_struct("CopyDone")
                .field("ok", ok)
                .field("mark", mark)
                .finish(),
        }
    }
}

/// What a copy result applies to: the pressed copy control and whether the caption is the
/// address one. It travels with `Effect::CopyText` and back with `Cmd::CopyDone`, so the result
/// never depends on what was pressed in between.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyMark {
    /// The press that copied.
    pub anchor: Press,
    /// The address caption (`주소 복사됨`) rather than the plain one.
    pub address: bool,
}

/// What was pressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Press {
    /// Esc (Windows `IDCANCEL`); Android back.
    Back,
    /// Windows-transitional: Enter (`IDOK`); the shell still resolves the focused edit (S4).
    Enter,
    /// A received-history card (S3 C1).
    Received(ReceivedPress),
    /// S13 `연결된 사이트` (S3 C2).
    Sites(SitesPress),
    /// The AI-explanation settings (S3 C3).
    Llm(LlmPress),
    /// The `WalletConnect` panel of S13 (S3 C2).
    Wc(WcPress),
    /// A hidden-account list (S3 C1).
    Hidden(HiddenPress),
    /// A side-file overlay or check (S3 C1).
    Sidecar(SidecarPress),
    /// The block-explorer card or an explorer link (S3 C3).
    Explorer(ExplorerPress),
    /// An account drop-down button or an activity recipient (S3 C1).
    Links(LinksPress),
    /// The address book, its chips, picker and save prompt (S3 C4).
    Book(BookPress),
    /// S22 `지갑 초기화` and T-WAIT-STALLED (S3 C5).
    Reset(ResetPress),
    /// S23 `Chrome 확장 설치` (S3 C5).
    Ext(ExtPress),
    /// The imported-key screens and card parts (S3 C5).
    Keys(KeysPress),
    /// The `rpc.json` import card (S3 C5).
    RpcImport(RpcImportPress),
    /// The recovery phrases and their pickers (S3 C6).
    Mn(MnPress),
    /// The `HyperCore` card, S-HC and settings block (S3 C7).
    Hc(HcPress),
    /// The Zcash tab (S3 C7).
    Zec(ZecPress),
    /// The Solana screens (S3 C8).
    Sol(SolPress),
    /// Windows-transitional bridge (S3 B2–D3): a control id whose handler is not converted yet.
    #[doc(hidden)]
    Legacy(u16),
}

impl Press {
    /// The chain whose received-history list a card's `새로고침` press also reads now, before the
    /// card's own handler runs (spec/04 §2.6). A chain family adds its `새로고침` arm when it
    /// converts (S3 C; C7: `HyperCore` and Zcash; C8: Solana); every other press has none.
    /// `Legacy` presses keep the shell's own observer until S3 D3.
    #[must_use]
    pub const fn refresh_chain(self) -> Option<RecvChain> {
        match self {
            Self::Hc(HcPress::Refresh) => Some(RecvChain::Hc),
            Self::Zec(ZecPress::Refresh) => Some(RecvChain::Zec),
            Self::Sol(SolPress::Refresh) => Some(RecvChain::Sol),
            Self::Back
            | Self::Enter
            | Self::Received(_)
            | Self::Sites(_)
            | Self::Llm(_)
            | Self::Wc(_)
            | Self::Hidden(_)
            | Self::Sidecar(_)
            | Self::Explorer(_)
            | Self::Links(_)
            | Self::Book(_)
            | Self::Reset(_)
            | Self::Ext(_)
            | Self::Keys(_)
            | Self::RpcImport(_)
            | Self::Mn(_)
            | Self::Hc(_)
            | Self::Zec(_)
            | Self::Sol(_)
            | Self::Legacy(_) => None,
        }
    }

    /// Whether the press shows or copies a receive address, which is refused while a passphrase
    /// wallet is open unverified (spec/02 §7.5; before any chain handler runs, so Bitcoin does
    /// not derive and store a new address). A chain family adds its arms when it converts (S3 C;
    /// C7: Zcash's two `주소 복사`; C8: Solana's `받기` and `주소 복사`); every other press is not
    /// one. `Legacy` presses keep the shell's own gate until S3 D3.
    #[must_use]
    pub const fn is_receive_gated(self) -> bool {
        match self {
            Self::Zec(ZecPress::CopyAddress | ZecPress::CardCopy)
            | Self::Sol(SolPress::ReceiveOpen | SolPress::CopyAddress) => true,
            Self::Back
            | Self::Enter
            | Self::Received(_)
            | Self::Sites(_)
            | Self::Llm(_)
            | Self::Wc(_)
            | Self::Hidden(_)
            | Self::Sidecar(_)
            | Self::Explorer(_)
            | Self::Links(_)
            | Self::Book(_)
            | Self::Reset(_)
            | Self::Ext(_)
            | Self::Keys(_)
            | Self::RpcImport(_)
            | Self::Mn(_)
            | Self::Hc(_)
            | Self::Zec(_)
            | Self::Sol(_)
            | Self::Legacy(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::form::{CredField, CredUnits};

    #[test]
    fn debug_prints_no_text_or_units() {
        let units: Vec<u16> = "token-abc".encode_utf16().collect();
        let press = Cmd::Press {
            press: Press::Legacy(524),
            input: PressInput::new(vec![
                (CredField::QnToken, CredUnits::Units(Zeroizing::new(units))),
                (CredField::AlchemyKey, CredUnits::Absent),
            ]),
        };
        let shown = format!("{press:?}");
        assert!(!shown.contains("token"), "{shown}");
        assert_eq!(
            shown,
            "Press { press: Legacy(524), input: PressInput { creds: [(QnToken, Units(9)), \
             (AlchemyKey, Absent)], misses: 0 } }"
        );
        let edit = Cmd::Edit {
            field: EditField::WcUri,
            text: Zeroizing::new("wc:abc@2?symKey=00".to_owned()),
        };
        let shown = format!("{edit:?}");
        assert!(!shown.contains("symKey"), "{shown}");
        assert_eq!(shown, "Edit { field: WcUri, len: 18 }");
        let form = Cmd::Form(FormSnapshot(vec![(
            EditField::LlmEndpoint,
            Zeroizing::new("https://example.com/v1".to_owned()),
        )]));
        let shown = format!("{form:?}");
        assert!(!shown.contains("example"), "{shown}");
        assert_eq!(shown, "Form(FormSnapshot({LlmEndpoint: 22}))");
        assert_eq!(
            format!(
                "{:?}",
                Cmd::CopyDone {
                    ok: false,
                    mark: CopyMark {
                        anchor: Press::Back,
                        address: false
                    }
                }
            ),
            "CopyDone { ok: false, mark: CopyMark { anchor: Back, address: false } }"
        );
        assert_eq!(
            format!("{:?}", Cmd::Timer(TimerId::SendCheck)),
            "Timer(SendCheck)"
        );
    }
}
