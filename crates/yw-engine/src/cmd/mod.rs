//! Inputs to the wallet logic (spec/15 §3.2, §11.4 S3): plain data, never a platform control id,
//! window handle, focus index or pixel, and never wallet-secret text (spec/15 §3.1). The shell
//! turns a click, a key or a field change into one [`Cmd`]; the logic answers with
//! [`crate::effect::Effect`]s and state.
//!
//! 2026-11-18 (S3 B1): created with `Press::{Back, Enter, Legacy}` only; one sub-enum per handler
//! family follows in the family's own commit. Windows-transitional (they go in S5 or earlier):
//! `Press::Legacy` (a control id whose handler is not converted yet; gone in S3 D3),
//! `Press::Enter` (the shell still resolves the focus), `Cmd::Form` (the edits' text read back
//! from the window) and the positional [`Row`].
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
//!
//! 2026-11-18 (S3 C9): Bitcoin (`Press::Btc`).
//!
//! 2026-11-18 (S3 C10): the EVM screens (`Press::Evm`).
//!
//! 2026-11-18 (S3 C11): the `YubiKey` tab and wizard, card actions and connect flow
//! (`Press::{Yk, YkManage, YkConnect}`).
//!
//! 2026-11-18 (S3 C12): the core screens, settings sections and URL rows (`Press::Core`);
//! every control of the main window is now a family press (`Legacy` is left for ids no
//! handler claimed, until S3 D3).
//!
//! 2026-11-18 (S3 D3): `Press::Legacy` is gone. An id no control of the main window sends (an
//! edit's, S22's painted hold area, the eighth id of a `YubiKey` connect choice row) is no press
//! at all: the Windows table gives `None` for it.
//!
//! 2026-11-19 (S4 B5): [`Cmd::ApprovalOpened`], the answer to `Effect::Approval(Open)`.
//!
//! 2026-11-19 (S4 B6): [`Cmd::Approval`], one input of an approval window (`ApprovalInput`: the
//! window's `ShownId`, its foreground sample for an interaction event, one signal). Built only by
//! the platform's input mapper (Windows: `ui::approval_input`); never stored, posted or queued
//! past the window message it came from.
//!
//! 2026-11-20 (S4 P3): [`Cmd::Opened`], the answer to `Effect::OpenUrl` (echoing its
//! [`LinkTarget`]), and [`Cmd::FolderMissing`], the answer to `Effect::OpenFolder` when the shell
//! finds no extension folder.
//!
//! 2026-11-20 (S4 P4): `Press::Enter` and `Press::Back` no longer make the logic read the focus
//! or the screen's controls: the shell resolves them into the concrete press they stand for
//! (see [`Press::Back`]).
//!
//! 2026-11-20 (S4 P6): [`CopyMark::band`] ([`CopyBand`]): a setup step's copy (S23's two, the
//! `WalletConnect` panel's `dashboard.reown.com`) answers with its instruction band rather than
//! the mark at the control, decided when the result arrives (`Cmd::CopyDone`), not by a read of
//! the result right after the copy.
//!
//! 2026-11-20 (S4 P7a1): [`Cmd::SecretOpened`], the answer to `Effect::Secret(OpenInput)` (the
//! secret session's serial and the window's [`OpenOutcome`]; never a secret).
//! 2026-11-20 (S4 P7b): it also answers `Effect::Secret(OpenDisplay)` (a display window's open;
//! the displayed secret never travels in it).
//!
//! 2026-11-21 (S4 W1): [`Cmd::HoldBegin`] and [`Cmd::HoldEnd`], S22's 2 s hold area (spec/04
//! §2.20): the shell finds the pressed area, keeps it and takes the pointer; the logic keeps only
//! the hold's gate. The area is no [`Press`] (S3 D3: no control sends it).
//!
//! 2026-11-21 (S4 W3, critique B-10): [`Cmd::MainHidden`], the main window's hidden-or-minimized
//! state for the wallet's mirror (the periodic reads pause while it is set). Windows sends it when
//! the window changes (made hidden, shown, minimized or restored, dropped); before, the logic read
//! the window itself.
//!
//! 2026-11-22 (S4c W15, plan §5 W15 as the owner's second batch amends it, critique B-1):
//! [`Cmd::Activate`] (a second start brings the wallet up), [`Cmd::Input`] (app input for the
//! idle timer) and [`Cmd::Tick`] (one part of the main timer, [`TickPart`]): the shell's entries
//! that are plain data. Before, the Windows shell called those wallet fns itself (through
//! `App`'s `DerefMut`, which non-test builds no longer have). A worker's result, a lock and the
//! shutdown are no `Cmd`: a result can hold a secret (a key worker's outcome, plan §7.1), so it
//! enters through a typed in-process call; the lock and the shutdown are the shell's
//! compositions of the wallet's halves around the shell's own wait for the key worker (spec/04
//! §1.5, §5.3).

use core::fmt;

use yw_core::secret::Zeroizing;

use crate::approval::flow::{ApprovalInput, OpenOutcome, ShownId};
use crate::effect::TimerId;
use crate::explorer::ExplorerNet;
use crate::form::{EditField, FormSnapshot, PressInput};
use crate::received::RecvChain;

mod book;
mod btc;
mod core_screens;
mod evm;
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
mod yubikey;
mod zec;

pub use book::{BookPress, BookRowAction};
pub use btc::{BtcActivityAction, BtcPress};
pub use core_screens::{CorePress, RpcRowAction};
pub use evm::{ChainRowAction, EvmActivityAction, EvmPress};
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
pub use yubikey::{YkConnectPress, YkManagePress, YkPress};
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
    /// Windows-transitional (goes in S5, with `Form`): what one plain edit shows right after the
    /// shell applied `Effect::SetField` or `Effect::ClearField` to it (`None`: no such edit); the
    /// logic puts it into the form state (2026-11-21, S4 W2, plan §3.4, D-4: the shell writes no
    /// wallet state; before, the effect executor wrote the form state itself, at the same point).
    FieldShown {
        /// The field written.
        field: EditField,
        /// Its text as the edit holds it now.
        text: Option<Zeroizing<String>>,
    },
    /// A one-shot timer asked for by `Effect::StartTimer` fired.
    Timer(TimerId),
    /// Result of `Effect::CopyText`, echoing its mark (it may arrive later on Android).
    CopyDone {
        /// Whether the text reached the clipboard.
        ok: bool,
        /// The mark of the copy effect.
        mark: CopyMark,
    },
    /// One input of an approval window (S4 B6): an input of a window that is not the shown one
    /// is dropped.
    Approval(ApprovalInput),
    /// Result of `Effect::Approval(ApprovalEffect::Open)` (S4 B5): the window it was asked for,
    /// whether it was made, and its width class (the wide layout applies) when it was.
    ApprovalOpened {
        /// The window the open was for (a result for a flow that has ended is dropped).
        shown: ShownId,
        /// What became of the open.
        outcome: OpenOutcome,
        /// The window's client area is wide (`>= 640` DIP); `false` when not made.
        wide: bool,
    },
    /// Result of `Effect::OpenUrl` (S4 P3), echoing its target (it may arrive later on Android).
    Opened {
        /// Whether the browser was started.
        ok: bool,
        /// The target of the open effect.
        which: LinkTarget,
    },
    /// Answer to `Effect::OpenFolder(Folder::Extension)` (S4 P3): no extension folder was found
    /// and nothing was opened. An open of the data or log folder is never answered.
    FolderMissing,
    /// Result of `Effect::Secret(SecretEffect::OpenInput)` (S4 P7a1) and of
    /// `SecretEffect::OpenDisplay` (S4 P7b): the secret session the window was for and what
    /// became of it. Never a secret (a submission reaches the logic
    /// in-process). A result for a session that has ended is dropped.
    SecretOpened {
        /// The secret session of the open effect.
        serial: u64,
        /// What became of the open.
        outcome: OpenOutcome,
    },
    /// S22's hold area was pressed (S4 W1, spec/04 §2.20): the shell found the pointer on it and
    /// takes the pointer capture. The logic starts the hold's 2 s gate at `now_ms`, the shell's
    /// monotonic clock read when the message arrived (one read per pointer press, hit or not,
    /// as before the split).
    HoldBegin {
        /// When the press arrived (the logic's `Clock`, monotonic ms).
        now_ms: u64,
    },
    /// The hold ended early (S4 W1): the button was released, or the pointer left the area it
    /// pressed. The logic cancels a running hold (and releases the pointer through
    /// `Effect::ReleaseHold`); with none running it does nothing.
    HoldEnd,
    /// The main window became hidden or minimized (`true`), or shown or restored (`false`)
    /// (S4 W3, critique B-10): the wallet's mirror, which pauses the periodic balance,
    /// `HyperCore` and received-history reads. Sent only when the value changed; no main window
    /// is not hidden.
    MainHidden(bool),
    /// A second start of the app asked for the wallet (S4c W15; Windows `WM_YW_ACTIVATE`, spec/04
    /// §1.1): the main window comes up (`Effect::RaiseMain`), then the unlock window when locked.
    Activate,
    /// Key or button input to one of the app's windows (S4c W15, spec/04 §5.1): the idle clock
    /// restarts at the logic's `Clock`. Input to other programs never comes here.
    Input,
    /// One part of the main timer's period (S4c W15): the logic runs that part at `now_ms`. The
    /// shell sends the parts one at a time and applies what each emitted before the next, as the
    /// timer ran them before (spec/04 §1.4).
    Tick {
        /// The shell's monotonic clock read once for the whole period (the logic's `Clock`).
        now_ms: u64,
        /// Which part.
        part: TickPart,
    },
}

/// The wallet's parts of the main timer's period, in the order the Windows timer sends them
/// (S4c W15), and the early reads after a main-window message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickPart {
    /// The idle clock: pause or resume, then the idle lock or the first-run discard when due.
    Idle,
    /// The loading waits that time out (T-WAIT-STALLED).
    Wait,
    /// S22's 2 s hold gate.
    ResetHold,
    /// The copy mark's end.
    Copied,
    /// EVM reads and the approval queue's expiry.
    Evm,
    /// `HyperCore` reads.
    HyperCore,
    /// Solana reads.
    Sol,
    /// Bitcoin reads.
    Btc,
    /// Zcash reads.
    Zec,
    /// The received-history reads.
    Received,
    /// Not the timer: the reads a main-window message made due start right after it (at most
    /// once per timer period; the timer's own checks).
    ReadsDue,
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
            Self::FieldShown { field, text } => formatter
                .debug_struct("FieldShown")
                .field("field", field)
                .field("len", &text.as_ref().map(|text| text.len()))
                .finish(),
            Self::Timer(timer) => formatter.debug_tuple("Timer").field(timer).finish(),
            Self::CopyDone { ok, mark } => formatter
                .debug_struct("CopyDone")
                .field("ok", ok)
                .field("mark", mark)
                .finish(),
            Self::Approval(input) => formatter.debug_tuple("Approval").field(input).finish(),
            Self::ApprovalOpened {
                shown,
                outcome,
                wide,
            } => formatter
                .debug_struct("ApprovalOpened")
                .field("shown", shown)
                .field("outcome", outcome)
                .field("wide", wide)
                .finish(),
            Self::Opened { ok, which } => formatter
                .debug_struct("Opened")
                .field("ok", ok)
                .field("which", which)
                .finish(),
            Self::FolderMissing => formatter.write_str("FolderMissing"),
            Self::SecretOpened { serial, outcome } => formatter
                .debug_struct("SecretOpened")
                .field("serial", serial)
                .field("outcome", outcome)
                .finish(),
            Self::HoldBegin { now_ms } => formatter
                .debug_struct("HoldBegin")
                .field("now_ms", now_ms)
                .finish(),
            Self::HoldEnd => formatter.write_str("HoldEnd"),
            Self::MainHidden(hidden) => formatter.debug_tuple("MainHidden").field(hidden).finish(),
            Self::Activate => formatter.write_str("Activate"),
            Self::Input => formatter.write_str("Input"),
            Self::Tick { now_ms, part } => formatter
                .debug_struct("Tick")
                .field("now_ms", now_ms)
                .field("part", part)
                .finish(),
        }
    }
}

/// What an `Effect::OpenUrl` opens (S4 P3). It travels with the effect and back with
/// `Cmd::Opened`, so the result never depends on what changed in between (as [`CopyMark`]).
#[derive(Clone, PartialEq, Eq)]
pub enum LinkTarget {
    /// A block-explorer page of `net` (spec/04 §2.6, §2.14).
    Explorer {
        /// The network (the `explorer.open` log names only it).
        net: ExplorerNet,
        /// The page's host name, for the result band (`None`: the URL gave none).
        host: Option<String>,
    },
}

/// The network and the host's length only (D28): never the host.
impl fmt::Debug for LinkTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explorer { net, host } => formatter
                .debug_struct("Explorer")
                .field("net", net)
                .field("host_len", &host.as_ref().map(String::len))
                .finish(),
        }
    }
}

/// What a copy result applies to: the pressed copy control, whether the caption is the
/// address one, and the band a setup step answers with instead of the mark. It travels with
/// `Effect::CopyText` and back with `Cmd::CopyDone`, so the result never depends on what was
/// pressed in between.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyMark {
    /// The press that copied.
    pub anchor: Press,
    /// The address caption (`주소 복사됨`) rather than the plain one.
    pub address: bool,
    /// 2026-11-20 (S4 P6): a copied setup step's instruction band, shown instead of the mark at
    /// the control (`None`: the mark). Before P6 the three handlers read the copy's result right
    /// after the copy (`copied.take()`), which only works while the result arrives inside it.
    pub band: Option<CopyBand>,
}

/// The instruction band a copied setup step answers with (2026-11-20, S4 P6): which step only;
/// the shell's text catalogue holds the words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyBand {
    /// S23 `경로 복사`: the extension folder's path.
    ExtensionPath,
    /// S23 `주소 복사`: `chrome://extensions`.
    ExtensionsUrl,
    /// The `WalletConnect` panel's `주소 복사`: `https://dashboard.reown.com`.
    ReownAddress,
}

/// What was pressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Press {
    /// Esc (Windows `IDCANCEL`); Android back. 2026-11-20 (S4 P4): the logic only does what
    /// every press does first (the last press, the copy mark); the shell then resolves what the
    /// key stands for on the screen (an overlay's `취소`, a cancel, a back link, closing a
    /// drop-down) and sends that control's own press. Before P4 the logic resolved it.
    Back,
    /// Windows-transitional: Enter (`IDOK`). 2026-11-20 (S4 P4): as [`Self::Back`] — the shell
    /// resolves the focused control (a button, or an edit's one action) into its own press
    /// after this one. Before P4 the logic read the focus.
    Enter,
    /// The core screens, settings sections and URL rows (S3 C12).
    Core(CorePress),
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
    /// The Bitcoin screens (S3 C9).
    Btc(BtcPress),
    /// The EVM screens (S3 C10).
    Evm(EvmPress),
    /// The `YubiKey` tab and enrolment wizard (S3 C11).
    Yk(YkPress),
    /// The `YubiKey` card actions re-slot and clear (S3 C11).
    YkManage(YkManagePress),
    /// The `YubiKey` connect flow (S3 C11).
    YkConnect(YkConnectPress),
}

/// A family's press is a [`Press`] (2026-11-24, spec/15 §11.4 S5-4: the screen model names its
/// controls by press, `screen::model::Act`).
macro_rules! family_presses {
    ($($family:ident => $variant:ident),* $(,)?) => {
        $(
            impl From<$family> for Press {
                fn from(press: $family) -> Self {
                    Self::$variant(press)
                }
            }
        )*
    };
}

family_presses! {
    CorePress => Core,
    ReceivedPress => Received,
    SitesPress => Sites,
    LlmPress => Llm,
    WcPress => Wc,
    HiddenPress => Hidden,
    SidecarPress => Sidecar,
    ExplorerPress => Explorer,
    LinksPress => Links,
    BookPress => Book,
    ResetPress => Reset,
    ExtPress => Ext,
    KeysPress => Keys,
    RpcImportPress => RpcImport,
    MnPress => Mn,
    HcPress => Hc,
    ZecPress => Zec,
    SolPress => Sol,
    BtcPress => Btc,
    EvmPress => Evm,
    YkPress => Yk,
    YkManagePress => YkManage,
    YkConnectPress => YkConnect,
}

impl Press {
    /// The chain whose received-history list a card's `새로고침` press also reads now, before the
    /// card's own handler runs (spec/04 §2.6). A chain family adds its `새로고침` arm when it
    /// converts (S3 C; C7: `HyperCore` and Zcash; C8: Solana; C9: Bitcoin; C10: EVM); every
    /// other press has none.
    #[must_use]
    pub const fn refresh_chain(self) -> Option<RecvChain> {
        match self {
            Self::Hc(HcPress::Refresh) => Some(RecvChain::Hc),
            Self::Zec(ZecPress::Refresh) => Some(RecvChain::Zec),
            Self::Sol(SolPress::Refresh) => Some(RecvChain::Sol),
            Self::Btc(BtcPress::Refresh) => Some(RecvChain::Btc),
            Self::Evm(EvmPress::Refresh) => Some(RecvChain::Evm),
            Self::Back
            | Self::Enter
            | Self::Core(_)
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
            | Self::Btc(_)
            | Self::Evm(_)
            | Self::Yk(_)
            | Self::YkManage(_)
            | Self::YkConnect(_) => None,
        }
    }

    /// Whether the press shows or copies a receive address, which is refused while a passphrase
    /// wallet is open unverified (spec/02 §7.5; before any chain handler runs, so Bitcoin does
    /// not derive and store a new address). A chain family adds its arms when it converts (S3 C;
    /// C7: Zcash's two `주소 복사`; C8: Solana's `받기` and `주소 복사`; C9: Bitcoin's `받기` and
    /// the account card's `주소 복사` — its receive screen's copy never was; C10: EVM's `받기` and
    /// `주소 복사`); every other press is not one. (Until S3 C12 the shell's legacy chain kept
    /// its own gate for ids not converted yet; S3 D3 removed `Legacy`.)
    #[must_use]
    pub const fn is_receive_gated(self) -> bool {
        match self {
            Self::Zec(ZecPress::CopyAddress | ZecPress::CardCopy)
            | Self::Sol(SolPress::ReceiveOpen | SolPress::CopyAddress)
            | Self::Btc(BtcPress::ReceiveOpen | BtcPress::CardCopy)
            | Self::Evm(EvmPress::ReceiveOpen | EvmPress::CopyAddress) => true,
            Self::Back
            | Self::Enter
            | Self::Core(_)
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
            | Self::Btc(_)
            | Self::Evm(_)
            | Self::Yk(_)
            | Self::YkManage(_)
            | Self::YkConnect(_) => false,
        }
    }

    /// The press with the state of its check box set to `None` (every other press unchanged):
    /// what a screen draws for that control, whose state is read only when it is clicked
    /// (2026-11-24, spec/15 §11.4 S5-2: the screen model's controls; the Windows lowering
    /// compares a drawn press with the one its control id maps back to, the state ignored).
    #[must_use]
    pub const fn without_check(self) -> Self {
        match self {
            Self::Book(BookPress::Verified(_)) => Self::Book(BookPress::Verified(None)),
            Self::Book(BookPress::Favorite(_)) => Self::Book(BookPress::Favorite(None)),
            Self::Book(BookPress::FormAck(_)) => Self::Book(BookPress::FormAck(None)),
            Self::Book(BookPress::PromptAck(_)) => Self::Book(BookPress::PromptAck(None)),
            Self::Core(CorePress::MismatchCheck(_)) => Self::Core(CorePress::MismatchCheck(None)),
            Self::Core(CorePress::CopyToggle(_)) => Self::Core(CorePress::CopyToggle(None)),
            Self::Core(CorePress::LocalhostToggle(_)) => {
                Self::Core(CorePress::LocalhostToggle(None))
            }
            Self::Core(CorePress::AutolaunchToggle(_)) => {
                Self::Core(CorePress::AutolaunchToggle(None))
            }
            Self::Core(CorePress::OverwriteCheck(_)) => Self::Core(CorePress::OverwriteCheck(None)),
            Self::Evm(EvmPress::SendAck(_)) => Self::Evm(EvmPress::SendAck(None)),
            Self::Evm(EvmPress::TokenHideZero(_)) => Self::Evm(EvmPress::TokenHideZero(None)),
            Self::Evm(EvmPress::RepinCheck(_)) => Self::Evm(EvmPress::RepinCheck(None)),
            Self::Llm(LlmPress::Enable(_)) => Self::Llm(LlmPress::Enable(None)),
            Self::Llm(LlmPress::NoticeCheck(_)) => Self::Llm(LlmPress::NoticeCheck(None)),
            Self::Received(ReceivedPress::Toggle { chain, .. }) => {
                Self::Received(ReceivedPress::Toggle {
                    chain,
                    checked: None,
                })
            }
            Self::Reset(ResetPress::SettingsCheck(_)) => {
                Self::Reset(ResetPress::SettingsCheck(None))
            }
            Self::Sidecar(SidecarPress::ResetAck(_)) => Self::Sidecar(SidecarPress::ResetAck(None)),
            other => other,
        }
    }

    /// Whether `self` and `other` are the same control's press (the state of a check box
    /// ignored, [`Self::without_check`]).
    #[must_use]
    pub fn same_control(self, other: Self) -> bool {
        self.without_check() == other.without_check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::form::{CredField, CredUnits};

    /// 2026-11-24 (S5-2): a check box's press without its state, every other press unchanged.
    #[test]
    fn without_check_clears_only_a_check_boxs_state() {
        for (pressed, drawn) in [
            (
                Press::Book(BookPress::Verified(Some(true))),
                Press::Book(BookPress::Verified(None)),
            ),
            (
                Press::Core(CorePress::CopyToggle(Some(false))),
                Press::Core(CorePress::CopyToggle(None)),
            ),
            (
                Press::Evm(EvmPress::SendAck(Some(true))),
                Press::Evm(EvmPress::SendAck(None)),
            ),
            (
                Press::Llm(LlmPress::NoticeCheck(Some(true))),
                Press::Llm(LlmPress::NoticeCheck(None)),
            ),
            (
                Press::Received(ReceivedPress::Toggle {
                    chain: RecvChain::Btc,
                    checked: Some(true),
                }),
                Press::Received(ReceivedPress::Toggle {
                    chain: RecvChain::Btc,
                    checked: None,
                }),
            ),
            (
                Press::Reset(ResetPress::SettingsCheck(Some(true))),
                Press::Reset(ResetPress::SettingsCheck(None)),
            ),
            (
                Press::Sidecar(SidecarPress::ResetAck(Some(false))),
                Press::Sidecar(SidecarPress::ResetAck(None)),
            ),
        ] {
            assert_eq!(pressed.without_check(), drawn);
            assert!(pressed.same_control(drawn) && drawn.same_control(pressed));
        }
        let lock = Press::Core(CorePress::Lock);
        assert_eq!(lock.without_check(), lock);
        assert!(!lock.same_control(Press::Core(CorePress::Exit)));
        assert!(
            !Press::Received(ReceivedPress::Toggle {
                chain: RecvChain::Btc,
                checked: None,
            })
            .same_control(Press::Received(ReceivedPress::Toggle {
                chain: RecvChain::Zec,
                checked: None,
            }))
        );
    }

    /// 2026-11-21 (S4 W1): S22's hold area commands print their name and the time only.
    #[test]
    fn hold_commands_print_their_name_and_time() {
        assert_eq!(
            format!("{:?}", Cmd::HoldBegin { now_ms: 1_234 }),
            "HoldBegin { now_ms: 1234 }"
        );
        assert_eq!(format!("{:?}", Cmd::HoldEnd), "HoldEnd");
    }

    /// 2026-11-21 (S4 W3, critique B-10): the main window's mirror command prints its value.
    #[test]
    fn main_hidden_prints_its_value() {
        assert_eq!(format!("{:?}", Cmd::MainHidden(true)), "MainHidden(true)");
        assert_eq!(format!("{:?}", Cmd::MainHidden(false)), "MainHidden(false)");
    }

    /// 2026-11-20 (S4 P6): a copy mark's band prints as the step's name (the words are the
    /// shell's catalogue's).
    #[test]
    fn copy_mark_debug_names_its_band() {
        assert_eq!(
            format!(
                "{:?}",
                Cmd::CopyDone {
                    ok: true,
                    mark: CopyMark {
                        anchor: Press::Ext(ExtPress::CopyUrl),
                        address: false,
                        band: Some(CopyBand::ExtensionsUrl),
                    }
                }
            ),
            "CopyDone { ok: true, mark: CopyMark { anchor: Ext(CopyUrl), address: false, \
             band: Some(ExtensionsUrl) } }"
        );
    }

    /// 2026-11-21 (S4 W2): one field's read-back after a field write prints the field and the
    /// length only.
    #[test]
    fn field_shown_prints_no_text() {
        let field = Cmd::FieldShown {
            field: EditField::WcUri,
            text: Some(Zeroizing::new("wc:abc@2?symKey=00".to_owned())),
        };
        let shown = format!("{field:?}");
        assert!(!shown.contains("symKey"), "{shown}");
        assert_eq!(shown, "FieldShown { field: WcUri, len: Some(18) }");
        assert_eq!(
            format!(
                "{:?}",
                Cmd::FieldShown {
                    field: EditField::LlmEndpoint,
                    text: None,
                }
            ),
            "FieldShown { field: LlmEndpoint, len: None }"
        );
    }

    #[test]
    fn debug_prints_no_text_or_units() {
        let units: Vec<u16> = "token-abc".encode_utf16().collect();
        let press = Cmd::Press {
            press: Press::Core(CorePress::TemplateSave),
            input: PressInput::new(vec![
                (CredField::QnToken, CredUnits::Units(Zeroizing::new(units))),
                (CredField::AlchemyKey, CredUnits::Absent),
            ]),
        };
        let shown = format!("{press:?}");
        assert!(!shown.contains("token"), "{shown}");
        // `misses` is counted (and printed) only in debug builds.
        #[cfg(debug_assertions)]
        assert_eq!(
            shown,
            "Press { press: Core(TemplateSave), input: PressInput { creds: [(QnToken, Units(9)), \
             (AlchemyKey, Absent)], misses: 0 } }"
        );
        #[cfg(not(debug_assertions))]
        assert_eq!(
            shown,
            "Press { press: Core(TemplateSave), input: PressInput { creds: [(QnToken, Units(9)), \
             (AlchemyKey, Absent)] } }"
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
                        address: false,
                        band: None,
                    }
                }
            ),
            "CopyDone { ok: false, mark: CopyMark { anchor: Back, address: false, band: None } }"
        );
        assert_eq!(
            format!("{:?}", Cmd::Timer(TimerId::SendCheck)),
            "Timer(SendCheck)"
        );
        assert_eq!(
            format!(
                "{:?}",
                Cmd::ApprovalOpened {
                    shown: ShownId(2),
                    outcome: OpenOutcome::Failed(crate::errors::ErrorCode::App009),
                    wide: false,
                }
            ),
            "ApprovalOpened { shown: ShownId(2), outcome: Failed(App009), wide: false }"
        );
        assert_eq!(
            format!(
                "{:?}",
                Cmd::Approval(ApprovalInput {
                    shown: ShownId(4),
                    foreground: false,
                    signal: crate::approval::flow::ApprovalSignal::Close,
                })
            ),
            "Approval(ApprovalInput { shown: ShownId(4), foreground: false, signal: Close })"
        );
        // S4 P3: the network and the host's length only.
        let opened = Cmd::Opened {
            ok: true,
            which: LinkTarget::Explorer {
                net: ExplorerNet::Evm(1),
                host: Some("etherscan.io".to_owned()),
            },
        };
        let shown = format!("{opened:?}");
        assert!(!shown.contains("etherscan"), "{shown}");
        assert_eq!(
            shown,
            "Opened { ok: true, which: Explorer { net: Evm(1), host_len: Some(12) } }"
        );
        assert_eq!(format!("{:?}", Cmd::FolderMissing), "FolderMissing");
    }

    /// S4 P7a1: a secret window's open result is its serial and outcome.
    #[test]
    fn secret_opened_debug_is_serial_and_outcome() {
        assert_eq!(
            format!(
                "{:?}",
                Cmd::SecretOpened {
                    serial: 5,
                    outcome: OpenOutcome::Shown {
                        capture_excluded: false
                    },
                }
            ),
            "SecretOpened { serial: 5, outcome: Shown { capture_excluded: false } }"
        );
    }
}
