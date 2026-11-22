//! Plain screen data the logic and the shell share (spec/04 §1.7, spec/15 §11.4 S4).
//!
//! 2026-11-20 (spec/15 §11.4 S4 P10a; plan E0a pulled forward for these two types only):
//! [`SettingsSection`] (was yw-app `app::SettingsSection`) and [`ScrollPlace`] (was yw-app
//! `app_scroll::ScrollPlace`) moved here unchanged, so the scroll effects of a screen entry and a
//! tab switch carry the place they read when the logic emits them
//! ([`crate::effect::Effect::ScreenLeaving`], [`crate::effect::Effect::ScreenEntered`],
//! [`crate::effect::Effect::TabTop`]). P10a had yw-app re-export both under their old paths;
//! 2026-11-21 (S4b final review, AGENTS.md §4): no longer, yw-app names `yw_engine::screen`.
//!
//! 2026-11-22 (spec/15 §11.4 S4d E0a): the screen data the wallet code takes from yw-app's shell
//! files moved here unchanged, with their texts (catalogue [`text`]): the banner [`Tone`] and its
//! tag words (was yw-app `ui::main_window::Tone`; its colors stay in the shell,
//! `ui::main_window::tone_colors`), the receive QR choice [`EvmQrKind`] and its payloads (was
//! `ui::qr`; the `qrcodegen` encoding and painting stay there), the removal block's
//! [`RemovedAccount`] and [`LastBalance`] (was `ui::removed`), an account's key source
//! [`AccountSource`] with the card roles and source words (was `ui::screens_accounts`), the EVM
//! activity row [`ActivityRowView`] (was `ui::screens_evm`) and the main window timer period
//! [`MAIN_TIMER_MS`] (was `shell_msg`). Before, the wallet named them in those shell modules.

use yw_core::evm::address::Address;
use yw_core::lang::Lang;
use yw_core::yubikey::plan::KeyRole;

use crate::meta::Tab;

/// Main window timer period (the shell's main timer; the wallet's read cadence counts in it).
pub const MAIN_TIMER_MS: u32 = 250;

/// Settings sections (S15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsSection {
    /// 보안.
    Security,
    /// 네트워크 (RPC 공급자, 네트워크 URL).
    Network,
    /// 브라우저·정보.
    Other,
    /// EVM 체인, 수수료 상한 (M4).
    Chains,
    /// Solana: 클러스터, 수수료 상한, 다른 경로 스캔 (M7).
    Solana,
    /// Bitcoin: 켜기·네트워크, 인덱서, Esplora URL (M8).
    Bitcoin,
    /// AI 설명 (M6, spec/06 §2).
    Ai,
    /// `YubiKey`: the enrolled cards, their slots and accounts, `YubiKey 등록`, `삭제` (spec/10).
    YubiKey,
    /// 복구 단어: the wallet's recovery phrases, adding, backup, removal (spec/04 §2.24).
    Mnemonics,
}

/// A screen whose scroll offset is remembered for the ways back (2026-11-10): each S10 chain tab,
/// each settings section, S08, S13 and S14.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrollPlace {
    /// S10 on a chain tab.
    Main(Tab),
    /// A settings section.
    Settings(SettingsSection),
    /// S08 '처음 설정' (`← 처음 설정으로` returns there).
    Done,
    /// S13.
    Sites,
    /// S14.
    AddressBook,
}

/// Where a screen just entered opens (2026-11-20, S4 P10a: worked out by the logic when it
/// emits [`crate::effect::Effect::ScreenEntered`], from the screen it entered and the one it left;
/// before, the shell read both while it applied the effect).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnteredAt {
    /// A confirmation overlay closed onto a screen that is not one: where the screen under the
    /// overlay was scrolled when it opened, if `same` (the screen entered is the one the overlay
    /// opened over); the noted offset is used up either way.
    UnderOverlay {
        /// The screen entered is the screen the overlay opened over.
        same: bool,
    },
    /// A way back: where the place was left in this run (`None`: a screen with no remembered
    /// place, at its top).
    LeftAt(Option<ScrollPlace>),
    /// At its top.
    Top,
}

/// Banner tone. Each tone has one meaning everywhere (spec/04 §1.6 status colors).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// 오류: an error with a code (the action did not happen or cannot start).
    Danger,
    /// 주의: check something before continuing.
    Warn,
    /// 정보: neutral information.
    Info,
    /// 테스트넷: `TESTNET_BG`.
    Testnet,
    /// `BTC_MAINNET_BG` / `BTC_MAINNET_TEXT` (spec/08 §2 `BITCOIN MAINNET`).
    BtcMainnet,
    /// `BTC_TESTNET4_BG` / `TEXT` (spec/08 §2 `BITCOIN TESTNET4 — 가치 없음`).
    BtcTestnet4,
    /// 고위험: a likely loss of funds (address poisoning, program-owned recipient …).
    HighRisk,
    /// 차단: the function is stopped until the cause is fixed.
    Blocked,
    /// 완료: an action succeeded.
    Success,
}

impl Tone {
    /// The status word drawn in the banner's tag (`None` for the Bitcoin network banners, whose
    /// text is the whole message).
    #[must_use]
    pub const fn label(self, lang: Lang) -> Option<&'static str> {
        let text = match self {
            Self::Danger => text::TONE_DANGER,
            Self::Warn => text::TONE_WARN,
            Self::Info => text::TONE_INFO,
            Self::Testnet => text::TONE_TESTNET,
            Self::HighRisk => text::TONE_HIGH_RISK,
            Self::Blocked => text::TONE_BLOCKED,
            Self::Success => text::TONE_SUCCESS,
            Self::BtcMainnet | Self::BtcTestnet4 => return None,
        };
        Some(text.get(lang))
    }
}

/// What the EVM receive QR encodes (spec/04 §2.8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EvmQrKind {
    /// EIP-681 `ethereum:<EIP-55 address>@<chainId>` (default; wallets pick the network).
    #[default]
    Eip681,
    /// The bare EIP-55 address, for exchange apps that reject `ethereum:` URIs.
    PlainAddress,
}

impl EvmQrKind {
    /// The choice label for the receive screen.
    #[must_use]
    pub const fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::Eip681 => text::QR_WALLET_APP.get(lang),
            Self::PlainAddress => text::QR_ADDRESS_ONLY.get(lang),
        }
    }
}

/// The EVM receive payload (EIP-681).
#[must_use]
pub fn evm_payload(address: &Address, chain_id: u64) -> String {
    format!("ethereum:{}@{chain_id}", address.to_checksum())
}

/// The EVM receive payload of `kind`: EIP-681 or the bare EIP-55 address.
#[must_use]
pub fn evm_receive_payload(address: &Address, chain_id: u64, kind: EvmQrKind) -> String {
    match kind {
        EvmQrKind::Eip681 => evm_payload(address, chain_id),
        EvmQrKind::PlainAddress => address.to_checksum(),
    }
}

/// A native balance as last read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LastBalance {
    /// More than zero: the amount text and the network.
    Positive {
        /// `1.25 SepoliaETH`.
        text: String,
        /// The network it was read on.
        network: String,
    },
    /// Zero on `network`.
    Zero {
        /// The network it was read on.
        network: String,
    },
    /// Never read on the network shown now.
    Unknown,
}

/// One account a removal takes out of the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovedAccount {
    /// The account's name.
    pub label: String,
    /// `EVM`, `Solana`, `Bitcoin`, `Zcash`.
    pub chain: &'static str,
    /// Full addresses, grouped (§3.3).
    pub addresses: Vec<String>,
    /// The balance as last read.
    pub balance: LastBalance,
    /// The key is gone for good with this removal (no recovery words and on no other card; an
    /// imported key).
    pub lost: bool,
    /// What still signs for it, when that is the question ("`YubiKey` #m(으)로 계속 서명").
    pub note: Option<String>,
    /// The account stays usable (another card holds the key): its balance is only shown.
    pub kept: bool,
}

/// Where an account's key comes from: the source part of its drop-down item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountSource {
    /// Derived from recovery words: `None` the wallet's first set, `Some(id)` an added set.
    Words(Option<[u8; 16]>),
    /// An imported private key.
    Imported,
    /// A key on `YubiKey` cards: its slot role (`None`: not known; the source then says
    /// `YubiKey` alone).
    Card(Option<KeyRole>),
    /// The key of EVM account `i` used for a Bitcoin address (spec/08 §3.5).
    EvmKey(u32),
}

/// The card role of the EVM `YubiKey` account `index` (`None` out of range).
#[must_use]
pub fn evm_card_role(index: u32) -> Option<KeyRole> {
    yw_core::bip32::path::AccountIndex::new(index)
        .ok()
        .map(|index| KeyRole::Evm { index, btc: None })
}

/// The card role of the Solana `YubiKey` account `index` (`None` out of range).
#[must_use]
pub fn sol_card_role(index: u32) -> Option<KeyRole> {
    yw_core::bip32::path::AccountIndex::new(index)
        .ok()
        .map(|index| KeyRole::Sol { index })
}

/// The card role of a Bitcoin `YubiKey` account on `network` (`None` for another account or an
/// unknown role).
#[must_use]
pub fn btc_card_role(
    account: &yw_core::btc::BtcAccountKey,
    network: yw_core::btc::BtcNetwork,
) -> Option<KeyRole> {
    match *account {
        yw_core::btc::BtcAccountKey::Hardware {
            key, script_type, ..
        } => key.role(network, script_type),
        _ => None,
    }
}

/// One activity row of the S10 list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityRowView {
    /// When it was made (Unix milliseconds); the render code prints it as local time before
    /// [`Self::head`] (2026-11-22, S4d E0c: the wallet formats no local time, plan D-30; before,
    /// `head` began with it).
    pub time_unix_ms: u64,
    /// Account label and title (the time is [`Self::time_unix_ms`]).
    pub head: String,
    /// Status.
    pub status: String,
    /// Hash text.
    pub hash: String,
    /// Group key when it is an open journal group (speed-up/cancel/resend/discard).
    pub open: Option<yw_core::journal::evm::GroupKey>,
    /// Manual resend/discard offered.
    pub manual: bool,
    /// The recipient (decoded token recipient for ERC-20 transfers) for `이 주소 저장`.
    pub counterparty: Option<Address>,
}

/// The fixed texts of this screen data (spec/14). 2026-11-22 (S4d E0a): the banner tags were
/// yw-app `ui::main_window::text`, the QR choices `ui::qr::text` and the source words
/// `ui::screens_accounts::text`; wording unchanged.
pub mod text {
    yw_core::texts! {
        /// Banner tag of [`super::Tone::Danger`].
        TONE_DANGER = "오류" / "Error";
        /// Banner tag of [`super::Tone::Warn`].
        TONE_WARN = "주의" / "Caution";
        /// Banner tag of [`super::Tone::Info`].
        TONE_INFO = "정보" / "Info";
        /// Banner tag of [`super::Tone::Testnet`].
        TONE_TESTNET = "테스트넷" / "Testnet";
        /// Banner tag of [`super::Tone::HighRisk`].
        TONE_HIGH_RISK = "고위험" / "High risk";
        /// Banner tag of [`super::Tone::Blocked`].
        TONE_BLOCKED = "차단" / "Blocked";
        /// Banner tag of [`super::Tone::Success`].
        TONE_SUCCESS = "완료" / "Done";
        /// The EIP-681 choice.
        QR_WALLET_APP = "지갑 앱용 QR (네트워크 포함)" / "QR for wallet apps (with network)";
        /// The bare-address choice.
        QR_ADDRESS_ONLY = "주소만 QR (거래소 앱용)" / "Address-only QR (for exchange apps)";
        /// The source of an account of the wallet's only recovery words (shown when the list
        /// mixes kinds of account).
        SOURCE_WORDS = "복구 단어" / "Recovery words";
        /// The source of an imported key's account.
        SOURCE_IMPORTED = "가져온 키" / "Imported key";
        /// The source of a Bitcoin account on an EVM account's key (2026-11-15; the Bitcoin
        /// list's `EVM 계정 {i} 키` badge before): {0} the EVM account index.
        SOURCE_EVM_KEY(1) = "EVM 계정 {0} 키" / "EVM account {0} key";
    }
}
