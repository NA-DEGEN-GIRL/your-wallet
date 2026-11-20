//! Plain screen data the logic and the shell share (spec/04 §1.7, spec/15 §11.4 S4).
//!
//! 2026-11-20 (spec/15 §11.4 S4 P10a; plan E0a pulled forward for these two types only):
//! [`SettingsSection`] (was yw-app `app::SettingsSection`) and [`ScrollPlace`] (was yw-app
//! `app_scroll::ScrollPlace`) moved here unchanged, so the scroll effects of a screen entry and a
//! tab switch carry the place they read when the logic emits them
//! ([`crate::effect::Effect::ScreenLeaving`], [`crate::effect::Effect::ScreenEntered`],
//! [`crate::effect::Effect::TabTop`]). yw-app re-exports both under their old paths.

use crate::meta::Tab;

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
