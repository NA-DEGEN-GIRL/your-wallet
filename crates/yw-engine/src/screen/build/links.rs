//! Copyable values, icon actions and the account drop-downs of the main wallet tab (2026-11-11,
//! spec/04 §2.6): a transaction hash or an address is drawn whole on a flat button whose click
//! copies it ([`Item::CopyLine`]), with small icon buttons at the right end of its line —
//! `탐색기에서 열기` ↗, `탐색기 링크 복사` 🔗, `이 주소 저장` ☆ — instead of the rows of
//! labelled buttons under it; and `내 계정` picks its account from a drop-down like the network's.
//!
//! Copy rules: the account cards' own address, the token contracts, the recipients of the
//! wallet's **own** sent transactions (its signed journal) and every transaction hash may be
//! copied. The senders of the received history (`screens_received`) never are — they stay
//! display-only (address poisoning, spec/07 §12.3).
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens_links.rs` with the
//! bodies unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine paths); its
//! control ids stay there (`ui::screens_links::ids`).

use super::Screen;
use crate::cmd::Press;
use crate::explorer::ExplorerNet;
use crate::screen::address::{AddressKind, own_address_spans};
use crate::screen::model::{Ctl, GLYPH_LINK, GLYPH_OPEN, GLYPH_SAVE, Item};
use yw_core::lang::Lang;

/// The fixed texts of this module (spec/14).
pub mod text {
    yw_core::texts! {
        /// The accessible name and tooltip of a copyable hash.
        T_HASH_COPY = "해시 복사" / "Copy hash";
        /// The accessible name and tooltip of a copyable address.
        T_ADDRESS_COPY = "주소 복사" / "Copy address";
        /// `탐색기에서 열기` (↗).
        T_EXPLORER_OPEN = "탐색기에서 열기" / "Open in explorer";
        /// `탐색기 링크 복사` (🔗).
        T_EXPLORER_COPY = "탐색기 링크 복사" / "Copy explorer link";
        /// `이 주소 저장` (☆).
        T_SAVE_ADDRESS = "이 주소 저장" / "Save this address";
        /// The account drop-down before an account is chosen.
        PICK_ACCOUNT = "계정을 고르세요" / "Choose an account";
        /// The account drop-down's label.
        ACCOUNT = "계정" / "Account";
    }
}

pub use text::{T_ADDRESS_COPY, T_EXPLORER_COPY, T_EXPLORER_OPEN, T_HASH_COPY, T_SAVE_ADDRESS};

/// A transaction hash on its own line: a click copies it (`copy`; display-only without one),
/// `actions` (the explorer icons) right after it. Shown short (2026-11-12, [`short_hash`]: the
/// whole 64–88 characters took a line or two of every activity row); the copy handlers copy
/// the whole hash from the row, and the tooltip shows it.
pub fn push_hash_line(
    items: &mut Vec<Item>,
    lang: Lang,
    copy: Option<Press>,
    hash: &str,
    actions: Vec<Ctl>,
) {
    let label = T_HASH_COPY.get(lang);
    push_value_line(items, copy, label, vec![(short_hash(hash), false)], actions);
    if let Some(Item::CopyLine { value, .. }) = items.last_mut() {
        value.tip = Some(format!("{label}: {hash}"));
    }
}

/// A transaction hash as its first 10 and last 6 characters (`0x1234abcd…5678ef`); a short one
/// whole. Display only — never for an address, and never where a hash is checked.
#[must_use]
pub fn short_hash(hash: &str) -> String {
    let count = hash.chars().count();
    if count <= 20 {
        return hash.to_owned();
    }
    let head: String = hash.chars().take(10).collect();
    let tail: String = hash.chars().skip(count.saturating_sub(6)).collect();
    format!("{head}…{tail}")
}

/// An address whole, the 4 characters after its prefix and the last 4 emphasized like the
/// account card's: a click copies it (`copy`), `actions` at the right end.
pub fn push_address_line(
    items: &mut Vec<Item>,
    lang: Lang,
    copy: Option<Press>,
    address: &str,
    kind: AddressKind,
    actions: Vec<Ctl>,
) {
    push_value_line(
        items,
        copy,
        T_ADDRESS_COPY.get(lang),
        own_address_spans(address, kind, false),
        actions,
    );
}

fn push_value_line(
    items: &mut Vec<Item>,
    copy: Option<Press>,
    label: &str,
    spans: Vec<(String, bool)>,
    actions: Vec<Ctl>,
) {
    if let Some(press) = copy {
        items.push(Item::CopyLine {
            value: Ctl::value(press, label, spans),
            actions,
        });
        return;
    }
    // Past the id span (never with the documented maxima): the value read-only.
    items.push(Item::Mono(
        spans.into_iter().map(|(piece, _)| piece).collect(),
    ));
    if !actions.is_empty() {
        items.push(Item::Row(actions));
    }
}

/// The `☆ 이 주소 저장` icon.
#[must_use]
pub fn save_icon(lang: Lang, press: impl Into<Press>) -> Ctl {
    Ctl::icon(press.into(), GLYPH_SAVE, T_SAVE_ADDRESS.get(lang))
}

/// One entry of an account drop-down: its id, label, whether it is the selected account, and
/// whether it may be chosen now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PickerEntry {
    /// The entry's press (the radio's of before; 2026-11-24 S5-4: its control id before).
    pub press: Press,
    /// `계정 2 · YubiKey: 메인·백업`, `가져온 계정 1 · 가져온 키` … (2026-11-15,
    /// `Screen::account_item_labels`).
    pub label: String,
    /// The selected account.
    pub selected: bool,
    /// May be chosen now.
    pub enabled: bool,
}

impl Screen<'_> {
    /// The `탐색기에서 열기` ↗ and `탐색기 링크 복사` 🔗 icons of `hash` on `network` (none when
    /// there is no transaction page, or past the id span).
    #[must_use]
    pub fn explorer_tx_icons(
        &self,
        network: impl Into<ExplorerNet>,
        hash: &str,
        presses: Option<(Press, Press)>,
    ) -> Vec<Ctl> {
        let lang = self.settings.language;
        match presses {
            Some((open, copy)) if self.explorer_tx_url(network, hash).is_some() => vec![
                Ctl::icon(open, GLYPH_OPEN, T_EXPLORER_OPEN.get(lang)),
                Ctl::icon(copy, GLYPH_LINK, T_EXPLORER_COPY.get(lang)),
            ],
            _ => Vec::new(),
        }
    }

    /// An account drop-down (2026-11-11, like S10's network drop-down): `계정` with a button
    /// naming the selected account and ▾ (`picker`), and while open the accounts under it, one
    /// per line (each entry keeps the id its radio had, so the same handler selects it).
    /// `usable == false` (2026-11-15, Zcash while a transaction is unfinished) disables the
    /// button and keeps the list closed.
    pub fn push_account_picker(
        &self,
        items: &mut Vec<Item>,
        picker: Press,
        entries: &[PickerEntry],
        usable: bool,
    ) {
        let lang = self.settings.language;
        // 2026-11-20 (S4 P6): the open drop-down is held as its button's press. 2026-11-24
        // (S5-4): compared by press (before, by `cmd_table::id_of` with the button's id).
        let open = usable
            && self
                .account_menu
                .is_some_and(|menu| menu.same_control(picker));
        let selected = entries
            .iter()
            .find(|entry| entry.selected)
            .map_or(text::PICK_ACCOUNT.get(lang), |entry| entry.label.as_str());
        items.push(Item::LabeledRow(
            text::ACCOUNT.get(lang).to_owned(),
            vec![
                Ctl::picker(picker, selected, open)
                    .fit(entries.iter().map(|entry| entry.label.as_str()))
                    .enabled(usable),
            ],
        ));
        if open {
            items.push(Item::Menu(
                entries
                    .iter()
                    .map(|entry| {
                        Ctl::entry(entry.press, &entry.label, entry.selected).enabled(entry.enabled)
                    })
                    .collect(),
            ));
        }
    }
}
