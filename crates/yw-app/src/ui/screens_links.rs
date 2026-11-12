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

use crate::app::App;
use crate::explorer::ExplorerNet;
use crate::ui::main_window::{Ctl, GLYPH_LINK, GLYPH_OPEN, GLYPH_SAVE, Item};
use crate::ui::theme::{AddressKind, own_address_spans};

/// Command ids (18,400–18,659; the whole map is `ui::command_ids`).
pub mod ids {
    /// The EVM `내 계정` drop-down button.
    pub const PICKER_EVM: u16 = 18_400;
    /// The Solana `내 Solana 계정` drop-down button.
    pub const PICKER_SOL: u16 = 18_401;
    /// The Bitcoin `Bitcoin 계정` drop-down button.
    pub const PICKER_BTC: u16 = 18_402;
    /// Every fixed id.
    pub const FIXED: [u16; 3] = [PICKER_EVM, PICKER_SOL, PICKER_BTC];
    /// EVM activity: a click on the recipient copies it (row order of `App::activity_rows`).
    pub const EVM_TO_BASE: u16 = 18_410;
    /// EVM recipient span (`app_evm::MAX_ACTIVITY_ROWS`).
    pub const EVM_TO_SPAN: u16 = 50;
    /// Solana activity recipients (display order, as `App::sol_activity_counterparties`).
    pub const SOL_TO_BASE: u16 = 18_460;
    /// Solana recipient span (the journal's 64 records).
    pub const SOL_TO_SPAN: u16 = 64;
    /// Bitcoin activity recipients (display order, as `BtcUi::activity_rows`).
    pub const BTC_TO_BASE: u16 = 18_530;
    /// Bitcoin recipient span (`app_btc::BTC_MAX_ACTIVITY_ROWS`).
    pub const BTC_TO_SPAN: u16 = 50;
    /// Zcash activity recipients (newest first, as drawn).
    pub const ZEC_TO_BASE: u16 = 18_580;
    /// Zcash recipient span (the journal's 80 records).
    pub const ZEC_TO_SPAN: u16 = 80;

    const _: () = assert!(PICKER_BTC < EVM_TO_BASE);
    const _: () = assert!(EVM_TO_BASE + EVM_TO_SPAN <= SOL_TO_BASE);
    const _: () = assert!(SOL_TO_BASE + SOL_TO_SPAN <= BTC_TO_BASE);
    const _: () = assert!(BTC_TO_BASE + BTC_TO_SPAN <= ZEC_TO_BASE);
    const _: () = assert!(ZEC_TO_BASE + ZEC_TO_SPAN <= 18_660);

    /// Row `row`'s id of a list starting at `base` (`None` past `span`).
    #[must_use]
    pub fn row_id(base: u16, span: u16, row: usize) -> Option<u16> {
        u16::try_from(row)
            .ok()
            .filter(|offset| *offset < span)
            .map(|offset| base + offset)
    }

    /// The row of `id` in a list starting at `base` (`None` outside it).
    #[must_use]
    pub fn row_of(id: u16, base: u16, span: u16) -> Option<usize> {
        id.checked_sub(base)
            .filter(|offset| *offset < span)
            .map(usize::from)
    }
}

/// The accessible name and tooltip of a copyable hash.
pub const T_HASH_COPY: &str = "해시 복사";
/// The accessible name and tooltip of a copyable address.
pub const T_ADDRESS_COPY: &str = "주소 복사";
/// `탐색기에서 열기` (↗).
pub const T_EXPLORER_OPEN: &str = "탐색기에서 열기";
/// `탐색기 링크 복사` (🔗).
pub const T_EXPLORER_COPY: &str = "탐색기 링크 복사";
/// `이 주소 저장` (☆).
pub const T_SAVE_ADDRESS: &str = "이 주소 저장";

/// A transaction hash on its own line: a click copies it (`copy`; display-only without one),
/// `actions` (the explorer icons) right after it. Shown short (2026-11-12, [`short_hash`]: the
/// whole 64–88 characters took a line or two of every activity row); the copy handlers copy
/// the whole hash from the row, and the tooltip shows it.
pub fn push_hash_line(items: &mut Vec<Item>, copy: Option<u16>, hash: &str, actions: Vec<Ctl>) {
    push_value_line(
        items,
        copy,
        T_HASH_COPY,
        vec![(short_hash(hash), false)],
        actions,
    );
    if let Some(Item::CopyLine { value, .. }) = items.last_mut() {
        value.tip = Some(format!("{T_HASH_COPY}: {hash}"));
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
    copy: Option<u16>,
    address: &str,
    kind: AddressKind,
    actions: Vec<Ctl>,
) {
    push_value_line(
        items,
        copy,
        T_ADDRESS_COPY,
        own_address_spans(address, kind, false),
        actions,
    );
}

fn push_value_line(
    items: &mut Vec<Item>,
    copy: Option<u16>,
    label: &str,
    spans: Vec<(String, bool)>,
    actions: Vec<Ctl>,
) {
    if let Some(id) = copy {
        items.push(Item::CopyLine {
            value: Ctl::value(id, label, spans),
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
pub fn save_icon(id: u16) -> Ctl {
    Ctl::icon(id, GLYPH_SAVE, T_SAVE_ADDRESS)
}

/// One entry of an account drop-down: its id, label, whether it is the selected account, and
/// whether it may be chosen now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PickerEntry {
    /// The entry's command id (the radio id of before).
    pub id: u16,
    /// `계정 1 · YubiKey`, `가져온 계정 · 가져온 키` …
    pub label: String,
    /// The selected account.
    pub selected: bool,
    /// May be chosen now.
    pub enabled: bool,
}

impl App {
    /// The `탐색기에서 열기` ↗ and `탐색기 링크 복사` 🔗 icons of `hash` on `network` (none when
    /// there is no transaction page, or past the id span).
    #[must_use]
    pub fn explorer_tx_icons(
        &self,
        network: impl Into<ExplorerNet>,
        hash: &str,
        ids: Option<(u16, u16)>,
    ) -> Vec<Ctl> {
        match ids {
            Some((open, copy)) if self.explorer_tx_url(network, hash).is_some() => vec![
                Ctl::icon(open, GLYPH_OPEN, T_EXPLORER_OPEN),
                Ctl::icon(copy, GLYPH_LINK, T_EXPLORER_COPY),
            ],
            _ => Vec::new(),
        }
    }

    /// An account drop-down (2026-11-11, like S10's network drop-down): `계정` with a button
    /// naming the selected account and ▾ (`picker`), and while open the accounts under it, one
    /// per line (each entry keeps the id its radio had, so the same handler selects it).
    pub fn push_account_picker(&self, items: &mut Vec<Item>, picker: u16, entries: &[PickerEntry]) {
        let open = self.account_menu == Some(picker);
        let selected = entries
            .iter()
            .find(|entry| entry.selected)
            .map_or("계정을 고르세요", |entry| entry.label.as_str());
        items.push(Item::LabeledRow(
            "계정".to_owned(),
            vec![
                Ctl::picker(picker, selected, open)
                    .fit(entries.iter().map(|entry| entry.label.as_str())),
            ],
        ));
        if open {
            items.push(Item::Menu(
                entries
                    .iter()
                    .map(|entry| {
                        Ctl::entry(entry.id, &entry.label, entry.selected).enabled(entry.enabled)
                    })
                    .collect(),
            ));
        }
    }

    /// Whether `id` is the selector of a drop-down (an account one or S10's network one).
    pub(crate) fn is_picker_button(id: u16) -> bool {
        ids::FIXED.contains(&id) || id == crate::ui::screens_evm::ids::NETWORK_PICKER
    }

    /// Closes the open account and network drop-downs (2026-11-12: Esc, any other command, a
    /// click on the window, another screen); whether one was open. The caller lays out again.
    pub(crate) fn close_pickers(&mut self) -> bool {
        let account = self.account_menu.take().is_some();
        let network = core::mem::take(&mut self.evm.network_picker);
        account || network
    }

    /// The drop-down buttons and the activity recipients; `false` when `id` is none of them.
    pub fn on_links_command(&mut self, id: u16) -> bool {
        if ids::FIXED.contains(&id) {
            self.account_menu = if self.account_menu == Some(id) {
                None
            } else {
                Some(id)
            };
            // One drop-down at a time.
            self.evm.network_picker = false;
            self.refresh();
            return true;
        }
        let address = if let Some(row) = ids::row_of(id, ids::EVM_TO_BASE, ids::EVM_TO_SPAN) {
            self.activity_rows()
                .get(row)
                .and_then(|view| view.counterparty)
                .map(yw_core::evm::address::Address::to_checksum)
        } else if let Some(row) = ids::row_of(id, ids::SOL_TO_BASE, ids::SOL_TO_SPAN) {
            self.sol_activity_counterparties().get(row).cloned()
        } else if let Some(row) = ids::row_of(id, ids::BTC_TO_BASE, ids::BTC_TO_SPAN) {
            let ctx = self.btc_ctx();
            self.btc
                .activity_rows(&ctx)
                .get(row)
                .map(|view| view.counterparty.clone())
        } else if let Some(row) = ids::row_of(id, ids::ZEC_TO_BASE, ids::ZEC_TO_SPAN) {
            self.zec_activity_recipients().get(row).cloned().flatten()
        } else {
            return false;
        };
        // The wallet's own sent transactions only (its signed journal): the received history's
        // senders have no copy id at all.
        if let Some(address) = address.filter(|address| !address.is_empty()) {
            self.copy_address_text(&address);
        }
        true
    }
}
