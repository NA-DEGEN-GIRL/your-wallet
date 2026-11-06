//! S14 주소록 (spec/04 §2.10) and the address-book parts of every send form: the `즐겨찾기`
//! chips above the recipient field, the Bitcoin `주소록에서 선택` list, and the inline
//! `주소록에 저장` prompt (send forms, send results, activity rows). State and commands are in
//! `crate::app_book`.

use yw_core::btc::BtcNetwork;
use yw_core::evm::address::parse_address;
use yw_core::evm::display::format_address;

use crate::app::App;
use crate::app_book::{BookTarget, PromptPlace, short_address};
use crate::meta::{BookChain, Contact};
use crate::ui::badge::Badge;
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::ui::screens_btc::grouped;

/// Command ids of the address book (14,000–15,699).
pub mod ids {
    /// S14 family tab: EVM.
    pub const CHAIN_EVM: u16 = 14_000;
    /// S14 family tab: Solana.
    pub const CHAIN_SOL: u16 = 14_001;
    /// S14 family tab: Bitcoin.
    pub const CHAIN_BTC: u16 = 14_002;
    /// S14 address edit.
    pub const ADDR_EDIT: u16 = 14_003;
    /// S14 label edit.
    pub const LABEL_EDIT: u16 = 14_004;
    /// S14 verified check.
    pub const VERIFIED: u16 = 14_005;
    /// S14 `즐겨찾기에 추가` check.
    pub const FAVORITE: u16 = 14_006;
    /// S14 `추가` / `저장`.
    pub const SAVE: u16 = 14_007;
    /// S14 `취소` (editing).
    pub const CANCEL: u16 = 14_008;
    /// S14 look-alike `주소 전체를 직접 확인했습니다`.
    pub const FORM_ACK: u16 = 14_009;
    /// Prompt label edit.
    pub const PROMPT_LABEL_EDIT: u16 = 14_010;
    /// Prompt `저장`.
    pub const PROMPT_SAVE: u16 = 14_011;
    /// Prompt `취소`.
    pub const PROMPT_CANCEL: u16 = 14_012;
    /// Prompt look-alike check.
    pub const PROMPT_ACK: u16 = 14_013;
    /// Send form `주소록에 저장` (opens the prompt for the parsed recipient).
    pub const SEND_SAVE: u16 = 14_014;
    /// Send result `주소록에 저장`.
    pub const RESULT_SAVE: u16 = 14_015;
    /// Bitcoin send form `주소록에서 선택`.
    pub const BTC_PICK: u16 = 14_016;
    /// Favorite chips of the current send form.
    pub const FAV_BASE: u16 = 14_020;
    /// Favorite chips span (≥ `app_book::FAVORITE_CHIPS`).
    pub const FAV_SPAN: u16 = 8;
    /// Bitcoin picker rows.
    pub const BTC_PICK_BASE: u16 = 14_030;
    /// Bitcoin picker span.
    pub const BTC_PICK_SPAN: u16 = 40;
    /// Solana activity `이 주소 저장` (one per row, ≤ `SOL_MAX_ACTIVITY_ROWS`).
    pub const SOL_ACTIVITY_BASE: u16 = 14_080;
    /// Solana activity span.
    pub const SOL_ACTIVITY_SPAN: u16 = 64;
    /// S14 rows ([`ROW_STRIDE`] ids per row: ★, 편집, 삭제), all families in display order.
    pub const ROW_BASE: u16 = 14_200;
    /// Ids per S14 row.
    pub const ROW_STRIDE: u16 = 3;
    /// S14 rows span (500 rows × 3).
    pub const ROW_SPAN: u16 = 1_500;

    const _: () = assert!(FAV_BASE + FAV_SPAN <= BTC_PICK_BASE);
    const _: () = assert!(BTC_PICK_BASE + BTC_PICK_SPAN <= SOL_ACTIVITY_BASE);
    const _: () = assert!(SOL_ACTIVITY_BASE + SOL_ACTIVITY_SPAN <= ROW_BASE);

    /// Every fixed id of this module (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        CHAIN_EVM,
        CHAIN_SOL,
        CHAIN_BTC,
        ADDR_EDIT,
        LABEL_EDIT,
        VERIFIED,
        FAVORITE,
        SAVE,
        CANCEL,
        FORM_ACK,
        PROMPT_LABEL_EDIT,
        PROMPT_SAVE,
        PROMPT_CANCEL,
        PROMPT_ACK,
        SEND_SAVE,
        RESULT_SAVE,
        BTC_PICK,
    ];
}

/// The S14 help line of the family sharing rules.
pub const T_BOOK_SHARED: &str = "EVM 주소 하나는 모든 EVM 체인(Ethereum·Arbitrum·Base·BNB·Robinhood·HyperEVM·직접 추가한 체인)에서 함께 씁니다. Solana 주소는 mainnet·devnet에서 같습니다. Bitcoin 주소는 mainnet(bc1…)과 testnet4(tb1…)가 달라 그 주소의 네트워크 보내기 화면에만 나옵니다.";

/// The family name of S14.
#[must_use]
pub const fn family_name(chain: BookChain) -> &'static str {
    match chain {
        BookChain::Evm => "EVM",
        BookChain::Sol => "Solana",
        BookChain::Btc => "Bitcoin",
    }
}

/// The full address as the screens draw it (EVM grouped checksum, SOL/BTC 4-character groups).
#[must_use]
pub fn shown_address(chain: BookChain, address: &str) -> String {
    match chain {
        BookChain::Evm => {
            parse_address(address).map_or_else(|_| address.to_owned(), |a| format_address(&a))
        }
        BookChain::Sol | BookChain::Btc => grouped(address),
    }
}

/// `★ 이름 · 0x1234…abcd` (a chip or picker label).
#[must_use]
pub fn chip_text(entry: &Contact, favorite: bool) -> String {
    format!(
        "{}{} · {}",
        if favorite { "★ " } else { "" },
        entry.label,
        short_address(entry.chain, &entry.address)
    )
}

impl App {
    /// T-BOOK-DELETE: names the entry; an EVM entry is gone on every EVM chain.
    #[must_use]
    pub fn book_delete_text(&self) -> String {
        let Some((chain, address)) = &self.book.delete else {
            return "선택한 주소록 항목을 지웁니다.".to_owned();
        };
        let label = self
            .meta
            .as_ref()
            .and_then(|meta| meta.contact(*chain, address))
            .map_or_else(String::new, |entry| format!("'{}' ", entry.label));
        let scope = match chain {
            BookChain::Evm => " EVM 항목은 모든 EVM 체인에서 함께 지워집니다.",
            BookChain::Sol => " Solana mainnet·devnet에서 함께 지워집니다.",
            BookChain::Btc => "",
        };
        format!(
            "{label}({}) 항목을 주소록에서 지웁니다.{scope} 블록체인에는 아무것도 보내지 않으며, 같은 주소를 언제든 다시 추가할 수 있습니다.",
            short_address(*chain, address)
        )
    }

    /// S14.
    pub fn book_screen(&self, items: &mut Vec<Item>) {
        items.push(crate::ui::screens::back_main());
        items.push(Item::Title("주소록".to_owned()));
        self.book_form_card(items);
        let rows = self.book_rows();
        let meta = self.meta.as_ref();
        let mut index = 0_u16;
        for chain in BookChain::ALL {
            let entries: Vec<&Contact> = rows.iter().filter(|entry| entry.chain == chain).collect();
            let heading = match chain {
                BookChain::Evm => format!("EVM 주소록 — 모든 EVM 체인 공용 ({}개)", entries.len()),
                BookChain::Sol => {
                    format!("Solana 주소록 — mainnet·devnet 공용 ({}개)", entries.len())
                }
                BookChain::Btc => format!("Bitcoin 주소록 ({}개)", entries.len()),
            };
            items.push(Item::CardStart(None));
            items.push(Item::Badged(
                Badge::family(chain),
                Box::new(Item::Subtitle(heading)),
            ));
            if entries.is_empty() {
                items.push(Item::Help(format!(
                    "{} 주소록이 비어 있습니다. 위에서 추가하거나, 보낸 뒤 '주소록에 저장'으로 넣을 수 있습니다.",
                    family_name(chain)
                )));
            }
            let count = entries.len();
            for (position, entry) in entries.into_iter().enumerate() {
                let base = ids::ROW_BASE.saturating_add(index.saturating_mul(ids::ROW_STRIDE));
                index = index.saturating_add(1);
                let favorite = meta.is_some_and(|meta| meta.is_favorite(chain, &entry.address));
                let verified = if entry.verified { " ✓ 확인됨" } else { "" };
                let star = if favorite { "★ " } else { "" };
                items.push(Item::Text(format!("{star}{}{verified}", entry.label)));
                items.push(Item::Mono(shown_address(chain, &entry.address)));
                if chain == BookChain::Btc
                    && let Some(net) = crate::app_book::btc_network_of(&entry.address)
                {
                    items.push(Item::Badged(
                        Badge::bitcoin(net),
                        Box::new(Item::Help(net.display_name().to_owned())),
                    ));
                }
                items.push(Item::Row(vec![
                    Ctl::link(
                        base,
                        if favorite {
                            "★ 즐겨찾기 해제"
                        } else {
                            "☆ 즐겨찾기"
                        },
                    ),
                    Ctl::button(base.saturating_add(1), "편집"),
                    Ctl::danger(base.saturating_add(2), "삭제"),
                ]));
                if position.saturating_add(1) < count {
                    items.push(Item::Rule);
                }
            }
            items.push(Item::CardEnd);
        }
    }

    fn book_form_card(&self, items: &mut Vec<Item>) {
        let form = &self.book.form;
        if let Some(message) = &form.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        let editing = form.editing.is_some();
        items.push(Item::CardStart(Some(if editing {
            format!("{} 주소 편집", family_name(form.chain))
        } else {
            "주소 추가".to_owned()
        })));
        items.push(Item::Help(
            "자주 보내는 주소에 이름을 붙여 두면 보내기와 승인 창에서 '주소록: 이름'으로 확인할 수 있고, 비슷하게 생긴 가짜 주소를 경고합니다. ★ 즐겨찾기는 보내기 화면 맨 위에 바로 고를 수 있게 나옵니다."
                .to_owned(),
        ));
        if !editing {
            let tabs = BookChain::ALL
                .iter()
                .map(|chain| {
                    let id = match chain {
                        BookChain::Evm => ids::CHAIN_EVM,
                        BookChain::Sol => ids::CHAIN_SOL,
                        BookChain::Btc => ids::CHAIN_BTC,
                    };
                    Ctl::tab(id, family_name(*chain), *chain == form.chain)
                        .badge(Badge::family(*chain))
                })
                .collect();
            items.push(Item::LabeledRow("체인".to_owned(), tabs));
            items.push(Item::Help(T_BOOK_SHARED.to_owned()));
        }
        let mut address = Ctl::edit(ids::ADDR_EDIT, &form.address, 430, false, 128);
        if editing {
            address = address.readonly();
        }
        items.push(Item::LabeledRow("주소".to_owned(), vec![address]));
        items.push(Item::LabeledRow(
            "이름".to_owned(),
            vec![Ctl::edit(ids::LABEL_EDIT, &form.label, 260, false, 64)],
        ));
        items.push(Item::Row(vec![Ctl::check(
            ids::VERIFIED,
            "다른 경로(전화·대면 등)로 이 주소를 확인했습니다",
            form.verified,
        )]));
        items.push(Item::Row(vec![Ctl::check(
            ids::FAVORITE,
            "★ 즐겨찾기 (보내기 화면 맨 위에 표시)",
            form.favorite,
        )]));
        if let Some(note) = &form.look_alike {
            items.push(Item::Banner(note.clone(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::FORM_ACK,
                "주소 전체를 직접 확인했습니다",
                form.ack,
            )]));
        }
        let mut row = vec![
            Ctl::primary(ids::SAVE, if editing { "저장" } else { "추가" })
                .enabled(form.look_alike.is_none() || form.ack),
        ];
        if editing {
            row.push(Ctl::button(ids::CANCEL, "취소"));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    /// The `즐겨찾기` chips of a send form (above the recipient field; nothing without favorites).
    pub fn favorite_chip_items(&self, target: BookTarget, items: &mut Vec<Item>) {
        let favorites = self.favorite_contacts(target);
        if favorites.is_empty() {
            return;
        }
        let chips = favorites
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                Ctl::button(
                    ids::FAV_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                    &chip_text(entry, true),
                )
            })
            .collect();
        items.push(Item::LabeledRow("즐겨찾기".to_owned(), chips));
    }

    /// Whether `address` is one of this wallet's own accounts (not offered for saving).
    fn own_address(&self, chain: BookChain, address: &str) -> bool {
        match chain {
            BookChain::Evm => self
                .own_accounts()
                .iter()
                .any(|(own, _)| own.to_lower_hex() == address),
            BookChain::Sol => self
                .sol_account_rows()
                .iter()
                .any(|(_, _, own)| own.to_base58() == address),
            BookChain::Btc => false,
        }
    }

    /// Whether `이 주소 저장` / `주소록에 저장` is offered for `address`.
    #[must_use]
    pub fn offer_save(&self, chain: BookChain, address: &str) -> bool {
        !address.is_empty() && !self.in_book(chain, address) && !self.own_address(chain, address)
    }

    /// Under the recipient of a send form: `주소록에 저장` for a parsed recipient that is not in
    /// the book, or its open prompt.
    pub fn recipient_save_items(&self, target: BookTarget, items: &mut Vec<Item>) {
        let Some(address) = self.send_recipient(target) else {
            return;
        };
        let chain = target.chain();
        if self.prompt_items(PromptPlace::SendForm, chain, &address, items) {
            return;
        }
        if self.offer_save(chain, &address) {
            items.push(Item::Row(vec![Ctl::link(
                ids::SEND_SAVE,
                "＋ 이 주소를 주소록에 저장",
            )]));
        }
    }

    /// The send-result part: a saved note, the prompt, or `주소록에 저장`.
    pub fn result_save_items(&self, target: BookTarget, items: &mut Vec<Item>) {
        let Some(address) = self.result_recipient(target) else {
            return;
        };
        let chain = target.chain();
        if self.book.saved.as_ref() == Some(&(chain, address.clone())) {
            items.push(Item::Banner(
                "받는 주소를 주소록에 저장했습니다. 다음 보내기부터 '주소록: 이름'으로 표시됩니다."
                    .to_owned(),
                Tone::Success,
            ));
            return;
        }
        if self.prompt_items(PromptPlace::Result, chain, &address, items) {
            return;
        }
        if self.offer_save(chain, &address) {
            items.push(Item::CardStart(None));
            items.push(Item::Text(format!(
                "받는 주소 {}는 주소록에 없습니다.",
                short_address(chain, &address)
            )));
            items.push(Item::Help(
                "저장해 두면 다음에 즐겨찾기·주소록에서 바로 고를 수 있고, 비슷하게 생긴 가짜 주소를 경고합니다."
                    .to_owned(),
            ));
            items.push(Item::Row(vec![Ctl::button(
                ids::RESULT_SAVE,
                "주소록에 저장",
            )]));
            items.push(Item::CardEnd);
        }
    }

    /// The inline prompt when it is open for `(place, chain, address)`; `true` when drawn.
    pub fn prompt_items(
        &self,
        place: PromptPlace,
        chain: BookChain,
        address: &str,
        items: &mut Vec<Item>,
    ) -> bool {
        let Some(prompt) = self
            .book
            .prompt
            .as_ref()
            .filter(|prompt| prompt.place == place && prompt.chain == chain)
            .filter(|prompt| prompt.address == address)
        else {
            return false;
        };
        let card = place == PromptPlace::Result;
        if card {
            items.push(Item::CardStart(None));
        }
        items.push(Item::Subtitle("주소록에 저장".to_owned()));
        items.push(Item::Mono(shown_address(chain, address)));
        items.push(Item::Help(match chain {
            BookChain::Evm => "모든 EVM 체인에서 같은 이름으로 보입니다.".to_owned(),
            BookChain::Sol => "Solana mainnet·devnet에서 같은 이름으로 보입니다.".to_owned(),
            BookChain::Btc => format!(
                "Bitcoin {} 보내기 화면에 나옵니다.",
                crate::app_book::btc_network_of(address).map_or("", BtcNetwork::display_name)
            ),
        }));
        if let Some(note) = &prompt.look_alike {
            items.push(Item::Banner(note.clone(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::PROMPT_ACK,
                "주소 전체를 직접 확인했습니다",
                prompt.ack,
            )]));
        }
        if let Some(message) = &prompt.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        items.push(Item::LabeledRow(
            "이름".to_owned(),
            vec![
                Ctl::edit(ids::PROMPT_LABEL_EDIT, &prompt.label, 220, false, 64),
                Ctl::button(ids::PROMPT_SAVE, "저장")
                    .enabled(prompt.look_alike.is_none() || prompt.ack),
                Ctl::link(ids::PROMPT_CANCEL, "취소"),
            ],
        ));
        if card {
            items.push(Item::CardEnd);
        }
        true
    }

    /// The Bitcoin `주소록에서 선택` button and list (the network's entries, filtered by the text).
    pub fn btc_picker_items(&self, target: BookTarget, items: &mut Vec<Item>) {
        if !self.book.btc_picker {
            return;
        }
        let entries = self.btc_picker_entries(target);
        if entries.is_empty() {
            items.push(Item::Help(
                "이 네트워크의 일치하는 주소록 항목이 없습니다. 주소록에 저장하면 여기에서 고를 수 있습니다."
                    .to_owned(),
            ));
        }
        let meta = self.meta.as_ref();
        for (index, entry) in entries.iter().enumerate() {
            let favorite = meta.is_some_and(|meta| meta.is_favorite(entry.chain, &entry.address));
            items.push(Item::Row(vec![Ctl::button(
                ids::BTC_PICK_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                &format!(
                    "{}주소록: {}",
                    if favorite { "★ " } else { "" },
                    entry.label
                ),
            )]));
            items.push(Item::Mono(grouped(&entry.address)));
        }
    }
}
