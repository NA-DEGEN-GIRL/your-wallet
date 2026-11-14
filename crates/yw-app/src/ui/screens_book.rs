//! S14 주소록 (spec/04 §2.10) and the address-book parts of every send form: the `즐겨찾기`
//! chips above the recipient field, the Bitcoin `주소록에서 선택` list, and the inline
//! `주소록에 저장` prompt (send forms, send results, activity rows). State and commands are in
//! `crate::app_book`.

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
    /// S14 `＋ 주소 추가`: opens the add form (2026-11-12: the list comes first).
    pub const ADD_OPEN: u16 = 14_017;
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
    /// S14 rows' address lines (2026-11-12): `COPY_BASE + row` copies that entry's address.
    pub const COPY_BASE: u16 = 18_700;
    /// Span of [`COPY_BASE`] (the address book's maximum).
    pub const COPY_SPAN: u16 = 500;

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
        ADD_OPEN,
    ];
}

/// S14 texts and the save prompts of the send forms (spec/04 §2.10; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        /// The S14 help line of the family sharing rules.
        BOOK_SHARED = "EVM 주소 하나는 모든 EVM 체인(Ethereum·Arbitrum·Base·BNB·Robinhood·HyperEVM·직접 추가한 체인)에서 함께 씁니다. Solana 주소는 mainnet·devnet에서 같습니다. Bitcoin 주소는 mainnet(bc1…)과 testnet4(tb1…)가 달라 그 주소의 네트워크 보내기 화면에만 나옵니다."
            / "One EVM address is shared by every EVM chain (Ethereum·Arbitrum·Base·BNB·Robinhood·HyperEVM·chains you added). A Solana address is the same on mainnet·devnet. Bitcoin addresses differ between mainnet (bc1…) and testnet4 (tb1…) and appear only on the send screen of their network.";
        DELETE_SELECTED = "선택한 주소록 항목을 지웁니다." / "Deletes the selected address-book entry.";
        DELETE_SCOPE_EVM = " EVM 항목은 모든 EVM 체인에서 함께 지워집니다."
            / " An EVM entry is deleted on every EVM chain.";
        DELETE_SCOPE_SOL = " Solana mainnet·devnet에서 함께 지워집니다."
            / " It is deleted on Solana mainnet·devnet alike.";
        /// `{0}` = `'label' ` or empty, `{1}` short address, `{2}` a `DELETE_SCOPE_*` or empty.
        DELETE(3) = "{0}({1}) 항목을 주소록에서 지웁니다.{2} 블록체인에는 아무것도 보내지 않으며, 같은 주소를 언제든 다시 추가할 수 있습니다."
            / "Deletes the entry {0}({1}) from the address book.{2} Nothing is sent to the blockchain, and you can add the same address again at any time.";
        TITLE = "주소록" / "Address book";
        ADD_OPEN = "＋ 주소 추가" / "＋ Add address";
        HEADING_EVM(1) = "EVM 주소록 — 모든 EVM 체인 공용 ({0}개)"
            / "EVM address book — shared by every EVM chain ({0})";
        HEADING_SOL(1) = "Solana 주소록 — mainnet·devnet 공용 ({0}개)"
            / "Solana address book — shared by mainnet·devnet ({0})";
        HEADING_BTC(1) = "Bitcoin 주소록 ({0}개)" / "Bitcoin address book ({0})";
        EMPTY(1) = "{0} 주소록이 비어 있습니다." / "The {0} address book is empty.";
        VERIFIED_MARK = " ✓ 확인됨" / " ✓ verified";
        UNFAVORITE = "즐겨찾기 해제" / "Remove from favorites";
        FAVORITE = "즐겨찾기" / "Favorite";
        EDIT = "편집" / "Edit";
        DELETE_ICON = "삭제" / "Delete";
        EDIT_TITLE(1) = "{0} 주소 편집" / "Edit {0} address";
        ADD_TITLE = "주소 추가" / "Add address";
        FORM_HELP = "이름을 붙인 주소는 보내기·승인 창에 '주소록: 이름'으로 나오고, 비슷하게 생긴 가짜 주소를 경고합니다. 보낸 뒤 '주소록에 저장'으로도 넣을 수 있습니다."
            / "A named address shows as 'Address book: name' on send and approval windows, and look-alike fake addresses are flagged. You can also add one after sending with 'Save to address book'.";
        CHAIN = "체인" / "Chain";
        SHARE_EVM = "EVM 주소 하나를 모든 EVM 체인에서 같이 씁니다."
            / "One EVM address is used on every EVM chain.";
        SHARE_SOL = "Solana mainnet·devnet에서 같이 씁니다." / "Used on Solana mainnet·devnet alike.";
        SHARE_BTC = "Bitcoin 주소는 그 주소의 네트워크(mainnet bc1… · testnet4 tb1…) 보내기 화면에만 나옵니다."
            / "A Bitcoin address appears only on the send screen of its network (mainnet bc1… · testnet4 tb1…).";
        ADDRESS = "주소" / "Address";
        NAME = "이름" / "Name";
        VERIFIED_CHECK = "다른 경로(전화·대면 등)로 확인한 주소"
            / "Address checked another way (phone, in person, …)";
        FAVORITE_CHECK = "★ 즐겨찾기 (보내기 화면 맨 위에)" / "★ Favorite (top of the send screen)";
        ACK = "주소 전체를 직접 확인했습니다" / "I checked the whole address myself";
        SAVE = "저장" / "Save";
        ADD = "추가" / "Add";
        CANCEL = "취소" / "Cancel";
        SAVE_THIS = "＋ 이 주소를 주소록에 저장" / "＋ Save this address to the address book";
        SAVED = "받는 주소를 주소록에 저장했습니다. 다음 보내기부터 '주소록: 이름'으로 표시됩니다."
            / "Saved the recipient to the address book. From the next send it shows as 'Address book: name'.";
        NOT_IN_BOOK(1) = "받는 주소 {0}는 주소록에 없습니다." / "The recipient {0} is not in the address book.";
        SAVE_HELP = "저장해 두면 다음에 즐겨찾기·주소록에서 바로 고를 수 있고, 비슷하게 생긴 가짜 주소를 경고합니다."
            / "Once saved, you can pick it from favorites or the address book next time, and look-alike fake addresses are flagged.";
        SAVE_TO_BOOK = "주소록에 저장" / "Save to address book";
        PROMPT_EVM = "모든 EVM 체인에서 같은 이름으로 보입니다." / "Shows with the same name on every EVM chain.";
        PROMPT_SOL = "Solana mainnet·devnet에서 같은 이름으로 보입니다."
            / "Shows with the same name on Solana mainnet·devnet.";
        PROMPT_BTC(1) = "Bitcoin {0} 보내기 화면에 나옵니다." / "Appears on the Bitcoin {0} send screen.";
        PICK_NONE = "이 네트워크의 일치하는 주소록 항목이 없습니다. 주소록에 저장하면 여기에서 고를 수 있습니다."
            / "No matching address-book entry for this network. Save one to the address book to pick it here.";
        /// A picker button (`{0}` = `★ ` or empty, `{1}` label).
        PICK(2) = "{0}주소록: {1}" / "{0}Address book: {1}";
    }
}

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
        let lang = self.settings.language;
        let Some((chain, address)) = &self.book.delete else {
            return text::DELETE_SELECTED.get(lang).to_owned();
        };
        let label = self
            .meta
            .as_ref()
            .and_then(|meta| meta.contact(*chain, address))
            .map_or_else(String::new, |entry| format!("'{}' ", entry.label));
        let scope = match chain {
            BookChain::Evm => text::DELETE_SCOPE_EVM.get(lang),
            BookChain::Sol => text::DELETE_SCOPE_SOL.get(lang),
            BookChain::Btc => "",
        };
        text::DELETE.fill(lang, [&label, &short_address(*chain, address), scope])
    }

    /// S14.
    pub fn book_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(crate::ui::screens::back_main(lang));
        items.push(Item::Title(text::TITLE.get(lang).to_owned()));
        let rows = self.book_rows();
        // The saved addresses first (2026-11-12): the form only while it is in use, or while
        // the book is empty.
        let form = &self.book.form;
        if form.open
            || form.editing.is_some()
            || form.message.is_some()
            || !form.address.is_empty()
            || rows.is_empty()
        {
            self.book_form_card(items);
        } else {
            items.push(Item::Row(vec![Ctl::primary(
                ids::ADD_OPEN,
                text::ADD_OPEN.get(lang),
            )]));
        }
        let meta = self.meta.as_ref();
        let mut index = 0_u16;
        for chain in BookChain::ALL {
            let entries: Vec<&Contact> = rows.iter().filter(|entry| entry.chain == chain).collect();
            let heading = match chain {
                BookChain::Evm => text::HEADING_EVM,
                BookChain::Sol => text::HEADING_SOL,
                BookChain::Btc => text::HEADING_BTC,
            }
            .fill(lang, [&entries.len().to_string()]);
            items.push(Item::CardStart(None));
            items.push(Item::Badged(
                Badge::family(chain),
                Box::new(Item::Subtitle(heading)),
            ));
            if entries.is_empty() {
                items.push(Item::Help(text::EMPTY.fill(lang, [family_name(chain)])));
            }
            let count = entries.len();
            for (position, entry) in entries.into_iter().enumerate() {
                let base = ids::ROW_BASE.saturating_add(index.saturating_mul(ids::ROW_STRIDE));
                let position_in_book = index;
                index = index.saturating_add(1);
                let favorite = meta.is_some_and(|meta| meta.is_favorite(chain, &entry.address));
                let verified = if entry.verified {
                    text::VERIFIED_MARK.get(lang)
                } else {
                    ""
                };
                let star = if favorite { "★ " } else { "" };
                items.push(Item::Text(format!("{star}{}{verified}", entry.label)));
                if chain == BookChain::Btc
                    && let Some(net) = crate::app_book::btc_network_of(&entry.address)
                {
                    items.push(Item::Badged(
                        Badge::bitcoin(net),
                        Box::new(Item::Help(
                            yw_core::btc::text::network_name(lang, net).to_owned(),
                        )),
                    ));
                }
                // 2026-11-12: the address (still the grouped form of §3.3) is the copy button
                // and the actions are icons right after it, not a row of buttons under it.
                let actions = vec![
                    Ctl::icon(
                        base,
                        if favorite { "★" } else { "☆" },
                        if favorite {
                            text::UNFAVORITE.get(lang)
                        } else {
                            text::FAVORITE.get(lang)
                        },
                    ),
                    Ctl::icon(base.saturating_add(1), "✎", text::EDIT.get(lang)),
                    Ctl::icon(base.saturating_add(2), "✕", text::DELETE_ICON.get(lang)),
                ];
                let shown = shown_address(chain, &entry.address);
                if position_in_book < ids::COPY_SPAN {
                    items.push(crate::ui::screens::receive_address_row(
                        lang,
                        &shown,
                        ids::COPY_BASE.saturating_add(position_in_book),
                        actions,
                    ));
                } else {
                    items.push(Item::Mono(shown));
                    items.push(Item::Row(actions));
                }
                if position.saturating_add(1) < count {
                    items.push(Item::Rule);
                }
            }
            items.push(Item::CardEnd);
        }
    }

    fn book_form_card(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let form = &self.book.form;
        if let Some(message) = &form.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        let editing = form.editing.is_some();
        items.push(Item::CardStart(Some(if editing {
            text::EDIT_TITLE.fill(lang, [family_name(form.chain)])
        } else {
            text::ADD_TITLE.get(lang).to_owned()
        })));
        items.push(Item::Help(text::FORM_HELP.get(lang).to_owned()));
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
            items.push(Item::LabeledRow(text::CHAIN.get(lang).to_owned(), tabs));
            // The sharing rule of the chosen family only (2026-11-12; all three before).
            items.push(Item::Help(
                match form.chain {
                    BookChain::Evm => text::SHARE_EVM,
                    BookChain::Sol => text::SHARE_SOL,
                    BookChain::Btc => text::SHARE_BTC,
                }
                .get(lang)
                .to_owned(),
            ));
        }
        let mut address = Ctl::edit(ids::ADDR_EDIT, &form.address, 430, false, 128);
        if editing {
            address = address.readonly();
        }
        items.push(Item::LabeledRow(
            text::ADDRESS.get(lang).to_owned(),
            vec![address],
        ));
        items.push(Item::LabeledRow(
            text::NAME.get(lang).to_owned(),
            vec![Ctl::edit(ids::LABEL_EDIT, &form.label, 260, false, 64)],
        ));
        items.push(Item::Row(vec![Ctl::check(
            ids::VERIFIED,
            text::VERIFIED_CHECK.get(lang),
            form.verified,
        )]));
        items.push(Item::Row(vec![Ctl::check(
            ids::FAVORITE,
            text::FAVORITE_CHECK.get(lang),
            form.favorite,
        )]));
        if let Some(note) = &form.look_alike {
            items.push(Item::Banner(note.clone(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::FORM_ACK,
                text::ACK.get(lang),
                form.ack,
            )]));
        }
        let mut row = vec![
            Ctl::primary(
                ids::SAVE,
                if editing { text::SAVE } else { text::ADD }.get(lang),
            )
            .enabled(form.look_alike.is_none() || form.ack),
        ];
        if editing || form.open {
            row.push(Ctl::button(ids::CANCEL, text::CANCEL.get(lang)));
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
        items.push(Item::LabeledRow(
            text::FAVORITE.get(self.settings.language).to_owned(),
            chips,
        ));
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
    /// the book, or its open prompt — neither while the form shows a W-ADDR-3 note (a suspected
    /// poison must not be saved from the warning; spec/04 §2.10).
    pub fn recipient_save_items(&self, target: BookTarget, items: &mut Vec<Item>) {
        if self.send_look_alike(target) {
            return;
        }
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
                text::SAVE_THIS.get(self.settings.language),
            )]));
        }
    }

    /// The send-result part: a saved note, the prompt, or `주소록에 저장`.
    pub fn result_save_items(&self, target: BookTarget, items: &mut Vec<Item>) {
        let Some(address) = self.result_recipient(target) else {
            return;
        };
        let chain = target.chain();
        let lang = self.settings.language;
        if self.book.saved.as_ref() == Some(&(chain, address.clone())) {
            items.push(Item::Banner(
                text::SAVED.get(lang).to_owned(),
                Tone::Success,
            ));
            return;
        }
        if self.prompt_items(PromptPlace::Result, chain, &address, items) {
            return;
        }
        if self.offer_save(chain, &address) {
            items.push(Item::CardStart(None));
            items.push(Item::Text(
                text::NOT_IN_BOOK.fill(lang, [&short_address(chain, &address)]),
            ));
            items.push(Item::Help(text::SAVE_HELP.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::button(
                ids::RESULT_SAVE,
                text::SAVE_TO_BOOK.get(lang),
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
        let lang = self.settings.language;
        let card = place == PromptPlace::Result;
        if card {
            items.push(Item::CardStart(None));
        }
        items.push(Item::Subtitle(text::SAVE_TO_BOOK.get(lang).to_owned()));
        items.push(Item::Mono(shown_address(chain, address)));
        items.push(Item::Help(match chain {
            BookChain::Evm => text::PROMPT_EVM.get(lang).to_owned(),
            BookChain::Sol => text::PROMPT_SOL.get(lang).to_owned(),
            BookChain::Btc => text::PROMPT_BTC.fill(
                lang,
                [crate::app_book::btc_network_of(address)
                    .map_or("", |net| yw_core::btc::text::network_name(lang, net))],
            ),
        }));
        if let Some(note) = &prompt.look_alike {
            items.push(Item::Banner(note.clone(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::PROMPT_ACK,
                text::ACK.get(lang),
                prompt.ack,
            )]));
        }
        if let Some(message) = &prompt.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        items.push(Item::LabeledRow(
            text::NAME.get(lang).to_owned(),
            vec![
                Ctl::edit(ids::PROMPT_LABEL_EDIT, &prompt.label, 220, false, 64),
                Ctl::button(ids::PROMPT_SAVE, text::SAVE.get(lang))
                    .enabled(prompt.look_alike.is_none() || prompt.ack),
                Ctl::link(ids::PROMPT_CANCEL, text::CANCEL.get(lang)),
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
        let lang = self.settings.language;
        let entries = self.btc_picker_entries(target);
        if entries.is_empty() {
            items.push(Item::Help(text::PICK_NONE.get(lang).to_owned()));
        }
        let meta = self.meta.as_ref();
        for (index, entry) in entries.iter().enumerate() {
            let favorite = meta.is_some_and(|meta| meta.is_favorite(entry.chain, &entry.address));
            items.push(Item::Row(vec![Ctl::button(
                ids::BTC_PICK_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                &text::PICK.fill(lang, [if favorite { "★ " } else { "" }, &entry.label]),
            )]));
            items.push(Item::Mono(grouped(&entry.address)));
        }
    }
}
