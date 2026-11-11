//! The received-history part of each chain's activity card (spec/04 §2.6, 2026-11-11): the
//! switch `받은 내역도 보기` (off by default, one setting for every chain) and, when on, the
//! sub-heading "받은 내역" with the address-poisoning help line, the rows (local time, "받음
//! {금액} {기호}", status, the sender — read only, grouped, never with a copy or select button,
//! with the exact address-book / own-account name or a look-alike warning tag — the hash on its
//! own line, a click copying it, with the ↗ `탐색기에서 열기` icon), and the muted count of hidden
//! dust transfers. One call per card:
//! [`App::received_items`].

use yw_core::evm::address::parse_address;
use yw_core::evm::display::format_address;
use yw_core::sol::SolAddress;

use crate::app::App;
use crate::received::{Incoming, RecvChain};
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids of the received history (17,800–18,399; spec/04 §2.6, `ui::command_ids`).
pub mod ids {
    /// Chains (slots of [`crate::received::RecvChain::slot`]).
    pub const CHAINS: u16 = 5;
    /// `받은 내역도 보기` of each chain's card (one setting; a card's own id).
    pub const TOGGLE_BASE: u16 = 17_800;
    /// `받은 내역 n건 더 보기 ▸` / `접기 ▾` of each chain's card.
    pub const MORE_BASE: u16 = 17_805;
    /// Fixed ids.
    pub const FIXED: [u16; 10] = [
        17_800, 17_801, 17_802, 17_803, 17_804, 17_805, 17_806, 17_807, 17_808, 17_809,
    ];
    /// Row buttons: `ROW_BASE + slot × CHAIN_SPAN + row × ROW_STRIDE`.
    pub const ROW_BASE: u16 = 17_900;
    /// Ids per row: 0 a click on the hash (copy, the `해시 복사` of before), 1 ↗ `탐색기에서 열기`.
    pub const ROW_STRIDE: u16 = 2;
    /// Ids per chain (50 rows × 2).
    pub const CHAIN_SPAN: u16 = 100;
    /// All row ids.
    pub const ROW_SPAN: u16 = 500;

    /// The switch of `chain`'s card.
    #[must_use]
    pub const fn toggle(chain: crate::received::RecvChain) -> u16 {
        TOGGLE_BASE + chain.slot()
    }

    /// `더 보기` of `chain`'s card.
    #[must_use]
    pub const fn more(chain: crate::received::RecvChain) -> u16 {
        MORE_BASE + chain.slot()
    }

    /// The first id of `row` of `chain` (`None` past the 50 rows).
    #[must_use]
    pub fn row(chain: crate::received::RecvChain, row: usize) -> Option<u16> {
        let row = u16::try_from(row)
            .ok()
            .filter(|row| *row < CHAIN_SPAN / ROW_STRIDE)?;
        Some(ROW_BASE + chain.slot() * CHAIN_SPAN + row * ROW_STRIDE)
    }
}

/// The switch's label.
pub const T_RECEIVED_TOGGLE: &str = "받은 내역도 보기";
/// The help line at the top of the section (address poisoning).
pub const T_RECEIVED_HELP: &str = "받은 내역은 참고용입니다. 여기의 주소를 복사해 보내지 마세요 — 보낼 주소는 주소록이나 상대에게 직접 받은 값을 쓰세요.";
/// The EVM line: native-coin deposits are not visible to standard RPC.
pub const T_EVM_NATIVE: &str =
    "네이티브 코인 입금은 표시하지 않습니다 — 계정 카드의 '탐색기에서 주소 보기'로 확인하세요.";
/// The muted line of the hidden dust transfers.
#[must_use]
pub fn dust_line(count: usize) -> String {
    format!("먼지 금액·0원 입금 {count}건은 숨겼습니다(주소 오염 대비).")
}
/// Rows shown before `더 보기`.
pub const FIRST_ROWS: usize = 10;

fn local_time(unix_ms: u64) -> String {
    let wall = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

/// How a sender relates to what the user knows: the exact name, or the look-alike warning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SenderNote {
    /// `" → 주소록: {이름}"` / `" → 내 계정: {라벨}"` (exact matches only).
    pub name: String,
    /// The warning tag when the sender imitates a known address (same ends, different middle).
    pub look_alike: Option<String>,
}

fn warning(whom: &str) -> String {
    format!("주소 오염 의심 — {whom}과 앞뒤가 같은 다른 주소")
}

impl App {
    /// The sender lines' annotation (the family's known set, as the send forms use it).
    fn sender_note(&self, chain: RecvChain, from: &str) -> SenderNote {
        match chain {
            RecvChain::Evm | RecvChain::Hc => {
                let Ok(address) = parse_address(from) else {
                    return SenderNote::default();
                };
                let known = self.known_addresses();
                let name = known
                    .iter()
                    .filter(|entry| entry.address == address && !entry.history)
                    .map(|entry| {
                        if entry.mine {
                            format!(" → 내 계정: {}", entry.name)
                        } else {
                            format!(" → 주소록: {}", entry.name)
                        }
                    })
                    .next()
                    .unwrap_or_default();
                let look_alike = yw_core::evm::address::poisoning_look_alike(&known, &address).map(
                    |(entry, _)| {
                        warning(&if entry.history {
                            "보낸 내역의 주소".to_owned()
                        } else if entry.mine {
                            format!("내 계정 '{}'", entry.name)
                        } else {
                            format!("주소록 '{}'", entry.name)
                        })
                    },
                );
                SenderNote { name, look_alike }
            }
            RecvChain::Sol => {
                use yw_core::sol::recipient::{KnownKind, is_lookalike};
                let Ok(address) = SolAddress::parse(from) else {
                    return SenderNote::default();
                };
                let known = self.sol_known();
                let own = |kind: &KnownKind| {
                    matches!(
                        kind,
                        KnownKind::Own { .. }
                            | KnownKind::OwnImported
                            | KnownKind::OwnHardware
                            | KnownKind::OwnMnemonic
                    )
                };
                let exact = known.iter().find(|entry| {
                    entry.address == address
                        && !matches!(entry.kind, KnownKind::Sent | KnownKind::History)
                });
                let name = exact.map_or_else(String::new, |entry| {
                    if own(&entry.kind) {
                        format!(" → 내 계정: {}", entry.label)
                    } else {
                        format!(" → 주소록: {}", entry.label)
                    }
                });
                let trusted = exact.is_some_and(|entry| {
                    own(&entry.kind) || matches!(entry.kind, KnownKind::Book { verified: true })
                });
                let look_alike = (!trusted)
                    .then(|| {
                        known
                            .iter()
                            .find(|entry| is_lookalike(&entry.address, &address))
                    })
                    .flatten()
                    .map(|entry| {
                        warning(&match entry.kind {
                            KnownKind::Book { .. } => format!("주소록 '{}'", entry.label),
                            KnownKind::Sent | KnownKind::History => "보낸 내역의 주소".to_owned(),
                            _ => format!("내 계정 '{}'", entry.label),
                        })
                    });
                SenderNote { name, look_alike }
            }
            RecvChain::Btc => {
                use crate::app_btc::BtcKnownSource;
                let ctx = self.btc_ctx();
                let known = crate::app_btc::known_addresses_on(&ctx, ctx.net());
                let lower = from.to_ascii_lowercase();
                let name = known
                    .iter()
                    .filter(|entry| entry.address == lower)
                    .find_map(|entry| match &entry.source {
                        BtcKnownSource::Book { label, .. } => Some(format!(" → 주소록: {label}")),
                        BtcKnownSource::Own { account } => Some(format!(" → 내 계정: {account}")),
                        BtcKnownSource::Sent => None,
                    })
                    .unwrap_or_default();
                let look_alike = crate::app_btc::btc_look_alike(&known, from)
                    .map(|(entry, _)| warning(&format!("'{}'", entry.name)));
                SenderNote { name, look_alike }
            }
            RecvChain::Zec => SenderNote::default(),
        }
    }

    /// The sender address in the chain's grouped display form (never copyable).
    fn sender_text(chain: RecvChain, from: &str) -> String {
        match chain {
            RecvChain::Evm | RecvChain::Hc => {
                parse_address(from).map_or_else(|_| from.to_owned(), |a| format_address(&a))
            }
            RecvChain::Sol => SolAddress::parse(from)
                .map_or_else(|_| from.to_owned(), |a| yw_core::sol::address::grouped(&a)),
            RecvChain::Btc | RecvChain::Zec => crate::ui::screens_btc::grouped(from),
        }
    }

    fn received_row(&self, chain: RecvChain, row: usize, entry: &Incoming, items: &mut Vec<Item>) {
        let when = entry.time_ms.map_or_else(
            || {
                entry
                    .block
                    .map_or_else(|| "시각 모름".to_owned(), |block| format!("블록 {block}"))
            },
            local_time,
        );
        items.push(Item::Text(format!(
            "{when} · 받음 {} {}",
            entry.amount, entry.symbol
        )));
        items.push(Item::Help(match (entry.pending, entry.block) {
            (true, _) => "상태: 대기 중 (아직 확인되지 않음)".to_owned(),
            (false, Some(block)) if entry.time_ms.is_some() && chain != RecvChain::Sol => {
                format!("상태: 확인됨 (블록 {block})")
            }
            (false, _) => "상태: 확인됨".to_owned(),
        }));
        match (&entry.from, entry.from_note) {
            (Some(from), _) => {
                let note = self.sender_note(chain, from);
                items.push(Item::Help(format!("보낸 주소{}", note.name)));
                // Read only: no copy or select button (address poisoning).
                items.push(Item::Mono(Self::sender_text(chain, from)));
                if let Some(text) = note.look_alike {
                    items.push(Item::Pill(text, Tone::HighRisk));
                }
            }
            (None, Some(note)) => items.push(Item::Help(note.to_owned())),
            (None, None) => items.push(Item::Help("보낸 주소 -".to_owned())),
        }
        if entry.hash.is_empty() {
            return;
        }
        // The hash (public data) on its own line: a click copies it, `탐색기에서 열기` ↗
        // (id + 1) at its right end when the list's network has a transaction page
        // (2026-11-11). The sender above stays read-only.
        let id = ids::row(chain, row);
        let explorer = id
            .filter(|_| {
                self.received_explorer_net(chain)
                    .and_then(|net| self.explorer_tx_url(net, &entry.hash))
                    .is_some()
            })
            .map(|id| {
                Ctl::icon(
                    id + 1,
                    crate::ui::main_window::GLYPH_OPEN,
                    crate::ui::screens_links::T_EXPLORER_OPEN,
                )
            });
        crate::ui::screens_links::push_hash_line(
            items,
            id,
            &entry.hash,
            explorer.into_iter().collect(),
        );
    }

    /// The switch and, when on, the received section of `chain`'s activity card (spec/04 §2.6).
    pub fn received_items(&self, chain: RecvChain, items: &mut Vec<Item>) {
        let on = self.settings.received_history;
        items.push(Item::Rule);
        items.push(Item::Row(vec![Ctl::check(
            ids::toggle(chain),
            T_RECEIVED_TOGGLE,
            on,
        )]));
        if !on {
            return;
        }
        items.push(Item::Subtitle("받은 내역".to_owned()));
        items.push(Item::Help(T_RECEIVED_HELP.to_owned()));
        if chain == RecvChain::Evm {
            items.push(Item::Muted(T_EVM_NATIVE.to_owned()));
        }
        let list = self
            .received_key(chain)
            .and_then(|key| self.received.lists.get(&key));
        let Some(list) = list else {
            items.push(Item::Muted(
                "받은 내역을 아직 불러오지 않았습니다.".to_owned(),
            ));
            return;
        };
        if let Some(text) = list.unsupported {
            items.push(Item::Muted(text.to_owned()));
            return;
        }
        if let Some(error) = &list.error {
            items.push(Item::Banner(
                format!("받은 내역을 불러오지 못했습니다: {error}"),
                Tone::Warn,
            ));
        }
        if !list.loaded {
            items.push(Item::Muted(if list.busy.is_some() {
                "받은 내역을 불러오는 중…".to_owned()
            } else {
                "받은 내역을 아직 불러오지 않았습니다.".to_owned()
            }));
        } else if list.entries.is_empty() {
            items.push(Item::Help("최근 받은 입금이 없습니다.".to_owned()));
        }
        let open = self
            .received
            .expanded
            .get(usize::from(chain.slot()))
            .copied()
            .unwrap_or(false);
        let shown = if open {
            list.entries.len()
        } else {
            list.entries.len().min(FIRST_ROWS)
        };
        for (row, entry) in list.entries.iter().take(shown).enumerate() {
            if row > 0 {
                items.push(Item::Rule);
            }
            self.received_row(chain, row, entry, items);
        }
        let folded = list.entries.len().saturating_sub(FIRST_ROWS);
        if folded > 0 {
            items.push(Item::Row(vec![Ctl::link(
                ids::more(chain),
                &if open {
                    "받은 내역 접기 ▾".to_owned()
                } else {
                    format!("받은 내역 {folded}건 더 보기 ▸")
                },
            )]));
        }
        if let Some(note) = list.note {
            items.push(Item::Muted(note.to_owned()));
        }
        if list.dust > 0 {
            items.push(Item::Muted(dust_line(list.dust)));
        }
    }
}
