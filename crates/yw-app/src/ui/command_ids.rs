//! The `WM_COMMAND` id map of the main window's child controls (spec/04 §1.8). Every screen module
//! keeps its own `ids` module; this file lists all of them in one place so a test can prove that
//! no two ranges overlap and that every indexed range is large enough for the longest list the
//! spec allows. Ids 1 and 2 are never used (`IsDialogMessageW` sends them for Enter / Esc).
//!
//! The approval window A01 and the secret windows W01–W10 have no child controls with command ids:
//! they hit-test their own owner-drawn rectangles, so they are not part of this map.
//!
//! | Block | Ids | Contents |
//! |---|---|---|
//! | core (`screens`) | 100–802 | S01–S09, top bar, settings 보안·네트워크·기타, overlays; network chips 210–249, URL rows 540–699 |
//! | EVM (`screens_evm`) | 900–3,560, 6,600 | send, chain rows 2,210–2,349, caps 2,400–2,439, activity 2,500–2,899, send assets 3,000–3,199, token rows 3,200–3,439, token `보내기` links 3,440–3,559, `이전 활동` 3,560 |
//! | sites (`screens_sites`) | 6,700–6,965 | S13 rows 6,710–6,965 |
//! | Solana (`screens_sol`) | 7,000–7,463 | send assets 7,015–7,018, token cards 7,027–7,029, picker 7,030–7,069, token hide 7,070–7,073, result `해시 복사` 7,076, scan rows 7,120–7,375, activity `해시 복사` 7,400–7,463 |
//! | Zcash (`screens_zec`) | 8,000–8,179 | EVM-key radios 8,020–8,035, `YubiKey` slots 8,040–8,047, imported keys 8,060–8,075, activity `해시 복사` 8,100–8,179 |
//! | Bitcoin (`screens_btc`) | 9,000–9,899 | account rows 9,130–9,194, UTXO rows 9,200–9,499, activity 9,500–9,899 |
//! | AI 설명 (`screens_llm`) | 10,000–10,099 | M6 settings |
//! | EVM accounts (`screens`) | 11,000–11,999 | one radio per row (index range 0..=999) |
//! | Solana accounts (`screens_sol`) | 12,000–12,999 | one radio per row (index range 0..=999) |
//! | imported keys (`screens_keys`) | 13,000–13,199 | S18/S19, script radios 13,010–13,013, selected imported Solana/Bitcoin account 13,022–13,025 (Bitcoin keys are rows of `btc.accounts`) |
//! | `YubiKey` (`screens_yubikey`) | 13,200–13,399 | S20, S21 wizard (`OpenPGP` SIG 13,210–13,221, AUT 13,230–13,241), settings tab; backup sources 13,260–13,267, `삭제` rows 13,270–13,277 |
//! | reset·extension (`screens_reset`) | 13,400–13,449 | S22 `지갑 초기화`, T-WAIT-STALLED, S23 `Chrome 확장 설치` |
//! | `HyperCore` (`screens_hypercore`) | 13,450–13,499 | the S10 card, S-HC, settings; spot asset radios 13,470–13,489, the card's `펼치기 ▸`·`접기 ▴` 13,494–13,495 |
//! | `YubiKey` connect (`screens_yubikey`) | 13,500–13,523, 13,720–13,927 | `YubiKey 연결하기 (복구 단어 없이)` 13,500–13,506, the factory-PIN bands' `PIN 설정` 13,510–13,517 (one per card), `어떻게 지우나요 ▸`·`슬롯·주소 자세히 ▸`·`PIN 안내 ▸`·re-slot `PIN 설정하기` 13,520–13,523, choice radios 13,720–13,927 (26 keys × 8) |
//! | recovery phrases (`screens_mnemonics`) | 13,600–13,699 | settings 복구 단어; card actions 13,620–13,657 (8 rows each), 계정 추가 picker 13,660–13,667, Solana picker 13,670–13,677, Bitcoin key source 13,680–13,687, Zcash key source 13,690–13,697 |
//! | address book (`screens_book`) | 14,000–15,699 | S14 form 14,000–14,016, favorite chips 14,020–14,027, BTC picker 14,030–14,069, SOL activity `이 주소 저장` 14,080–14,143, S14 rows 14,200–15,699 (★·편집·삭제) |
//! | `WalletConnect` (`screens_walletconnect`) | 16,000–16,099 | S13 panel, session rows 16,020–16,083 |
//! | hidden accounts (`app_hidden`) | 16,200–16,589 | toggles 16,200–16,201, EVM `다시 보이기` rows 16,210–16,399, Solana rows 16,400–16,589 |
//! | side-file choices (`app_sidecar`) | 16,600–16,609 | meta `닫기`, `고급`, journal `선택 다시 보기`, the Bitcoin form's check after a journal reset |
//! | first setup·RPC (`screens`) | 16,700–16,783 | S08 '처음 설정' 16,700–16,705, `모두 테스트` 16,706, the chain tabs' `RPC 설정하기` 16,707–16,710, the EVM·Solana failure bands' `이 네트워크 RPC 테스트`·`RPC 설정 열기` 16,711–16,714, failed-network links 16,720–16,783 |

use crate::ui::{
    screens, screens_book, screens_btc, screens_evm, screens_hypercore, screens_keys, screens_llm,
    screens_mnemonics, screens_reset, screens_sites, screens_sol, screens_walletconnect,
    screens_yubikey, screens_zec,
};

/// Largest number of rows of the Solana recovery scan (spec/07 §3.3: 50 standard + 50 BIP44
/// accounts, the BIP44 root, the seed and the 5 Sollet sources).
pub const SOL_SCAN_MAX_ROWS: usize = 107;

/// An indexed id range: `max_rows` rows of `stride` ids from `base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdRange {
    /// Name (module and list).
    pub name: &'static str,
    /// First id.
    pub base: u16,
    /// Number of ids reserved.
    pub span: u16,
    /// Ids per row.
    pub stride: u16,
    /// The longest list the screen can show (spec bound or render cap).
    pub max_rows: usize,
}

impl IdRange {
    /// One past the last id.
    #[must_use]
    pub const fn end(&self) -> u32 {
        self.base as u32 + self.span as u32
    }

    /// Whether `id` falls in the range.
    #[must_use]
    pub fn contains(&self, id: u16) -> bool {
        u32::from(id) >= u32::from(self.base) && u32::from(id) < self.end()
    }
}

const fn range(name: &'static str, base: u16, span: u16, stride: u16, max_rows: usize) -> IdRange {
    IdRange {
        name,
        base,
        span,
        stride,
        max_rows,
    }
}

/// Most tokens in one built-in chain's registry.
fn max_registry_tokens() -> usize {
    yw_core::evm::chain::builtin_chains()
        .iter()
        .map(|chain| chain.tokens.len())
        .max()
        .unwrap_or(0)
}

/// Most allowlisted SPL tokens of one cluster.
fn max_spl_tokens() -> usize {
    [
        yw_core::sol::SolCluster::Mainnet,
        yw_core::sol::SolCluster::Devnet,
    ]
    .into_iter()
    .map(|cluster| yw_core::sol::template::spl_entries(cluster).count())
    .max()
    .unwrap_or(0)
}

/// Every indexed range of the main window with its documented maximum.
#[must_use]
#[expect(clippy::too_many_lines, reason = "one entry per indexed list")]
pub fn ranges() -> Vec<IdRange> {
    use crate::meta::{MAX_ADDRESS_BOOK, MAX_EVM_ACCOUNTS, MAX_RAW_ACCOUNTS};
    use crate::settings::MAX_CUSTOM_EVM_CHAINS;
    let evm_chains = crate::network::BUILTIN_EVM.len() + MAX_CUSTOM_EVM_CHAINS;
    // URL rows: every EVM chain, solana:mainnet/devnet, bitcoin:mainnet/testnet4,
    // zcash:mainnet/testnet (spec/04 §2.11.1).
    let url_rows = evm_chains + 2 + 2 + 2;
    vec![
        range(
            "mnemonics.sol_pick",
            screens_mnemonics::ids::SOL_PICK_BASE,
            screens_mnemonics::ids::ROW_SPAN,
            1,
            yw_core::vault::MAX_MNEMONICS,
        ),
        range(
            "mnemonics.btc_pick",
            screens_mnemonics::ids::BTC_PICK_BASE,
            screens_mnemonics::ids::ROW_SPAN,
            1,
            yw_core::vault::MAX_MNEMONICS,
        ),
        range(
            "mnemonics.zec_pick",
            screens_mnemonics::ids::ZEC_PICK_BASE,
            screens_mnemonics::ids::ROW_SPAN,
            1,
            yw_core::vault::MAX_MNEMONICS,
        ),
        range(
            "hidden.evm_rows",
            crate::app_hidden::ids::EVM_ROW_BASE,
            crate::app_hidden::ids::ROW_SPAN,
            1,
            usize::from(crate::app_hidden::ids::ROW_SPAN),
        ),
        range(
            "hidden.sol_rows",
            crate::app_hidden::ids::SOL_ROW_BASE,
            crate::app_hidden::ids::ROW_SPAN,
            1,
            usize::from(crate::app_hidden::ids::ROW_SPAN),
        ),
        range(
            "walletconnect.sessions",
            screens_walletconnect::ids::ROW_BASE,
            screens_walletconnect::ids::ROW_SPAN,
            1,
            crate::walletconnect::engine::MAX_SESSIONS,
        ),
        range(
            "hypercore.assets",
            screens_hypercore::ids::ASSET_BASE,
            screens_hypercore::ids::ASSET_SPAN,
            1,
            usize::from(screens_hypercore::ids::ASSET_SPAN),
        ),
        range(
            "core.network_chips",
            screens::ids::NETWORK_BASE,
            screens::ids::NETWORK_SPAN,
            1,
            evm_chains,
        ),
        range(
            "core.accounts",
            screens::ids::ACCOUNT_BASE,
            screens::ids::ACCOUNT_SPAN,
            1,
            MAX_EVM_ACCOUNTS + MAX_RAW_ACCOUNTS,
        ),
        range(
            "core.url_rows",
            screens::ids::ROW_BASE,
            screens::ids::ROW_SPAN,
            3,
            url_rows,
        ),
        range(
            "core.rpc_row_links",
            screens::ids::RPC_ROW_OPEN_BASE,
            screens::ids::RPC_ROW_OPEN_SPAN,
            1,
            url_rows,
        ),
        range(
            "evm.token_send",
            screens_evm::ids::TOKEN_SEND_BASE,
            screens_evm::ids::TOKEN_SEND_SPAN,
            1,
            max_registry_tokens() + crate::meta::MAX_TOKENS_PER_NETWORK,
        ),
        range(
            "evm.send_assets",
            screens_evm::ids::SEND_ASSET_BASE,
            screens_evm::ids::SEND_ASSET_SPAN,
            1,
            1 + max_registry_tokens() + crate::meta::MAX_TOKENS_PER_NETWORK,
        ),
        range(
            "evm.send_picker",
            screens_evm::ids::SEND_PICK_BASE,
            screens_evm::ids::SEND_PICK_SPAN,
            1,
            usize::from(screens_evm::ids::SEND_PICK_SPAN),
        ),
        range(
            "book.rows",
            screens_book::ids::ROW_BASE,
            screens_book::ids::ROW_SPAN,
            screens_book::ids::ROW_STRIDE,
            MAX_ADDRESS_BOOK,
        ),
        range(
            "book.favorites",
            screens_book::ids::FAV_BASE,
            screens_book::ids::FAV_SPAN,
            1,
            crate::app_book::FAVORITE_CHIPS,
        ),
        range(
            "book.btc_picker",
            screens_book::ids::BTC_PICK_BASE,
            screens_book::ids::BTC_PICK_SPAN,
            1,
            usize::from(screens_book::ids::BTC_PICK_SPAN),
        ),
        range(
            "book.sol_activity",
            screens_book::ids::SOL_ACTIVITY_BASE,
            screens_book::ids::SOL_ACTIVITY_SPAN,
            1,
            crate::app_sol::SOL_MAX_ACTIVITY_ROWS,
        ),
        range(
            "evm.chain_rows",
            screens_evm::ids::CHAIN_ROW_BASE,
            screens_evm::ids::CHAIN_ROW_SPAN,
            3,
            evm_chains,
        ),
        range(
            "evm.caps_chains",
            screens_evm::ids::CAPS_CHAIN_BASE,
            screens_evm::ids::CAPS_CHAIN_SPAN,
            1,
            evm_chains,
        ),
        range(
            "evm.token_rows",
            screens_evm::ids::TOKEN_ROW_BASE,
            screens_evm::ids::TOKEN_ROW_SPAN,
            screens_evm::ids::TOKEN_ROW_STRIDE,
            max_registry_tokens() + crate::meta::MAX_TOKENS_PER_NETWORK,
        ),
        range(
            "evm.activity",
            screens_evm::ids::ACTIVITY_BASE,
            screens_evm::ids::ACTIVITY_SPAN,
            screens_evm::ids::ACTIVITY_STRIDE,
            crate::app_evm::MAX_ACTIVITY_ROWS,
        ),
        range(
            "sites.rows",
            screens_sites::ids::SITE_ROW_BASE,
            screens_sites::ids::SITE_ROW_SPAN,
            1,
            screens_sites::ids::SITES_PAGE_ROWS,
        ),
        range(
            "sol.send_assets",
            screens_sol::ids::SEND_ASSET_BASE,
            screens_sol::ids::SEND_ASSET_SPAN,
            1,
            1 + max_spl_tokens(),
        ),
        range(
            "sol.token_send",
            screens_sol::ids::TOKEN_SEND_BASE,
            screens_sol::ids::TOKEN_SEND_SPAN,
            1,
            max_spl_tokens(),
        ),
        range(
            "sol.token_hide",
            screens_sol::ids::TOKEN_HIDE_BASE,
            screens_sol::ids::TOKEN_HIDE_SPAN,
            1,
            max_spl_tokens(),
        ),
        range(
            "sol.send_picker",
            screens_sol::ids::SEND_PICK_BASE,
            screens_sol::ids::SEND_PICK_SPAN,
            1,
            usize::from(screens_sol::ids::SEND_PICK_SPAN),
        ),
        range(
            "sol.scan_rows",
            screens_sol::ids::SCAN_ROW_BASE,
            screens_sol::ids::SCAN_ROW_SPAN,
            screens_sol::ids::SCAN_ROW_STRIDE,
            SOL_SCAN_MAX_ROWS,
        ),
        range(
            "sol.accounts",
            screens_sol::ids::ACCOUNT_BASE,
            screens_sol::ids::ACCOUNT_SPAN,
            1,
            MAX_EVM_ACCOUNTS + MAX_RAW_ACCOUNTS,
        ),
        range(
            "btc.accounts",
            screens_btc::ids::ACCOUNT_BASE,
            screens_btc::ids::ACCOUNT_SPAN,
            1,
            usize::from(screens_btc::ids::ACCOUNT_SPAN),
        ),
        range(
            "btc.evm_accounts",
            screens_btc::ids::EVM_ACCOUNT_BASE,
            screens_btc::ids::EVM_ACCOUNT_SPAN,
            1,
            usize::from(screens_btc::ids::EVM_ACCOUNT_SPAN),
        ),
        range(
            "btc.utxo_rows",
            screens_btc::ids::UTXO_BASE,
            screens_btc::ids::UTXO_SPAN,
            1,
            usize::from(screens_btc::ids::UTXO_SPAN),
        ),
        range(
            "yubikey.backup_sources",
            screens_yubikey::ids::BACKUP_BASE,
            screens_yubikey::ids::BACKUP_SPAN,
            1,
            yw_core::yubikey::plan::MAX_CARDS,
        ),
        range(
            "yubikey.remove_rows",
            screens_yubikey::ids::REMOVE_BASE,
            screens_yubikey::ids::REMOVE_SPAN,
            1,
            yw_core::yubikey::plan::MAX_CARDS,
        ),
        range(
            "yubikey.pin_rows",
            screens_yubikey::ids::PINS_BASE,
            screens_yubikey::ids::PINS_SPAN,
            1,
            yw_core::yubikey::plan::MAX_CARDS,
        ),
        range(
            "yubikey.reslot_rows",
            screens_yubikey::ids::RESLOT_BASE,
            screens_yubikey::ids::RESLOT_SPAN,
            1,
            yw_core::yubikey::plan::MAX_CARDS,
        ),
        range(
            "yubikey.clear_rows",
            screens_yubikey::ids::CLEAR_BASE,
            screens_yubikey::ids::CLEAR_SPAN,
            1,
            yw_core::yubikey::plan::MAX_CARDS,
        ),
        range(
            "yubikey.reslot_backup_rows",
            screens_yubikey::ids::RESLOT_BACKUP_BASE,
            screens_yubikey::ids::RESLOT_BACKUP_SPAN,
            1,
            yw_core::yubikey::plan::MAX_CARDS,
        ),
        range(
            "yubikey.connect_choices",
            screens_yubikey::ids::CONNECT_CHOICE_BASE,
            screens_yubikey::ids::CONNECT_CHOICE_SPAN,
            screens_yubikey::ids::CONNECT_CHOICE_STRIDE,
            usize::from(screens_yubikey::ids::CONNECT_CHOICE_ROWS),
        ),
        range(
            "yubikey.pin_gate_rows",
            screens_yubikey::ids::PIN_GATE_BASE,
            screens_yubikey::ids::PIN_GATE_SPAN,
            1,
            yw_core::yubikey::plan::MAX_CARDS,
        ),
        range(
            "mnemonics.rename",
            screens_mnemonics::ids::RENAME_BASE,
            screens_mnemonics::ids::ROW_SPAN,
            1,
            yw_core::vault::MAX_MNEMONICS,
        ),
        range(
            "mnemonics.reveal",
            screens_mnemonics::ids::REVEAL_BASE,
            screens_mnemonics::ids::ROW_SPAN,
            1,
            yw_core::vault::MAX_MNEMONICS,
        ),
        range(
            "mnemonics.backup",
            screens_mnemonics::ids::BACKUP_BASE,
            screens_mnemonics::ids::ROW_SPAN,
            1,
            yw_core::vault::MAX_MNEMONICS,
        ),
        range(
            "mnemonics.remove",
            screens_mnemonics::ids::REMOVE_BASE,
            screens_mnemonics::ids::ROW_SPAN,
            1,
            yw_core::vault::MAX_MNEMONICS,
        ),
        range(
            "mnemonics.pick",
            screens_mnemonics::ids::PICK_BASE,
            screens_mnemonics::ids::ROW_SPAN,
            1,
            yw_core::vault::MAX_MNEMONICS,
        ),
        range(
            "btc.activity",
            screens_btc::ids::ACTIVITY_BASE,
            screens_btc::ids::ACTIVITY_SPAN,
            screens_btc::ids::ACTIVITY_STRIDE,
            crate::app_btc::BTC_MAX_ACTIVITY_ROWS,
        ),
        range(
            "sol.activity_copy",
            screens_sol::ids::ACTIVITY_COPY_BASE,
            screens_sol::ids::ACTIVITY_COPY_SPAN,
            1,
            yw_core::journal::sol::SOL_JOURNAL_MAX_RECORDS
                .max(crate::app_sol::SOL_MAX_ACTIVITY_ROWS),
        ),
        range(
            "zec.activity_copy",
            screens_zec::ids::ACTIVITY_COPY_BASE,
            screens_zec::ids::ACTIVITY_COPY_SPAN,
            1,
            yw_core::journal::zec::ZEC_JOURNAL_MAX_RECORDS,
        ),
    ]
}

/// Every fixed id of the main window, by module.
#[must_use]
pub fn fixed() -> Vec<(&'static str, &'static [u16])> {
    vec![
        ("core", screens::ids::FIXED),
        ("evm", screens_evm::ids::FIXED),
        ("book", screens_book::ids::FIXED),
        ("sites", screens_sites::ids::FIXED),
        ("sol", screens_sol::ids::FIXED),
        ("btc", &screens_btc::ids::FIXED),
        ("zec", &screens_zec::ids::FIXED),
        ("llm", screens_llm::ids::FIXED),
        ("keys", screens_keys::ids::FIXED),
        ("yubikey", screens_yubikey::ids::FIXED),
        ("mnemonics", screens_mnemonics::ids::FIXED),
        ("reset", screens_reset::ids::FIXED),
        ("hypercore", screens_hypercore::ids::FIXED),
        ("walletconnect", screens_walletconnect::ids::FIXED),
        ("hidden", crate::app_hidden::ids::FIXED),
        ("sidecar", crate::app_sidecar::ids::FIXED),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{IdRange, SOL_SCAN_MAX_ROWS, fixed, ranges};

    #[test]
    fn indexed_ranges_hold_their_longest_list() {
        for range in ranges() {
            let needed = range.max_rows.saturating_mul(usize::from(range.stride));
            assert!(
                needed <= usize::from(range.span),
                "{}: {} rows × {} > span {}",
                range.name,
                range.max_rows,
                range.stride,
                range.span
            );
            assert!(range.stride >= 1, "{}", range.name);
            assert!(u16::try_from(range.end()).is_ok(), "{}", range.name);
            assert!(range.base > 2, "{} uses IDOK/IDCANCEL", range.name);
        }
        // The documented scan maximum covers what the app actually scans.
        assert!(crate::sol::scan::scan_sources().len() <= SOL_SCAN_MAX_ROWS);
    }

    #[test]
    fn ranges_and_fixed_ids_are_disjoint() {
        let all = ranges();
        for (index, left) in all.iter().enumerate() {
            for right in all.iter().skip(index + 1) {
                let disjoint =
                    left.end() <= u32::from(right.base) || right.end() <= u32::from(left.base);
                assert!(disjoint, "{} overlaps {}", left.name, right.name);
            }
        }
        let mut seen: BTreeMap<u16, &str> = BTreeMap::new();
        for (module, ids) in fixed() {
            for &id in ids {
                assert!(id > 2, "{module}: {id} is IDOK/IDCANCEL");
                let other = seen.insert(id, module);
                assert!(
                    other.is_none(),
                    "fixed id {id} in both {other:?} and {module}"
                );
                let inside: Vec<&IdRange> = all.iter().filter(|range| range.contains(id)).collect();
                assert!(
                    inside.is_empty(),
                    "fixed id {id} ({module}) inside {:?}",
                    inside.iter().map(|range| range.name).collect::<Vec<_>>()
                );
            }
        }
    }

    /// Token-row ids (2026-11-03): every row of the longest EVM token list maps back to its
    /// row and action, and the token-card ids collide with nothing (above).
    #[test]
    fn every_token_row_id_maps_back_to_its_row() {
        use crate::ui::screens_evm::ids::{TokenAction, token_action, token_row_id};
        let rows = super::max_registry_tokens() + crate::meta::MAX_TOKENS_PER_NETWORK;
        let mut seen = std::collections::BTreeSet::new();
        for row in 0..rows {
            for action in [TokenAction::ToggleHidden(row), TokenAction::Delete(row)] {
                let id = token_row_id(action).unwrap();
                assert_eq!(token_action(id), Some(action), "row {row}");
                assert!(seen.insert(id), "row {row} id {id} reused");
                for range in ranges() {
                    assert!(
                        range.name == "evm.token_rows" || !range.contains(id),
                        "row {row} id {id} inside {}",
                        range.name
                    );
                }
            }
        }
        assert_eq!(token_action(3_199), None);
        assert_eq!(token_action(3_440), None);
        let fixed_new = [
            crate::ui::screens_evm::ids::SEND_HIDDEN_TOGGLE,
            crate::ui::screens_evm::ids::TOKEN_HIDE_ZERO,
            crate::ui::screens_evm::ids::TOKEN_HIDDEN_TOGGLE,
            crate::ui::screens_sol::ids::TOKEN_HIDDEN_TOGGLE,
        ];
        for id in fixed_new {
            assert!(
                fixed().iter().any(|(_, ids)| ids.contains(&id)),
                "{id} not listed as a fixed id"
            );
        }
    }

    #[test]
    fn every_scan_row_id_maps_back_to_its_row() {
        // Regression of the 2026-10-28 audit: scan rows 7,120 + 2 × 240 covered the account
        // radios at 7,200, so the buttons of row 40 and later selected an account instead.
        use crate::ui::screens_sol::ids::scan_row_id;
        use crate::ui::screens_sol::ids::{ACCOUNT_BASE, ACCOUNT_SPAN, ScanAction, scan_action};
        let accounts = IdRange {
            name: "sol.accounts",
            base: ACCOUNT_BASE,
            span: ACCOUNT_SPAN,
            stride: 1,
            max_rows: 0,
        };
        for row in 0..SOL_SCAN_MAX_ROWS {
            for action in [ScanAction::Add(row), ScanAction::Move(row)] {
                let id = scan_row_id(action).unwrap();
                assert_eq!(scan_action(id), Some(action), "row {row}");
                assert!(!accounts.contains(id), "row {row} id {id}");
            }
        }
        assert_eq!(scan_action(7_200), Some(ScanAction::Add(40)));
    }
}
