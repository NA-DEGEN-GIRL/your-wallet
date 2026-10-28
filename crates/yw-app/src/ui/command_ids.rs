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
//! | EVM (`screens_evm`) | 900–3,199, 6,600 | send, book rows 1,020–2,019, chain rows 2,210–2,349, caps 2,400–2,439, activity 2,500–2,899, send assets 3,000–3,199 |
//! | sites (`screens_sites`) | 6,700–6,965 | S13 rows 6,710–6,965 |
//! | Solana (`screens_sol`) | 7,000–7,909 | send assets 7,015–7,018, token cards 7,027–7,029, picker 7,030–7,069, scan rows 7,120–7,375, book rows 7,410–7,909 |
//! | Bitcoin (`screens_btc`) | 9,000–9,899 | account rows 9,130–9,194, UTXO rows 9,200–9,499, activity 9,500–9,899 |
//! | AI 설명 (`screens_llm`) | 10,000–10,099 | M6 settings |
//! | EVM accounts (`screens`) | 11,000–11,999 | one radio per row (index range 0..=999) |
//! | Solana accounts (`screens_sol`) | 12,000–12,999 | one radio per row (index range 0..=999) |

use crate::ui::{screens, screens_btc, screens_evm, screens_llm, screens_sites, screens_sol};

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
    use crate::meta::{MAX_ADDRESS_BOOK, MAX_EVM_ACCOUNTS, MAX_RAW_ACCOUNTS, MAX_SITES};
    use crate::settings::MAX_CUSTOM_EVM_CHAINS;
    let evm_chains = crate::network::BUILTIN_EVM.len() + MAX_CUSTOM_EVM_CHAINS;
    // URL rows: every EVM chain, solana:mainnet/devnet, bitcoin:mainnet/testnet4 (spec/04 §2.11.1).
    let url_rows = evm_chains + 2 + 2;
    vec![
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
            4,
            url_rows,
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
            "evm.book_rows",
            screens_evm::ids::BOOK_ROW_BASE,
            screens_evm::ids::BOOK_ROW_SPAN,
            2,
            MAX_ADDRESS_BOOK,
        ),
        range(
            "evm.chain_rows",
            screens_evm::ids::CHAIN_ROW_BASE,
            screens_evm::ids::CHAIN_ROW_SPAN,
            4,
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
            MAX_SITES,
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
            "sol.book_rows",
            screens_sol::ids::BOOK_ROW_BASE,
            screens_sol::ids::BOOK_ROW_SPAN,
            1,
            MAX_ADDRESS_BOOK,
        ),
        range(
            "sol.accounts",
            screens_sol::ids::ACCOUNT_BASE,
            screens_sol::ids::ACCOUNT_SPAN,
            1,
            MAX_EVM_ACCOUNTS,
        ),
        range(
            "btc.accounts",
            screens_btc::ids::ACCOUNT_BASE,
            screens_btc::ids::ACCOUNT_SPAN,
            1,
            usize::from(screens_btc::ids::ACCOUNT_SPAN),
        ),
        range(
            "btc.utxo_rows",
            screens_btc::ids::UTXO_BASE,
            screens_btc::ids::UTXO_SPAN,
            1,
            usize::from(screens_btc::ids::UTXO_SPAN),
        ),
        range(
            "btc.activity",
            screens_btc::ids::ACTIVITY_BASE,
            screens_btc::ids::ACTIVITY_SPAN,
            screens_btc::ids::ACTIVITY_STRIDE,
            crate::app_btc::BTC_MAX_ACTIVITY_ROWS,
        ),
    ]
}

/// Every fixed id of the main window, by module.
#[must_use]
pub fn fixed() -> Vec<(&'static str, &'static [u16])> {
    vec![
        ("core", screens::ids::FIXED),
        ("evm", screens_evm::ids::FIXED),
        ("sites", screens_sites::ids::FIXED),
        ("sol", screens_sol::ids::FIXED),
        ("btc", &screens_btc::ids::FIXED),
        ("llm", screens_llm::ids::FIXED),
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
