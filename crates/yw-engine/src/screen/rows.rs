//! How many rows of each list a screen draws as pressable controls (spec/15 §11.3): the bound of
//! the [`Row`](crate::cmd::Row) a list's presses carry. A list longer than its bound draws the
//! rows past it without those controls (read-only, or not at all), as each screen says.
//!
//! 2026-11-24 (spec/15 §11.4 S5-4): created when the screens stopped naming control ids. Before,
//! each screen bounded its rows by the span of the press's control-id range (yw-app
//! `ui::screens_*::ids::*_SPAN`, divided by the stride of a strided range), which still sets
//! the same numbers on Windows: yw-app table test `screen_rows_are_the_id_ranges` pins every
//! value here to its range. A press past its bound would be drawn at another control's id on
//! Windows; the lowering counts such a press (`press_mismatch`).

/// S10's network drop-down (`CorePress::Network`).
pub const NETWORKS: u16 = 40;
/// S10's EVM account drop-down (`CorePress::Account`).
pub const EVM_ACCOUNTS: u16 = 1_000;
/// The URL rows of settings → 네트워크(RPC) (`CorePress::RpcRow`).
pub const RPC_ROWS: u16 = 53;
/// The `열기` links of failed RPC rows (`CorePress::RpcRowOpen`).
pub const RPC_ROW_OPENS: u16 = 64;
/// The address book's copyable addresses (`BookPress::Copy`).
pub const BOOK_COPIES: u16 = 500;
/// Solana activity rows with `☆ 이 주소 저장` (`BookPress::SolActivitySave`).
pub const SOL_ACTIVITY_SAVES: u16 = 64;
/// The Bitcoin account drop-down (`BtcPress::Account`).
pub const BTC_ACCOUNTS: u16 = 65;
/// Bitcoin's `EVM 키로 만들기` choices (`BtcPress::EvmAccount`).
pub const BTC_EVM_ACCOUNTS: u16 = 32;
/// The Bitcoin coin-control list (`BtcPress::Utxo`).
pub const BTC_UTXOS: u16 = 300;
/// EVM token rows with `보내기` (`EvmPress::TokenSend`).
pub const EVM_TOKEN_SENDS: u16 = 120;
/// EVM token rows with `숨기기` and `삭제` (`EvmPress::{TokenToggleHidden, TokenDelete}`).
pub const EVM_TOKEN_ROWS: u16 = 120;
/// EVM token rows with a copyable contract (`EvmPress::TokenCopy`).
pub const EVM_TOKEN_COPIES: u16 = 120;
/// The EVM send form's asset choices (`EvmPress::SendAsset`).
pub const EVM_SEND_ASSETS: u16 = 200;
/// The latest EVM activity rows shown before `더 보기` (a row still in flight is never folded
/// away).
pub const EVM_ACTIVITY_FIRST: usize = 10;
/// The user chains of settings → 체인 (`EvmPress::ChainRow`).
pub const EVM_CHAIN_ROWS: u16 = 46;
/// The chains of the fee-cap card (`EvmPress::CapsChain`).
pub const EVM_CAPS_CHAINS: u16 = 40;
/// The hidden EVM and Solana accounts with `다시 보이기` (`HiddenPress::{EvmUnhide, SolUnhide}`).
pub const HIDDEN_ROWS: u16 = 190;
/// The hidden Bitcoin accounts with `다시 보이기` (`HiddenPress::BtcUnhide`).
pub const HIDDEN_BTC_ROWS: u16 = 65;
/// `HyperCore` asset rows (`HcPress::Asset`).
pub const HC_ASSETS: u16 = 20;
/// The recovery phrases and their pickers (`MnPress::*(Row)`).
pub const MNEMONICS: u16 = 8;
/// The Solana account drop-down (`SolPress::Account`).
pub const SOL_ACCOUNTS: u16 = 1_000;
/// Solana activity rows with a copyable signature (`SolPress::ActivityCopy`).
pub const SOL_ACTIVITY_COPIES: u16 = 64;
/// The Solana send form's asset choices (`SolPress::SendAsset`).
pub const SOL_SEND_ASSETS: u16 = 4;
/// Solana token rows with a copyable mint (`SolPress::TokenCopy`).
pub const SOL_TOKEN_COPIES: u16 = 4;
/// Solana token rows with `숨기기` (`SolPress::TokenHide`).
pub const SOL_TOKEN_HIDES: u16 = 4;
/// The rows of the Solana account scan (`SolPress::ScanRow`).
pub const SOL_SCAN_ROWS: u16 = 128;
/// The received-history rows of one chain with a copyable hash and explorer link
/// (`ReceivedPress::{CopyHash, OpenExplorer}`).
pub const RECEIVED_ROWS: u16 = 50;
/// The `WalletConnect` sessions with `연결 해제` (`WcPress::Disconnect`).
pub const WC_SESSIONS: u16 = 64;
/// The `YubiKey` PIN gates (`YkPress::PinGate`).
pub const YK_PIN_GATES: u16 = 8;
/// EVM activity rows with a copyable recipient (`LinksPress::EvmTo`).
pub const EVM_TO: u16 = 50;
/// Solana activity rows with a copyable recipient (`LinksPress::SolTo`).
pub const SOL_TO: u16 = 64;
/// Bitcoin activity rows with a copyable recipient (`LinksPress::BtcTo`).
pub const BTC_TO: u16 = 50;
/// Zcash activity rows with a copyable recipient (`LinksPress::ZecTo`).
pub const ZEC_TO: u16 = 80;
/// Solana activity rows with explorer links (`ExplorerPress::SolActivity`).
pub const SOL_ACTIVITY_LINKS: u16 = 64;
/// Bitcoin activity rows with explorer links (`ExplorerPress::BtcActivity`).
pub const BTC_ACTIVITY_LINKS: u16 = 50;
/// Zcash activity rows with explorer links (`ExplorerPress::ZecActivity`).
pub const ZEC_ACTIVITY_LINKS: u16 = 80;
/// Zcash activity rows with a copyable transaction id (`ZecPress::ActivityCopy`).
pub const ZEC_ACTIVITY_COPIES: u16 = 80;

/// Row `row` of a list bounded by `rows`, or `None` past it.
#[must_use]
pub fn row(row: usize, rows: u16) -> Option<crate::cmd::Row> {
    u16::try_from(row)
        .ok()
        .filter(|row| *row < rows)
        .map(crate::cmd::Row)
}

#[cfg(test)]
mod tests {
    use super::row;
    use crate::cmd::Row;

    #[test]
    fn row_is_bounded() {
        assert_eq!(row(0, 2), Some(Row(0)));
        assert_eq!(row(1, 2), Some(Row(1)));
        assert_eq!(row(2, 2), None);
        assert_eq!(row(usize::MAX, u16::MAX), None);
    }
}
