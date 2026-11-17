//! Fixed texts of the Bitcoin RPC layer (spec/08 §2, §8, §11.3, §13; spec/14): chain-check
//! and form errors, the Esplora test result and the indexer lag warning. 2026-11-14 (Step 3):
//! Korean literals in `btc::{chain, flow, broadcast, work}` before, with the same Korean bytes.

yw_core::texts! {
    /// `CoreCheckFailure`/`BtcBlock::NetworkMismatch` (spec/08 §13; the yw-core text).
    NETWORK_MISMATCH = "BTC 네트워크 설정이 지갑 데이터와 다릅니다"
        / "The BTC network setting differs from the wallet data";
    /// W-BTC-IDX-LAG (spec/04 §2.16; `{0}` blocks).
    LAG_WARNING(1) = "인덱서와 노드의 블록 높이가 {0} 차이 납니다. 잔액·확인 수가 늦게 반영될 수 있습니다"
        / "The indexer and node block heights differ by {0}. Balances and confirmations may update late";
    /// T-BTC-IDX-OK (`{0}` network name).
    ESPLORA_OK(1) = "Esplora 서버가 작동합니다. ({0}, genesis 일치)"
        / "The Esplora server works. ({0}, genesis matches)";
    /// `sendrawtransaction`/Esplora returned another txid (spec/08 §11.3).
    TXID_MISMATCH = "응답 txid 불일치" / "Response txid mismatch";
    /// `PrepareError` texts (spec/08 §8.2–§8.3).
    CANCELLED = "작업을 취소했습니다" / "The task was cancelled";
    NO_ESTIMATE(1) = "노드가 수수료 추정을 주지 않았습니다. 직접 입력하세요(하한 {0})"
        / "The node gave no fee estimate. Enter the fee manually (floor {0})";
    BELOW_FLOOR(1) = "수수료율이 노드 하한({0})보다 낮습니다" / "The fee rate is below the node floor ({0})";
    /// `{0}` the B02 text, `{1}` grouped sats.
    NEEDS_TYPED_FEE(2) = "{0} 상한을 풀려면 수수료(sats)를 정확히 입력하세요: {1} sats"
        / "{0} To lift the cap, enter the exact fee (sats): {1} sats";
    /// `{0}` Core blocks, `{1}` indexer height, `{2}` `BTC_PLAN_TIP_AHEAD_MAX`.
    TIP_AHEAD(3) = "노드 블록 높이({0})가 인덱서({1})보다 {2}블록 넘게 앞서 보내기를 멈췄습니다. 잠시 뒤 다시 검토하거나 노드(RPC) 설정을 확인하세요"
        / "Sending stopped: the node block height ({0}) is more than {2} blocks ahead of the indexer ({1}). Review again in a moment or check the node (RPC) settings";
}
