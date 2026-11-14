//! The `HyperCore 전송` approval texts in Korean and English (spec/11 §6, spec/14).
//!
//! The network label (`HcNetwork::label`) and the action name reach the approval display and the
//! activity rows; they are mapped here per language. The network's Korean side delegates to the
//! original function (the catalogue copy is checked against it in the tests); the action name
//! lives only here (2026-11-14: `HcKind::korean` removed).

use super::{HcKind, HcNetwork};
use crate::lang::Lang;

crate::texts! {
    /// `HcNetwork::label`.
    NETWORK_MAINNET = "HyperCore 메인넷" / "HyperCore mainnet";
    NETWORK_TESTNET = "HyperCore 테스트넷" / "HyperCore testnet";
    /// The action name ([`kind_name`]).
    KIND_USD_SEND = "USDC 보내기 (HyperCore)" / "Send USDC (HyperCore)";
    KIND_SPOT_SEND = "현물 토큰 보내기 (HyperCore)" / "Send spot token (HyperCore)";
    KIND_WITHDRAW = "Arbitrum으로 USDC 출금" / "Withdraw USDC to Arbitrum";
    KIND_USD_CLASS_TRANSFER = "현물↔선물 USDC 이동" / "Move USDC spot↔perp";
    KIND_SEND_ASSET = "HyperEVM으로 이동" / "Move to HyperEVM";

    /// Title.
    TITLE(2) = "[{0}] HyperCore 전송: {1}" / "[{0}] HyperCore transfer: {1}";
    /// Network field.
    NETWORK(3) = "Hyperliquid {0} (chainId {1}로 서명 · hyperliquidChain {2})"
        / "Hyperliquid {0} (signed with chainId {1} · hyperliquidChain {2})";
    /// Action field of `usdClassTransfer`.
    DIRECTION(2) = "{0}\n방향: {1}" / "{0}\nDirection: {1}";
    SPOT_TO_PERP = "현물(spot) → 선물(perp)" / "Spot → perp";
    PERP_TO_SPOT = "선물(perp) → 현물(spot)" / "Perp → spot";
    /// Recipient notes.
    NOTE_EVM_SYSTEM = "HyperEVM 시스템 주소 — 토큰은 HyperEVM의 같은 주소(서명 계정)로 들어갑니다"
        / "HyperEVM system address — the tokens arrive at the same address (the signing account) on HyperEVM";
    NOTE_WITHDRAW = "Arbitrum One의 이 주소로 USDC가 들어갑니다"
        / "USDC arrives at this address on Arbitrum One";
    NOTE_SAME_ACCOUNT = "보내는 계정과 같은 주소입니다" / "Same address as the sending account";
    /// Token and amount.
    TOKEN(4) = "{0} (토큰 index {1}, tokenId {2}, 소수 {3}자리)"
        / "{0} (token index {1}, tokenId {2}, {3} decimals)";
    WITHDRAW_AMOUNT(3) = "{0} USDC\nArbitrum 도착 = 금액 − {1} USDC = {2} USDC"
        / "{0} USDC\nArrives on Arbitrum = amount − {1} USDC = {2} USDC";
    /// Fee.
    FEE_WITHDRAW(1) = "{0} USDC (고정 출금 수수료, HyperCore에서 차감)"
        / "{0} USDC (fixed withdrawal fee, deducted on HyperCore)";
    FEE_SEND_ASSET = "HyperCore에서 HYPE로 HyperEVM 가스(200k gas)를 냅니다"
        / "HyperEVM gas (200k gas) is paid in HYPE on HyperCore";
    FEE_NONE = "없음 (HyperCore 사용자 서명 작업)" / "None (HyperCore user-signed action)";
    /// Nonce.
    NONCE(1) = "{0} (unix ms, 서명 시각)" / "{0} (unix ms, signing time)";
}

/// The network label (`HcNetwork::label`).
#[must_use]
pub fn network_label(lang: Lang, network: HcNetwork) -> &'static str {
    match network {
        HcNetwork::Mainnet => NETWORK_MAINNET.get(lang),
        HcNetwork::Testnet => NETWORK_TESTNET.get(lang),
    }
}

/// The action name (approval, activity).
#[must_use]
pub const fn kind_name(lang: Lang, kind: HcKind) -> &'static str {
    match kind {
        HcKind::UsdSend => KIND_USD_SEND,
        HcKind::SpotSend => KIND_SPOT_SEND,
        HcKind::Withdraw => KIND_WITHDRAW,
        HcKind::UsdClassTransfer => KIND_USD_CLASS_TRANSFER,
        HcKind::SendAsset => KIND_SEND_ASSET,
    }
    .get(lang)
}
