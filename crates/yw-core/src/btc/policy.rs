//! BTC policy (spec/08 §10, §11.3, §13): the `B01`–`B08` warning rules (`RuleId` family `'B'`)
//! with their levels and fixed Korean texts, the fixed error texts, the Core `reject-reason`
//! token table, RPC error texts, and the pure decisions of the pre-broadcast check
//! (`testmempoolaccept`) and of `sendrawtransaction`. Inputs are values the yw-app RPC layer
//! already parsed; no server string is ever returned for display (tokens are compared, never
//! shown).
#![deny(clippy::indexing_slicing)]

use super::amount::Sats;
use super::tx::Txid;
use crate::approval::{RiskLevel, RuleId, Warning};
use crate::bip32::path::BtcChain;

/// `B01` fee rate above 10,000 sat/vB (blocked, cannot be lifted).
pub const B01: RuleId = RuleId::new(b'B', 1);
/// `B02` fee cap exceeded without the typed override (blocked).
pub const B02: RuleId = RuleId::new(b'B', 2);
/// `B03` fee cap lifted by the send form's typed override (high).
pub const B03: RuleId = RuleId::new(b'B', 3);
/// `B04` fee above 2 % of the amount (high).
pub const B04: RuleId = RuleId::new(b'B', 4);
/// `B05` first-time recipient (caution).
pub const B05: RuleId = RuleId::new(b'B', 5);
/// `B06` recipient amount reduced by a send-max bump / UTXOs left out of a send-max (caution).
pub const B06: RuleId = RuleId::new(b'B', 6);
/// `B07` the recipient is an address of this wallet (info).
pub const B07: RuleId = RuleId::new(b'B', 7);
/// `B08` legacy (P2PKH) or script (P2SH, P2WSH) recipient (info).
pub const B08: RuleId = RuleId::new(b'B', 8);

/// The level of a `B` rule (spec/08 §10 table).
#[must_use]
pub fn level_of(rule: RuleId) -> Option<RiskLevel> {
    Some(match rule {
        r if r == B01 || r == B02 => RiskLevel::Blocked,
        r if r == B03 || r == B04 => RiskLevel::High,
        r if r == B05 || r == B06 => RiskLevel::Caution,
        r if r == B07 || r == B08 => RiskLevel::Info,
        _ => return None,
    })
}

/// Fixed texts (spec/08 §10, §12.1, §13).
pub mod texts {
    /// B01.
    pub const FEE_UNOVERRIDABLE: &str =
        "수수료율이 10,000 sat/vB를 넘습니다 — 어떤 입력으로도 보낼 수 없습니다";
    /// B02.
    pub const FEE_CAP_BLOCKED: &str = "수수료가 상한(500 sat/vB 또는 0.005 BTC)을 넘습니다 — 보내기 화면에서 수수료(sats)를 정확히 입력해야 상한이 해제됩니다";
    /// B03.
    pub const FEE_CAP_OVERRIDDEN: &str =
        "수수료 상한(500 sat/vB 또는 0.005 BTC)을 직접 입력으로 해제했습니다";
    /// B04.
    pub const FEE_RATIO: &str = "수수료가 보내는 금액의 2%를 넘습니다";
    /// B05.
    pub const FIRST_TIME: &str =
        "처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요.";
    /// B06 (send-max bump).
    pub const RECIPIENT_DECREASED: &str =
        "수신 금액 감소: 늘어난 수수료만큼 받는 금액이 줄어듭니다";
    /// B08 (P2PKH).
    pub const LEGACY_RECIPIENT: &str = "레거시 형식(P2PKH) 주소입니다";
    /// B08 (P2SH, P2WSH).
    pub const SCRIPT_RECIPIENT: &str =
        "스크립트 주소(P2SH·P2WSH)입니다: 수신자가 스크립트를 관리합니다";
    /// D20 in-flight refusal (spec/08 §12.1).
    pub const IN_FLIGHT: &str =
        "진행 중인 Bitcoin 거래가 확인된 뒤 보낼 수 있습니다. 수수료 올리기는 가능합니다";
    /// A plan input is used by an in-flight journal entry (spec/08 §5).
    pub const INPUT_IN_FLIGHT: &str = "진행 중인 거래가 쓰는 입력은 다시 쓸 수 없습니다";
    /// The fee-bump target is not replaceable.
    pub const NOT_BUMPABLE: &str = "수수료를 올릴 수 있는 거래가 아닙니다";
    /// Change derivation failed.
    pub const DERIVATION_FAILED: &str = "주소 파생에 실패했습니다";
    /// Plan arithmetic overflow.
    pub const PLAN_OVERFLOW: &str = "거래 크기 또는 금액 계산 범위를 넘었습니다";
    /// `NetworkMismatch` (spec/08 §2, §13).
    pub const NETWORK_MISMATCH: &str = "BTC 네트워크 설정이 지갑 데이터와 다릅니다";
    /// `KeyMismatch` (spec/08 §3.1, §13).
    pub const KEY_MISMATCH: &str = "파생한 키가 계정 공개키와 다릅니다. 서명을 중단했습니다";
    /// `AmountRecordMismatch` (spec/08 §5, §13).
    pub const AMOUNT_RECORD_MISMATCH: &str =
        "기록된 입력 금액과 계획 금액이 다릅니다. 서명을 중단했습니다";
    /// The approval does not match the plan.
    pub const APPROVAL_MISMATCH: &str = "승인한 내용과 서명할 거래가 다릅니다. 서명하지 않았습니다";
    /// Internal signing check failure.
    pub const SIGN_INTERNAL: &str = "내부 검증에 실패해 서명하지 않았습니다.";
    /// Post-sign verification failure (spec/08 §11.2).
    pub const POST_SIGN: &str = "서명 검증 실패(내부 오류). 거래를 폐기했습니다";
    /// `testmempoolaccept` differs from the local values (spec/08 §11.3).
    pub const PRECHECK_MISMATCH: &str = "노드 검사 결과가 로컬 계산과 다릅니다";
    /// `sendrawtransaction` returned another txid (spec/08 §11.3).
    pub const TXID_MISMATCH: &str = "응답 txid 불일치";
    /// Unknown `reject-reason` token (spec/08 §13).
    pub const UNKNOWN_REJECT: &str = "알 수 없는 거부 사유";
    /// RPC `-25`.
    pub const RPC_MISSING_INPUTS: &str = "입력이 없거나 이미 사용되었습니다";
    /// RPC `-26`.
    pub const RPC_REJECTED: &str = "노드가 거래를 거부했습니다";
    /// `Abandoned` confirmation (spec/08 §12.1).
    pub const ABANDON_CONFIRM: &str = "이미 다른 노드에 퍼졌다면 나중에 확정될 수 있습니다";
}

fn warning(rule: RuleId, text: String) -> Warning {
    Warning {
        rule,
        level: level_of(rule).unwrap_or(RiskLevel::High),
        text,
    }
}

/// A `B` warning of spec/08 §10.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcWarning {
    /// B01.
    FeeUnoverridable,
    /// B02.
    FeeCapBlocked,
    /// B03.
    FeeCapOverridden,
    /// B04.
    FeeRatio,
    /// B05.
    FirstTimeRecipient,
    /// B06: a send-max bump reduces the recipient amount.
    RecipientDecreased,
    /// B06: a send-max leaves `count` UTXOs out (100-input limit).
    UtxosExcluded {
        /// Left-out candidates.
        count: u32,
    },
    /// B07: our own address `m/84'/{coin}'/0'/{chain}/{index}`.
    OwnAddress {
        /// Coin type (0 or 1).
        coin: u32,
        /// Chain.
        chain: BtcChain,
        /// Index.
        index: u32,
    },
    /// B08: P2PKH.
    LegacyRecipient,
    /// B08: P2SH or P2WSH.
    ScriptRecipient,
}

impl BtcWarning {
    /// The rule id.
    #[must_use]
    pub const fn rule(self) -> RuleId {
        match self {
            Self::FeeUnoverridable => B01,
            Self::FeeCapBlocked => B02,
            Self::FeeCapOverridden => B03,
            Self::FeeRatio => B04,
            Self::FirstTimeRecipient => B05,
            Self::RecipientDecreased | Self::UtxosExcluded { .. } => B06,
            Self::OwnAddress { .. } => B07,
            Self::LegacyRecipient | Self::ScriptRecipient => B08,
        }
    }

    /// The fixed text.
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::FeeUnoverridable => texts::FEE_UNOVERRIDABLE.to_owned(),
            Self::FeeCapBlocked => texts::FEE_CAP_BLOCKED.to_owned(),
            Self::FeeCapOverridden => texts::FEE_CAP_OVERRIDDEN.to_owned(),
            Self::FeeRatio => texts::FEE_RATIO.to_owned(),
            Self::FirstTimeRecipient => texts::FIRST_TIME.to_owned(),
            Self::RecipientDecreased => texts::RECIPIENT_DECREASED.to_owned(),
            Self::UtxosExcluded { count } => {
                format!("UTXO {count}개는 포함되지 않음(입력 최대 100개)")
            }
            Self::OwnAddress { coin, chain, index } => format!(
                "이 지갑의 주소입니다 (m/84'/{coin}'/0'/{}/{index})",
                chain.index()
            ),
            Self::LegacyRecipient => texts::LEGACY_RECIPIENT.to_owned(),
            Self::ScriptRecipient => texts::SCRIPT_RECIPIENT.to_owned(),
        }
    }

    /// The display warning (rule, level, text).
    #[must_use]
    pub fn warning(self) -> Warning {
        warning(self.rule(), self.text())
    }
}

/// The `reject-reason` tokens of spec/08 §13 (exact, case-sensitive).
pub const REJECT_TOKENS: [&str; 11] = [
    "min relay fee not met",
    "mempool min fee not met",
    "insufficient fee",
    "txn-mempool-conflict",
    "missing-inputs",
    "bad-txns-inputs-missingorspent",
    "non-final",
    "dust",
    "max-fee-exceeded",
    "txn-already-in-mempool",
    "txn-already-known",
];

/// The static copy of a known `reject-reason` token (what the RPC layer keeps and logs instead
/// of the server string), `None` for anything else.
#[must_use]
pub fn known_reject_token(token: &str) -> Option<&'static str> {
    REJECT_TOKENS.iter().copied().find(|known| *known == token)
}

/// The fixed text of a Core `reject-reason` token (spec/08 §13): exact token match only, anything
/// else is "알 수 없는 거부 사유". The token itself is for logs only.
#[must_use]
pub fn reject_reason_text(token: &str) -> &'static str {
    match token {
        "min relay fee not met" | "mempool min fee not met" => {
            "수수료율이 노드 최소값보다 낮습니다"
        }
        "insufficient fee" => "교체 수수료가 부족합니다",
        "txn-mempool-conflict" => "다른 미확정 거래와 충돌합니다",
        "missing-inputs" | "bad-txns-inputs-missingorspent" => texts::RPC_MISSING_INPUTS,
        "non-final" => "잠금 시간이 아직 지나지 않았습니다(노드 높이 확인)",
        "dust" => "먼지 출력이 있습니다",
        "max-fee-exceeded" => "수수료 상한을 넘었습니다",
        "txn-already-in-mempool" | "txn-already-known" => "이미 전송된 거래입니다",
        _ => texts::UNKNOWN_REJECT,
    }
}

/// The fixed text of a Core JSON-RPC error code (spec/08 §13): `-25`, `-26`, or
/// "RPC 오류(코드 {n})". `error.message` is never shown.
#[must_use]
pub fn rpc_error_text(code: i64) -> String {
    match code {
        -25 => texts::RPC_MISSING_INPUTS.to_owned(),
        -26 => texts::RPC_REJECTED.to_owned(),
        other => format!("RPC 오류(코드 {other})"),
    }
}

/// The local facts the node's answers are compared with (from
/// `verify::VerifiedSignedTx::local`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalTx {
    /// txid (internal order).
    pub txid: Txid,
    /// wtxid (internal order).
    pub wtxid: [u8; 32],
    /// Actual vsize.
    pub vsize: u64,
    /// Fee.
    pub fee: Sats,
}

/// One parsed `testmempoolaccept` result element (the RPC layer checks the array has exactly one
/// element; hashes are parsed from display hex into internal order, `fees.base` with
/// `parse_btc_decimal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolAccept {
    /// `txid`.
    pub txid: Txid,
    /// `wtxid` (internal order).
    pub wtxid: [u8; 32],
    /// `allowed`.
    pub allowed: bool,
    /// `vsize` (present when allowed).
    pub vsize: Option<u64>,
    /// `fees.base` (present when allowed).
    pub fee_base: Option<Sats>,
    /// `reject-reason` token (log only; compared, never shown).
    pub reject_reason: Option<String>,
}

/// The pre-broadcast decision (spec/08 §11.3). A transport error is not a result: the record
/// stays `Signed` and the app offers [다시 시도].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrecheckOutcome {
    /// Allowed and identical to the local values: go to `Broadcasting`.
    Accepted,
    /// `allowed == false` with `txn-already-in-mempool` / `txn-already-known` for our own
    /// `txid` and `wtxid`: the node already has this transaction (mempool or chain), so it is
    /// never `Rejected` (its inputs may be spent by it). The record goes `Signed → Broadcasting →
    /// BroadcastUnknown` (both steps are in the §12.1 table; `Submitted` would claim a send
    /// result, and the dry run gives no `vsize`/`fees.base` to compare) without a send, and
    /// §12.2 tracking moves it to `InMempool`/`Confirmed`.
    AlreadyKnown {
        /// Fixed text ("이미 전송된 거래입니다").
        text: &'static str,
    },
    /// The record becomes `Rejected` with this fixed text.
    Rejected {
        /// Fixed text.
        text: &'static str,
    },
}

/// The `reject-reason` tokens that mean the node already has the transaction.
const ALREADY_KNOWN_TOKENS: [&str; 2] = ["txn-already-in-mempool", "txn-already-known"];

/// Compares a `testmempoolaccept` result with the local transaction: `allowed == false` →
/// [`PrecheckOutcome::AlreadyKnown`] for an already-known token with our `txid` and `wtxid`,
/// else the `reject-reason` text; otherwise `txid`, `wtxid`, `vsize` and `fees.base` must all
/// equal the local values, else "노드 검사 결과가 로컬 계산과 다릅니다".
#[must_use]
pub fn check_mempool_accept(result: &MempoolAccept, local: &LocalTx) -> PrecheckOutcome {
    if !result.allowed {
        if let Some(token) = result
            .reject_reason
            .as_deref()
            .filter(|token| ALREADY_KNOWN_TOKENS.contains(token))
        {
            return if result.txid == local.txid && result.wtxid == local.wtxid {
                PrecheckOutcome::AlreadyKnown {
                    text: reject_reason_text(token),
                }
            } else {
                PrecheckOutcome::Rejected {
                    text: texts::PRECHECK_MISMATCH,
                }
            };
        }
        return PrecheckOutcome::Rejected {
            text: result
                .reject_reason
                .as_deref()
                .map_or(texts::UNKNOWN_REJECT, reject_reason_text),
        };
    }
    if result.txid == local.txid
        && result.wtxid == local.wtxid
        && result.vsize == Some(local.vsize)
        && result.fee_base == Some(local.fee)
    {
        PrecheckOutcome::Accepted
    } else {
        PrecheckOutcome::Rejected {
            text: texts::PRECHECK_MISMATCH,
        }
    }
}

/// What `sendrawtransaction` produced, as parsed by the RPC layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SendRawResult {
    /// A 64-hex txid result.
    Txid(Txid),
    /// A `result` that is not a lowercase 64-hex txid (treated as a different txid).
    NotTxid,
    /// A JSON-RPC error code.
    RpcError {
        /// `error.code`.
        code: i64,
    },
    /// The call deadline passed.
    Timeout,
    /// Transport failure (TLS, connection, HTTP 5xx, 429 abort).
    Transport,
    /// No usable answer that is not a communication failure (HTTP 4xx other than 429, a
    /// malformed envelope) or nothing sent (the chain check before the call failed).
    Refused,
}

/// The journal state after `sendrawtransaction` (spec/08 §11.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// `Submitted` (same txid, or `-27` already in the chain).
    Submitted,
    /// `BroadcastUnknown`, with a fixed note.
    BroadcastUnknown {
        /// Fixed note ("응답 txid 불일치", "RPC 오류(코드 n)") or `None`.
        text: Option<String>,
        /// The last Core send was a communication failure (timeout/transport): the Esplora
        /// manual broadcast may be offered (spec/08 §11.3).
        comm_failure: bool,
    },
    /// `Rejected` (`-25`, `-26`) with the fixed text.
    Rejected {
        /// Fixed text.
        text: String,
    },
}

/// Maps a `sendrawtransaction` result to the next state (spec/08 §11.3).
#[must_use]
pub fn broadcast_outcome(result: &SendRawResult, local_txid: &Txid) -> BroadcastOutcome {
    match result {
        SendRawResult::Txid(txid) if txid == local_txid => BroadcastOutcome::Submitted,
        SendRawResult::Txid(_) | SendRawResult::NotTxid => BroadcastOutcome::BroadcastUnknown {
            text: Some(texts::TXID_MISMATCH.to_owned()),
            comm_failure: false,
        },
        SendRawResult::RpcError { code: -27 } => BroadcastOutcome::Submitted,
        SendRawResult::RpcError {
            code: code @ (-25 | -26),
        } => BroadcastOutcome::Rejected {
            text: rpc_error_text(*code),
        },
        SendRawResult::RpcError { code } => BroadcastOutcome::BroadcastUnknown {
            text: Some(rpc_error_text(*code)),
            comm_failure: false,
        },
        SendRawResult::Timeout | SendRawResult::Transport => BroadcastOutcome::BroadcastUnknown {
            text: None,
            comm_failure: true,
        },
        SendRawResult::Refused => BroadcastOutcome::BroadcastUnknown {
            text: None,
            comm_failure: false,
        },
    }
}
