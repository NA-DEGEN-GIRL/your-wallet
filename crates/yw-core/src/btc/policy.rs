//! BTC policy (spec/08 §10, §11.3, §13): the `B01`–`B08` warning rules (`RuleId` family `'B'`)
//! with their levels and fixed Korean/English texts (spec/14), the fixed error texts, the Core `reject-reason`
//! token table, RPC error texts, and the pure decisions of the pre-broadcast check
//! (`testmempoolaccept`) and of `sendrawtransaction`. Inputs are values the yw-app RPC layer
//! already parsed; no server string is ever returned for display (tokens are compared, never
//! shown).
#![deny(clippy::indexing_slicing)]

use super::amount::Sats;
use super::text as btc_text;
use super::tx::Txid;
use crate::approval::{RiskLevel, RuleId, Warning};
use crate::bip32::path::BtcChain;
use crate::lang::{Lang, Text};

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

/// Fixed texts (spec/08 §10, §12.1, §13): bilingual [`Text`]s of the btc catalogue (`btc::text`,
/// spec/14). 2026-11-14: the `B` warning texts were Korean `&str` before Step 2, the error and
/// confirmation texts before Step 3 (same Korean bytes).
///
/// [`Text`]: crate::lang::Text
pub mod texts {
    use crate::btc::text;
    use crate::lang::Text;

    /// B01.
    pub const FEE_UNOVERRIDABLE: Text = text::B01_FEE_UNOVERRIDABLE;
    /// B02.
    pub const FEE_CAP_BLOCKED: Text = text::B02_FEE_CAP_BLOCKED;
    /// B03.
    pub const FEE_CAP_OVERRIDDEN: Text = text::B03_FEE_CAP_OVERRIDDEN;
    /// B04.
    pub const FEE_RATIO: Text = text::B04_FEE_RATIO;
    /// B05.
    pub const FIRST_TIME: Text = text::B05_FIRST_TIME;
    /// B06 (send-max bump).
    pub const RECIPIENT_DECREASED: Text = text::B06_RECIPIENT_DECREASED;
    /// B08 (P2PKH).
    pub const LEGACY_RECIPIENT: Text = text::B08_LEGACY_RECIPIENT;
    /// B08 (P2SH, P2WSH).
    pub const SCRIPT_RECIPIENT: Text = text::B08_SCRIPT_RECIPIENT;
    /// D20 in-flight refusal (spec/08 §12.1).
    pub const IN_FLIGHT: Text = text::IN_FLIGHT;
    /// A plan input is used by an in-flight journal entry (spec/08 §5).
    pub const INPUT_IN_FLIGHT: Text = text::INPUT_IN_FLIGHT;
    /// The fee-bump target is not replaceable.
    pub const NOT_BUMPABLE: Text = text::NOT_BUMPABLE;
    /// Change derivation failed.
    pub const DERIVATION_FAILED: Text = text::DERIVATION_FAILED;
    /// Plan arithmetic overflow.
    pub const PLAN_OVERFLOW: Text = text::PLAN_OVERFLOW;
    /// `NetworkMismatch` (spec/08 §2, §13).
    pub const NETWORK_MISMATCH: Text = text::NETWORK_MISMATCH;
    /// `KeyMismatch` (spec/08 §3.1, §13).
    pub const KEY_MISMATCH: Text = text::KEY_MISMATCH;
    /// `AmountRecordMismatch` (spec/08 §5, §13).
    pub const AMOUNT_RECORD_MISMATCH: Text = text::AMOUNT_RECORD_MISMATCH;
    /// The approval does not match the plan.
    pub const APPROVAL_MISMATCH: Text = text::APPROVAL_MISMATCH;
    /// Internal signing check failure.
    pub const SIGN_INTERNAL: Text = text::SIGN_INTERNAL;
    /// Post-sign verification failure (spec/08 §11.2).
    pub const POST_SIGN: Text = text::POST_SIGN;
    /// `testmempoolaccept` differs from the local values (spec/08 §11.3).
    pub const PRECHECK_MISMATCH: Text = text::PRECHECK_MISMATCH;
    /// `sendrawtransaction` returned another txid (spec/08 §11.3).
    pub const TXID_MISMATCH: Text = text::TXID_MISMATCH;
    /// Unknown `reject-reason` token (spec/08 §13).
    pub const UNKNOWN_REJECT: Text = text::UNKNOWN_REJECT;
    /// RPC `-25`.
    pub const RPC_MISSING_INPUTS: Text = text::RPC_MISSING_INPUTS;
    /// RPC `-26`.
    pub const RPC_REJECTED: Text = text::RPC_REJECTED;
    /// `Abandoned` confirmation (spec/08 §12.1).
    pub const ABANDON_CONFIRM: Text = text::ABANDON_CONFIRM;
    /// [취소] of a `Signed` record whose bytes were already handed to the RPC (journal flags
    /// bit7, spec/08 §12.1 "공개된 거래").
    pub const CANCEL_DISCLOSED_CONFIRM: Text = text::CANCEL_DISCLOSED_CONFIRM;
    /// The result screen of a `Rejected` record whose bytes the RPC received (spec/08 §12.1).
    pub const REJECTED_DISCLOSED: Text = text::REJECTED_DISCLOSED;
    /// A live abandoned transaction cannot be conflicted by the new send (spec/08 §12.1).
    pub const ABANDONED_NOT_CONFLICTED: Text = text::ABANDONED_NOT_CONFLICTED;
    /// A Core tip at or above 500,000,000 (spec/08 §2 step 2).
    pub const TIP_IMPLAUSIBLE: Text = text::TIP_IMPLAUSIBLE;
    /// The change chain is exhausted (spec/08 §3.2).
    pub const CHANGE_INDEX_EXHAUSTED: Text = text::CHANGE_INDEX_EXHAUSTED;
    /// A planned input is no longer recorded (a refresh during the approval removed it).
    pub const INPUT_NOT_RECORDED: Text = text::INPUT_NOT_RECORDED;
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
    /// B07: our own address `(chain, index)` of the spending account.
    OwnAddress {
        /// The spending account.
        account: super::account::BtcAccountKey,
        /// Network (coin type of the path text).
        network: super::network::BtcNetwork,
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

    /// The fixed text in `lang`.
    #[must_use]
    pub fn text(self, lang: Lang) -> String {
        let fixed = |text: Text| text.get(lang).to_owned();
        match self {
            Self::FeeUnoverridable => fixed(texts::FEE_UNOVERRIDABLE),
            Self::FeeCapBlocked => fixed(texts::FEE_CAP_BLOCKED),
            Self::FeeCapOverridden => fixed(texts::FEE_CAP_OVERRIDDEN),
            Self::FeeRatio => fixed(texts::FEE_RATIO),
            Self::FirstTimeRecipient => fixed(texts::FIRST_TIME),
            Self::RecipientDecreased => fixed(texts::RECIPIENT_DECREASED),
            Self::UtxosExcluded { count } => {
                btc_text::B06_UTXOS_EXCLUDED.fill(lang, [&count.to_string()])
            }
            Self::OwnAddress {
                account,
                network,
                chain,
                index,
            } => btc_text::B07_OWN_ADDRESS.fill(
                lang,
                [&btc_text::path_text(lang, &account, network, chain, index)],
            ),
            Self::LegacyRecipient => fixed(texts::LEGACY_RECIPIENT),
            Self::ScriptRecipient => fixed(texts::SCRIPT_RECIPIENT),
        }
    }

    /// The display warning (rule, level, text) in `lang`.
    #[must_use]
    pub fn warning(self, lang: Lang) -> Warning {
        warning(self.rule(), self.text(lang))
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

/// The fixed text of a Core `reject-reason` token in `lang` (spec/08 §13): exact token match only,
/// anything else is "알 수 없는 거부 사유". The token itself is for logs only.
#[must_use]
pub fn reject_reason_text(lang: Lang, token: &str) -> &'static str {
    match token {
        "min relay fee not met" | "mempool min fee not met" => btc_text::REJECT_MIN_FEE,
        "insufficient fee" => btc_text::REJECT_INSUFFICIENT_FEE,
        "txn-mempool-conflict" => btc_text::REJECT_CONFLICT,
        "missing-inputs" | "bad-txns-inputs-missingorspent" => texts::RPC_MISSING_INPUTS,
        "non-final" => btc_text::REJECT_NON_FINAL,
        "dust" => btc_text::REJECT_DUST,
        "max-fee-exceeded" => btc_text::REJECT_MAX_FEE,
        "txn-already-in-mempool" | "txn-already-known" => btc_text::REJECT_ALREADY_SENT,
        _ => texts::UNKNOWN_REJECT,
    }
    .get(lang)
}

/// The fixed text of a Core JSON-RPC error code in `lang` (spec/08 §13): `-25`, `-26`, or
/// "RPC 오류(코드 {n})". `error.message` is never shown.
#[must_use]
pub fn rpc_error_text(lang: Lang, code: i64) -> String {
    match code {
        -25 => texts::RPC_MISSING_INPUTS.get(lang).to_owned(),
        -26 => texts::RPC_REJECTED.get(lang).to_owned(),
        other => btc_text::RPC_ERROR_CODE.fill(lang, [&other.to_string()]),
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
/// equal the local values, else "노드 검사 결과가 로컬 계산과 다릅니다". Texts are in `lang`.
#[must_use]
pub fn check_mempool_accept(
    lang: Lang,
    result: &MempoolAccept,
    local: &LocalTx,
) -> PrecheckOutcome {
    if !result.allowed {
        if let Some(token) = result
            .reject_reason
            .as_deref()
            .filter(|token| ALREADY_KNOWN_TOKENS.contains(token))
        {
            return if result.txid == local.txid && result.wtxid == local.wtxid {
                PrecheckOutcome::AlreadyKnown {
                    text: reject_reason_text(lang, token),
                }
            } else {
                PrecheckOutcome::Rejected {
                    text: texts::PRECHECK_MISMATCH.get(lang),
                }
            };
        }
        return PrecheckOutcome::Rejected {
            text: result
                .reject_reason
                .as_deref()
                .map_or(texts::UNKNOWN_REJECT.get(lang), |token| {
                    reject_reason_text(lang, token)
                }),
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
            text: texts::PRECHECK_MISMATCH.get(lang),
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
    /// malformed envelope). (A chain check that fails before the call sends nothing: the app
    /// keeps the record `Broadcasting` and never maps it here.)
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

/// Maps a `sendrawtransaction` result to the next state (spec/08 §11.3); texts in `lang`.
#[must_use]
pub fn broadcast_outcome(
    lang: Lang,
    result: &SendRawResult,
    local_txid: &Txid,
) -> BroadcastOutcome {
    match result {
        SendRawResult::Txid(txid) if txid == local_txid => BroadcastOutcome::Submitted,
        SendRawResult::Txid(_) | SendRawResult::NotTxid => BroadcastOutcome::BroadcastUnknown {
            text: Some(texts::TXID_MISMATCH.get(lang).to_owned()),
            comm_failure: false,
        },
        SendRawResult::RpcError { code: -27 } => BroadcastOutcome::Submitted,
        SendRawResult::RpcError {
            code: code @ (-25 | -26),
        } => BroadcastOutcome::Rejected {
            text: rpc_error_text(lang, *code),
        },
        SendRawResult::RpcError { code } => BroadcastOutcome::BroadcastUnknown {
            text: Some(rpc_error_text(lang, *code)),
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
