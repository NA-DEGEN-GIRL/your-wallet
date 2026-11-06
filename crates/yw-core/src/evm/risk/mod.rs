//! Risk rules (spec/03 §10): the rule table and the transaction, typed-data and message rule
//! evaluation. Only E05, E06, E10, E11, E34, E35, T16 and S01–S04 block (§10.4); simulation and
//! gas-estimation problems are high risk (D15).

mod rules;

pub use rules::*;

use super::abi::AbiValue;
use super::address::Address;
use super::amount::{Delta, U256};
use super::chain::ChainInfo;
use super::decode::DecodedCall;
use super::eip712::{DecodedTypedData, HlUserAction, KnownSchema, TdNode};
use super::simulate::{
    ApprovalKindEvm, AssetChange, AssetId, LogEvent, SimResult, is_verified_asset,
};
use super::tx::Eip1559Tx;
use crate::approval::{ApprovalOrigin, ChainFacts, CodeKind, RuleId, Warning};

const THIRTY_DAYS: u64 = 30 * 86_400;
const ONE_DAY: u64 = 86_400;
const HALF_YEAR: u64 = 180 * 86_400;
const MAX_U48: u64 = (1 << 48) - 1;
/// Allowances of at least `2^EFFECTIVELY_UNLIMITED_BITS` are treated as unlimited (E14).
pub const EFFECTIVELY_UNLIMITED_BITS: u16 = 128;

/// Why an allowance counts as unlimited (E14, spec/03 §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unlimited {
    /// Exactly the type maximum.
    Maximum,
    /// At least 2^128.
    Huge,
    /// Above the signing account's known balance of the token.
    AboveBalance,
}

impl Unlimited {
    /// The E14 cause line (none for the exact maximum).
    #[must_use]
    pub const fn cause(self) -> Option<&'static str> {
        match self {
            Self::Maximum => None,
            Self::Huge => Some("2^128 이상의 승인 — 사실상 무제한"),
            Self::AboveBalance => Some("잔액보다 큰 승인 — 사실상 무제한"),
        }
    }
}

/// Whether an allowance is unlimited in effect: the type maximum, at least 2^128, or above the
/// known balance.
#[must_use]
pub fn unlimited_allowance(amount: &U256, max: &U256, balance: Option<U256>) -> Option<Unlimited> {
    if amount == max {
        Some(Unlimited::Maximum)
    } else if !amount.fits_bits(EFFECTIVELY_UNLIMITED_BITS) {
        Some(Unlimited::Huge)
    } else if balance.is_some_and(|balance| *amount > balance) {
        Some(Unlimited::AboveBalance)
    } else {
        None
    }
}

/// Whether a registry-external token claims a registry or native symbol (E19/T20).
fn claims_known_symbol(chain: &ChainInfo, facts: &ChainFacts, token: &Address) -> bool {
    if chain.token(token).is_some() {
        return false;
    }
    let Some(symbol) = facts.token(token).and_then(|meta| meta.symbol.as_deref()) else {
        return false;
    };
    let lowered = symbol.to_ascii_lowercase();
    chain
        .tokens
        .iter()
        .any(|known| known.symbol.to_ascii_lowercase() == lowered)
        || chain.native_symbol.to_ascii_lowercase() == lowered
}

/// Inputs of the transaction rules.
#[derive(Clone, Copy, Debug)]
pub struct TxRiskInput<'a> {
    /// Chain.
    pub chain: &'a ChainInfo,
    /// Origin.
    pub origin: &'a ApprovalOrigin,
    /// Signing account.
    pub account: &'a Address,
    /// Transaction.
    pub tx: &'a Eip1559Tx,
    /// Interpretation after R4.
    pub call: &'a DecodedCall,
    /// R4 left an `approve`/`transferFrom` ambiguous.
    pub r4_unresolved: bool,
    /// Simulation result.
    pub sim: &'a SimResult,
    /// Chain facts.
    pub facts: &'a ChainFacts,
    /// Wall clock.
    pub now_unix_ms: u64,
}

fn now_secs(now_unix_ms: u64) -> u64 {
    now_unix_ms / 1_000
}

fn is_zero(address: &Address) -> bool {
    address.as_bytes() == &[0; 20]
}

fn arg_address(call: &DecodedCall, name: &str) -> Option<Address> {
    match call.arg(name)? {
        AbiValue::Address(address) => Some(*address),
        _ => None,
    }
}

fn arg_uint(call: &DecodedCall, name: &str) -> Option<U256> {
    match call.arg(name)? {
        AbiValue::Uint(value) => Some(*value),
        _ => None,
    }
}

fn arg_bool(call: &DecodedCall, name: &str) -> Option<bool> {
    match call.arg(name)? {
        AbiValue::Bool(value) => Some(*value),
        _ => None,
    }
}

/// Flattens a call and its multicall inner calls.
fn calls(call: &DecodedCall) -> Vec<&DecodedCall> {
    match call {
        DecodedCall::Multicall { inner, .. } => inner.iter().collect(),
        _ => vec![call],
    }
}

/// An approval intent (from logs, or from calldata under R8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalIntent {
    /// Token.
    pub token: Address,
    /// Spender / operator.
    pub spender: Address,
    /// Kind.
    pub kind: ApprovalKindEvm,
}

/// R8: approval intents of the calldata (ambiguous `approve` counts as ERC-20).
#[must_use]
pub fn calldata_approvals(call: &DecodedCall, to: &Address) -> Vec<ApprovalIntent> {
    let mut out = Vec::new();
    for call in calls(call) {
        let Some(kind) = call.kind() else { continue };
        let intent = match kind {
            "erc20_approve" => arg_address(call, "spender").and_then(|spender| {
                let amount = arg_uint(call, "amount")
                    .or_else(|| arg_uint(call, super::decode::AMOUNT_OR_TOKEN_ID))?;
                Some(ApprovalIntent {
                    token: *to,
                    spender,
                    kind: ApprovalKindEvm::Erc20 { amount },
                })
            }),
            "erc721_approve" => arg_address(call, "approved").and_then(|approved| {
                Some(ApprovalIntent {
                    token: *to,
                    spender: approved,
                    kind: ApprovalKindEvm::Erc721 {
                        token_id: arg_uint(call, "token_id")?,
                        revoked: is_zero(&approved),
                    },
                })
            }),
            "erc20_increase_allowance" => arg_address(call, "spender").and_then(|spender| {
                Some(ApprovalIntent {
                    token: *to,
                    spender,
                    kind: ApprovalKindEvm::Erc20 {
                        amount: arg_uint(call, "added")?,
                    },
                })
            }),
            "set_approval_for_all" => arg_address(call, "operator").and_then(|operator| {
                Some(ApprovalIntent {
                    token: *to,
                    spender: operator,
                    kind: ApprovalKindEvm::ForAll {
                        approved: arg_bool(call, "approved")?,
                    },
                })
            }),
            "permit2_approve" => (|| {
                Some(ApprovalIntent {
                    token: arg_address(call, "token")?,
                    spender: arg_address(call, "spender")?,
                    kind: ApprovalKindEvm::Permit2 {
                        amount: arg_uint(call, "amount")?,
                        expiration: arg_uint(call, "expiration")?.to_u64()?,
                    },
                })
            })(),
            "permit2_lockdown" => {
                if let Some(AbiValue::Array(pairs)) = call.arg("pairs") {
                    for pair in pairs {
                        if let AbiValue::Tuple(items) = pair
                            && let [AbiValue::Address(token), AbiValue::Address(spender)] =
                                items.as_slice()
                        {
                            out.push(ApprovalIntent {
                                token: *token,
                                spender: *spender,
                                kind: ApprovalKindEvm::Permit2Lockdown,
                            });
                        }
                    }
                }
                None
            }
            _ => None,
        };
        out.extend(intent);
    }
    out
}

fn approval_intents(input: &TxRiskInput<'_>) -> Vec<ApprovalIntent> {
    match input.sim.diff() {
        Some(diff) => diff
            .approvals
            .iter()
            .map(|change| ApprovalIntent {
                token: change.asset,
                spender: change.spender,
                kind: change.kind,
            })
            .collect(),
        None => calldata_approvals(input.call, &input.tx.to),
    }
}

/// R6: whether an interpreted intent is confirmed by a log of the same class and addresses.
fn r6_confirmed(call: &DecodedCall, input: &TxRiskInput<'_>, events: &[LogEvent]) -> bool {
    let to = input.tx.to;
    let user = *input.account;
    let Some(kind) = call.kind() else {
        return true;
    };
    let address = |name| arg_address(call, name);
    let uint = |name| arg_uint(call, name);
    match kind {
        "erc20_transfer" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc20Transfer { token, from, to: dst, amount }
                if *token == to && *from == user && Some(*dst) == address("to")
                    && Some(*amount) == uint("amount"))
        }),
        "erc20_transfer_from" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc20Transfer { token, from, to: dst, amount }
                if *token == to && Some(*from) == address("from") && Some(*dst) == address("to")
                    && Some(*amount) == uint("amount"))
        }),
        "erc721_transfer_from" | "erc721_safe_transfer" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc721Transfer { token, from, to: dst, .. }
                if *token == to && Some(*from) == address("from") && Some(*dst) == address("to"))
        }),
        "erc1155_safe_transfer" | "erc1155_safe_batch_transfer" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc1155Transfer { token, from, to: dst, .. }
                if *token == to && Some(*from) == address("from") && Some(*dst) == address("to"))
        }),
        "erc20_approve" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc20Approval { token, owner, spender, amount }
                if *token == to && *owner == user && Some(*spender) == address("spender")
                    && Some(*amount) == uint("amount"))
        }),
        "erc20_increase_allowance" | "erc20_decrease_allowance" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc20Approval { token, owner, spender, .. }
                if *token == to && *owner == user && Some(*spender) == address("spender"))
        }),
        "erc721_approve" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc721Approval { token, approved, .. }
                if *token == to && Some(*approved) == address("approved"))
        }),
        "set_approval_for_all" => events.iter().any(|event| {
            matches!(event, LogEvent::ApprovalForAll { token, owner, operator, .. }
                if *token == to && *owner == user && Some(*operator) == address("operator"))
        }),
        "weth_deposit" => events.iter().any(|event| {
            matches!(event, LogEvent::WethDeposit { token, dst, wad }
                if *token == to && *dst == user && *wad == input.tx.value)
        }),
        "weth_withdraw" => events.iter().any(|event| {
            matches!(event, LogEvent::WethWithdrawal { token, src, wad }
                if *token == to && *src == user && Some(*wad) == uint("amount"))
        }),
        "permit2_approve" => events.iter().any(|event| {
            matches!(event, LogEvent::Permit2Approval { owner, token, spender, .. }
                if *owner == user && Some(*token) == address("token")
                    && Some(*spender) == address("spender"))
        }),
        "permit2_lockdown" => calldata_approvals(call, &to).iter().all(|intent| {
            events.iter().any(|event| {
                matches!(event, LogEvent::Permit2Lockdown { owner, token, spender }
                    if *owner == user && *token == intent.token && *spender == intent.spender)
            })
        }),
        "erc2612_permit_submit" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc20Approval { token, owner, spender, .. }
                if *token == to && Some(*owner) == address("owner")
                    && Some(*spender) == address("spender"))
        }),
        "dai_permit_submit" => events.iter().any(|event| {
            matches!(event, LogEvent::Erc20Approval { token, owner, spender, .. }
                if *token == to && Some(*owner) == address("holder")
                    && Some(*spender) == address("spender"))
        }),
        _ => true,
    }
}

/// Unregistered NFT collections of the diff (E33 only: no symbol/decimals rules).
fn involved_collections(input: &TxRiskInput<'_>) -> Vec<Address> {
    let mut collections = Vec::new();
    if let Some(diff) = input.sim.diff() {
        for change in &diff.changes {
            if let AssetId::Token(token) = change.asset
                && change.token_id.is_some()
                && input.chain.token(&token).is_none()
                && !collections.contains(&token)
            {
                collections.push(token);
            }
        }
    }
    collections
}

fn involved_tokens(input: &TxRiskInput<'_>) -> Vec<Address> {
    let mut tokens = Vec::new();
    let mut push = |token: Address| {
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    };
    if calls(input.call).iter().any(|call| {
        call.kind()
            .is_some_and(|kind| kind.starts_with("erc20_") || kind.ends_with("permit_submit"))
    }) {
        push(input.tx.to);
    }
    if let Some(diff) = input.sim.diff() {
        for change in &diff.changes {
            if let AssetId::Token(token) = change.asset
                && change.token_id.is_none()
            {
                push(token);
            }
        }
        for approval in &diff.approvals {
            if matches!(
                approval.kind,
                ApprovalKindEvm::Erc20 { .. }
                    | ApprovalKindEvm::Permit2 { .. }
                    | ApprovalKindEvm::Permit2Lockdown
            ) {
                push(approval.asset);
            }
        }
    }
    for intent in calldata_approvals(input.call, &input.tx.to) {
        if matches!(intent.kind, ApprovalKindEvm::Permit2 { .. }) {
            push(intent.token);
        }
    }
    tokens
}

/// Transaction rules E12–E33 from interpretation, simulation and facts (spec/03 §10.2).
#[must_use]
#[expect(clippy::too_many_lines, reason = "one block per rule of spec/03 §10.2")]
pub fn tx_rules(input: &TxRiskInput<'_>) -> Vec<Warning> {
    let mut warnings = Vec::new();
    let chain = input.chain;
    let facts = input.facts;
    let tx = input.tx;

    // E12
    if input.call.has_uninterpreted() {
        let cause = match input.call {
            DecodedCall::Multicall { inner, .. } if inner.is_empty() => {
                Some("내부 호출이 없는 묶음 호출")
            }
            DecodedCall::Multicall { .. } => Some("해석되지 않은 호출 포함"),
            _ => None,
        };
        warnings.push(warning(E12, cause));
    }
    // E13 (R4/R6, only with usable logs)
    if let Some(events) = input.sim.events() {
        if input.r4_unresolved {
            warnings.push(warning(
                E13,
                Some("시뮬레이션 로그로 토큰 종류(ERC-20/ERC-721)를 정할 수 없습니다"),
            ));
        }
        let unconfirmed = calls(input.call)
            .into_iter()
            .any(|call| !r6_confirmed(call, input, events));
        if unconfirmed {
            warnings.push(warning(
                E13,
                Some("해석한 승인·이동이 시뮬레이션 로그에 없거나 다릅니다"),
            ));
        }
    }
    // Approvals: E14, E15, E16, E20, E21, E22, E30, E39
    let now = now_secs(input.now_unix_ms);
    let allowance = |amount: &U256, max: &U256, token: &Address| match unlimited_allowance(
        amount,
        max,
        facts.balance(token),
    ) {
        Some(unlimited) => warning(E14, unlimited.cause()),
        None => warning(E20, None),
    };
    for intent in approval_intents(input) {
        let revocation = match intent.kind {
            ApprovalKindEvm::Erc20 { amount } => {
                if !amount.is_zero() {
                    warnings.push(allowance(&amount, &U256::MAX, &intent.token));
                }
                amount.is_zero()
            }
            ApprovalKindEvm::Erc721 { revoked, .. } => {
                if !revoked {
                    warnings.push(warning(E20, None));
                }
                revoked
            }
            ApprovalKindEvm::ForAll { approved } => {
                if approved {
                    warnings.push(warning(E15, None));
                }
                !approved
            }
            ApprovalKindEvm::Permit2 { amount, expiration } => {
                if !amount.is_zero() {
                    warnings.push(allowance(&amount, &U256::MAX_U160, &intent.token));
                }
                if expiration == MAX_U48 || expiration > now.saturating_add(THIRTY_DAYS) {
                    warnings.push(warning(E22, None));
                }
                amount.is_zero()
            }
            ApprovalKindEvm::Permit2Lockdown => true,
        };
        if revocation {
            warnings.push(warning(E30, None));
            continue;
        }
        let registered = chain.label(&intent.spender).is_some();
        match facts.code_of(&intent.spender) {
            Some(CodeKind::Eoa | CodeKind::Delegated7702 { .. }) => {
                warnings.push(warning(E16, None));
            }
            Some(CodeKind::Contract) if !registered => {
                warnings.push(warning(E21, None));
            }
            // A failed lookup must not hide an EOA spender (fail closed, spec/03 §8.5).
            Some(CodeKind::Unknown) if !registered => {
                warnings.push(warning(E39, None));
            }
            _ => {}
        }
    }
    // E17
    match facts.account_code {
        CodeKind::Eoa => {}
        CodeKind::Unknown => {
            warnings.push(warning(E17, Some("서명 계정의 코드를 확인할 수 없습니다")));
        }
        CodeKind::Contract | CodeKind::Delegated7702 { .. } => {
            warnings.push(warning(E17, None));
        }
    }
    // E18
    let mut zero_or_self = !tx.value.is_zero() && tx.data.is_empty() && is_zero(&tx.to);
    for call in calls(input.call) {
        if let Some(recipient) = arg_address(call, "to")
            && call.kind().is_some_and(|kind| kind.contains("transfer"))
            && (is_zero(&recipient) || recipient == tx.to)
        {
            zero_or_self = true;
        }
    }
    if let Some(diff) = input.sim.diff() {
        for row in &diff.transfers {
            let to_self_token = matches!(row.asset, AssetId::Token(token) if token == row.to);
            if row.from == *input.account && (is_zero(&row.to) || to_self_token) {
                zero_or_self = true;
            }
        }
    }
    if zero_or_self {
        warnings.push(warning(E18, None));
    }
    // E19, E25, E26, E33
    for token in involved_tokens(input) {
        if chain.token(&token).is_some() {
            continue;
        }
        let meta = facts.token(&token);
        if meta.and_then(|meta| meta.symbol.as_deref()).is_none() {
            warnings.push(warning(E26, None));
        } else if claims_known_symbol(chain, facts, &token) {
            warnings.push(warning(E19, None));
        }
        if meta.and_then(|meta| meta.decimals).is_none() {
            warnings.push(warning(E25, None));
        }
        warnings.push(warning(E33, None));
    }
    if !involved_collections(input).is_empty() {
        warnings.push(warning(E33, None));
    }
    // E23, E40: only the native asset and registry tokens count as received — any contract can
    // emit a Transfer log naming the user (spec/03 §6.4).
    if let Some(diff) = input.sim.diff() {
        let verified = |change: &AssetChange| {
            is_verified_asset(chain, &change.asset, change.token_id.as_ref())
        };
        let sending = |change: &&AssetChange| matches!(change.delta, Some(Delta::Out(_)) | None);
        let receiving = |change: &&AssetChange| matches!(change.delta, Some(Delta::In(_)));
        let sends = diff.changes.iter().any(|change| sending(&change));
        let verified_sends = diff.changes.iter().filter(sending).any(&verified);
        let verified_receipts = diff.changes.iter().filter(receiving).any(&verified);
        let unverified_receipts = diff
            .changes
            .iter()
            .filter(receiving)
            .any(|change| !verified(change));
        if matches!(input.origin, ApprovalOrigin::Site(_)) && sends && !verified_receipts {
            let cause = unverified_receipts.then_some("받는 자산은 등록되지 않은 토큰·NFT뿐입니다");
            warnings.push(warning(E23, cause));
        }
        if verified_sends && unverified_receipts {
            warnings.push(warning(E40, None));
        }
    }
    // E24
    if tx.to == *input.account && !tx.data.is_empty() {
        warnings.push(warning(E24, None));
    }
    // E28
    if matches!(input.origin, ApprovalOrigin::App) {
        let recipient = match input.call {
            DecodedCall::NativeTransfer => Some(tx.to),
            call if call.kind() == Some("erc20_transfer") => arg_address(call, "to"),
            _ => None,
        };
        if let Some(recipient) = recipient
            && facts.book_name(&recipient).is_none()
        {
            warnings.push(warning(E28, None));
        }
    }
    // E29
    if matches!(input.call, DecodedCall::NativeTransfer)
        && facts.code_of(&tx.to) == Some(CodeKind::Contract)
    {
        warnings.push(warning(E29, None));
    }
    // E32
    if let Some(diff) = input.sim.diff()
        && diff.other_events > 0
    {
        warnings.push(warning_text(
            E32,
            format!("기타 이벤트 {}개", diff.other_events),
        ));
    }
    warnings
}

/// Inputs of the typed-data rules.
#[derive(Clone, Copy, Debug)]
pub struct TypedRiskInput<'a> {
    /// Chain.
    pub chain: &'a ChainInfo,
    /// Signing account.
    pub account: &'a Address,
    /// Validated typed data.
    pub typed: &'a DecodedTypedData,
    /// Chain facts.
    pub facts: &'a ChainFacts,
    /// Wall clock.
    pub now_unix_ms: u64,
}

fn deadline_t12(deadline: Option<U256>, now: u64, zero_is_none: bool) -> bool {
    let Some(deadline) = deadline else {
        return false;
    };
    if deadline == U256::MAX || (zero_is_none && deadline.is_zero()) {
        return true;
    }
    match deadline.to_u64() {
        Some(seconds) => seconds <= now || seconds > now.saturating_add(THIRTY_DAYS),
        None => true,
    }
}

/// T09 for an EOA/delegated spender, T18 when its classification failed (fail closed).
fn spender_rule(chain: &ChainInfo, facts: &ChainFacts, spender: Option<Address>) -> Option<RuleId> {
    let spender = spender?;
    match facts.code_of(&spender) {
        Some(CodeKind::Eoa | CodeKind::Delegated7702 { .. }) => Some(T09),
        Some(CodeKind::Unknown) if chain.label(&spender).is_none() => Some(T18),
        _ => None,
    }
}

/// Seaport item types counted as "received" (T08): native (0) and registry ERC-20 (1).
fn seaport_item_verified(chain: &ChainInfo, item: &TdNode) -> bool {
    match item
        .field("itemType")
        .and_then(TdNode::uint)
        .and_then(U256::to_u64)
    {
        Some(0) => true,
        Some(1) => item
            .field("token")
            .and_then(TdNode::address)
            .is_some_and(|token| chain.token(&token).is_some()),
        _ => false,
    }
}

/// ERC-20 tokens named by a recognized typed-data schema (T20 candidates).
fn typed_tokens(typed: &DecodedTypedData) -> Vec<Address> {
    let root = &typed.root;
    let mut tokens = Vec::new();
    let mut push = |token: Option<Address>| {
        if let Some(token) = token
            && !tokens.contains(&token)
        {
            tokens.push(token);
        }
    };
    let token_of = |node: &TdNode| node.field("token").and_then(TdNode::address);
    let items = |name: &str| -> Vec<&TdNode> {
        match root.field(name) {
            Some(TdNode::Array(items)) => items.iter().collect(),
            Some(node) => vec![node],
            None => Vec::new(),
        }
    };
    match &typed.schema {
        Some(KnownSchema::Eip2612Permit | KnownSchema::DaiPermit) => {
            push(typed.domain.verifying_contract);
        }
        Some(KnownSchema::Permit2Single | KnownSchema::Permit2Batch) => {
            for detail in items("details") {
                push(token_of(detail));
            }
        }
        Some(
            KnownSchema::Permit2Transfer
            | KnownSchema::Permit2BatchTransfer
            | KnownSchema::Permit2WitnessTransfer { .. }
            | KnownSchema::Permit2BatchWitnessTransfer { .. },
        ) => {
            for permitted in items("permitted") {
                push(token_of(permitted));
            }
        }
        Some(KnownSchema::SeaportOrder) => {
            for item in items("offer").into_iter().chain(items("consideration")) {
                let fungible = item
                    .field("itemType")
                    .and_then(TdNode::uint)
                    .and_then(U256::to_u64)
                    == Some(1);
                if fungible {
                    push(token_of(item));
                }
            }
        }
        Some(KnownSchema::HyperliquidUser(_) | KnownSchema::HyperliquidL1Agent) | None => {}
    }
    tokens
}

/// Typed-data rules T03–T15 and T17–T20 (T16 is added by the display builder).
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one block per schema of spec/03 §10.3"
)]
pub fn typed_rules(input: &TypedRiskInput<'_>, hidden_characters: bool) -> Vec<Warning> {
    let mut warnings = Vec::new();
    let typed = input.typed;
    let root = &typed.root;
    let now = now_secs(input.now_unix_ms);
    let account = *input.account;
    let field_address = |node: &TdNode, name: &str| node.field(name).and_then(TdNode::address);
    let field_uint = |node: &TdNode, name: &str| node.field(name).and_then(TdNode::uint);
    let spender = |address: Option<Address>| {
        spender_rule(input.chain, input.facts, address).map(|rule| warning(rule, None))
    };

    if typed.domain.chain_id.is_none() {
        warnings.push(warning(T03, None));
    }
    match &typed.schema {
        None => warnings.push(warning(T04, None)),
        Some(schema) => match schema {
            KnownSchema::Eip2612Permit => {
                warnings.push(warning(T05, None));
                if field_address(root, "owner") != Some(account) {
                    warnings.push(warning(T07, None));
                }
                warnings.extend(spender(field_address(root, "spender")));
                if deadline_t12(field_uint(root, "deadline"), now, false) {
                    warnings.push(warning(T12, None));
                }
            }
            KnownSchema::DaiPermit => {
                let allowed = root.field("allowed").and_then(TdNode::boolean);
                if allowed == Some(true) {
                    warnings.push(warning(T05, None));
                } else {
                    warnings.push(warning(T15, None));
                }
                if field_address(root, "holder") != Some(account) {
                    warnings.push(warning(T07, None));
                }
                warnings.extend(spender(field_address(root, "spender")));
                if allowed == Some(true) && deadline_t12(field_uint(root, "expiry"), now, true) {
                    warnings.push(warning(T12, None));
                }
            }
            KnownSchema::Permit2Single | KnownSchema::Permit2Batch => {
                warnings.push(warning(T05, None));
                warnings.extend(spender(field_address(root, "spender")));
                let details: Vec<&TdNode> = match root.field("details") {
                    Some(TdNode::Array(items)) => items.iter().collect(),
                    Some(node) => vec![node],
                    None => Vec::new(),
                };
                let expiry_risky = details.iter().any(|detail| {
                    field_uint(detail, "expiration").is_some_and(|expiration| {
                        (!expiration.is_zero() && deadline_t12(Some(expiration), now, false))
                            || expiration == U256::from_u64(MAX_U48)
                    })
                });
                let sig_deadline = field_uint(root, "sigDeadline");
                if expiry_risky
                    || sig_deadline
                        .and_then(U256::to_u64)
                        .is_some_and(|deadline| deadline <= now)
                {
                    warnings.push(warning(T12, None));
                }
                if sig_deadline.is_some_and(|deadline| {
                    deadline
                        .to_u64()
                        .is_none_or(|deadline| deadline > now.saturating_add(ONE_DAY))
                }) {
                    warnings.push(warning(T13, None));
                }
            }
            KnownSchema::Permit2Transfer
            | KnownSchema::Permit2BatchTransfer
            | KnownSchema::Permit2WitnessTransfer { .. }
            | KnownSchema::Permit2BatchWitnessTransfer { .. } => {
                let witness = matches!(
                    schema,
                    KnownSchema::Permit2WitnessTransfer { .. }
                        | KnownSchema::Permit2BatchWitnessTransfer { .. }
                );
                warnings.push(warning(if witness { T06 } else { T05 }, None));
                warnings.extend(spender(field_address(root, "spender")));
                if deadline_t12(field_uint(root, "deadline"), now, false) {
                    warnings.push(warning(T12, None));
                }
            }
            KnownSchema::HyperliquidUser(action) => {
                warnings.push(warning(
                    match action {
                        HlUserAction::Transfer(_) => H01,
                        HlUserAction::ApproveAgent => H06,
                        HlUserAction::ApproveBuilderFee => H08,
                    },
                    None,
                ));
                if root.field("hyperliquidChain").and_then(TdNode::string) == Some("Testnet") {
                    warnings.push(warning(H09, None));
                }
            }
            KnownSchema::HyperliquidL1Agent => {
                warnings.push(warning(H07, None));
                if root.field("source").and_then(TdNode::string) == Some("b") {
                    warnings.push(warning(H09, None));
                }
            }
            KnownSchema::SeaportOrder => {
                let offer = root
                    .field("offer")
                    .and_then(TdNode::elements)
                    .unwrap_or(&[]);
                if field_address(root, "offerer") == Some(account) {
                    // Signing hands the offer to whoever fulfils the order (T19).
                    if !offer.is_empty() {
                        warnings.push(warning(T19, None));
                    }
                } else {
                    warnings.push(warning(T07, None));
                }
                let consideration = root
                    .field("consideration")
                    .and_then(TdNode::elements)
                    .unwrap_or(&[]);
                let mine: Vec<&TdNode> = consideration
                    .iter()
                    .filter(|item| field_address(item, "recipient") == Some(account))
                    .collect();
                // Only native or registry ERC-20 consideration counts as received (T08).
                if !mine
                    .iter()
                    .any(|item| seaport_item_verified(input.chain, item))
                {
                    let cause =
                        (!mine.is_empty()).then_some("받는 것이 등록되지 않은 토큰·NFT뿐입니다");
                    warnings.push(warning(T08, cause));
                }
                let end = field_uint(root, "endTime");
                if end.and_then(U256::to_u64).is_some_and(|end| end <= now) {
                    warnings.push(warning(T12, None));
                }
                if end.is_some_and(|end| {
                    end.to_u64()
                        .is_none_or(|end| end > now.saturating_add(HALF_YEAR))
                }) {
                    warnings.push(warning(T13, None));
                }
                let criteria = offer.iter().chain(consideration).any(|item| {
                    matches!(
                        field_uint(item, "itemType").and_then(U256::to_u64),
                        Some(4 | 5)
                    ) && field_uint(item, "identifierOrCriteria").is_some_and(|id| id.is_zero())
                });
                let contract_order =
                    field_uint(root, "orderType").and_then(U256::to_u64) == Some(4);
                if criteria || contract_order {
                    warnings.push(warning(T14, None));
                }
            }
        },
    }
    // T20: the typed-data form of E19.
    if typed_tokens(typed)
        .iter()
        .any(|token| claims_known_symbol(input.chain, input.facts, token))
    {
        warnings.push(warning(T20, None));
    }
    let hyperliquid = matches!(
        typed.schema,
        Some(KnownSchema::HyperliquidUser(_) | KnownSchema::HyperliquidL1Agent)
    );
    match typed.domain.verifying_contract {
        // Hyperliquid signs with a zero verifying contract by design (spec/11 §7).
        None if hyperliquid => {}
        None => warnings.push(warning(T10, None)),
        Some(contract) => {
            if input.facts.code_of(&contract) == Some(CodeKind::Eoa) {
                warnings.push(warning(T11, None));
            }
        }
    }
    if hidden_characters {
        warnings.push(warning(T17, None));
    }
    warnings
}
