//! Approval titles and display-field builders for EVM requests (spec/03 §7.3, §8.3–§8.4, §9.2,
//! §11.1–§11.2).
//!
//! Derived from `archive/spec-v2.4:crates/wallet-protocol/src/authorization.rs:36-325,470-837`
//! (field derivation) and `archive/spec-v2.4:crates/approval-wire/src/lib.rs:231-777` (display
//! model) with v3 changes: decimal units instead of wei hex, no 512/1023-byte rejection (values
//! scroll), typed data allowed, simulation diff and simulation-state warnings added.

pub(crate) mod time;

use core::fmt::Write as _;

use super::abi::AbiValue;
use super::address::{Address, to_checksum};
use super::amount::{Delta, U256, format_amount, format_gwei, format_units};
use super::chain::{ChainInfo, OPENSEA_CONDUIT_KEY};
use super::decode::{AMOUNT_OR_TOKEN_ID, DecodedCall, DecodedTx, resolve_token_standard};
use super::eip191::{DecodedPersonalMessage, HexReason, personal_preimage};
use super::eip712::{DecodedTypedData, KnownSchema, TdNode, TdValue};
use super::fee::{expected_fee, max_total_fee};
use super::risk::{
    self, P01, P02, P03, P04, T16, TxRiskInput, TypedRiskInput, sort_warnings, tx_rules,
    typed_rules,
};
use super::simulate::{ApprovalChange, ApprovalKindEvm, AssetChange, AssetId, SimResult};
use super::siwe::{SiweContext, check_marker_only, check_siwe};
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin,
    ChainFacts, ChainRef, CodeKind, DisplayError, DisplayField, FieldKey, MAX_DISPLAY_FIELDS,
    MAX_DISPLAY_WARNINGS, MAX_TITLE_BYTES, Signer, SigningPayload, SimNoneReason,
    SimulationBinding, Warning, escape_edges, escape_untrusted,
};
use crate::vault::EvmKeySource;
use time::{format_utc, format_utc_relative};

const TREE_MAX_DEPTH: usize = 8;
const TREE_MAX_LEAVES: usize = 512;
const TREE_MAX_STRING: usize = 1_024;
const TREE_MAX_BYTES: usize = 1_024;
const NO_EXPIRY_SECONDS: u64 = 1 << 40;

/// `0x5aAe b605 3F3E …`: EIP-55 checksum in groups of four (spec/03 §2.2).
#[must_use]
pub fn format_address(address: &Address) -> String {
    let checksum = to_checksum(address);
    let digits: Vec<char> = checksum.chars().skip(2).collect();
    let mut out = String::with_capacity(52);
    out.push_str("0x");
    for (index, chunk) in digits.chunks(4).enumerate() {
        if index != 0 {
            out.push(' ');
        }
        out.extend(chunk.iter());
    }
    out
}

/// Escapes untrusted text for a one-line label (LF becomes `[U+000A]`).
fn escape_inline(text: &str) -> (String, bool) {
    let escaped = escape_untrusted(text);
    (escaped.text.replace('\n', "[U+000A]"), escaped.hidden)
}

/// Escapes a whole untrusted single-line value (typed-data strings, SIWE statement) so it is a
/// valid display string (non-empty, no edges). LF becomes `[U+000A]`: a line break inside the
/// value must not pass for another `path = value` row (spec/03 §9.2).
fn escape_value(text: &str) -> (String, bool) {
    let (inline, hidden) = escape_inline(text);
    let value = escape_edges(&inline);
    if value.is_empty() {
        ("(빈 문자열)".to_owned(), hidden)
    } else {
        (value, hidden)
    }
}

/// A multi-line message value: edges escaped, and every inner LF marked `[U+000A]` before the
/// break so a message line is visibly part of the message, never a separate row.
fn message_value(escaped_text: &str) -> String {
    let value = escape_edges(escaped_text);
    if value.is_empty() {
        "(빈 메시지)".to_owned()
    } else {
        value.replace('\n', "[U+000A]\n")
    }
}

/// Address with registry label, classification and address-book label (spec/03 §2.2, §8.5).
#[must_use]
pub fn describe_address(chain: &ChainInfo, facts: &ChainFacts, address: &Address) -> String {
    let mut out = format_address(address);
    if let Some(label) = chain.label(address) {
        out.push_str(" [");
        out.push_str(label);
        out.push(']');
    } else {
        match facts.code_of(address) {
            Some(CodeKind::Contract) => out.push_str(" [컨트랙트]"),
            Some(CodeKind::Eoa) => out.push_str(" [일반 계정(EOA)]"),
            Some(CodeKind::Delegated7702 { target }) => {
                out.push_str(" [위임된 계정(EIP-7702) → ");
                out.push_str(&format_address(&target));
                out.push(']');
            }
            Some(CodeKind::Unknown) => out.push_str(" [계정 종류 확인 불가]"),
            None => {}
        }
    }
    if let Some(name) = facts.book_name(address) {
        out.push_str(" [주소록: ");
        out.push_str(&escape_inline(name).0);
        out.push(']');
    }
    out
}

/// Token amount with trusted or unverified metadata (spec/03 §2.5). Decimals of an unregistered
/// token come from its own contract via RPC, so they never shape the primary amount: the raw
/// integer leads exactly as when decimals are unknown, and the RPC-scaled value follows as a
/// labelled hint (security review L10) — an unregistered token never looks like a registered
/// `1,000,000 USDC`.
#[must_use]
pub fn format_token_amount(
    chain: &ChainInfo,
    facts: &ChainFacts,
    token: &Address,
    amount: &U256,
) -> String {
    if let Some(known) = chain.token(token) {
        return format_amount(amount, known.decimals, known.symbol);
    }
    let meta = facts.token(token);
    // Symbols come from RPC via yw-app; escape defensively (X-20) even though the §2.5 decoder
    // only admits 0x21–0x7E.
    let symbol = meta
        .and_then(|meta| meta.symbol.as_deref())
        .map_or_else(|| "?".to_owned(), |symbol| escape_inline(symbol).0);
    let raw = format_units(amount, 0);
    match meta.and_then(|meta| meta.decimals) {
        Some(decimals) => format!(
            "{raw} (원시 단위) {symbol} (미확인 · decimals {decimals} 적용 시 {})",
            format_units(amount, decimals)
        ),
        None => format!("{raw} (원시 단위) {symbol} (미확인)"),
    }
}

fn native_amount(chain: &ChainInfo, amount: &U256) -> String {
    format_amount(amount, chain.native_decimals, &chain.native_symbol)
}

/// Time display: `YYYY-MM-DD HH:MM:SS UTC (약 N일 후/전)`; ≥ 2^40 → raw + "사실상 만료 없음".
#[must_use]
pub fn format_time(value: &U256, now_unix_ms: u64) -> String {
    match value.to_u64() {
        Some(seconds) if seconds < NO_EXPIRY_SECONDS => {
            format_utc_relative(i64::try_from(seconds).unwrap_or(i64::MAX), now_unix_ms)
        }
        _ => format!("{} (사실상 만료 없음)", value.to_decimal_string()),
    }
}

fn hex_with_len(bytes: &[u8]) -> String {
    format!("0x{} ({}바이트)", crate::hex::encode(bytes), bytes.len())
}

fn substitute(title: &str, chain: &ChainInfo) -> String {
    let wrapped = chain.weth().map_or("?", |token| token.symbol);
    title
        .replace("{native}", &chain.native_symbol)
        .replace("{wrapped}", wrapped)
}

struct Ctx<'a> {
    chain: &'a ChainInfo,
    facts: &'a ChainFacts,
    to: Address,
    now_unix_ms: u64,
}

impl Ctx<'_> {
    fn address(&self, address: &Address) -> String {
        describe_address(self.chain, self.facts, address)
    }

    /// An amount; for allowances (`unlimited` = the type maximum) the maximum is "무제한" and
    /// any value of at least 2^128 is marked "사실상 무제한" (E14).
    fn token_amount(&self, token: &Address, amount: &U256, unlimited: Option<U256>) -> String {
        if unlimited == Some(*amount) {
            return "무제한".to_owned();
        }
        let text = format_token_amount(self.chain, self.facts, token, amount);
        if unlimited.is_some() && !amount.fits_bits(risk::EFFECTIVELY_UNLIMITED_BITS) {
            format!("{text} (사실상 무제한)")
        } else {
            text
        }
    }

    fn uint_arg(&self, call: &DecodedCall, kind: &str, name: &str, value: &U256) -> String {
        let token_of = |arg: &str| match call.arg(arg) {
            Some(AbiValue::Address(token)) => Some(*token),
            _ => None,
        };
        match (kind, name) {
            ("erc20_transfer" | "erc20_transfer_from" | "weth_withdraw", "amount")
            | ("erc20_increase_allowance", "added")
            | ("erc20_decrease_allowance", "subtracted") => {
                self.token_amount(&self.to, value, None)
            }
            ("erc20_approve", "amount") | ("erc2612_permit_submit", "value") => {
                self.token_amount(&self.to, value, Some(U256::MAX))
            }
            ("permit2_approve", "amount") => match token_of("token") {
                Some(token) => self.token_amount(&token, value, Some(U256::MAX_U160)),
                None => value.to_decimal_string(),
            },
            ("permit2_approve", "expiration") => permit2_expiration(value, self.now_unix_ms),
            ("dai_permit_submit", "expiry") if value.is_zero() => "만료 없음".to_owned(),
            (_, "deadline" | "expiry") => format_time(value, self.now_unix_ms),
            (_, AMOUNT_OR_TOKEN_ID) => format!("{} (금액 또는 토큰 ID)", value.to_decimal_string()),
            _ => value.to_decimal_string(),
        }
    }

    fn arg(&self, call: &DecodedCall, kind: &str, name: &str, value: &AbiValue) -> String {
        match value {
            AbiValue::Address(address) => self.address(address),
            AbiValue::Uint(number) => self.uint_arg(call, kind, name, number),
            AbiValue::Bool(true) => "예".to_owned(),
            AbiValue::Bool(false) => "아니오".to_owned(),
            AbiValue::Bytes(bytes) => hex_with_len(bytes),
            AbiValue::Bytes32(bytes) => format!("0x{}", crate::hex::encode(bytes)),
            AbiValue::Array(items) if items.is_empty() => "(없음)".to_owned(),
            AbiValue::Array(items) => items
                .iter()
                .map(|item| self.arg(call, kind, name, item))
                .collect::<Vec<_>>()
                .join("\n"),
            AbiValue::Tuple(items) => items
                .iter()
                .map(|item| self.arg(call, kind, name, item))
                .collect::<Vec<_>>()
                .join(" → "),
        }
    }
}

fn permit2_expiration(value: &U256, now_unix_ms: u64) -> String {
    if value.is_zero() {
        "사용 블록에서만 유효".to_owned()
    } else if value.to_u64() == Some((1 << 48) - 1) {
        "만료 없음".to_owned()
    } else {
        format_time(value, now_unix_ms)
    }
}

fn call_title(call: &DecodedCall, chain: &ChainInfo) -> String {
    match call {
        DecodedCall::NativeTransfer => format!("{} 보내기", chain.native_symbol),
        DecodedCall::Known { title, .. } => substitute(title, chain),
        DecodedCall::Multicall { inner, .. } => format!("묶음 호출 ({}개)", inner.len()),
        DecodedCall::Uninterpreted {
            label: Some(label), ..
        } => {
            format!("해석되지 않은 컨트랙트 호출 ({label})")
        }
        DecodedCall::Uninterpreted { label: None, .. } => "해석되지 않은 컨트랙트 호출".to_owned(),
    }
}

fn action_title(ctx: &Ctx<'_>, call: &DecodedCall, value: &U256) -> String {
    let base = call_title(call, ctx.chain);
    let amount = match call {
        DecodedCall::NativeTransfer => Some(native_amount(ctx.chain, value)),
        DecodedCall::Known {
            kind: "erc20_transfer",
            ..
        } => match call.arg("amount") {
            Some(AbiValue::Uint(amount)) => Some(ctx.token_amount(&ctx.to, amount, None)),
            _ => None,
        },
        _ => None,
    };
    match amount {
        Some(amount) => format!("{base}: {amount}"),
        None => base,
    }
}

fn title(chain: &ChainInfo, action: &str) -> String {
    let full = format!("[{}] {action}", chain.name);
    if full.len() <= MAX_TITLE_BYTES {
        return full;
    }
    let mut short = format!("[{}] ", chain.name);
    for character in action.chars() {
        if short
            .len()
            .saturating_add(character.len_utf8())
            .saturating_add(3)
            > MAX_TITLE_BYTES
        {
            break;
        }
        short.push(character);
    }
    short.trim_end().to_owned() + "…"
}

struct Fields(Vec<DisplayField>, FieldCap);

/// What [`Fields::push`] does at [`MAX_DISPLAY_FIELDS`].
#[derive(Clone, Copy)]
enum FieldCap {
    /// Keep pushing: [`ApprovalDisplay::new`] fails with `TooMany` (transactions, messages).
    Fail,
    /// Typed data (spec/03 §8.4): stop at one below the cap, count what was left out and leave
    /// the last slot for the note; the builder adds T16 (blocked), so the request is shown and
    /// refused instead of failing as an internal error.
    Truncate { dropped: usize },
}

impl Fields {
    const fn new() -> Self {
        Self(Vec::new(), FieldCap::Fail)
    }

    const fn truncating() -> Self {
        Self(Vec::new(), FieldCap::Truncate { dropped: 0 })
    }

    fn push(&mut self, key: FieldKey, sub_label: &str, value: String) -> Result<(), DisplayError> {
        if let FieldCap::Truncate { dropped } = &mut self.1
            && self.0.len() >= MAX_DISPLAY_FIELDS.saturating_sub(1)
        {
            *dropped = dropped.saturating_add(1);
            return Ok(());
        }
        self.0.push(DisplayField::new(key, sub_label, value)?);
        Ok(())
    }

    /// Fields left out by a truncating list (0 otherwise); when any, the note takes the last slot.
    fn close_truncated(&mut self) -> Result<usize, DisplayError> {
        let FieldCap::Truncate { dropped } = self.1 else {
            return Ok(0);
        };
        if dropped > 0 {
            self.0.push(DisplayField::new(
                FieldKey::TD_TREE,
                "",
                format!("(표시 한도 초과: 항목 {dropped}개 생략)"),
            )?);
        }
        Ok(dropped)
    }
}

fn header(
    fields: &mut Fields,
    origin: &ApprovalOrigin,
    chain: &ChainInfo,
    facts: &ChainFacts,
    account: &Address,
) -> Result<(), DisplayError> {
    let origin_text = match origin {
        ApprovalOrigin::App => crate::approval::APP_ORIGIN_TEXT.to_owned(),
        ApprovalOrigin::Site(site) => site.as_str().to_owned(),
    };
    fields.push(FieldKey::ORIGIN, "", origin_text)?;
    fields.push(
        FieldKey::NETWORK,
        "",
        format!("{} (chainId {})", chain.name, chain.chain_id),
    )?;
    fields.push(
        FieldKey::ACCOUNT,
        "",
        describe_address(chain, facts, account),
    )
}

fn chain_ref(chain: &ChainInfo) -> ChainRef {
    ChainRef::Evm {
        chain_id: chain.chain_id,
        genesis: chain.genesis_hash().unwrap_or([0; 32]),
    }
}

fn finish_display(
    title_text: String,
    fields: Fields,
    mut warnings: Vec<Warning>,
) -> Result<ApprovalDisplay, DisplayError> {
    sort_warnings(&mut warnings);
    warnings.truncate(MAX_DISPLAY_WARNINGS);
    ApprovalDisplay::new(title_text, fields.0, warnings)
}

fn asset_label(ctx: &Ctx<'_>, asset: &AssetId) -> String {
    match asset {
        AssetId::Native => ctx.chain.native_symbol.clone(),
        AssetId::Token(token) => ctx.address(token),
    }
}

fn change_row(ctx: &Ctx<'_>, change: &AssetChange) -> String {
    let amount = match change.delta {
        Some(Delta::In(amount) | Delta::Out(amount)) => amount,
        Some(Delta::Zero) => U256::ZERO,
        None => return format!("합산 불가 · {}", asset_label(ctx, &change.asset)),
    };
    match (change.asset, change.token_id) {
        (AssetId::Native, _) => native_amount(ctx.chain, &amount),
        (AssetId::Token(token), None) => {
            let text = format_token_amount(ctx.chain, ctx.facts, &token, &amount);
            if ctx.chain.token(&token).is_some() {
                text
            } else {
                format!("{text} · {}", format_address(&token))
            }
        }
        // NFTs are never registry assets: any contract can emit their Transfer logs (E40).
        (AssetId::Token(token), Some(id)) if amount == U256::ONE => format!(
            "NFT #{} · {} (미확인)",
            id.to_decimal_string(),
            ctx.address(&token)
        ),
        (AssetId::Token(token), Some(id)) => format!(
            "{} × {} · {} (미확인)",
            id.to_decimal_string(),
            amount.to_decimal_string(),
            ctx.address(&token)
        ),
    }
}

fn approval_row(ctx: &Ctx<'_>, change: &ApprovalChange) -> String {
    let token = ctx.address(&change.asset);
    let spender = ctx.address(&change.spender);
    match change.kind {
        ApprovalKindEvm::Erc20 { amount } => format!(
            "{token}\n사용자: {spender}\n금액: {}",
            ctx.token_amount(&change.asset, &amount, Some(U256::MAX))
        ),
        ApprovalKindEvm::Erc721 { token_id, revoked } => {
            if revoked {
                format!("{token} #{}\n개별 승인 해제", token_id.to_decimal_string())
            } else {
                format!(
                    "{token} #{}\n승인 대상: {spender}",
                    token_id.to_decimal_string()
                )
            }
        }
        ApprovalKindEvm::ForAll { approved } => format!(
            "{token} 전체\n운영자: {spender}\n{}",
            if approved {
                "권한 부여"
            } else {
                "권한 해제"
            }
        ),
        ApprovalKindEvm::Permit2 { amount, expiration } => format!(
            "{token} (Permit2)\n사용자: {spender}\n금액: {}\n만료: {}",
            ctx.token_amount(&change.asset, &amount, Some(U256::MAX_U160)),
            permit2_expiration(&U256::from_u64(expiration), ctx.now_unix_ms)
        ),
        ApprovalKindEvm::Permit2Lockdown => {
            format!("{token} (Permit2) 승인 해제\n사용자: {spender}")
        }
    }
}

fn simulation_basis(sim: &SimResult) -> String {
    match sim {
        SimResult::Simulated { diff, .. } => format!(
            "블록 {} · {}",
            format_units(&U256::from_u64(diff.block.number), 0),
            format_utc(i64::try_from(diff.block.timestamp).unwrap_or(i64::MAX))
        ),
        SimResult::Unavailable {
            reason: SimNoneReason::Unsupported,
            ..
        } => "시뮬레이션 없음: 미지원 체인".to_owned(),
        SimResult::Unavailable {
            reason: SimNoneReason::Skipped,
            ..
        } => "시뮬레이션 없음: 차단 조건으로 실행하지 않음".to_owned(),
        SimResult::Unavailable { warning, .. } => {
            let cause = warning
                .as_ref()
                .and_then(|warning| warning.text.split_once('\n'))
                .map_or("알 수 없는 원인", |(_, cause)| cause);
            format!("시뮬레이션 없음: {cause}")
        }
    }
}

fn arg_fields(
    fields: &mut Fields,
    ctx: &Ctx<'_>,
    call: &DecodedCall,
    prefix: &str,
) -> Result<(), DisplayError> {
    match call {
        DecodedCall::Known { kind, args, .. } => {
            for (name, value) in args {
                fields.push(
                    FieldKey::CALL_ARG,
                    &format!("{prefix}{name}"),
                    ctx.arg(call, kind, name, value),
                )?;
            }
        }
        DecodedCall::Multicall { kind, head, inner } => {
            for (name, value) in head {
                let text = match (*name, value) {
                    ("deadline", AbiValue::Uint(deadline)) => {
                        format_time(deadline, ctx.now_unix_ms)
                    }
                    _ => ctx.arg(call, kind, name, value),
                };
                fields.push(FieldKey::CALL_ARG, &format!("{prefix}{name}"), text)?;
            }
            for (index, inner_call) in inner.iter().enumerate() {
                let inner_prefix = format!("calls[{index}].");
                fields.push(
                    FieldKey::CALL_ARG,
                    &format!("calls[{index}]"),
                    call_title(inner_call, ctx.chain),
                )?;
                arg_fields(fields, ctx, inner_call, &inner_prefix)?;
            }
        }
        DecodedCall::NativeTransfer | DecodedCall::Uninterpreted { .. } => {}
    }
    Ok(())
}

/// Builds an EVM transaction approval draft (spec/03 §11.1). `warnings` are the §3.7 steps 1–7
/// warnings (E05, E06, E10, E11, E34, E35, E37, E38, E31); with a blocking one, `sim` must be
/// [`SimResult::skipped`].
///
/// # Errors
///
/// [`DisplayError`] if a display string breaks the §11.2 rules (defensive; inputs are escaped).
#[expect(
    clippy::too_many_arguments,
    reason = "argument list fixed by spec/03 §11.1"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one block per field key of spec/03 §11.2"
)]
pub fn build_evm_tx_request(
    id: ApprovalId,
    origin: ApprovalOrigin,
    signer: EvmKeySource,
    account: Address,
    kind: ApprovalKind,
    chain: &ChainInfo,
    decoded: &DecodedTx,
    sim: &SimResult,
    facts: &ChainFacts,
    mut warnings: Vec<Warning>,
    now_unix_ms: u64,
) -> Result<ApprovalDraft, DisplayError> {
    let tx = &decoded.tx;
    let (call, r4_unresolved) = resolve_token_standard(&decoded.call, &tx.to, sim.events());
    warnings.extend(sim.warnings());
    warnings.extend(tx_rules(&TxRiskInput {
        chain,
        origin: &origin,
        account: &account,
        tx,
        call: &call,
        r4_unresolved,
        sim,
        facts,
        now_unix_ms,
    }));
    let ctx = Ctx {
        chain,
        facts,
        to: tx.to,
        now_unix_ms,
    };
    let mut fields = Fields::new();
    header(&mut fields, &origin, chain, facts, &account)?;
    fields.push(FieldKey::TO, "", ctx.address(&tx.to))?;
    fields.push(FieldKey::VALUE, "", native_amount(chain, &tx.value))?;
    fields.push(FieldKey::CALL, "", call_title(&call, chain))?;
    arg_fields(&mut fields, &ctx, &call, "")?;
    if let SimResult::Simulated { diff, .. } = sim {
        for change in &diff.changes {
            let key = match change.delta {
                Some(Delta::In(_)) => FieldKey::RECEIVED,
                _ => FieldKey::SENT,
            };
            fields.push(key, "", change_row(&ctx, change))?;
        }
        for approval in &diff.approvals {
            fields.push(FieldKey::APPROVAL, "", approval_row(&ctx, approval))?;
        }
        if diff.other_events > 0 {
            fields.push(
                FieldKey::OTHER_EVENTS,
                "",
                format!("기타 이벤트 {}개", diff.other_events),
            )?;
        }
    }
    let max_fee = max_total_fee(tx.gas_limit, &tx.max_fee_per_gas)
        .map_or_else(|| "계산 불가".to_owned(), |fee| native_amount(chain, &fee));
    fields.push(FieldKey::MAX_FEE, "", max_fee)?;
    let expected = match sim {
        SimResult::Simulated { diff, .. } => expected_fee(
            diff.gas_used,
            &tx.max_fee_per_gas,
            &diff.block.base_fee,
            &tx.max_priority_fee_per_gas,
        )
        .map_or_else(|| "알 수 없음".to_owned(), |fee| native_amount(chain, &fee)),
        SimResult::Unavailable { .. } => "알 수 없음".to_owned(),
    };
    fields.push(FieldKey::EXPECTED_FEE, "", expected)?;
    fields.push(
        FieldKey::FEE_PARAMS,
        "",
        format!(
            "maxFee {} · tip {}",
            format_gwei(&tx.max_fee_per_gas),
            format_gwei(&tx.max_priority_fee_per_gas)
        ),
    )?;
    fields.push(
        FieldKey::GAS_LIMIT,
        "",
        format_units(&U256::from_u64(tx.gas_limit), 0),
    )?;
    fields.push(FieldKey::NONCE, "", tx.nonce.to_string())?;
    fields.push(FieldKey::SIMULATION, "", simulation_basis(sim))?;
    if !tx.access_list.is_empty() {
        let slots: usize = tx
            .access_list
            .iter()
            .map(|item| item.storage_keys.len())
            .sum();
        let mut text = format!("주소 {}개 · 슬롯 {slots}개", tx.access_list.len());
        for item in &tx.access_list {
            let _ = write!(
                text,
                "\n{} · 슬롯 {}개",
                format_address(&item.address),
                item.storage_keys.len()
            );
        }
        fields.push(FieldKey::ACCESS_LIST, "", text)?;
    }
    let calldata = match tx.data.get(..4) {
        None if tx.data.is_empty() => "없음 (0바이트)".to_owned(),
        Some(selector) => format!(
            "{}바이트 · selector 0x{}\n0x{}",
            tx.data.len(),
            crate::hex::encode(selector),
            crate::hex::encode(&tx.data)
        ),
        None => hex_with_len(&tx.data),
    };
    fields.push(FieldKey::CALLDATA, "", calldata)?;
    let display = finish_display(
        title(chain, &action_title(&ctx, &call, &tx.value)),
        fields,
        warnings,
    )?;
    Ok(ApprovalDraft {
        id,
        origin,
        chain: chain_ref(chain),
        account: AccountRef::Evm(account),
        signer: Signer::Evm(signer),
        kind,
        payload: SigningPayload::EvmTx(tx.clone()),
        display,
        simulation: sim.binding(),
    })
}

/// Adds the `0x0125` field (대체 대상 거래: the replaced hash and its maximum fee) to a speed-up or
/// cancel draft (spec/03 §4.6, §11.2) right after `0x0124`; a cancel gets the title
/// `[{network}] 거래 취소 (nonce N)`. The new maximum fee stays in `0x0120`.
///
/// # Errors
///
/// [`DisplayError`] (defensive).
pub fn add_replacement(
    mut draft: ApprovalDraft,
    chain: &ChainInfo,
    replaced_hash: &[u8; 32],
    old_max_total_fee: Option<U256>,
) -> Result<ApprovalDraft, DisplayError> {
    let old =
        old_max_total_fee.map_or_else(|| "계산 불가".to_owned(), |fee| native_amount(chain, &fee));
    let value = format!(
        "0x{}\n기존 최대 수수료 {old}",
        crate::hex::encode(replaced_hash)
    );
    let field = DisplayField::new(FieldKey::REPLACES, "", value)?;
    let mut fields = draft.display.fields.clone();
    let position = fields
        .iter()
        .position(|existing| existing.key > FieldKey::REPLACES)
        .unwrap_or(fields.len());
    fields.insert(position, field);
    let new_title = match (&draft.kind, &draft.payload) {
        (ApprovalKind::EvmCancel, SigningPayload::EvmTx(tx)) => {
            title(chain, &format!("거래 취소 (nonce {})", tx.nonce))
        }
        _ => draft.display.title.clone(),
    };
    draft.display = ApprovalDisplay::new(new_title, fields, draft.display.warnings.clone())?;
    Ok(draft)
}

fn hex_lines(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0x".to_owned();
    }
    let lines: Vec<String> = bytes.chunks(32).map(crate::hex::encode).collect();
    format!("0x{}", lines.join("\n"))
}

fn siwe_fields(
    fields: &mut Fields,
    message: &super::siwe::SiweMessage,
    now_unix_ms: u64,
) -> Result<(), DisplayError> {
    let time =
        |raw: &str, seconds: i64| format!("{raw}\n{}", format_utc_relative(seconds, now_unix_ms));
    let domain = if message.scheme_explicit {
        format!("{}://{}", message.scheme, message.domain)
    } else {
        message.domain.clone()
    };
    fields.push(FieldKey::SIWE_FIELD, "도메인", domain)?;
    fields.push(
        FieldKey::SIWE_FIELD,
        "주소",
        format_address(&message.address),
    )?;
    if let Some(statement) = &message.statement {
        fields.push(FieldKey::SIWE_FIELD, "설명", escape_value(statement).0)?;
    }
    fields.push(FieldKey::SIWE_FIELD, "URI", message.uri.clone())?;
    fields.push(
        FieldKey::SIWE_FIELD,
        "체인 ID",
        message.chain_id.to_string(),
    )?;
    fields.push(FieldKey::SIWE_FIELD, "Nonce", message.nonce.clone())?;
    fields.push(
        FieldKey::SIWE_FIELD,
        "발급 시각",
        time(&message.issued_at_text, message.issued_at),
    )?;
    if let (Some(raw), Some(seconds)) = (&message.expiration_time_text, message.expiration_time) {
        fields.push(FieldKey::SIWE_FIELD, "만료 시각", time(raw, seconds))?;
    }
    if let (Some(raw), Some(seconds)) = (&message.not_before_text, message.not_before) {
        fields.push(FieldKey::SIWE_FIELD, "유효 시작", time(raw, seconds))?;
    }
    if let Some(request_id) = &message.request_id {
        let value = if request_id.is_empty() {
            "(빈 값)".to_owned()
        } else {
            request_id.clone()
        };
        fields.push(FieldKey::SIWE_FIELD, "요청 ID", value)?;
    }
    if message.resources_present {
        let value = if message.resources.is_empty() {
            "(없음)".to_owned()
        } else {
            message.resources.join("\n")
        };
        fields.push(FieldKey::SIWE_FIELD, "리소스", value)?;
    }
    Ok(())
}

/// Builds a `personal_sign` approval draft (spec/03 §9, §11.1).
///
/// # Errors
///
/// [`DisplayError`] (defensive).
#[expect(
    clippy::too_many_arguments,
    reason = "argument list fixed by spec/03 §11.1"
)]
pub fn build_personal_request(
    id: ApprovalId,
    origin: ApprovalOrigin,
    signer: EvmKeySource,
    account: Address,
    kind: ApprovalKind,
    chain: &ChainInfo,
    message: &DecodedPersonalMessage,
    now_unix_ms: u64,
) -> Result<ApprovalDraft, DisplayError> {
    let facts = ChainFacts::default();
    let mut fields = Fields::new();
    header(&mut fields, &origin, chain, &facts, &account)?;
    let mut warnings = Vec::new();
    let text = message
        .text
        .as_deref()
        .map(message_value)
        .filter(|value| value.len() <= crate::approval::MAX_DISPLAY_VALUE_BYTES);
    if message.text.is_some() && text.is_none() {
        warnings.push(risk::warning(P02, None));
    }
    if let Some(value) = text {
        fields.push(FieldKey::MESSAGE_TEXT, "", value)?;
        if message.escaped {
            warnings.push(risk::warning(P02, None));
        }
    } else {
        // Non-UTF-8 (P01), UTF-8 that looks binary (P04), or UTF-8 whose escaped form exceeds
        // the value limit (P02 above).
        fields.push(FieldKey::MESSAGE_HEX, "", hex_lines(&message.bytes))?;
        match message.hex_reason {
            Some(HexReason::Hash32) => warnings.push(risk::warning(
                P04,
                Some("정확히 32바이트입니다 — 해시에 서명하는 것일 수 있습니다"),
            )),
            Some(HexReason::Control) => warnings.push(risk::warning(
                P04,
                Some("TAB·줄바꿈 외의 제어 문자가 있습니다"),
            )),
            None if message.text.is_none() => warnings.push(risk::warning(P01, None)),
            None => {}
        }
    }
    fields.push(
        FieldKey::MESSAGE_BYTES,
        "",
        format!("{}바이트", message.bytes.len()),
    )?;
    let site = match &origin {
        ApprovalOrigin::Site(site) => Some(site),
        ApprovalOrigin::App => None,
    };
    let context = SiweContext {
        origin: site,
        account: &account,
        active_chain_id: chain.chain_id,
        now_unix_ms,
    };
    let action = if let Some(siwe) = &message.siwe {
        siwe_fields(&mut fields, siwe, now_unix_ms)?;
        warnings.extend(check_siwe(siwe, &context));
        "로그인 요청 (SIWE)"
    } else {
        if message.siwe_marker_only {
            // S08 plus the first-line domain checks (S01/S02 block; unreadable domain → S01).
            let raw = core::str::from_utf8(&message.bytes).unwrap_or("");
            warnings.extend(check_marker_only(raw, &context));
        } else if message.text.is_some() && !message.escaped {
            warnings.push(risk::warning(P03, None));
        }
        "메시지 서명"
    };
    let display = finish_display(title(chain, action), fields, warnings)?;
    Ok(ApprovalDraft {
        id,
        origin,
        chain: chain_ref(chain),
        account: AccountRef::Evm(account),
        signer: Signer::Evm(signer),
        kind,
        payload: SigningPayload::EvmPersonal(personal_preimage(&message.bytes)),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}

struct Tree<'a> {
    fields: Option<&'a mut Fields>,
    leaves: usize,
    exceeded: bool,
    hidden: bool,
}

impl Tree<'_> {
    fn leaf_text(&mut self, value: &TdValue) -> String {
        match value {
            TdValue::Address(address) => format_address(address),
            TdValue::Uint(number) => number.to_decimal_string(),
            TdValue::Int {
                negative,
                magnitude,
            } => {
                if *negative {
                    format!("-{}", magnitude.to_decimal_string())
                } else {
                    magnitude.to_decimal_string()
                }
            }
            TdValue::Bool(true) => "예".to_owned(),
            TdValue::Bool(false) => "아니오".to_owned(),
            TdValue::Bytes(bytes) => {
                if bytes.len() > TREE_MAX_BYTES {
                    self.exceeded = true;
                    return format!("(표시 한도 초과: {}바이트)", bytes.len());
                }
                hex_with_len(bytes)
            }
            TdValue::String(text) => {
                let (value, hidden) = escape_value(text);
                self.hidden |= hidden;
                if text.len() > TREE_MAX_STRING {
                    self.exceeded = true;
                    return format!("(표시 한도 초과: {}바이트)", text.len());
                }
                value
            }
        }
    }

    fn walk(&mut self, node: &TdNode, path: &str, depth: usize) -> Result<(), DisplayError> {
        if depth > TREE_MAX_DEPTH {
            self.exceeded = true;
            return Ok(());
        }
        match node {
            TdNode::Struct { fields, .. } => {
                for (name, child) in fields {
                    let (name, hidden) = escape_inline(name);
                    self.hidden |= hidden;
                    let child_path = if path.is_empty() {
                        name
                    } else {
                        format!("{path}.{name}")
                    };
                    self.walk(child, &child_path, depth.saturating_add(1))?;
                }
            }
            TdNode::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    self.walk(child, &format!("{path}[{index}]"), depth.saturating_add(1))?;
                }
            }
            TdNode::Value(value) => {
                self.leaves = self.leaves.saturating_add(1);
                if self.leaves > TREE_MAX_LEAVES {
                    self.exceeded = true;
                    return Ok(());
                }
                let text = self.leaf_text(value);
                if let Some(fields) = self.fields.as_deref_mut() {
                    fields.push(FieldKey::TD_TREE, path, text)?;
                }
            }
        }
        Ok(())
    }
}

fn domain_text(ctx: &Ctx<'_>, typed: &DecodedTypedData) -> (String, bool, bool) {
    let mut lines = Vec::new();
    let mut hidden = false;
    let mut exceeded = false;
    if let TdNode::Struct { fields, .. } = &typed.domain.tree {
        for (name, node) in fields {
            let value = match (name.as_str(), node.value()) {
                ("verifyingContract", Some(TdValue::Address(address))) => ctx.address(address),
                (_, Some(TdValue::String(text))) => {
                    let (value, flagged) = escape_inline(text);
                    hidden |= flagged;
                    if text.len() > TREE_MAX_STRING {
                        exceeded = true;
                        format!("(표시 한도 초과: {}바이트)", text.len())
                    } else if value.is_empty() {
                        "(빈 문자열)".to_owned()
                    } else {
                        escape_edges(&value)
                    }
                }
                (_, Some(TdValue::Uint(number))) => number.to_decimal_string(),
                (_, Some(TdValue::Address(address))) => format_address(address),
                (_, Some(TdValue::Bytes(bytes))) => format!("0x{}", crate::hex::encode(bytes)),
                (_, Some(TdValue::Bool(flag))) => if *flag { "예" } else { "아니오" }.to_owned(),
                (
                    _,
                    Some(TdValue::Int {
                        negative,
                        magnitude,
                    }),
                ) => {
                    format!(
                        "{}{}",
                        if *negative { "-" } else { "" },
                        magnitude.to_decimal_string()
                    )
                }
                (_, None) => "(구조)".to_owned(),
            };
            lines.push(format!("{name}: {value}"));
        }
    }
    if lines.is_empty() {
        lines.push("(빈 도메인)".to_owned());
    }
    (lines.join("\n"), hidden, exceeded)
}

fn schema_name(typed: &DecodedTypedData) -> (String, &'static str) {
    match &typed.schema {
        Some(KnownSchema::Eip2612Permit) => {
            ("EIP-2612 Permit".to_owned(), "토큰 사용 허가 서명 (permit)")
        }
        Some(KnownSchema::DaiPermit) => ("DAI Permit".to_owned(), "DAI 사용 허가 서명"),
        Some(KnownSchema::Permit2Single) => {
            ("Permit2 PermitSingle".to_owned(), "Permit2 승인 서명")
        }
        Some(KnownSchema::Permit2Batch) => ("Permit2 PermitBatch".to_owned(), "Permit2 승인 서명"),
        Some(KnownSchema::Permit2Transfer) => (
            "Permit2 PermitTransferFrom".to_owned(),
            "Permit2 즉시 이체 서명",
        ),
        Some(KnownSchema::Permit2BatchTransfer) => (
            "Permit2 PermitBatchTransferFrom".to_owned(),
            "Permit2 즉시 이체 서명",
        ),
        Some(KnownSchema::Permit2WitnessTransfer { .. }) => (
            "Permit2 PermitWitnessTransferFrom".to_owned(),
            "Permit2 즉시 이체 서명(조건 포함)",
        ),
        Some(KnownSchema::Permit2BatchWitnessTransfer { .. }) => (
            "Permit2 PermitBatchWitnessTransferFrom".to_owned(),
            "Permit2 즉시 이체 서명(조건 포함)",
        ),
        Some(KnownSchema::SeaportOrder) => {
            ("Seaport OrderComponents".to_owned(), "NFT 마켓 주문 서명")
        }
        None => (
            format!("알 수 없는 형식: {}", escape_inline(&typed.primary_type).0),
            "타입 데이터 서명",
        ),
    }
}

fn seaport_item(ctx: &Ctx<'_>, item: &TdNode) -> String {
    let uint = |name: &str| {
        item.field(name)
            .and_then(TdNode::uint)
            .unwrap_or(U256::ZERO)
    };
    let token = item
        .field("token")
        .and_then(TdNode::address)
        .unwrap_or_else(|| Address::from_bytes([0; 20]));
    let id = uint("identifierOrCriteria");
    let (start, end) = (uint("startAmount"), uint("endAmount"));
    let amount_text = |amount: &U256| match uint("itemType").to_u64() {
        Some(0) => native_amount(ctx.chain, amount),
        Some(1) => format_token_amount(ctx.chain, ctx.facts, &token, amount),
        _ => amount.to_decimal_string(),
    };
    let quantity = if start == end {
        amount_text(&start)
    } else {
        format!(
            "시작 {} → 종료 {} (시간에 따라 변함)",
            amount_text(&start),
            amount_text(&end)
        )
    };
    let mut text = match uint("itemType").to_u64() {
        Some(0) => quantity,
        Some(1) => format!("{quantity} · {}", ctx.address(&token)),
        Some(2) => format!("NFT #{} · {}", id.to_decimal_string(), ctx.address(&token)),
        Some(3) => format!(
            "{} × {quantity} · {}",
            id.to_decimal_string(),
            ctx.address(&token)
        ),
        Some(4 | 5) if id.is_zero() => {
            format!("컬렉션의 아무 토큰 × {quantity} · {}", ctx.address(&token))
        }
        Some(4 | 5) => format!(
            "기준 루트 0x{} × {quantity} · {}",
            crate::hex::encode(id.as_be_bytes()),
            ctx.address(&token)
        ),
        _ => format!(
            "알 수 없는 itemType {}",
            uint("itemType").to_decimal_string()
        ),
    };
    if let Some(recipient) = item.field("recipient").and_then(TdNode::address) {
        text.push_str("\n받는 주소: ");
        text.push_str(&ctx.address(&recipient));
    }
    text
}

#[expect(
    clippy::too_many_lines,
    reason = "one block per schema of spec/03 §8.3"
)]
fn structured_fields(
    fields: &mut Fields,
    ctx: &Ctx<'_>,
    typed: &DecodedTypedData,
    account: &Address,
) -> Result<(), DisplayError> {
    let root = &typed.root;
    let address = |name: &str| root.field(name).and_then(TdNode::address);
    let uint = |name: &str| root.field(name).and_then(TdNode::uint);
    let push_address = |fields: &mut Fields, label: &str, name: &str| {
        address(name).map_or(Ok(()), |value| {
            fields.push(FieldKey::TD_FIELD, label, ctx.address(&value))
        })
    };
    let Some(schema) = &typed.schema else {
        return Ok(());
    };
    match schema {
        KnownSchema::Eip2612Permit => {
            let token = typed.domain.verifying_contract;
            if let Some(token) = token {
                fields.push(FieldKey::TD_FIELD, "토큰", ctx.address(&token))?;
            }
            push_address(fields, "소유자", "owner")?;
            push_address(fields, "사용자", "spender")?;
            if let (Some(token), Some(value)) = (token, uint("value")) {
                fields.push(
                    FieldKey::TD_FIELD,
                    "금액",
                    ctx.token_amount(&token, &value, Some(U256::MAX)),
                )?;
            }
            if let Some(nonce) = uint("nonce") {
                fields.push(FieldKey::TD_FIELD, "nonce", nonce.to_decimal_string())?;
            }
            if let Some(deadline) = uint("deadline") {
                fields.push(
                    FieldKey::TD_FIELD,
                    "기한",
                    format_time(&deadline, ctx.now_unix_ms),
                )?;
            }
        }
        KnownSchema::DaiPermit => {
            push_address(fields, "소유자", "holder")?;
            push_address(fields, "사용자", "spender")?;
            if let Some(nonce) = uint("nonce") {
                fields.push(FieldKey::TD_FIELD, "nonce", nonce.to_decimal_string())?;
            }
            if let Some(expiry) = uint("expiry") {
                let text = if expiry.is_zero() {
                    "만료 없음".to_owned()
                } else {
                    format_time(&expiry, ctx.now_unix_ms)
                };
                fields.push(FieldKey::TD_FIELD, "기한", text)?;
            }
            if let Some(allowed) = root.field("allowed").and_then(TdNode::boolean) {
                let text = if allowed {
                    "무제한 허용"
                } else {
                    "허용 해제"
                };
                fields.push(FieldKey::TD_FIELD, "허용", text.to_owned())?;
            }
        }
        KnownSchema::Permit2Single | KnownSchema::Permit2Batch => {
            let (items, indexed): (Vec<&TdNode>, bool) = match root.field("details") {
                Some(TdNode::Array(items)) => (items.iter().collect(), true),
                Some(node) => (vec![node], false),
                None => (Vec::new(), false),
            };
            for (index, detail) in items.iter().enumerate() {
                let prefix = if indexed {
                    format!("항목 {} ", index.saturating_add(1))
                } else {
                    String::new()
                };
                let token = detail.field("token").and_then(TdNode::address);
                if let Some(token) = token {
                    fields.push(
                        FieldKey::TD_FIELD,
                        &format!("{prefix}토큰"),
                        ctx.address(&token),
                    )?;
                    if let Some(amount) = detail.field("amount").and_then(TdNode::uint) {
                        fields.push(
                            FieldKey::TD_FIELD,
                            &format!("{prefix}금액"),
                            ctx.token_amount(&token, &amount, Some(U256::MAX_U160)),
                        )?;
                    }
                }
                if let Some(expiration) = detail.field("expiration").and_then(TdNode::uint) {
                    fields.push(
                        FieldKey::TD_FIELD,
                        &format!("{prefix}허용 만료"),
                        permit2_expiration(&expiration, ctx.now_unix_ms),
                    )?;
                }
                if let Some(nonce) = detail.field("nonce").and_then(TdNode::uint) {
                    fields.push(
                        FieldKey::TD_FIELD,
                        &format!("{prefix}nonce"),
                        nonce.to_decimal_string(),
                    )?;
                }
            }
            push_address(fields, "사용자", "spender")?;
            if let Some(deadline) = uint("sigDeadline") {
                fields.push(
                    FieldKey::TD_FIELD,
                    "서명 기한",
                    format_time(&deadline, ctx.now_unix_ms),
                )?;
            }
        }
        KnownSchema::Permit2Transfer
        | KnownSchema::Permit2BatchTransfer
        | KnownSchema::Permit2WitnessTransfer { .. }
        | KnownSchema::Permit2BatchWitnessTransfer { .. } => {
            let (items, indexed): (Vec<&TdNode>, bool) = match root.field("permitted") {
                Some(TdNode::Array(items)) => (items.iter().collect(), true),
                Some(node) => (vec![node], false),
                None => (Vec::new(), false),
            };
            for (index, permitted) in items.iter().enumerate() {
                let prefix = if indexed {
                    format!("항목 {} ", index.saturating_add(1))
                } else {
                    String::new()
                };
                if let Some(token) = permitted.field("token").and_then(TdNode::address) {
                    fields.push(
                        FieldKey::TD_FIELD,
                        &format!("{prefix}토큰"),
                        ctx.address(&token),
                    )?;
                    if let Some(amount) = permitted.field("amount").and_then(TdNode::uint) {
                        fields.push(
                            FieldKey::TD_FIELD,
                            &format!("{prefix}금액"),
                            ctx.token_amount(&token, &amount, None),
                        )?;
                    }
                }
            }
            push_address(fields, "사용자", "spender")?;
            if let Some(nonce) = uint("nonce") {
                fields.push(FieldKey::TD_FIELD, "nonce", nonce.to_decimal_string())?;
            }
            if let Some(deadline) = uint("deadline") {
                fields.push(
                    FieldKey::TD_FIELD,
                    "기한",
                    format_time(&deadline, ctx.now_unix_ms),
                )?;
            }
            fields.push(
                FieldKey::TD_FIELD,
                "안내",
                "이 서명으로 spender가 토큰을 바로 가져갈 수 있습니다".to_owned(),
            )?;
            if let KnownSchema::Permit2WitnessTransfer { witness_type }
            | KnownSchema::Permit2BatchWitnessTransfer { witness_type } = schema
            {
                fields.push(
                    FieldKey::TD_FIELD,
                    "witness 타입",
                    escape_inline(witness_type).0,
                )?;
            }
        }
        KnownSchema::SeaportOrder => {
            push_address(fields, "offerer", "offerer")?;
            push_address(fields, "zone", "zone")?;
            if let Some(order_type) = uint("orderType") {
                let name = match order_type.to_u64() {
                    Some(0) => "FULL_OPEN".to_owned(),
                    Some(1) => "PARTIAL_OPEN".to_owned(),
                    Some(2) => "FULL_RESTRICTED".to_owned(),
                    Some(3) => "PARTIAL_RESTRICTED".to_owned(),
                    Some(4) => "CONTRACT".to_owned(),
                    _ => order_type.to_decimal_string(),
                };
                fields.push(FieldKey::TD_FIELD, "orderType", name)?;
            }
            if let Some(start) = uint("startTime") {
                fields.push(
                    FieldKey::TD_FIELD,
                    "시작 시각",
                    format_time(&start, ctx.now_unix_ms),
                )?;
            }
            if let Some(end) = uint("endTime") {
                fields.push(
                    FieldKey::TD_FIELD,
                    "종료 시각",
                    format_time(&end, ctx.now_unix_ms),
                )?;
            }
            let offer = root
                .field("offer")
                .and_then(TdNode::elements)
                .unwrap_or(&[]);
            for item in offer {
                fields.push(FieldKey::TD_FIELD, "내가 주는 것", seaport_item(ctx, item))?;
            }
            let consideration = root
                .field("consideration")
                .and_then(TdNode::elements)
                .unwrap_or(&[]);
            for item in consideration {
                let mine = item.field("recipient").and_then(TdNode::address) == Some(*account);
                let label = if mine {
                    "내가 받는 것"
                } else {
                    "다른 사람이 받는 것"
                };
                fields.push(FieldKey::TD_FIELD, label, seaport_item(ctx, item))?;
            }
            if let Some(key) = root.field("conduitKey").and_then(TdNode::bytes) {
                let mut text = format!("0x{}", crate::hex::encode(key));
                if key == OPENSEA_CONDUIT_KEY {
                    text.push_str(" [OpenSea Conduit]");
                }
                fields.push(FieldKey::TD_FIELD, "conduitKey", text)?;
            }
            if let Some(counter) = uint("counter") {
                fields.push(FieldKey::TD_FIELD, "counter", counter.to_decimal_string())?;
            }
            if let Some(salt) = uint("salt") {
                fields.push(FieldKey::TD_FIELD, "salt", salt.to_decimal_string())?;
            }
            if let Some(hash) = root.field("zoneHash").and_then(TdNode::bytes) {
                fields.push(
                    FieldKey::TD_FIELD,
                    "zoneHash",
                    format!("0x{}", crate::hex::encode(hash)),
                )?;
            }
        }
    }
    Ok(())
}

/// Builds an `eth_signTypedData_v4` approval draft (spec/03 §8, §11.1).
///
/// # Errors
///
/// [`DisplayError`] (defensive).
#[expect(
    clippy::too_many_arguments,
    reason = "argument list fixed by spec/03 §11.1"
)]
pub fn build_typed_request(
    id: ApprovalId,
    origin: ApprovalOrigin,
    signer: EvmKeySource,
    account: Address,
    kind: ApprovalKind,
    chain: &ChainInfo,
    typed: &DecodedTypedData,
    facts: &ChainFacts,
    now_unix_ms: u64,
) -> Result<ApprovalDraft, DisplayError> {
    let ctx = Ctx {
        chain,
        facts,
        to: typed
            .domain
            .verifying_contract
            .unwrap_or_else(|| Address::from_bytes([0; 20])),
        now_unix_ms,
    };
    let mut fields = Fields::truncating();
    header(&mut fields, &origin, chain, facts, &account)?;
    let (domain, mut hidden, domain_exceeded) = domain_text(&ctx, typed);
    fields.push(FieldKey::TD_DOMAIN, "", domain)?;
    let (schema_text, action) = schema_name(typed);
    hidden |= escape_untrusted(&typed.primary_type).hidden;
    fields.push(FieldKey::TD_SCHEMA, "", schema_text)?;
    structured_fields(&mut fields, &ctx, typed, &account)?;
    let mut tree = Tree {
        fields: Some(&mut fields),
        leaves: 0,
        exceeded: false,
        hidden: false,
    };
    match &typed.schema {
        None => tree.walk(&typed.root, "", 0)?,
        Some(schema) => {
            if matches!(
                schema,
                KnownSchema::Permit2WitnessTransfer { .. }
                    | KnownSchema::Permit2BatchWitnessTransfer { .. }
            ) && let TdNode::Struct { fields: items, .. } = &typed.root
                && let Some((name, witness)) = items.get(4)
            {
                tree.walk(witness, &escape_inline(name).0, 1)?;
            }
            // The whole message of a recognized schema is still measured against the tree
            // limits (T16, spec/03 §8.4) and its strings checked for hidden characters (T17).
            let mut scan = Tree {
                fields: None,
                leaves: 0,
                exceeded: false,
                hidden: false,
            };
            scan.walk(&typed.root, "", 0)?;
            tree.hidden |= scan.hidden;
            tree.exceeded |= scan.exceeded;
        }
    }
    let (tree_exceeded, tree_hidden) = (tree.exceeded, tree.hidden);
    let truncated = fields.close_truncated()? > 0;
    let exceeded = tree_exceeded || domain_exceeded || truncated;
    hidden |= tree_hidden;
    let mut warnings = typed_rules(
        &TypedRiskInput {
            chain,
            account: &account,
            typed,
            facts,
            now_unix_ms,
        },
        hidden,
    );
    if exceeded {
        warnings.push(risk::warning(T16, None));
    }
    let display = finish_display(title(chain, action), fields, warnings)?;
    Ok(ApprovalDraft {
        id,
        origin,
        chain: chain_ref(chain),
        account: AccountRef::Evm(account),
        signer: Signer::Evm(signer),
        kind,
        payload: SigningPayload::EvmTypedData(typed.preimage),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}
