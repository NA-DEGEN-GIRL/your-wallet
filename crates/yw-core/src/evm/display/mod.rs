//! Approval titles and display-field builders for EVM requests (spec/03 §7.3, §8.3–§8.4, §9.2,
//! §11.1–§11.2).
//!
//! Derived from `archive/spec-v2.4:crates/wallet-protocol/src/authorization.rs:36-325,470-837`
//! (field derivation) and `archive/spec-v2.4:crates/approval-wire/src/lib.rs:231-777` (display
//! model) with v3 changes: decimal units instead of wei hex, no 512/1023-byte rejection (values
//! scroll), typed data allowed, simulation diff and simulation-state warnings added.

pub mod text;
pub mod time;

use super::abi::AbiValue;
use super::address::{Address, to_checksum};
use super::amount::{Delta, U256, format_amount, format_gwei, format_units};
use super::chain::{ChainInfo, OPENSEA_CONDUIT_KEY};
use super::decode::{AMOUNT_OR_TOKEN_ID, DecodedCall, DecodedTx, resolve_token_standard};
use super::eip191::{DecodedPersonalMessage, HexReason, personal_preimage};
use super::eip712::{DecodedTypedData, HlUserAction, KnownSchema, TdNode, TdValue};
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
use crate::lang::Lang;
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
fn escape_value(lang: Lang, text: &str) -> (String, bool) {
    let (inline, hidden) = escape_inline(text);
    let value = escape_edges(&inline);
    if value.is_empty() {
        (text::EMPTY_STRING.get(lang).to_owned(), hidden)
    } else {
        (value, hidden)
    }
}

/// A multi-line message value: edges escaped, and every inner LF marked `[U+000A]` before the
/// break so a message line is visibly part of the message, never a separate row.
fn message_value(lang: Lang, escaped_text: &str) -> String {
    let value = escape_edges(escaped_text);
    if value.is_empty() {
        text::EMPTY_MESSAGE.get(lang).to_owned()
    } else {
        value.replace('\n', "[U+000A]\n")
    }
}

/// Address with registry label, classification, own-account label and address-book label
/// (`✓ 확인됨` for an entry the user verified; spec/03 §2.2, §8.5).
#[must_use]
pub fn describe_address(
    lang: Lang,
    chain: &ChainInfo,
    facts: &ChainFacts,
    address: &Address,
) -> String {
    let mut out = format_address(address);
    let mut note = |text: &str| {
        out.push_str(" [");
        out.push_str(text);
        out.push(']');
    };
    if let Some(label) = chain.label_in(address, lang) {
        note(label);
    } else {
        match facts.code_of(address) {
            Some(CodeKind::Contract) => note(text::NOTE_CONTRACT.get(lang)),
            Some(CodeKind::Eoa) => note(text::NOTE_EOA.get(lang)),
            Some(CodeKind::Delegated7702 { target }) => note(&format!(
                "{}{}",
                text::NOTE_DELEGATED.get(lang),
                format_address(&target)
            )),
            Some(CodeKind::Unknown) => note(text::NOTE_KIND_UNKNOWN.get(lang)),
            None => {}
        }
    }
    if let Some(name) = facts.own_name(address) {
        note(&format!(
            "{}{}",
            text::NOTE_MINE.get(lang),
            escape_inline(name).0
        ));
    }
    if let Some(name) = facts.book_name(address) {
        let verified = if facts.book_verified(address) {
            text::NOTE_VERIFIED.get(lang)
        } else {
            ""
        };
        note(&format!(
            "{}{}{verified}",
            text::NOTE_BOOK.get(lang),
            escape_inline(name).0
        ));
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
    lang: Lang,
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
        Some(decimals) => text::RAW_UNVERIFIED_DECIMALS.fill(
            lang,
            [
                &raw,
                &symbol,
                &decimals.to_string(),
                &format_units(amount, decimals),
            ],
        ),
        None => text::RAW_UNVERIFIED.fill(lang, [&raw, &symbol]),
    }
}

fn native_amount(chain: &ChainInfo, amount: &U256) -> String {
    format_amount(amount, chain.native_decimals, &chain.native_symbol)
}

/// Time display: `YYYY-MM-DD HH:MM:SS UTC (약 N일 후/전)`; ≥ 2^40 → raw + "사실상 만료 없음".
#[must_use]
pub fn format_time(lang: Lang, value: &U256, now_unix_ms: u64) -> String {
    match value.to_u64() {
        Some(seconds) if seconds < NO_EXPIRY_SECONDS => format_utc_relative(
            lang,
            i64::try_from(seconds).unwrap_or(i64::MAX),
            now_unix_ms,
        ),
        _ => text::NO_EXPIRY_RAW.fill(lang, [&value.to_decimal_string()]),
    }
}

fn hex_with_len(lang: Lang, bytes: &[u8]) -> String {
    text::BYTES_HEX.fill(lang, [&crate::hex::encode(bytes), &bytes.len().to_string()])
}

fn substitute(title: &str, chain: &ChainInfo) -> String {
    let wrapped = chain.weth().map_or("?", |token| token.symbol);
    title
        .replace("{native}", &chain.native_symbol)
        .replace("{wrapped}", wrapped)
}

struct Ctx<'a> {
    lang: Lang,
    chain: &'a ChainInfo,
    facts: &'a ChainFacts,
    to: Address,
    now_unix_ms: u64,
}

impl Ctx<'_> {
    fn address(&self, address: &Address) -> String {
        describe_address(self.lang, self.chain, self.facts, address)
    }

    /// An amount; for allowances (`unlimited` = the type maximum) the maximum is "무제한" and
    /// any value of at least 2^128 is marked "사실상 무제한" (E14).
    fn token_amount(&self, token: &Address, amount: &U256, unlimited: Option<U256>) -> String {
        if unlimited == Some(*amount) {
            return text::UNLIMITED.get(self.lang).to_owned();
        }
        let amount_text = format_token_amount(self.lang, self.chain, self.facts, token, amount);
        if unlimited.is_some() && !amount.fits_bits(risk::EFFECTIVELY_UNLIMITED_BITS) {
            text::EFFECTIVELY_UNLIMITED.fill(self.lang, [&amount_text])
        } else {
            amount_text
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
            ("permit2_approve", "expiration") => {
                permit2_expiration(self.lang, value, self.now_unix_ms)
            }
            ("dai_permit_submit", "expiry") if value.is_zero() => {
                text::NO_EXPIRY.get(self.lang).to_owned()
            }
            (_, "deadline" | "expiry") => format_time(self.lang, value, self.now_unix_ms),
            (_, AMOUNT_OR_TOKEN_ID) => {
                text::AMOUNT_OR_TOKEN_ID.fill(self.lang, [&value.to_decimal_string()])
            }
            _ => value.to_decimal_string(),
        }
    }

    fn arg(&self, call: &DecodedCall, kind: &str, name: &str, value: &AbiValue) -> String {
        match value {
            AbiValue::Address(address) => self.address(address),
            AbiValue::Uint(number) => self.uint_arg(call, kind, name, number),
            AbiValue::Bool(flag) => yes_no(self.lang, *flag),
            AbiValue::Bytes(bytes) => hex_with_len(self.lang, bytes),
            AbiValue::Bytes32(bytes) => format!("0x{}", crate::hex::encode(bytes)),
            AbiValue::Array(items) if items.is_empty() => {
                text::NONE_PAREN.get(self.lang).to_owned()
            }
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

fn permit2_expiration(lang: Lang, value: &U256, now_unix_ms: u64) -> String {
    if value.is_zero() {
        text::BLOCK_ONLY.get(lang).to_owned()
    } else if value.to_u64() == Some((1 << 48) - 1) {
        text::NO_EXPIRY.get(lang).to_owned()
    } else {
        format_time(lang, value, now_unix_ms)
    }
}

fn call_title(lang: Lang, call: &DecodedCall, chain: &ChainInfo) -> String {
    match call {
        DecodedCall::NativeTransfer => text::SEND_NATIVE.fill(lang, [&chain.native_symbol]),
        DecodedCall::Known { title, .. } => substitute(title.get(lang), chain),
        DecodedCall::Multicall { inner, .. } => {
            text::MULTICALL.fill(lang, [&inner.len().to_string()])
        }
        DecodedCall::Uninterpreted {
            label: Some(label), ..
        } => text::UNINTERPRETED_LABEL.fill(lang, [label]),
        DecodedCall::Uninterpreted { label: None, .. } => text::UNINTERPRETED.get(lang).to_owned(),
    }
}

fn action_title(ctx: &Ctx<'_>, call: &DecodedCall, value: &U256) -> String {
    let base = call_title(ctx.lang, call, ctx.chain);
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

fn title(lang: Lang, chain: &ChainInfo, action: &str) -> String {
    let name = chain.display_name(lang);
    let full = format!("[{name}] {action}");
    if full.len() <= MAX_TITLE_BYTES {
        return full;
    }
    let mut short = format!("[{name}] ");
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
    fn close_truncated(&mut self, lang: Lang) -> Result<usize, DisplayError> {
        let FieldCap::Truncate { dropped } = self.1 else {
            return Ok(0);
        };
        if dropped > 0 {
            self.0.push(DisplayField::new(
                FieldKey::TD_TREE,
                "",
                text::TREE_TRUNCATED.fill(lang, [&dropped.to_string()]),
            )?);
        }
        Ok(dropped)
    }
}

fn header(
    lang: Lang,
    fields: &mut Fields,
    origin: &ApprovalOrigin,
    chain: &ChainInfo,
    facts: &ChainFacts,
    account: &Address,
) -> Result<(), DisplayError> {
    let origin_text = match origin {
        ApprovalOrigin::App => crate::approval::APP_ORIGIN.get(lang).to_owned(),
        ApprovalOrigin::Site(site) => site.as_str().to_owned(),
    };
    fields.push(FieldKey::ORIGIN, "", origin_text)?;
    fields.push(
        FieldKey::NETWORK,
        "",
        format!("{} (chainId {})", chain.display_name(lang), chain.chain_id),
    )?;
    fields.push(
        FieldKey::ACCOUNT,
        "",
        describe_address(lang, chain, facts, account),
    )
}

fn chain_ref(chain: &ChainInfo) -> ChainRef {
    ChainRef::Evm {
        chain_id: chain.chain_id,
        genesis: chain.genesis_hash().unwrap_or([0; 32]),
    }
}

fn finish_display(
    lang: Lang,
    title_text: String,
    fields: Fields,
    mut warnings: Vec<Warning>,
) -> Result<ApprovalDisplay, DisplayError> {
    sort_warnings(&mut warnings);
    warnings.truncate(MAX_DISPLAY_WARNINGS);
    ApprovalDisplay::new(lang, title_text, fields.0, warnings)
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
        None => return text::SUM_UNAVAILABLE.fill(ctx.lang, [&asset_label(ctx, &change.asset)]),
    };
    match (change.asset, change.token_id) {
        (AssetId::Native, _) => native_amount(ctx.chain, &amount),
        (AssetId::Token(token), None) => {
            let amount_text = format_token_amount(ctx.lang, ctx.chain, ctx.facts, &token, &amount);
            if ctx.chain.token(&token).is_some() {
                amount_text
            } else {
                format!("{amount_text} · {}", format_address(&token))
            }
        }
        // NFTs are never registry assets: any contract can emit their Transfer logs (E40).
        (AssetId::Token(token), Some(id)) if amount == U256::ONE => {
            text::NFT_UNVERIFIED.fill(ctx.lang, [&id.to_decimal_string(), &ctx.address(&token)])
        }
        (AssetId::Token(token), Some(id)) => text::MULTI_UNVERIFIED.fill(
            ctx.lang,
            [
                &id.to_decimal_string(),
                &amount.to_decimal_string(),
                &ctx.address(&token),
            ],
        ),
    }
}

fn approval_row(ctx: &Ctx<'_>, change: &ApprovalChange) -> String {
    let lang = ctx.lang;
    let token = ctx.address(&change.asset);
    let spender = ctx.address(&change.spender);
    match change.kind {
        ApprovalKindEvm::Erc20 { amount } => text::APPROVAL_ERC20.fill(
            lang,
            [
                &token,
                &spender,
                &ctx.token_amount(&change.asset, &amount, Some(U256::MAX)),
            ],
        ),
        ApprovalKindEvm::Erc721 { token_id, revoked } => {
            if revoked {
                text::APPROVAL_721_REVOKED.fill(lang, [&token, &token_id.to_decimal_string()])
            } else {
                text::APPROVAL_721.fill(lang, [&token, &token_id.to_decimal_string(), &spender])
            }
        }
        ApprovalKindEvm::ForAll { approved } => {
            let permission = if approved {
                text::PERMISSION_GRANTED
            } else {
                text::PERMISSION_REVOKED
            };
            text::APPROVAL_FOR_ALL.fill(lang, [&token, &spender, permission.get(lang)])
        }
        ApprovalKindEvm::Permit2 { amount, expiration } => text::APPROVAL_PERMIT2.fill(
            lang,
            [
                &token,
                &spender,
                &ctx.token_amount(&change.asset, &amount, Some(U256::MAX_U160)),
                &permit2_expiration(lang, &U256::from_u64(expiration), ctx.now_unix_ms),
            ],
        ),
        ApprovalKindEvm::Permit2Lockdown => {
            text::APPROVAL_PERMIT2_LOCKDOWN.fill(lang, [&token, &spender])
        }
    }
}

fn simulation_basis(lang: Lang, sim: &SimResult) -> String {
    match sim {
        SimResult::Simulated { diff, .. } => text::SIM_BASIS.fill(
            lang,
            [
                &format_units(&U256::from_u64(diff.block.number), 0),
                &format_utc(i64::try_from(diff.block.timestamp).unwrap_or(i64::MAX)),
            ],
        ),
        SimResult::Unavailable {
            reason: SimNoneReason::Unsupported,
            ..
        } => text::SIM_NONE_UNSUPPORTED.get(lang).to_owned(),
        SimResult::Unavailable {
            reason: SimNoneReason::Skipped,
            ..
        } => text::SIM_NONE_SKIPPED.get(lang).to_owned(),
        SimResult::Unavailable { warning, .. } => {
            let cause = warning
                .as_ref()
                .and_then(|warning| warning.text.split_once('\n'))
                .map_or(text::SIM_NONE_UNKNOWN_CAUSE.get(lang), |(_, cause)| cause);
            text::SIM_NONE.fill(lang, [cause])
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
                        format_time(ctx.lang, deadline, ctx.now_unix_ms)
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
                    call_title(ctx.lang, inner_call, ctx.chain),
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
    lang: Lang,
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
        lang,
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
        lang,
        chain,
        facts,
        to: tx.to,
        now_unix_ms,
    };
    let mut fields = Fields::new();
    header(lang, &mut fields, &origin, chain, facts, &account)?;
    fields.push(FieldKey::TO, "", ctx.address(&tx.to))?;
    fields.push(FieldKey::VALUE, "", native_amount(chain, &tx.value))?;
    fields.push(FieldKey::CALL, "", call_title(lang, &call, chain))?;
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
                text::OTHER_EVENTS.fill(lang, [&diff.other_events.to_string()]),
            )?;
        }
    }
    // spec/03 §3.4a: on an OP-stack chain the L1 data fee is added to both fee lines.
    let l1 = facts.l1_fee;
    let max_fee = max_total_fee(tx.gas_limit, &tx.max_fee_per_gas)
        .and_then(|fee| fee.checked_add(l1.map_or(U256::ZERO, |quote| quote.max)))
        .map_or_else(
            || text::NOT_COMPUTABLE.get(lang).to_owned(),
            |fee| match l1 {
                Some(quote) => text::FEE_WITH_L1_MAX.fill(
                    lang,
                    [
                        &native_amount(chain, &fee),
                        &native_amount(chain, &quote.max),
                    ],
                ),
                None => native_amount(chain, &fee),
            },
        );
    fields.push(FieldKey::MAX_FEE, "", max_fee)?;
    let expected = match sim {
        SimResult::Simulated { diff, .. } => expected_fee(
            diff.gas_used,
            &tx.max_fee_per_gas,
            &diff.block.base_fee,
            &tx.max_priority_fee_per_gas,
        )
        .and_then(|fee| fee.checked_add(l1.map_or(U256::ZERO, |quote| quote.estimate)))
        .map_or_else(
            || text::UNKNOWN.get(lang).to_owned(),
            |fee| match l1 {
                Some(quote) => text::FEE_WITH_L1_ESTIMATE.fill(
                    lang,
                    [
                        &native_amount(chain, &fee),
                        &native_amount(chain, &quote.estimate),
                    ],
                ),
                None => native_amount(chain, &fee),
            },
        ),
        SimResult::Unavailable { .. } => text::UNKNOWN.get(lang).to_owned(),
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
    fields.push(FieldKey::SIMULATION, "", simulation_basis(lang, sim))?;
    if !tx.access_list.is_empty() {
        let slots: usize = tx
            .access_list
            .iter()
            .map(|item| item.storage_keys.len())
            .sum();
        let mut list = text::ACCESS_LIST.fill(
            lang,
            [&tx.access_list.len().to_string(), &slots.to_string()],
        );
        for item in &tx.access_list {
            list.push_str(&text::ACCESS_ITEM.fill(
                lang,
                [
                    &format_address(&item.address),
                    &item.storage_keys.len().to_string(),
                ],
            ));
        }
        fields.push(FieldKey::ACCESS_LIST, "", list)?;
    }
    let calldata = match tx.data.get(..4) {
        None if tx.data.is_empty() => text::CALLDATA_NONE.get(lang).to_owned(),
        Some(selector) => text::CALLDATA.fill(
            lang,
            [
                &tx.data.len().to_string(),
                &crate::hex::encode(selector),
                &crate::hex::encode(&tx.data),
            ],
        ),
        None => hex_with_len(lang, &tx.data),
    };
    fields.push(FieldKey::CALLDATA, "", calldata)?;
    let display = finish_display(
        lang,
        title(lang, chain, &action_title(&ctx, &call, &tx.value)),
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
    let lang = draft.display.lang;
    let old = old_max_total_fee.map_or_else(
        || text::NOT_COMPUTABLE.get(lang).to_owned(),
        |fee| native_amount(chain, &fee),
    );
    let value = text::REPLACES.fill(lang, [&crate::hex::encode(replaced_hash), &old]);
    let field = DisplayField::new(FieldKey::REPLACES, "", value)?;
    let mut fields = draft.display.fields.clone();
    let position = fields
        .iter()
        .position(|existing| existing.key > FieldKey::REPLACES)
        .unwrap_or(fields.len());
    fields.insert(position, field);
    let new_title = match (&draft.kind, &draft.payload) {
        (ApprovalKind::EvmCancel, SigningPayload::EvmTx(tx)) => title(
            lang,
            chain,
            &text::CANCEL_TITLE.fill(lang, [&tx.nonce.to_string()]),
        ),
        _ => draft.display.title.clone(),
    };
    draft.display = ApprovalDisplay::new(lang, new_title, fields, draft.display.warnings.clone())?;
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
    lang: Lang,
    fields: &mut Fields,
    message: &super::siwe::SiweMessage,
    now_unix_ms: u64,
) -> Result<(), DisplayError> {
    let time = |raw: &str, seconds: i64| {
        format!("{raw}\n{}", format_utc_relative(lang, seconds, now_unix_ms))
    };
    let domain = if message.scheme_explicit {
        format!("{}://{}", message.scheme, message.domain)
    } else {
        message.domain.clone()
    };
    let key = FieldKey::SIWE_FIELD;
    fields.push(key, text::SIWE_DOMAIN.get(lang), domain)?;
    fields.push(
        key,
        text::SIWE_ADDRESS.get(lang),
        format_address(&message.address),
    )?;
    if let Some(statement) = &message.statement {
        fields.push(
            key,
            text::SIWE_STATEMENT.get(lang),
            escape_value(lang, statement).0,
        )?;
    }
    fields.push(key, "URI", message.uri.clone())?;
    fields.push(
        key,
        text::SIWE_CHAIN_ID.get(lang),
        message.chain_id.to_string(),
    )?;
    fields.push(key, "Nonce", message.nonce.clone())?;
    fields.push(
        key,
        text::SIWE_ISSUED_AT.get(lang),
        time(&message.issued_at_text, message.issued_at),
    )?;
    if let (Some(raw), Some(seconds)) = (&message.expiration_time_text, message.expiration_time) {
        fields.push(key, text::SIWE_EXPIRATION.get(lang), time(raw, seconds))?;
    }
    if let (Some(raw), Some(seconds)) = (&message.not_before_text, message.not_before) {
        fields.push(key, text::SIWE_NOT_BEFORE.get(lang), time(raw, seconds))?;
    }
    if let Some(request_id) = &message.request_id {
        let value = if request_id.is_empty() {
            text::EMPTY_VALUE.get(lang).to_owned()
        } else {
            request_id.clone()
        };
        fields.push(key, text::SIWE_REQUEST_ID.get(lang), value)?;
    }
    if message.resources_present {
        let value = if message.resources.is_empty() {
            text::NONE_PAREN.get(lang).to_owned()
        } else {
            message.resources.join("\n")
        };
        fields.push(key, text::SIWE_RESOURCES.get(lang), value)?;
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
    lang: Lang,
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
    header(lang, &mut fields, &origin, chain, &facts, &account)?;
    let mut warnings = Vec::new();
    let message_text = message
        .text
        .as_deref()
        .map(|text| message_value(lang, text))
        .filter(|value| value.len() <= crate::approval::MAX_DISPLAY_VALUE_BYTES);
    if message.text.is_some() && message_text.is_none() {
        warnings.push(risk::warning(lang, P02, None));
    }
    if let Some(value) = message_text {
        fields.push(FieldKey::MESSAGE_TEXT, "", value)?;
        if message.escaped {
            warnings.push(risk::warning(lang, P02, None));
        }
    } else {
        // Non-UTF-8 (P01), UTF-8 that looks binary (P04), or UTF-8 whose escaped form exceeds
        // the value limit (P02 above).
        fields.push(FieldKey::MESSAGE_HEX, "", hex_lines(&message.bytes))?;
        match message.hex_reason {
            Some(HexReason::Hash32) => {
                warnings.push(risk::warning(lang, P04, Some(text::HASH32.get(lang))));
            }
            Some(HexReason::Control) => {
                warnings.push(risk::warning(
                    lang,
                    P04,
                    Some(text::CONTROL_CHARS.get(lang)),
                ));
            }
            None if message.text.is_none() => warnings.push(risk::warning(lang, P01, None)),
            None => {}
        }
    }
    fields.push(
        FieldKey::MESSAGE_BYTES,
        "",
        text::BYTES.fill(lang, [&message.bytes.len().to_string()]),
    )?;
    let site = match &origin {
        ApprovalOrigin::Site(site) => Some(site),
        ApprovalOrigin::App => None,
    };
    let context = SiweContext {
        lang,
        origin: site,
        account: &account,
        active_chain_id: chain.chain_id,
        now_unix_ms,
    };
    let action = if let Some(siwe) = &message.siwe {
        siwe_fields(lang, &mut fields, siwe, now_unix_ms)?;
        warnings.extend(check_siwe(siwe, &context));
        text::SIWE_TITLE.get(lang)
    } else {
        if message.siwe_marker_only {
            // S08 plus the first-line domain checks (S01/S02 block; unreadable domain → S01).
            let raw = core::str::from_utf8(&message.bytes).unwrap_or("");
            warnings.extend(check_marker_only(raw, &context));
        } else if message.text.is_some() && !message.escaped {
            warnings.push(risk::warning(lang, P03, None));
        }
        text::MESSAGE_TITLE.get(lang)
    };
    let display = finish_display(lang, title(lang, chain, action), fields, warnings)?;
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
    lang: Lang,
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
            TdValue::Bool(flag) => yes_no(self.lang, *flag),
            TdValue::Bytes(bytes) => {
                if bytes.len() > TREE_MAX_BYTES {
                    self.exceeded = true;
                    return text::OVER_LIMIT_BYTES.fill(self.lang, [&bytes.len().to_string()]);
                }
                hex_with_len(self.lang, bytes)
            }
            TdValue::String(string) => {
                let (value, hidden) = escape_value(self.lang, string);
                self.hidden |= hidden;
                if string.len() > TREE_MAX_STRING {
                    self.exceeded = true;
                    return text::OVER_LIMIT_BYTES.fill(self.lang, [&string.len().to_string()]);
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
    let lang = ctx.lang;
    let mut lines = Vec::new();
    let mut hidden = false;
    let mut exceeded = false;
    if let TdNode::Struct { fields, .. } = &typed.domain.tree {
        for (name, node) in fields {
            let value = match (name.as_str(), node.value()) {
                ("verifyingContract", Some(TdValue::Address(address))) => ctx.address(address),
                (_, Some(TdValue::String(string))) => {
                    let (value, flagged) = escape_inline(string);
                    hidden |= flagged;
                    if string.len() > TREE_MAX_STRING {
                        exceeded = true;
                        text::OVER_LIMIT_BYTES.fill(lang, [&string.len().to_string()])
                    } else if value.is_empty() {
                        text::EMPTY_STRING.get(lang).to_owned()
                    } else {
                        escape_edges(&value)
                    }
                }
                (_, Some(TdValue::Uint(number))) => number.to_decimal_string(),
                (_, Some(TdValue::Address(address))) => format_address(address),
                (_, Some(TdValue::Bytes(bytes))) => format!("0x{}", crate::hex::encode(bytes)),
                (_, Some(TdValue::Bool(flag))) => yes_no(lang, *flag),
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
                (_, None) => text::STRUCT.get(lang).to_owned(),
            };
            lines.push(format!("{name}: {value}"));
        }
    }
    if lines.is_empty() {
        lines.push(text::EMPTY_DOMAIN.get(lang).to_owned());
    }
    (lines.join("\n"), hidden, exceeded)
}

fn schema_name(lang: Lang, typed: &DecodedTypedData) -> (String, &'static str) {
    let (schema, action) = match &typed.schema {
        Some(KnownSchema::Eip2612Permit) => ("EIP-2612 Permit".to_owned(), text::ACTION_PERMIT),
        Some(KnownSchema::DaiPermit) => ("DAI Permit".to_owned(), text::ACTION_DAI_PERMIT),
        Some(KnownSchema::Permit2Single) => {
            ("Permit2 PermitSingle".to_owned(), text::ACTION_PERMIT2)
        }
        Some(KnownSchema::Permit2Batch) => ("Permit2 PermitBatch".to_owned(), text::ACTION_PERMIT2),
        Some(KnownSchema::Permit2Transfer) => (
            "Permit2 PermitTransferFrom".to_owned(),
            text::ACTION_PERMIT2_TRANSFER,
        ),
        Some(KnownSchema::Permit2BatchTransfer) => (
            "Permit2 PermitBatchTransferFrom".to_owned(),
            text::ACTION_PERMIT2_TRANSFER,
        ),
        Some(KnownSchema::Permit2WitnessTransfer { .. }) => (
            "Permit2 PermitWitnessTransferFrom".to_owned(),
            text::ACTION_PERMIT2_WITNESS,
        ),
        Some(KnownSchema::Permit2BatchWitnessTransfer { .. }) => (
            "Permit2 PermitBatchWitnessTransferFrom".to_owned(),
            text::ACTION_PERMIT2_WITNESS,
        ),
        Some(KnownSchema::SeaportOrder) => {
            ("Seaport OrderComponents".to_owned(), text::ACTION_SEAPORT)
        }
        Some(KnownSchema::HyperliquidUser(action)) => (
            format!(
                "Hyperliquid {}{}",
                escape_inline(&typed.primary_type).0,
                if action.interpreted() {
                    ""
                } else {
                    text::HL_UNINTERPRETED_SUFFIX.get(lang)
                }
            ),
            match action {
                HlUserAction::Transfer(_) => text::ACTION_HL_TRANSFER,
                HlUserAction::ApproveAgent => text::ACTION_HL_AGENT,
                HlUserAction::ApproveBuilderFee => text::ACTION_HL_BUILDER,
                HlUserAction::ConvertToMultiSig => text::ACTION_HL_MULTISIG,
                HlUserAction::Unknown => text::ACTION_HL_UNKNOWN,
            },
        ),
        Some(KnownSchema::HyperliquidL1Agent) => (
            "Hyperliquid L1 Agent (chainId 1337)".to_owned(),
            text::ACTION_HL_L1,
        ),
        None => (
            text::UNKNOWN_SCHEMA.fill(lang, [&escape_inline(&typed.primary_type).0]),
            text::TYPED_TITLE,
        ),
    };
    (schema, action.get(lang))
}

fn yes_no(lang: Lang, flag: bool) -> String {
    if flag { text::YES } else { text::NO }.get(lang).to_owned()
}

/// The fields of a recognized Hyperliquid user-signed action (spec/11 §7), in the SDK order.
fn hyperliquid_fields(
    fields: &mut Fields,
    ctx: &Ctx<'_>,
    root: &TdNode,
    action: HlUserAction,
    account: &Address,
) -> Result<(), DisplayError> {
    let lang = ctx.lang;
    let string = |name: &str| root.field(name).and_then(TdNode::string);
    let kind = match action {
        HlUserAction::Transfer(kind) => Some(kind),
        _ => None,
    };
    let check = kind.map(|kind| {
        crate::hypercore::display::site_transfer_check(
            kind,
            root,
            account,
            ctx.facts.hyperliquid.as_ref(),
        )
    });
    let name = match action {
        HlUserAction::Transfer(kind) => crate::hypercore::text::kind_name(lang, kind),
        HlUserAction::ApproveAgent => text::HL_AGENT.get(lang),
        HlUserAction::ApproveBuilderFee => text::HL_BUILDER.get(lang),
        HlUserAction::ConvertToMultiSig => text::HL_MULTISIG.get(lang),
        HlUserAction::Unknown => text::HL_UNKNOWN.get(lang),
    };
    fields.push(
        FieldKey::TD_FIELD,
        text::TD_ACTION.get(lang),
        name.to_owned(),
    )?;
    // Not interpreted: the message follows as the plain field tree (every field, nested ones
    // included); `convertToMultiSigUser` also gets its `signers` read out.
    if !action.interpreted() {
        if action == HlUserAction::ConvertToMultiSig
            && let Some(signers) = string("signers")
        {
            fields.push(
                FieldKey::TD_FIELD,
                text::TD_SIGNERS.get(lang),
                hl_signers(lang, signers),
            )?;
        }
        return Ok(());
    }
    let network = match string("hyperliquidChain") {
        Some("Mainnet") => text::HL_MAINNET.get(lang).to_owned(),
        Some("Testnet") => text::HL_TESTNET.get(lang).to_owned(),
        Some(other) => text::UNKNOWN_WITH.fill(lang, [&escape_inline(other).0]),
        None => text::NONE.get(lang).to_owned(),
    };
    fields.push(FieldKey::TD_FIELD, "hyperliquidChain", network)?;
    let usd = matches!(
        action,
        HlUserAction::Transfer(
            crate::hypercore::HcKind::UsdSend
                | crate::hypercore::HcKind::Withdraw
                | crate::hypercore::HcKind::UsdClassTransfer
        )
    );
    let withdraw = action == HlUserAction::Transfer(crate::hypercore::HcKind::Withdraw);
    let TdNode::Struct { fields: items, .. } = root else {
        return Ok(());
    };
    for (key, node) in items {
        let value = match (key.as_str(), node.value()) {
            ("hyperliquidChain", _) => continue,
            ("destination", Some(TdValue::String(destination))) => {
                let mut out =
                    hl_destination(lang, destination, account, kind, check.as_ref(), ctx.facts);
                if withdraw {
                    out.push_str(text::HL_WITHDRAW_DESTINATION.get(lang));
                }
                out
            }
            ("amount", Some(TdValue::String(amount))) if withdraw => text::HL_WITHDRAW_AMOUNT.fill(
                lang,
                [
                    &escape_inline(amount).0,
                    crate::hypercore::WITHDRAW_FEE_USDC,
                    &crate::hypercore::display::withdraw_arrival(amount),
                ],
            ),
            ("amount", Some(TdValue::String(amount))) if usd => {
                format!("{} USDC", escape_inline(amount).0)
            }
            ("toPerp", Some(TdValue::Bool(to_perp))) => if *to_perp {
                text::HL_SPOT_TO_PERP
            } else {
                text::HL_PERP_TO_SPOT
            }
            .get(lang)
            .to_owned(),
            (_, Some(TdValue::Address(address))) => ctx.address(address),
            (_, Some(TdValue::String(value))) if value.is_empty() => {
                text::EMPTY_STRING.get(lang).to_owned()
            }
            (_, Some(TdValue::String(value))) => escape_inline(value).0,
            (_, Some(TdValue::Uint(number))) => number.to_decimal_string(),
            (_, Some(TdValue::Bool(flag))) => yes_no(lang, *flag),
            _ => continue,
        };
        fields.push(FieldKey::TD_FIELD, &escape_inline(key).0, value)?;
    }
    Ok(())
}

/// The `signers` of `convertToMultiSigUser` (SDK: the JSON text `{"authorizedUsers": [...],
/// "threshold": n}`): the threshold and every address, or the escaped text when it is not that.
fn hl_signers(lang: Lang, signers: &str) -> String {
    let parsed = yw_json::parse(signers.as_bytes(), &yw_json::Limits::REQUEST)
        .ok()
        .and_then(|value| {
            let object = value.as_object()?;
            let threshold = object
                .get("threshold")?
                .as_number()
                .and_then(yw_json::Number::as_u64)?;
            let users = object
                .get("authorizedUsers")?
                .as_array()?
                .iter()
                .map(|user| {
                    user.as_str()
                        .and_then(|user| super::address::parse_address(user).ok())
                })
                .collect::<Option<Vec<Address>>>()?;
            Some((threshold, users))
        });
    match parsed {
        Some((threshold, users)) => {
            let mut out =
                text::HL_SIGNERS.fill(lang, [&users.len().to_string(), &threshold.to_string()]);
            for user in &users {
                out.push('\n');
                out.push_str(&format_address(user));
            }
            out
        }
        None => text::HL_SIGNERS_UNREADABLE.fill(lang, [&escape_inline(signers).0]),
    }
}

/// A Hyperliquid `destination` (spec/11 §7): the full address with the app's `HyperCore` notes —
/// never this EVM chain's code classification (a `HyperCore` account is not checked by
/// `eth_getCode`, so no "일반 계정(EOA)" reassurance). A system address gets the reason of its
/// rule: the move (H04), not spot → spot from the signer itself (H14), another token's or an
/// unconfirmed token's address (H13), or a kind without a token.
fn hl_destination(
    lang: Lang,
    destination: &str,
    account: &Address,
    kind: Option<crate::hypercore::HcKind>,
    check: Option<&crate::hypercore::display::HlSiteCheck>,
    facts: &ChainFacts,
) -> String {
    let Ok(address) = super::address::parse_address(destination) else {
        return text::HL_NOT_ADDRESS.fill(lang, [&escape_inline(destination).0]);
    };
    let mut out = format_address(&address);
    let system = crate::hypercore::system_address_index(&address).is_some()
        || address == crate::hypercore::HYPE_SYSTEM_ADDRESS;
    if check.is_some_and(|check| check.evm_move) {
        out.push_str(text::HL_EVM_MOVE.get(lang));
        return out;
    }
    if system {
        let token = check.and_then(|check| check.token.as_ref());
        let with_token = matches!(
            kind,
            Some(crate::hypercore::HcKind::SpotSend | crate::hypercore::HcKind::SendAsset)
        );
        out.push_str(
            match token {
                Some(token) if token.evm.is_some() && token.system_address() == address => {
                    text::HL_SYSTEM_NOT_SPOT
                }
                Some(_) => text::HL_SYSTEM_OTHER_TOKEN,
                None if with_token => text::HL_SYSTEM_UNCONFIRMED,
                None => text::HL_SYSTEM,
            }
            .get(lang),
        );
        return out;
    }
    if address == *account {
        out.push_str(text::HL_SELF.get(lang));
        return out;
    }
    match facts
        .hyperliquid
        .as_ref()
        .and_then(|hl| hl.recipient.as_ref())
    {
        Some(recipient) => {
            for note in &recipient.notes {
                out.push('\n');
                out.push_str(&escape_inline(note).0);
            }
        }
        None => out.push_str(text::HL_NO_BOOK.get(lang)),
    }
    out
}

fn seaport_item(ctx: &Ctx<'_>, item: &TdNode) -> String {
    let lang = ctx.lang;
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
        Some(1) => format_token_amount(lang, ctx.chain, ctx.facts, &token, amount),
        _ => amount.to_decimal_string(),
    };
    let quantity = if start == end {
        amount_text(&start)
    } else {
        text::SEAPORT_RANGE.fill(lang, [&amount_text(&start), &amount_text(&end)])
    };
    let mut out = match uint("itemType").to_u64() {
        Some(0) => quantity,
        Some(1) => format!("{quantity} · {}", ctx.address(&token)),
        Some(2) => format!("NFT #{} · {}", id.to_decimal_string(), ctx.address(&token)),
        Some(3) => format!(
            "{} × {quantity} · {}",
            id.to_decimal_string(),
            ctx.address(&token)
        ),
        Some(4 | 5) if id.is_zero() => {
            text::SEAPORT_ANY_TOKEN.fill(lang, [&quantity, &ctx.address(&token)])
        }
        Some(4 | 5) => text::SEAPORT_CRITERIA.fill(
            lang,
            [
                &crate::hex::encode(id.as_be_bytes()),
                &quantity,
                &ctx.address(&token),
            ],
        ),
        _ => text::SEAPORT_UNKNOWN_ITEM.fill(lang, [&uint("itemType").to_decimal_string()]),
    };
    if let Some(recipient) = item.field("recipient").and_then(TdNode::address) {
        out.push_str(text::SEAPORT_RECIPIENT.get(lang));
        out.push_str(&ctx.address(&recipient));
    }
    out
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
    let lang = ctx.lang;
    let label = |text: crate::lang::Text| text.get(lang);
    let item_label = |prefix: &str, text: crate::lang::Text| format!("{prefix}{}", text.get(lang));
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
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_TOKEN),
                    ctx.address(&token),
                )?;
            }
            push_address(fields, label(text::TD_OWNER), "owner")?;
            push_address(fields, label(text::TD_SPENDER), "spender")?;
            if let (Some(token), Some(value)) = (token, uint("value")) {
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_AMOUNT),
                    ctx.token_amount(&token, &value, Some(U256::MAX)),
                )?;
            }
            if let Some(nonce) = uint("nonce") {
                fields.push(FieldKey::TD_FIELD, "nonce", nonce.to_decimal_string())?;
            }
            if let Some(deadline) = uint("deadline") {
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_DEADLINE),
                    format_time(lang, &deadline, ctx.now_unix_ms),
                )?;
            }
        }
        KnownSchema::DaiPermit => {
            push_address(fields, label(text::TD_OWNER), "holder")?;
            push_address(fields, label(text::TD_SPENDER), "spender")?;
            if let Some(nonce) = uint("nonce") {
                fields.push(FieldKey::TD_FIELD, "nonce", nonce.to_decimal_string())?;
            }
            if let Some(expiry) = uint("expiry") {
                let value = if expiry.is_zero() {
                    text::NO_EXPIRY.get(lang).to_owned()
                } else {
                    format_time(lang, &expiry, ctx.now_unix_ms)
                };
                fields.push(FieldKey::TD_FIELD, label(text::TD_DEADLINE), value)?;
            }
            if let Some(allowed) = root.field("allowed").and_then(TdNode::boolean) {
                let value = if allowed {
                    text::DAI_ALLOWED
                } else {
                    text::DAI_REVOKED
                };
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_ALLOWED),
                    value.get(lang).to_owned(),
                )?;
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
                    text::TD_ITEM.fill(lang, [&index.saturating_add(1).to_string()])
                } else {
                    String::new()
                };
                let token = detail.field("token").and_then(TdNode::address);
                if let Some(token) = token {
                    fields.push(
                        FieldKey::TD_FIELD,
                        &item_label(&prefix, text::TD_TOKEN),
                        ctx.address(&token),
                    )?;
                    if let Some(amount) = detail.field("amount").and_then(TdNode::uint) {
                        fields.push(
                            FieldKey::TD_FIELD,
                            &item_label(&prefix, text::TD_AMOUNT),
                            ctx.token_amount(&token, &amount, Some(U256::MAX_U160)),
                        )?;
                    }
                }
                if let Some(expiration) = detail.field("expiration").and_then(TdNode::uint) {
                    fields.push(
                        FieldKey::TD_FIELD,
                        &item_label(&prefix, text::TD_ALLOWANCE_EXPIRY),
                        permit2_expiration(lang, &expiration, ctx.now_unix_ms),
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
            push_address(fields, label(text::TD_SPENDER), "spender")?;
            if let Some(deadline) = uint("sigDeadline") {
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_SIG_DEADLINE),
                    format_time(lang, &deadline, ctx.now_unix_ms),
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
                    text::TD_ITEM.fill(lang, [&index.saturating_add(1).to_string()])
                } else {
                    String::new()
                };
                if let Some(token) = permitted.field("token").and_then(TdNode::address) {
                    fields.push(
                        FieldKey::TD_FIELD,
                        &item_label(&prefix, text::TD_TOKEN),
                        ctx.address(&token),
                    )?;
                    if let Some(amount) = permitted.field("amount").and_then(TdNode::uint) {
                        fields.push(
                            FieldKey::TD_FIELD,
                            &item_label(&prefix, text::TD_AMOUNT),
                            ctx.token_amount(&token, &amount, None),
                        )?;
                    }
                }
            }
            push_address(fields, label(text::TD_SPENDER), "spender")?;
            if let Some(nonce) = uint("nonce") {
                fields.push(FieldKey::TD_FIELD, "nonce", nonce.to_decimal_string())?;
            }
            if let Some(deadline) = uint("deadline") {
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_DEADLINE),
                    format_time(lang, &deadline, ctx.now_unix_ms),
                )?;
            }
            fields.push(
                FieldKey::TD_FIELD,
                label(text::TD_NOTE),
                text::PERMIT2_TRANSFER_NOTE.get(lang).to_owned(),
            )?;
            if let KnownSchema::Permit2WitnessTransfer { witness_type }
            | KnownSchema::Permit2BatchWitnessTransfer { witness_type } = schema
            {
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_WITNESS),
                    escape_inline(witness_type).0,
                )?;
            }
        }
        KnownSchema::HyperliquidUser(action) => {
            hyperliquid_fields(fields, ctx, root, *action, account)?;
        }
        KnownSchema::HyperliquidL1Agent => {
            let network = match root.field("source").and_then(TdNode::string) {
                Some("a") => text::HL_L1_MAINNET.get(lang).to_owned(),
                Some("b") => text::HL_L1_TESTNET.get(lang).to_owned(),
                Some(other) => text::HL_L1_UNKNOWN_SOURCE.fill(lang, [&escape_inline(other).0]),
                None => text::UNKNOWN.get(lang).to_owned(),
            };
            fields.push(FieldKey::TD_FIELD, label(text::TD_NETWORK), network)?;
            if let Some(hash) = root.field("connectionId").and_then(TdNode::bytes) {
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_ACTION_HASH),
                    text::HL_L1_HASH.fill(lang, [&crate::hex::encode(hash)]),
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
                    label(text::TD_START),
                    format_time(lang, &start, ctx.now_unix_ms),
                )?;
            }
            if let Some(end) = uint("endTime") {
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_END),
                    format_time(lang, &end, ctx.now_unix_ms),
                )?;
            }
            let offer = root
                .field("offer")
                .and_then(TdNode::elements)
                .unwrap_or(&[]);
            for item in offer {
                fields.push(
                    FieldKey::TD_FIELD,
                    label(text::TD_YOU_GIVE),
                    seaport_item(ctx, item),
                )?;
            }
            let consideration = root
                .field("consideration")
                .and_then(TdNode::elements)
                .unwrap_or(&[]);
            for item in consideration {
                let mine = item.field("recipient").and_then(TdNode::address) == Some(*account);
                let receiver = if mine {
                    text::TD_YOU_RECEIVE
                } else {
                    text::TD_OTHERS_RECEIVE
                };
                fields.push(FieldKey::TD_FIELD, label(receiver), seaport_item(ctx, item))?;
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
    lang: Lang,
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
        lang,
        chain,
        facts,
        to: typed
            .domain
            .verifying_contract
            .unwrap_or_else(|| Address::from_bytes([0; 20])),
        now_unix_ms,
    };
    let mut fields = Fields::truncating();
    header(lang, &mut fields, &origin, chain, facts, &account)?;
    let (domain, mut hidden, domain_exceeded) = domain_text(&ctx, typed);
    fields.push(FieldKey::TD_DOMAIN, "", domain)?;
    let (schema_text, action) = schema_name(lang, typed);
    hidden |= escape_untrusted(&typed.primary_type).hidden;
    fields.push(FieldKey::TD_SCHEMA, "", schema_text)?;
    structured_fields(&mut fields, &ctx, typed, &account)?;
    let mut tree = Tree {
        lang,
        fields: Some(&mut fields),
        leaves: 0,
        exceeded: false,
        hidden: false,
    };
    match &typed.schema {
        // Recognized by name only (a Hyperliquid action not interpreted): every field is shown,
        // as for an unknown schema.
        None => tree.walk(&typed.root, "", 0)?,
        Some(schema) if schema.is_uninterpreted() => tree.walk(&typed.root, "", 0)?,
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
                lang,
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
    let truncated = fields.close_truncated(lang)? > 0;
    let exceeded = tree_exceeded || domain_exceeded || truncated;
    hidden |= tree_hidden;
    let mut warnings = typed_rules(
        &TypedRiskInput {
            lang,
            chain,
            account: &account,
            typed,
            facts,
            now_unix_ms,
        },
        hidden,
    );
    if exceeded {
        warnings.push(risk::warning(lang, T16, None));
    }
    let display = finish_display(lang, title(lang, chain, action), fields, warnings)?;
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
