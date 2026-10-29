//! Response validation (spec/06 §5): HTTP and envelope, the strict content schema, forbidden
//! content, and the consistency check against the trusted sets of the input. Pure (no network).

use yw_json::{Limits, Object, Value};

use super::input::{CriticalAction, ExplainInput, TrustedSets, hex_tokens, norm, number_tokens};
use super::{ExplainError, HiddenReason, MAX_RESPONSE_BODY, MismatchReason};

const ENVELOPE_LIMITS: Limits = Limits {
    max_bytes: MAX_RESPONSE_BODY,
    max_depth: 32,
    max_nodes: 16_384,
    max_items: 16_384,
};
const SUMMARY_MAX: usize = 400;
const UNKNOWNS_MAX: usize = 5;
const UNKNOWN_MAX: usize = 200;
const ACTIONS_MAX: usize = 8;
const ASSET_MAX_BYTES: usize = 42;
const AMOUNT_MAX_BYTES: usize = 80;
/// Verdict and reassurance expressions (§5.2), already in [`verdict_norm`] form: they are
/// matched against the normalized text (whitespace and punctuation removed, lowercase), so
/// `안 전`, `S.A.F.E` or `no-risk` match too. This is a safety filter: a false positive only
/// hides the reference text.
const VERDICTS: [&str; 25] = [
    "안전",
    "정상",
    "신뢰",
    "믿을수",
    "문제없",
    "괜찮",
    "승인해도",
    "승인하세요",
    "승인하십시오",
    "서명해도",
    "서명하세요",
    "위험이없",
    "위험없",
    "위험하지않",
    "무해",
    "안심",
    "검증된",
    "공식",
    "safe",
    "harmless",
    "legit",
    "trusted",
    "verified",
    "norisk",
    "risk free",
];

/// The action type enum (§4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionType {
    /// `send`.
    Send,
    /// `receive`.
    Receive,
    /// `approve`.
    Approve,
    /// `revoke_approval`.
    RevokeApproval,
    /// `approve_all`.
    ApproveAll,
    /// `permit`.
    Permit,
    /// `sign_in`.
    SignIn,
    /// `sign_message`.
    SignMessage,
    /// `contract_call`.
    ContractCall,
    /// `other`.
    Other,
}

impl ActionType {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "send" => Self::Send,
            "receive" => Self::Receive,
            "approve" => Self::Approve,
            "revoke_approval" => Self::RevokeApproval,
            "approve_all" => Self::ApproveAll,
            "permit" => Self::Permit,
            "sign_in" => Self::SignIn,
            "sign_message" => Self::SignMessage,
            "contract_call" => Self::ContractCall,
            "other" => Self::Other,
            _ => return None,
        })
    }

    /// The fixed Korean label (§6).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Send => "보냄",
            Self::Receive => "받음",
            Self::Approve => "사용 권한 부여",
            Self::RevokeApproval => "권한 취소",
            Self::ApproveAll => "전체 권한 부여",
            Self::Permit => "권한 서명(permit)",
            Self::SignIn => "로그인 서명",
            Self::SignMessage => "메시지 서명",
            Self::ContractCall => "컨트랙트 호출",
            Self::Other => "기타",
        }
    }
}

/// One validated action: every field passed the consistency check.
#[derive(Clone, PartialEq, Eq)]
pub struct ExplainAction {
    /// Type.
    pub kind: ActionType,
    /// `""`, `native` or a lowercase token address (∈ `S`).
    pub asset: String,
    /// `norm(amount)` (∈ `M`), `무제한`, or `""`.
    pub amount: String,
    /// Sender (∈ `A`).
    pub from: Option<[u8; 20]>,
    /// Receiver (∈ `A`).
    pub to: Option<[u8; 20]>,
}

impl core::fmt::Debug for ExplainAction {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ExplainAction")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// A validated explanation. `Debug` prints sizes only (§8).
#[derive(Clone, PartialEq, Eq)]
pub struct Explanation {
    /// Summary (allowlisted characters; LF allowed).
    pub summary: String,
    /// Actions.
    pub actions: Vec<ExplainAction>,
    /// What the model could not determine.
    pub unknowns: Vec<String>,
}

impl core::fmt::Debug for Explanation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Explanation")
            .field("summary_chars", &self.summary.chars().count())
            .field("actions", &self.actions.len())
            .field("unknowns", &self.unknowns.len())
            .finish()
    }
}

struct RawAction {
    kind: ActionType,
    asset: String,
    amount: String,
    from: String,
    to: String,
}

fn scalars(text: &str) -> usize {
    text.chars().count()
}

fn address_bytes(text: &str) -> Option<[u8; 20]> {
    let digits = text.strip_prefix("0x")?;
    if digits.len() != 40 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    yw_core::hex::decode_array::<20>(&digits.to_ascii_lowercase()).ok()
}

/// §5.1: status, `Content-Type`, size, strict parse, `choices[0]`.
fn envelope_content(
    status: u16,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<String, ExplainError> {
    if status != 200 {
        return Err(ExplainError::Http(status));
    }
    let json_type = content_type.is_some_and(|value| {
        value
            .get(..16)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/json"))
    });
    if !json_type {
        return Err(ExplainError::Envelope);
    }
    if body.len() > MAX_RESPONSE_BODY {
        return Err(ExplainError::TooLarge);
    }
    let root = yw_json::parse(body, &ENVELOPE_LIMITS).map_err(|_| ExplainError::Envelope)?;
    let first = root
        .as_object()
        .and_then(|object| object.get("choices"))
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(Value::as_object)
        .ok_or(ExplainError::Envelope)?;
    let message = first
        .get("message")
        .and_then(Value::as_object)
        .ok_or(ExplainError::Envelope)?;
    if message.get("refusal").and_then(Value::as_str).is_some() {
        return Err(ExplainError::Refusal);
    }
    if matches!(
        first.get("finish_reason").and_then(Value::as_str),
        Some("length" | "content_filter")
    ) {
        return Err(ExplainError::Truncated);
    }
    message
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ExplainError::Envelope)
}

fn exact_keys(object: &Object, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.get(key).is_some())
}

fn string_field(object: &Object, key: &str) -> Result<String, ExplainError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ExplainError::Schema)
}

/// §5.2 first paragraph: the content is exactly the schema of §4.5 with the length limits.
fn schema(content: &str) -> Result<(String, Vec<RawAction>, Vec<String>), ExplainError> {
    let trimmed = content.trim_matches(|character: char| character.is_ascii_whitespace());
    let value =
        yw_json::parse(trimmed.as_bytes(), &ENVELOPE_LIMITS).map_err(|_| ExplainError::Schema)?;
    let object = value.as_object().ok_or(ExplainError::Schema)?;
    if !exact_keys(object, &["summary", "actions", "unknowns"]) {
        return Err(ExplainError::Schema);
    }
    let summary = string_field(object, "summary")?;
    if !(1..=SUMMARY_MAX).contains(&scalars(&summary)) {
        return Err(ExplainError::Schema);
    }
    let unknowns_value = object
        .get("unknowns")
        .and_then(Value::as_array)
        .ok_or(ExplainError::Schema)?;
    if unknowns_value.len() > UNKNOWNS_MAX {
        return Err(ExplainError::Schema);
    }
    let mut unknowns = Vec::with_capacity(unknowns_value.len());
    for item in unknowns_value {
        let text = item.as_str().ok_or(ExplainError::Schema)?;
        if !(1..=UNKNOWN_MAX).contains(&scalars(text)) {
            return Err(ExplainError::Schema);
        }
        unknowns.push(text.to_owned());
    }
    let actions_value = object
        .get("actions")
        .and_then(Value::as_array)
        .ok_or(ExplainError::Schema)?;
    if actions_value.len() > ACTIONS_MAX {
        return Err(ExplainError::Schema);
    }
    let mut actions = Vec::with_capacity(actions_value.len());
    for item in actions_value {
        let action = item.as_object().ok_or(ExplainError::Schema)?;
        if !exact_keys(action, &["type", "asset", "amount", "from", "to"]) {
            return Err(ExplainError::Schema);
        }
        let kind = ActionType::parse(&string_field(action, "type")?).ok_or(ExplainError::Schema)?;
        let asset = string_field(action, "asset")?;
        let amount = string_field(action, "amount")?;
        let from = string_field(action, "from")?;
        let to = string_field(action, "to")?;
        let address_ok = |text: &str| text.is_empty() || address_bytes(text).is_some();
        if asset.len() > ASSET_MAX_BYTES
            || amount.len() > AMOUNT_MAX_BYTES
            || !address_ok(&from)
            || !address_ok(&to)
        {
            return Err(ExplainError::Schema);
        }
        actions.push(RawAction {
            kind,
            asset,
            amount,
            from,
            to,
        });
    }
    Ok((summary, actions, unknowns))
}

/// The output character allowlist (§5.2): U+0020–U+007E, Hangul syllables, and a few
/// punctuation marks; LF only in the summary.
fn allowed(character: char, summary: bool) -> bool {
    matches!(
        character,
        '\u{20}'..='\u{7E}'
            | '\u{AC00}'..='\u{D7A3}'
            | '\u{B7}'
            | '\u{2013}'
            | '\u{2014}'
            | '\u{2018}'
            | '\u{2019}'
            | '\u{201C}'
            | '\u{201D}'
            | '\u{2026}'
            | '\u{2190}'
            | '\u{2192}'
    ) || (summary && character == '\n')
}

fn has_link(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("://") || lower.contains("www.")
}

/// The verdict-matching form of `text` (§5.2): every character that is not a letter or digit
/// (whitespace, punctuation, symbols) removed, the rest lowercased.
#[must_use]
pub fn verdict_norm(text: &str) -> String {
    text.chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn has_verdict(text: &str) -> bool {
    let normalized = verdict_norm(text);
    VERDICTS
        .iter()
        .any(|word| normalized.contains(&verdict_norm(word)))
}

/// §5.2 second paragraph.
fn forbidden(
    summary: &str,
    actions: &[RawAction],
    unknowns: &[String],
) -> Result<(), HiddenReason> {
    let action_strings = actions.iter().flat_map(|action| {
        [
            action.asset.as_str(),
            action.amount.as_str(),
            action.from.as_str(),
            action.to.as_str(),
        ]
    });
    let summary_ok = summary.chars().all(|character| allowed(character, true));
    let others_ok = unknowns
        .iter()
        .map(String::as_str)
        .chain(action_strings)
        .all(|text| text.chars().all(|character| allowed(character, false)));
    if !summary_ok || !others_ok {
        return Err(HiddenReason::ForbiddenChar);
    }
    let texts = || core::iter::once(summary).chain(unknowns.iter().map(String::as_str));
    if texts().any(has_link) {
        return Err(HiddenReason::Link);
    }
    if texts().any(has_verdict) {
        return Err(HiddenReason::Verdict);
    }
    Ok(())
}

fn asset_key(asset: &str) -> String {
    if asset.starts_with("0x") {
        asset.to_ascii_lowercase()
    } else {
        asset.to_owned()
    }
}

/// §5.3: every action value, hex token and significant number must come from the input.
fn consistent(
    trusted: &TrustedSets,
    summary: &str,
    actions: Vec<RawAction>,
    unknowns: &[String],
) -> Result<Vec<ExplainAction>, MismatchReason> {
    let mut out = Vec::with_capacity(actions.len());
    for action in actions {
        let asset = asset_key(&action.asset);
        if !asset.is_empty() && !trusted.has_asset(&asset) {
            return Err(MismatchReason::ActionAsset);
        }
        let amount = if action.amount.is_empty() {
            String::new()
        } else {
            let normalized = norm(&action.amount);
            if !trusted.has_amount(&normalized) {
                return Err(MismatchReason::ActionAmount);
            }
            normalized
        };
        let address = |text: &str| -> Result<Option<[u8; 20]>, MismatchReason> {
            if text.is_empty() {
                return Ok(None);
            }
            match address_bytes(text) {
                Some(bytes) if trusted.has_address(&bytes) => Ok(Some(bytes)),
                _ => Err(MismatchReason::ActionAddress),
            }
        };
        out.push(ExplainAction {
            kind: action.kind,
            asset,
            amount,
            from: address(&action.from)?,
            to: address(&action.to)?,
        });
    }
    for text in core::iter::once(summary).chain(unknowns.iter().map(String::as_str)) {
        for (start, end) in hex_tokens(text) {
            let token = text.get(start..end).unwrap_or("");
            let ok = match address_bytes(token) {
                Some(bytes) => trusted.has_address(&bytes),
                None => trusted.has_hex(&token.to_ascii_lowercase()),
            };
            if !ok {
                return Err(MismatchReason::HexToken);
            }
        }
        // Every number, however short: a one- or two-digit value ("5 ETH", "1개") is checked
        // like a long one. Numbers the wallet writes as trusted values (call kinds such as
        // `erc20_transfer`, token standards, decimals, the chain id) are in `D`; the panel's own
        // lines (action lines, the footer's seconds) are built locally and never checked here.
        for token in number_tokens(text) {
            if !trusted.has_number(&norm(&token)) {
                return Err(MismatchReason::NumberToken);
            }
        }
    }
    Ok(out)
}

/// Action types that count as mentioning `critical`.
const fn mentioning_types(critical: CriticalAction) -> &'static [ActionType] {
    match critical {
        CriticalAction::Approval => &[
            ActionType::Approve,
            ActionType::ApproveAll,
            ActionType::Permit,
        ],
        CriticalAction::Permit => &[ActionType::Permit, ActionType::Approve],
        CriticalAction::ApprovalForAll => &[ActionType::ApproveAll],
        CriticalAction::Transfer => &[ActionType::Send],
    }
}

/// Summary words (in [`verdict_norm`] form) that count as mentioning `critical`.
const fn mentioning_words(critical: CriticalAction) -> &'static [&'static str] {
    match critical {
        CriticalAction::Approval => &["승인", "허용", "권한", "허가", "approv", "allowance"],
        CriticalAction::Permit => &[
            "permit",
            "서명허가",
            "허가",
            "권한",
            "승인",
            "허용",
            "approv",
            "allowance",
        ],
        CriticalAction::ApprovalForAll => &[
            "setapprovalforall",
            "approvalforall",
            "approveall",
            "전체승인",
            "전체권한",
            "컬렉션전체",
            "모든nft",
            "전체nft",
            "모든토큰",
            "모든자산",
            "모든권한",
            "allnft",
        ],
        CriticalAction::Transfer => &[
            "전송", "이체", "보내", "보냅", "보낸", "보낼", "송금", "이동", "출금", "지불", "나갑",
            "transfer", "send", "sent", "pay",
        ],
    }
}

/// Structural consistency: the effects of the request (from the wallet's own decoding,
/// [`ExplainInput::critical`]) that neither an action of a matching type nor a matching word of
/// the normalized summary mentions. Non-empty means the explanation is inconsistent: it is
/// labelled "설명 불일치 — 무시하세요" and folded away (`panel`).
#[must_use]
pub fn omitted_actions(input: &ExplainInput, explanation: &Explanation) -> Vec<CriticalAction> {
    let summary = verdict_norm(&explanation.summary);
    input
        .critical()
        .iter()
        .copied()
        .filter(|critical| {
            let by_type = explanation
                .actions
                .iter()
                .any(|action| mentioning_types(*critical).contains(&action.kind));
            let by_word = mentioning_words(*critical)
                .iter()
                .any(|word| summary.contains(word));
            !by_type && !by_word
        })
        .collect()
}

/// The whole of §5 for one HTTP response. No network.
///
/// # Errors
///
/// The [`ExplainError`] of the first failed rule.
pub fn parse_response(
    status: u16,
    content_type: Option<&str>,
    body: &[u8],
    input: &ExplainInput,
) -> Result<Explanation, ExplainError> {
    let content = envelope_content(status, content_type, body)?;
    let (summary, actions, unknowns) = schema(&content)?;
    forbidden(&summary, &actions, &unknowns).map_err(ExplainError::Hidden)?;
    let actions = consistent(input.trusted(), &summary, actions, &unknowns)
        .map_err(ExplainError::Mismatch)?;
    Ok(Explanation {
        summary,
        actions,
        unknowns,
    })
}
