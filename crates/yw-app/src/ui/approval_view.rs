//! The A01 content model (spec/04 §3.2–§3.3): which fields go to the fixed header, the fixed
//! simulation band, and the scrolling summary / asset-change / warnings + acknowledgement /
//! critical-field areas and the folded 자세히 (non-critical fields and raw data). Pure, so AP-4/AP-6 are tested without windows; `ui::approval_window` paints it.

use core::fmt::Write as _;

use yw_core::approval::{ApprovalRequest, DisplayField, FieldKey, RiskLevel, RuleId, Warning};
use yw_core::evm::display::text as evm_text;
use yw_core::evm::risk::{
    E01, E02, E03, E04, E07, E08, E09, E28, E29, E36, H01, M04, P03, S09, W08,
};
use yw_core::evm::text as call_text;
use yw_core::lang::{Lang, Text, Tpl};

/// Information lines that restate the summary (`HyperCore` user action, ownership proof, SIWE,
/// SIWS, message signature): one muted line of the summary card instead of their own boxes
/// (2026-11-10). C04 (the `WalletConnect` Verify caution) is not one of them.
const RESTATING: [RuleId; 5] = [H01, M04, S09, W08, P03];

use crate::errors::ErrorCode;
use crate::ui::approval::{field_label, validate_for_display};
use crate::ui::approval_text as text;
use crate::ui::interaction::{
    PrepareStage, PrepareState, ReadyContent, SIM_WAIT_MAX_MS, SimState, ack_needed, sim_state,
};

/// Text tone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// `DANGER_BG`: 고위험.
    Danger,
    /// `BLOCKED_BG`: 차단 (the request cannot be approved).
    Blocked,
    /// `WARN_BG`: caution.
    Warn,
    /// Plain information.
    Plain,
}

/// The fixed simulation band (spec/04 §3.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Band {
    /// First line of the warning plus `(E-SIM-00n)`.
    pub head: String,
    /// Cause lines.
    pub detail: String,
    /// `시뮬레이션 다시 시도` (only for `NoResult`).
    pub retry: bool,
}

/// A block of the scrolling area.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// The one-sentence summary (bold 12 pt) with the full address it refers to and the
    /// display title under it (spec/04 §3.2 `요약`).
    Summary {
        /// The sentence.
        sentence: String,
        /// The full recipient / contract address, if the sentence refers to one.
        address: Option<String>,
        /// What the wallet knows about that address ("일반 계정(EOA) · 주소록: …"), or empty.
        notes: String,
        /// `display.title`.
        title: String,
        /// The information lines that restate the summary (H01, M04, S09, W08, P03), as one
        /// muted 9 pt line "참고: … · …" at the bottom of the card (2026-11-10; no box, no tag).
        remark: Option<String>,
    },
    /// A large title line (the connect window's origin).
    Title(String),
    /// A sub-heading inside a card ("로그인 내용", "메시지 원문").
    Subheading(&'static str),
    /// A warning (or the preparation failure).
    Warning {
        /// Text.
        text: String,
        /// Tone.
        tone: Tone,
    },
    /// The single "위 경고를 모두 확인했습니다" checkbox (D16).
    Ack,
    /// A section header.
    Section(&'static str),
    /// A field.
    Field {
        /// Label (`이름 · sub_label`).
        label: String,
        /// Value.
        value: String,
        /// Consolas.
        mono: bool,
    },
    /// Secondary text.
    Muted(String),
    /// `자세히 ▸/▾`: the non-critical fields and the raw data.
    RawToggle {
        /// Open.
        open: bool,
    },
    /// Preparation notice (spinner).
    Notice(String),
    /// A connect-window account checkbox (spec/05 §4.2).
    Account {
        /// Index in the offered list.
        index: usize,
        /// Account label.
        label: String,
        /// EIP-55 address.
        address: String,
        /// Selected.
        checked: bool,
    },
}

/// The Bitcoin network banner of the A01 header (spec/08 §2 table: mainnet red, testnet4
/// orange).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcBanner {
    /// `BITCOIN MAINNET`.
    Mainnet,
    /// `BITCOIN TESTNET4 — 가치 없음`.
    Testnet4,
}

impl BtcBanner {
    /// The banner of a network.
    #[must_use]
    pub const fn of(network: yw_core::btc::BtcNetwork) -> Self {
        match network {
            yw_core::btc::BtcNetwork::Mainnet => Self::Mainnet,
            yw_core::btc::BtcNetwork::Testnet4 => Self::Testnet4,
        }
    }

    /// The fixed text (spec/08 §2; English spec/14 §2).
    #[must_use]
    pub fn text(self, lang: Lang) -> &'static str {
        match self {
            Self::Mainnet => yw_core::btc::BtcNetwork::Mainnet.banner_in(lang),
            Self::Testnet4 => yw_core::btc::BtcNetwork::Testnet4.banner_in(lang),
        }
    }
}

/// The whole A01 content.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent display flags of one window"
)]
pub struct ApprovalView {
    /// The language of every fixed text of the window: the request's display language
    /// (digested) for a signing request, the app language for the connect and preparing views.
    pub lang: Lang,
    /// Header rows (`요청 출처`, `네트워크`, `서명 계정`).
    pub header: Vec<(String, String)>,
    /// Header badges (user chain, testnet).
    pub badges: Vec<String>,
    /// The chain badge drawn before the `네트워크` header value (app chrome, not part of the
    /// digested display).
    pub chain: Option<crate::ui::badge::Badge>,
    /// Testnet coloring.
    pub testnet: bool,
    /// Bitcoin network banner (header colored red / orange instead of the testnet band).
    pub btc_banner: Option<BtcBanner>,
    /// Simulation band.
    pub band: Option<Band>,
    /// Scrolling blocks.
    pub blocks: Vec<Block>,
    /// Blocked request: approve disabled, "승인할 수 없음".
    pub blocked: bool,
    /// High-risk interaction: 2 s hold.
    pub high: bool,
    /// Foldable details (non-critical fields, raw data) exist.
    pub has_raw: bool,
}

/// `[U+XXXX]` escape markers to color with `ESCAPE_TEXT` (byte ranges).
#[must_use]
pub fn escape_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0_usize;
    while let Some(offset) = text.get(index..).and_then(|rest| rest.find("[U+")) {
        let start = index.saturating_add(offset);
        let digits_start = start.saturating_add(3);
        let mut end = digits_start;
        while end < bytes.len()
            && end.saturating_sub(digits_start) < 6
            && bytes
                .get(end)
                .is_some_and(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
        {
            end = end.saturating_add(1);
        }
        let count = end.saturating_sub(digits_start);
        if (4..=6).contains(&count) && bytes.get(end) == Some(&b']') {
            spans.push((start, end.saturating_add(1)));
            index = end.saturating_add(1);
        } else {
            index = digits_start;
        }
    }
    spans
}

const fn is_header(key: FieldKey) -> bool {
    matches!(key.0, 0x0001..=0x0003)
}

const fn is_diff(key: FieldKey) -> bool {
    matches!(key.0, 0x0110..=0x0113)
}

const fn is_raw(field: &DisplayField) -> bool {
    !field.critical && matches!(field.key.0, 0x0140..=0x014F | 0x0540 | 0x0706)
}

const fn is_mono(key: FieldKey) -> bool {
    matches!(
        key.0,
        0x0003
            | 0x0101
            | 0x0125
            | 0x0140
            | 0x0141
            | 0x0501
            | 0x0509
            | 0x0511
            | 0x0513
            | 0x0514
            | 0x051A
            | 0x0540
            | 0x0601
            | 0x0702
            | 0x0706
    )
}

/// SOL amount/fee rows shown in the asset-change area (spec/04 §3.2: "SOL·BTC는 해당 문서의
/// 금액·수수료 행").
const fn is_sol_money(key: FieldKey) -> bool {
    matches!(key.0, 0x0502..=0x0505)
}

/// The changes and fee rows of a dApp Solana transaction (spec/07 §20.6: the window shows them
/// first, then the instructions).
const fn is_sol_tx_money(key: FieldKey) -> bool {
    matches!(key.0, 0x0515 | 0x0516)
}

/// BTC amount, change, inputs, fee and total rows (spec/08 §10: the asset-change area is
/// `0x0603`–`0x0607`).
const fn is_btc_money(key: FieldKey) -> bool {
    matches!(key.0, 0x0603..=0x0607)
}

fn label_of(lang: Lang, field: &DisplayField) -> String {
    let name = field_label(field.key, lang).unwrap_or("?");
    if field.sub_label.is_empty() {
        name.to_owned()
    } else {
        format!("{name} · {}", field.sub_label)
    }
}

const fn band_code(state: SimState) -> ErrorCode {
    match state {
        SimState::Reverted => ErrorCode::Sim001,
        SimState::NoResult | SimState::Ok => ErrorCode::Sim002,
        SimState::Unsupported => ErrorCode::Sim003,
        SimState::Incomplete => ErrorCode::Sim004,
    }
}

fn band_warning(warnings: &[Warning], state: SimState) -> Option<usize> {
    warnings.iter().position(|warning| match state {
        SimState::Unsupported => warning.rule == E36,
        SimState::NoResult => warning.rule == E01,
        SimState::Reverted => warning.rule == E02,
        SimState::Incomplete => [E03, E04, E07, E08, E09].contains(&warning.rule),
        SimState::Ok => false,
    })
}

/// Reformats the calldata value's hex line into rows with offsets (spec/04 §3.3: 32 bytes per
/// row at ≥ 80 columns, otherwise 16; the selector alone on the first row). Only presentation:
/// no characters of the hex are added or removed.
#[must_use]
pub fn calldata_rows(value: &str, wide: bool) -> String {
    let mut lines = value.splitn(2, '\n');
    let head = lines.next().unwrap_or("");
    let Some(hex) = lines.next().and_then(|line| line.strip_prefix("0x")) else {
        return value.to_owned();
    };
    if hex.len() < 8 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return value.to_owned();
    }
    let per_line = if wide { 64 } else { 32 };
    let (selector, rest) = hex.split_at(8);
    let mut out = format!("{head}\n[0x0000] {selector}");
    let mut offset = 4_usize;
    let mut cursor = rest;
    while !cursor.is_empty() {
        let take = per_line.min(cursor.len());
        let (row, tail) = cursor.split_at(take);
        let _ = write!(out, "\n[0x{offset:04x}] {row}");
        offset = offset.saturating_add(take / 2);
        cursor = tail;
    }
    out
}

fn tone_of(level: RiskLevel) -> Tone {
    match level {
        RiskLevel::High => Tone::Danger,
        RiskLevel::Blocked => Tone::Blocked,
        RiskLevel::Caution => Tone::Warn,
        RiskLevel::Info => Tone::Plain,
    }
}

fn first_line(value: &str) -> &str {
    value.split('\n').next().unwrap_or("")
}

fn field_value(display: &yw_core::approval::ApprovalDisplay, key: u16) -> Option<&str> {
    display
        .fields
        .iter()
        .find(|field| field.key.0 == key)
        .map(|field| field.value.as_str())
}

/// The value of the top-level call argument `name` (`호출 인수 · {name}`, `0x0104`).
fn call_arg<'d>(display: &'d yw_core::approval::ApprovalDisplay, name: &str) -> Option<&'d str> {
    display
        .fields
        .iter()
        .find(|field| field.key == FieldKey::CALL_ARG && field.sub_label == name)
        .map(|field| field.value.as_str())
}

/// The network name of the header value (`Sepolia 테스트넷 (chainId 11155111)` → the name).
fn network_name(display: &yw_core::approval::ApprovalDisplay) -> String {
    let value = field_value(display, 0x0002).map_or("", first_line);
    value
        .split(" (chainId ")
        .next()
        .unwrap_or(value)
        .trim()
        .to_owned()
}

/// The bracketed notes of a recipient value (`0x… [일반 계정(EOA)] [주소록: A]` →
/// `일반 계정(EOA) · 주소록: A`).
fn address_notes(value: &str) -> String {
    first_line(value)
        .split(" [")
        .skip(1)
        .map(|note| note.trim_end().trim_end_matches(']'))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The address part of a recipient value (`0x… [일반 계정(EOA)]` → `0x…`).
fn address_part(value: &str) -> String {
    first_line(value)
        .split(" [")
        .next()
        .unwrap_or("")
        .trim()
        .to_owned()
}

/// The value of the typed-data structured field `label` (`0x0303`).
fn td_field<'d>(display: &'d yw_core::approval::ApprovalDisplay, label: &str) -> Option<&'d str> {
    display
        .fields
        .iter()
        .find(|field| field.key == FieldKey::TD_FIELD && field.sub_label == label)
        .map(|field| field.value.as_str())
}

/// The chain's own label of an address value (a token symbol, `Uniswap Permit2`): its first
/// bracketed note that is not the account kind nor the wallet's own or book name (the core's
/// notes in the display's language).
fn chain_label(lang: Lang, value: &str) -> Option<&str> {
    let kinds = [
        evm_text::NOTE_CONTRACT,
        evm_text::NOTE_EOA,
        evm_text::NOTE_KIND_UNKNOWN,
    ];
    let prefixes = [
        evm_text::NOTE_DELEGATED,
        evm_text::NOTE_MINE,
        evm_text::NOTE_BOOK,
    ];
    first_line(value)
        .split(" [")
        .skip(1)
        .map(|note| note.trim_end().trim_end_matches(']'))
        .find(|note| {
            !kinds.iter().any(|kind| *note == kind.get(lang))
                && !prefixes
                    .iter()
                    .any(|prefix| note.starts_with(prefix.get(lang).trim_end()))
        })
}

/// The fixed parts before and after `{0}` of a one-argument template.
fn around_arg(template: Tpl<1>, lang: Lang) -> (&'static str, &'static str) {
    template
        .template(lang)
        .split_once("{0}")
        .unwrap_or((template.template(lang), ""))
}

/// Whether `value` is an instance of the one-argument template.
fn matches_template(value: &str, template: Tpl<1>, lang: Lang) -> bool {
    let (head, tail) = around_arg(template, lang);
    value.len() > head.len().saturating_add(tail.len())
        && value.starts_with(head)
        && value.ends_with(tail)
}

/// An amount display that is zero (`0 USDC`, `0 (원시 단위) …`).
fn is_zero_amount(amount: &str) -> bool {
    first_line(amount).split(' ').next() == Some("0")
}

/// `{amount}을(를)` with the token named once: "무제한" says which token
/// (`USDC를 무제한으로`), an amount that already ends in the token's name stands alone. In
/// English the object has no particle (`an unlimited amount of USDC`, `USDC 10`).
fn amount_object(lang: Lang, token: &str, amount: &str) -> String {
    let amount = first_line(amount).trim();
    let particle = |what: &str| match lang {
        Lang::Ko => crate::ui::theme::object_particle(what),
        Lang::En => "",
    };
    if amount == evm_text::UNLIMITED.get(lang) {
        return text::UNLIMITED_OBJECT.fill(lang, [token, particle(token)]);
    }
    let what = if amount.contains(token) {
        amount.to_owned()
    } else {
        format!("{token} {amount}")
    };
    format!("{what}{}", particle(&what))
}

/// "…까지" of an allowance expiry (`만료 없음` → `기한 없이`; English `until …`).
fn until(lang: Lang, expiration: &str) -> String {
    let expiration = first_line(expiration).trim();
    if expiration == evm_text::NO_EXPIRY.get(lang) {
        text::NO_TIME_LIMIT.get(lang).to_owned()
    } else if expiration.starts_with(|character: char| character.is_ascii_digit()) {
        text::UNTIL.fill(lang, [expiration])
    } else {
        format!("({expiration})")
    }
}

/// `{place}아래 주소의 권한을 거둡니다(승인 해제).`
fn revoke_sentence(lang: Lang, place: &str) -> String {
    text::REVOKE.fill(lang, [place])
}

/// The summary of a permission a transaction gives (spec/04 §3.2 요약, 2026-11-10): who gets
/// what — the address is the one receiving the permission (spender, operator), with its notes.
/// `None` for any other call (the general sentence stays).
fn grant_summary<'d>(
    display: &'d yw_core::approval::ApprovalDisplay,
    call: &str,
    place: &str,
) -> Option<(String, Option<&'d str>)> {
    let lang = display.lang;
    let token = || {
        field_value(display, 0x0101)
            .and_then(|value| chain_label(lang, value))
            .unwrap_or(text::TOKEN.get(lang))
            .to_owned()
    };
    let is = |title: Text| call == title.get(lang);
    if is(call_text::TITLE_TOKEN_APPROVE) {
        let spender = call_arg(display, "spender")?;
        let amount = call_arg(display, "amount")?;
        return Some(if is_zero_amount(amount) {
            (revoke_sentence(lang, place), Some(spender))
        } else {
            (
                text::GRANT_TOKEN.fill(lang, [place, &token(), first_line(amount).trim()]),
                Some(spender),
            )
        });
    }
    match call {
        // `increaseAllowance` adds to what the spender may already use (security review
        // 2026-11-10): its amount is the increase, not the new total, and 0 changes nothing —
        // never "승인 해제", which a revoke-looking site could otherwise show for a no-op.
        _ if is(call_text::TITLE_ALLOWANCE_INCREASE) => {
            let spender = call_arg(display, "spender")?;
            let added = first_line(call_arg(display, "added")?).trim();
            let sentence = if is_zero_amount(added) {
                text::GRANT_INCREASE_ZERO.fill(lang, [place, &token()])
            } else {
                text::GRANT_INCREASE.fill(lang, [place, &token(), added])
            };
            Some((sentence, Some(spender)))
        }
        _ if is(call_text::TITLE_APPROVAL_FOR_ALL) => {
            let operator = call_arg(display, "operator")?;
            let approved = call_arg(display, "approved")?;
            Some(if approved == evm_text::YES.get(lang) {
                (text::GRANT_FOR_ALL.fill(lang, [place]), Some(operator))
            } else if approved == evm_text::NO.get(lang) {
                (revoke_sentence(lang, place), Some(operator))
            } else {
                return None;
            })
        }
        _ if is(call_text::TITLE_PERMIT2_APPROVE) => {
            let spender = call_arg(display, "spender")?;
            let amount = call_arg(display, "amount")?;
            if is_zero_amount(amount) {
                return Some((revoke_sentence(lang, place), Some(spender)));
            }
            let token = call_arg(display, "token")
                .and_then(|value| chain_label(lang, value))
                .unwrap_or(text::TOKEN.get(lang));
            let expiration = call_arg(display, "expiration")?;
            Some((
                text::GRANT_PERMIT2_TX.fill(
                    lang,
                    [
                        place,
                        &amount_object(lang, token, amount),
                        &until(lang, expiration),
                    ],
                ),
                Some(spender),
            ))
        }
        _ if is(call_text::TITLE_PERMIT2_LOCKDOWN) => {
            // The first pair's spender (`token → spender` lines).
            let pairs = call_arg(display, "pairs")?;
            let spender = first_line(pairs).split(" → ").nth(1)?;
            Some((revoke_sentence(lang, place), Some(spender)))
        }
        _ => None,
    }
}

/// The summary of a permission a typed-data signature gives (spec/04 §3.2 요약, 2026-11-10),
/// from the structured fields (`사용자`, `금액`, `허용 만료`); `None` when they are not there.
fn permit_summary<'d>(
    display: &'d yw_core::approval::ApprovalDisplay,
    action: &str,
    place: &str,
) -> Option<(String, Option<&'d str>)> {
    let lang = display.lang;
    let label = |text: Text| text.get(lang);
    let token = || {
        td_field(display, label(evm_text::TD_TOKEN))
            .and_then(|value| chain_label(lang, value))
            .unwrap_or(text::TOKEN.get(lang))
            .to_owned()
    };
    // A batch names how many tokens (`항목 n 토큰`) instead of one amount.
    let (item_head, _) = around_arg(evm_text::TD_ITEM, lang);
    let token_tail = format!(" {}", label(evm_text::TD_TOKEN));
    let batch = display
        .fields
        .iter()
        .filter(|field| {
            field.key == FieldKey::TD_FIELD
                && field.sub_label.starts_with(item_head)
                && field.sub_label.ends_with(&token_tail)
        })
        .count();
    let is = |title: Text| action == title.get(lang);
    let spender = || td_field(display, label(evm_text::TD_SPENDER));
    let amount = || td_field(display, label(evm_text::TD_AMOUNT));
    if is(evm_text::ACTION_PERMIT) {
        let spender = spender()?;
        let amount = amount()?;
        return Some(if is_zero_amount(amount) {
            (revoke_sentence(lang, place), Some(spender))
        } else {
            (
                text::PERMIT_SIG.fill(lang, [place, &amount_object(lang, &token(), amount)]),
                Some(spender),
            )
        });
    }
    if is(evm_text::ACTION_DAI_PERMIT) {
        let spender = spender()?;
        let allowed = td_field(display, label(evm_text::TD_ALLOWED))?;
        return Some(if allowed == evm_text::DAI_ALLOWED.get(lang) {
            (
                text::PERMIT_SIG.fill(
                    lang,
                    [
                        place,
                        &amount_object(lang, "DAI", evm_text::UNLIMITED.get(lang)),
                    ],
                ),
                Some(spender),
            )
        } else {
            (revoke_sentence(lang, place), Some(spender))
        });
    }
    if is(evm_text::ACTION_PERMIT2) {
        let spender = spender()?;
        if batch > 0 {
            return Some((
                text::PERMIT2_BATCH.fill(lang, [place, &batch.to_string()]),
                Some(spender),
            ));
        }
        let amount = amount()?;
        if is_zero_amount(amount) {
            return Some((revoke_sentence(lang, place), Some(spender)));
        }
        return Some((
            text::PERMIT2_SIG.fill(
                lang,
                [
                    place,
                    &amount_object(lang, &token(), amount),
                    &until(
                        lang,
                        td_field(display, label(evm_text::TD_ALLOWANCE_EXPIRY))?,
                    ),
                ],
            ),
            Some(spender),
        ));
    }
    if is(evm_text::ACTION_PERMIT2_TRANSFER) || is(evm_text::ACTION_PERMIT2_WITNESS) {
        let spender = spender()?;
        let what = if batch > 0 {
            text::TOKEN_KINDS.fill(lang, [&batch.to_string()])
        } else {
            let amount = first_line(amount()?).trim();
            match lang {
                Lang::Ko => format!("{amount}{}", crate::ui::theme::object_particle(amount)),
                Lang::En => amount.to_owned(),
            }
        };
        return Some((
            text::PERMIT2_TRANSFER.fill(lang, [place, &what]),
            Some(spender),
        ));
    }
    if is(evm_text::ACTION_HL_AGENT) {
        let agent = td_field(display, "agentAddress")?;
        return Some((text::HL_AGENT.fill(lang, [place]), Some(agent)));
    }
    None
}

/// The action of `[{network}] {action}`.
fn title_action(title: &str) -> &str {
    title
        .split_once("] ")
        .map_or(title, |(_, action)| action)
        .trim()
}

/// The `personal_sign` summary: a parsed SIWE message says what it is (2026-11-08) — the site
/// log-in and the domain the message names (a domain other than the requesting site is S01,
/// blocked); any other message keeps the general sentence.
fn personal_sign_summary(display: &yw_core::approval::ApprovalDisplay, place: &str) -> String {
    let lang = display.lang;
    let siwe_domain = display
        .fields
        .iter()
        .find(|field| field.key.0 == 0x0404 && field.sub_label == evm_text::SIWE_DOMAIN.get(lang))
        .map(|field| first_line(&field.value).trim().to_owned())
        .filter(|_| title_action(&display.title) == evm_text::SIWE_TITLE.get(lang));
    siwe_domain.map_or_else(
        || text::PERSONAL.fill(lang, [place]),
        |domain| text::SIWE.fill(lang, [place, &domain]),
    )
}

/// The typed-data summary: a known schema names its action in the title ('토큰 사용 허가 서명
/// (permit)', 'Permit2 즉시 이체 서명', 'NFT 마켓 주문 서명') and the summary repeats it
/// (2026-11-08); an unknown one keeps the general sentence.
fn typed_data_summary(display: &yw_core::approval::ApprovalDisplay, place: &str) -> String {
    let lang = display.lang;
    let action = title_action(&display.title);
    if action.is_empty() || action == evm_text::TYPED_TITLE.get(lang) {
        text::TYPED_GENERIC.fill(lang, [place])
    } else {
        text::TYPED_ACTION.fill(lang, [place, action])
    }
}

/// The one-sentence plain-Korean summary at the top of A01 (spec/04 §3.2 `요약`) and the full
/// address it refers to. Derived only from the validated display model (the digest is
/// unchanged); addresses are never shortened (spec/04 §0): the sentence says `아래 주소` and
/// the full grouped address follows it.
#[must_use]
pub fn summary(request: &ApprovalRequest) -> (String, Option<String>) {
    let (sentence, value) = summary_value(request);
    (
        sentence,
        value
            .map(address_part)
            .filter(|address| !address.is_empty()),
    )
}

/// `{place}{amount}을(를) 아래 주소로 보냅니다.`
fn send_sentence(lang: Lang, place: &str, amount: &str) -> String {
    let amount = first_line(amount).trim();
    let particle = match lang {
        Lang::Ko => crate::ui::theme::object_particle(amount),
        Lang::En => "",
    };
    text::SEND.fill(lang, [place, amount, particle])
}

/// Whether `sentence` is a [`send_sentence`] (its recipient notes go right under the summary).
fn is_send_sentence(lang: Lang, sentence: &str) -> bool {
    let template = text::SEND.template(lang);
    let tail = template.rsplit_once('}').map_or(template, |(_, tail)| tail);
    sentence.ends_with(tail)
}

/// [`summary`] with the whole display value of the address (the address and its bracketed
/// notes).
fn summary_value(request: &ApprovalRequest) -> (String, Option<&str>) {
    use yw_core::approval::ApprovalKind;
    let display = &request.display;
    let lang = display.lang;
    let network = network_name(display);
    let place = if network.is_empty() {
        String::new()
    } else {
        text::PLACE.fill(lang, [&network])
    };
    let send = |amount: Option<&str>, asset: Text| match amount {
        Some(amount) => send_sentence(lang, &place, amount),
        None => text::SEND_ASSET.fill(lang, [&place, asset.get(lang)]),
    };
    // A Sign-In-With-Bitcoin message (yw-core `SIWB_MARKER` on its first line) says it is a site
    // log-in and which domain it names (2026-11-10).
    if request.kind == ApprovalKind::BtcMessage
        && let Some(domain) = field_value(display, 0x0401).and_then(|text| {
            yw_core::btc::msgsign::sign_in_domain(text.as_bytes())
                .map(str::trim)
                .filter(|domain| !domain.is_empty())
        })
    {
        return (text::SIWB.fill(lang, [&place, domain]), None);
    }
    match request.kind {
        ApprovalKind::EvmTransaction => {
            // The core names a plain native transfer "{symbol} 보내기" (spec/03 §9) and gives it
            // no call arguments.
            let call = field_value(display, 0x0103).map(first_line);
            let plain = call.is_none_or(|call| matches_template(call, evm_text::SEND_NATIVE, lang))
                && field_value(display, 0x0104).is_none();
            // A strict ERC-20 `transfer` ("토큰 전송") without native value: the tokens go to the
            // decoded `to` (its row carries the account kind and book notes), not to the token
            // contract of `0x0101` — the address a user checks must be the recipient's.
            let no_value = field_value(display, 0x0102)
                .is_some_and(|value| first_line(value).split(' ').next() == Some("0"));
            let token = (call == Some(call_text::TITLE_TOKEN_TRANSFER.get(lang)) && no_value)
                .then(|| call_arg(display, "amount").zip(call_arg(display, "to")))
                .flatten();
            // A permission (approve, increaseAllowance, setApprovalForAll, Permit2) names who
            // gets it and how much; the address is the one receiving it (2026-11-10).
            if let Some(grant) = call.and_then(|call| grant_summary(display, call, &place)) {
                return grant;
            }
            match (plain, field_value(display, 0x0102), token) {
                (true, Some(amount), _) => (
                    send_sentence(lang, &place, amount),
                    field_value(display, 0x0101),
                ),
                (_, _, Some((amount, to))) => (send_sentence(lang, &place, amount), Some(to)),
                _ => (
                    text::CONTRACT_CALL.fill(lang, [&place, title_action(&display.title)]),
                    field_value(display, 0x0101),
                ),
            }
        }
        ApprovalKind::EvmSpeedUp => (text::SPEED_UP.fill(lang, [&place]), None),
        ApprovalKind::EvmCancel => (text::CANCEL.fill(lang, [&place]), None),
        ApprovalKind::EvmPersonalSign => (personal_sign_summary(display, &place), None),
        ApprovalKind::EvmTypedData => permit_summary(display, title_action(&display.title), &place)
            .unwrap_or_else(|| (typed_data_summary(display, &place), None)),
        ApprovalKind::SolTransfer => {
            let amount = field_value(display, 0x0502);
            let to = amount.and(field_value(display, 0x0501));
            (send(amount, text::ASSET_SOL), to)
        }
        ApprovalKind::BtcSend => {
            let amount = field_value(display, 0x0603);
            let to = amount.and(field_value(display, 0x0601));
            (send(amount, text::ASSET_BTC), to)
        }
        ApprovalKind::ZecSend => {
            let amount = field_value(display, 0x0803);
            let to = amount.and(field_value(display, 0x0801));
            (send(amount, text::ASSET_ZEC), to)
        }
        ApprovalKind::BtcFeeBump => (text::FEE_BUMP.fill(lang, [&place]), None),
        ApprovalKind::SolMessage | ApprovalKind::BtcMessage => {
            (text::OWNERSHIP.fill(lang, [&place]), None)
        }
        ApprovalKind::HyperCoreAction => (
            text::HYPERCORE.fill(
                lang,
                [&place, field_value(display, 0x0701).map_or("", first_line)],
            ),
            field_value(display, 0x0702),
        ),
        ApprovalKind::SolSignIn => (text::SIWS.fill(lang, [&place]), None),
        // The mode and count come from the request row `0x0510` (spec/07 §20.6).
        ApprovalKind::SolTransaction => {
            let request_row = field_value(display, 0x0510).unwrap_or("");
            let send_mode = yw_core::sol::dapp::text::SUMMARY_SEND.get(lang);
            if request_row.starts_with(send_mode.split(" — ").next().unwrap_or(send_mode)) {
                (text::SOL_TX_SEND.fill(lang, [&place]), None)
            } else {
                // The count line of the sign-only request row (`거래 {n}건`).
                let count_line = yw_core::sol::dapp::text::SUMMARY_SIGN_ONLY
                    .template(lang)
                    .lines()
                    .nth(1)
                    .unwrap_or("");
                let (head, tail) = count_line.split_once("{0}").unwrap_or((count_line, ""));
                let count = request_row
                    .lines()
                    .find_map(|line| line.strip_prefix(head)?.strip_suffix(tail))
                    .unwrap_or("1");
                (text::SOL_TX_SIGN.fill(lang, [&place, count]), None)
            }
        }
    }
}

fn push_simulation_section(
    view: &mut ApprovalView,
    display: &yw_core::approval::ApprovalDisplay,
    state: Option<SimState>,
    show_diff: bool,
) {
    let lang = display.lang;
    view.blocks
        .push(Block::Section(text::SECTION_CHANGES.get(lang)));
    if show_diff {
        for field in display
            .fields
            .iter()
            .filter(|field| is_diff(field.key) || field.key == FieldKey::SIMULATION)
        {
            view.blocks.push(Block::Field {
                label: label_of(lang, field),
                value: field.value.clone(),
                mono: false,
            });
        }
        if state == Some(SimState::Incomplete) {
            view.blocks
                .push(Block::Muted(text::CHANGES_PARTIAL.get(lang).to_owned()));
        }
    } else {
        view.blocks
            .push(Block::Muted(text::CHANGES_NONE.get(lang).to_owned()));
    }
}

/// Builds the view of a signing request: summary, asset changes, warnings with the single
/// acknowledgement, the critical fields, then `자세히` (every non-critical field and the raw
/// data, folded unless `details_open`; spec/04 §3.2).
///
/// # Errors
///
/// [`ErrorCode::Ui001`] when the request must not be displayed (spec/04 §3.3, AP-4).
#[expect(clippy::too_many_lines, reason = "the A01 areas in order")]
pub fn signing_view(
    request: &ApprovalRequest,
    details_open: bool,
    wide: bool,
    badges: Vec<String>,
    testnet: bool,
) -> Result<ApprovalView, ErrorCode> {
    validate_for_display(&request.display)?;
    let display = &request.display;
    let lang = display.lang;
    let state = sim_state(request);
    let mut view = ApprovalView {
        lang,
        badges,
        testnet,
        blocked: display.risk == RiskLevel::Blocked,
        high: ack_needed(request),
        ..ApprovalView::default()
    };
    for field in display.fields.iter().filter(|field| is_header(field.key)) {
        view.header
            .push((label_of(lang, field), field.value.clone()));
    }
    let band_index = state
        .filter(|state| *state != SimState::Ok)
        .and_then(|state| band_warning(&display.warnings, state).map(|index| (index, state)));
    if let Some((index, state)) = band_index
        && let Some(warning) = display.warnings.get(index)
    {
        let mut lines = warning.text.splitn(2, '\n');
        let first = lines.next().unwrap_or("");
        view.band = Some(Band {
            head: format!("{first} ({})", band_code(state).code()),
            detail: lines.next().unwrap_or("").to_owned(),
            retry: state == SimState::NoResult,
        });
    }
    let (sentence, value) = summary_value(request);
    let address = value
        .map(address_part)
        .filter(|address| !address.is_empty());
    let notes = value
        .filter(|_| address.is_some())
        .map(address_notes)
        .unwrap_or_default();
    let shown_warnings: Vec<&Warning> = display
        .warnings
        .iter()
        .enumerate()
        .filter(|(index, _)| band_index.is_none_or(|(band, _)| band != *index))
        .map(|(_, warning)| warning)
        .collect();
    // Information lines go below the attention ones (2026-11-08) and, since 2026-11-10, where
    // they belong: the lines that restate the summary become one muted line of its card, a note
    // on the recipient goes right under the card when the summary is the recipient's sentence,
    // and the rest follow the key fields ("참고"). Every line is still shown and never folded;
    // levels, the digest and the ack are unchanged.
    let (attention, infos): (Vec<&Warning>, Vec<&Warning>) = shown_warnings
        .into_iter()
        .partition(|warning| warning.level != RiskLevel::Info);
    let (restated, infos): (Vec<&Warning>, Vec<&Warning>) = infos
        .into_iter()
        .partition(|warning| RESTATING.contains(&warning.rule));
    let recipient = address.is_some() && is_send_sentence(lang, &sentence);
    let (recipient_notes, notes_left): (Vec<&Warning>, Vec<&Warning>) = infos
        .into_iter()
        .partition(|warning| recipient && [E28, E29].contains(&warning.rule));
    let remark = (!restated.is_empty()).then(|| {
        text::REMARK.fill(
            lang,
            [&restated
                .iter()
                .map(|warning| warning.text.replace('\n', " — "))
                .collect::<Vec<_>>()
                .join(" · ")],
        )
    });
    view.blocks.push(Block::Summary {
        sentence,
        address,
        notes,
        title: display.title.clone(),
        remark,
    });
    for warning in recipient_notes {
        view.blocks.push(Block::Warning {
            text: warning.text.clone(),
            tone: Tone::Plain,
        });
    }
    let show_diff = matches!(state, Some(SimState::Ok | SimState::Incomplete));
    let sol = request.kind == yw_core::approval::ApprovalKind::SolTransfer;
    // dApp Solana transactions (spec/07 §20.6): no EVM simulation card; the changes (a
    // simulation reference) and the fee take the money area.
    let sol_tx = request.kind.is_sol_transaction();
    let btc = request.kind.is_btc();
    // Message signatures move no assets: no "자산 변화" card (it would only say "no simulation").
    let message = matches!(
        request.kind,
        yw_core::approval::ApprovalKind::EvmPersonalSign
            | yw_core::approval::ApprovalKind::EvmTypedData
    ) || request.kind.is_chain_message();
    // HyperCore (spec/11 §6): no simulation; its amount and fee rows take the money area.
    let hc = request.kind == yw_core::approval::ApprovalKind::HyperCoreAction;
    let money = |key: FieldKey| {
        (sol && is_sol_money(key))
            || (sol_tx && is_sol_tx_money(key))
            || (btc && is_btc_money(key))
            || (hc && matches!(key.0, 0x0703 | 0x0704))
    };
    // The EVM asset-change card ends with the fee (2026-11-10): the expected fee of the
    // simulation and the maximum, so they are not looked for below.
    let fee_in_card =
        !(sol || sol_tx || btc || hc || message) && field_value(display, 0x0120).is_some();
    if sol || sol_tx || btc || hc {
        view.blocks.push(Block::Section(
            if sol_tx {
                text::SECTION_SOL_TX_MONEY
            } else {
                text::SECTION_MONEY
            }
            .get(lang),
        ));
        for field in display.fields.iter().filter(|field| money(field.key)) {
            view.blocks.push(Block::Field {
                label: label_of(lang, field),
                value: field.value.clone(),
                mono: false,
            });
        }
    } else if !message {
        push_simulation_section(&mut view, display, state, show_diff);
        if let Some(max) = field_value(display, 0x0120) {
            let value = match field_value(display, 0x0121)
                .filter(|fee| *fee != evm_text::UNKNOWN.get(lang))
            {
                Some(expected) => text::FEE_EXPECTED.fill(lang, [expected, max]),
                None => text::FEE_MAX.fill(lang, [max]),
            };
            view.blocks.push(Block::Field {
                label: text::FEE.get(lang).to_owned(),
                value,
                mono: false,
            });
        }
    }
    let acknowledge = view.high && !view.blocked;
    if !attention.is_empty() || acknowledge {
        view.blocks
            .push(Block::Section(text::SECTION_WARNINGS.get(lang)));
    }
    if attention.is_empty() && acknowledge {
        view.blocks
            .push(Block::Muted(text::ACK_HINT.get(lang).to_owned()));
    }
    for warning in attention {
        view.blocks.push(Block::Warning {
            text: warning.text.clone(),
            tone: tone_of(warning.level),
        });
    }
    if acknowledge {
        view.blocks.push(Block::Ack);
    }
    let shown_above = |field: &DisplayField| {
        is_header(field.key)
            || money(field.key)
            || (show_diff && (is_diff(field.key) || field.key == FieldKey::SIMULATION))
            || (fee_in_card && matches!(field.key.0, 0x0120 | 0x0121))
    };
    let key_fields: Vec<&DisplayField> = display
        .fields
        .iter()
        .filter(|field| field.critical && !shown_above(field))
        .collect();
    if !key_fields.is_empty() {
        view.blocks
            .push(Block::Section(text::SECTION_KEY.get(lang)));
    }
    // A log-in message (SIWE, SIWS) shows what it parsed first and the message after it, both
    // open (2026-11-10).
    let action = title_action(&display.title);
    let login = action == evm_text::SIWE_TITLE.get(lang)
        || action == yw_core::sol::text::ACTION_SIWS.get(lang);
    let is_login_field = |field: &DisplayField| {
        field.key == FieldKey::SIWE_FIELD || field.key == FieldKey::SIWS_FIELD
    };
    let (login_fields, other_fields): (Vec<&DisplayField>, Vec<&DisplayField>) = key_fields
        .into_iter()
        .partition(|field| login && is_login_field(field));
    if !login_fields.is_empty() {
        view.blocks
            .push(Block::Subheading(text::SUB_LOGIN.get(lang)));
    }
    for field in login_fields {
        view.blocks.push(Block::Field {
            label: label_of(lang, field),
            value: field.value.clone(),
            mono: is_mono(field.key),
        });
    }
    if login && !other_fields.is_empty() {
        view.blocks
            .push(Block::Subheading(text::SUB_MESSAGE.get(lang)));
    }
    for field in other_fields {
        view.blocks.push(Block::Field {
            label: label_of(lang, field),
            value: field.value.clone(),
            mono: is_mono(field.key),
        });
    }
    if !notes_left.is_empty() {
        view.blocks
            .push(Block::Section(text::SECTION_NOTES.get(lang)));
    }
    for warning in notes_left {
        view.blocks.push(Block::Warning {
            text: warning.text.clone(),
            tone: tone_of(warning.level),
        });
    }
    let details: Vec<&DisplayField> = display
        .fields
        .iter()
        .filter(|field| !field.critical && !shown_above(field))
        .collect();
    view.has_raw = !details.is_empty();
    if view.has_raw {
        view.blocks.push(Block::RawToggle { open: details_open });
        if details_open {
            // Plain details first, then the raw data (access list, calldata) in field order.
            for raw in [false, true] {
                for field in details.iter().filter(|field| is_raw(field) == raw) {
                    let value = if field.key == FieldKey::CALLDATA {
                        calldata_rows(&field.value, wide)
                    } else {
                        field.value.clone()
                    };
                    view.blocks.push(Block::Field {
                        label: label_of(lang, field),
                        value,
                        mono: raw || is_mono(field.key),
                    });
                }
            }
        }
    }
    Ok(view)
}

/// yw-app's W-ADDR-3 note on the summary's recipient (spec/04 §3.3): a `WARN_BG` block right
/// under the summary card. It is built from meta (book, own addresses, sent history) and is not
/// part of the digested display — the Bitcoin and Zcash sends, whose forms already required
/// `주소 전체를 직접 확인했습니다`, show it again here (an EVM recipient gets the digested rule
/// E43 instead). Nothing is added without a summary address.
pub fn attach_address_note(view: &mut ApprovalView, lang: Lang, note: &str) {
    let Some(index) = view.blocks.iter().position(|block| {
        matches!(
            block,
            Block::Summary {
                address: Some(_),
                ..
            }
        )
    }) else {
        return;
    };
    view.blocks.insert(
        index.saturating_add(1),
        Block::Warning {
            text: text::ADDRESS_NOTE.fill(lang, [&yw_core::approval::escape_untrusted(note).text]),
            tone: Tone::Warn,
        },
    );
}

/// Builds the view of any preparation state. `failure` is the text of a `Failed` state.
///
/// # Errors
///
/// [`ErrorCode::Ui001`] for a request that must not be displayed.
#[expect(
    clippy::too_many_arguments,
    reason = "the window state and its language, all needed for every preparation state"
)]
pub fn view(
    lang: Lang,
    state: &PrepareState,
    now_ms: u64,
    details_open: bool,
    wide: bool,
    badges: Vec<String>,
    testnet: bool,
    failure: Option<&str>,
) -> Result<ApprovalView, ErrorCode> {
    match state {
        PrepareState::Ready(ReadyContent::Signing(request)) => {
            signing_view(request, details_open, wide, badges, testnet)
        }
        PrepareState::Ready(ReadyContent::Connect(_)) => Ok(ApprovalView {
            lang,
            badges,
            testnet,
            ..ApprovalView::default()
        }),
        PrepareState::Preparing(PrepareStage::Building) => Ok(ApprovalView {
            lang,
            badges,
            testnet,
            blocks: vec![Block::Notice(text::PREPARING.get(lang).to_owned())],
            ..ApprovalView::default()
        }),
        PrepareState::Preparing(PrepareStage::Simulating { since_ms }) => {
            let seconds = now_ms.saturating_sub(*since_ms).min(SIM_WAIT_MAX_MS) / 1_000;
            Ok(ApprovalView {
                lang,
                badges,
                testnet,
                blocks: vec![Block::Notice(
                    text::SIMULATING.fill(lang, [&seconds.to_string()]),
                )],
                ..ApprovalView::default()
            })
        }
        PrepareState::Failed { code, .. } => Ok(ApprovalView {
            lang,
            badges,
            testnet,
            blocked: true,
            blocks: vec![Block::Warning {
                text: failure.map_or_else(|| code.text_in(lang), str::to_owned),
                tone: Tone::Danger,
            }],
            ..ApprovalView::default()
        }),
    }
}

/// The compatibility-mode badge of the connect and site approval windows (spec/05 §2.12, §4.2):
/// the request came from a page where the extension presented itself as another wallet. The
/// origin shown above it is still the real site origin.
#[must_use]
pub fn compat_mode_badge(lang: Lang, mode: crate::browser::envelope::CompatMode) -> String {
    text::BADGE_COMPAT.fill(lang, [mode.label()])
}

/// The name of a connect-window row label: its first line without the `  [...]` tags.
#[must_use]
pub fn account_name(label: &str) -> &str {
    let first = first_line(label);
    first.split("  [").next().unwrap_or(first).trim_end()
}

/// The connect window content (spec/05 §4.2): the origin in large type, the http and punycode
/// badges, the fixed guidance, the account checkboxes and the origin chain.
#[must_use]
pub fn connect_view(
    lang: Lang,
    origin: &str,
    http: bool,
    accounts: &[(String, String)],
    selected: &[bool],
    chain_name: &str,
    family: yw_core::policy::Family,
) -> ApprovalView {
    use yw_core::policy::Family;
    let mut badges = Vec::new();
    if http {
        badges.push(text::BADGE_HTTP.get(lang).to_owned());
    }
    if origin
        .split(['/', '.', ':'])
        .any(|label| label.starts_with("xn--"))
    {
        badges.push(text::BADGE_PUNYCODE_CHECK.get(lang).to_owned());
    }
    let mut blocks = vec![
        Block::Title(origin.to_owned()),
        Block::Warning {
            text: match family {
                Family::Evm => text::CONNECT_EVM,
                // spec/04 §3 (2026-11-12, D38): Solana dApps also get transaction signing.
                Family::Solana => text::CONNECT_SOL,
                Family::Bitcoin => text::CONNECT_BTC,
            }
            .get(lang)
            .to_owned(),
            tone: Tone::Plain,
        },
        Block::Section(
            match family {
                Family::Evm => text::CONNECT_SECTION_EVM,
                Family::Solana => text::CONNECT_SECTION_SOL,
                Family::Bitcoin => text::CONNECT_SECTION_BTC,
            }
            .get(lang),
        ),
    ];
    for (index, (label, address)) in accounts.iter().enumerate() {
        blocks.push(Block::Account {
            index,
            label: label.clone(),
            address: address.clone(),
            checked: selected.get(index).copied().unwrap_or(false),
        });
    }
    let count = selected.iter().filter(|checked| **checked).count();
    if count > 16 {
        blocks.push(Block::Muted(text::CONNECT_LIMIT.get(lang).to_owned()));
    }
    // The account a dApp uses is the first checked one in list order (spec/05 §4.2); say which
    // (2026-11-08) so the choice is not a guess — its name only (2026-11-10: a row's label
    // carries its tags and, on a second line, its source and path).
    if family == Family::Evm
        && let Some((label, _)) = accounts
            .iter()
            .zip(selected)
            .find(|(_, checked)| **checked)
            .map(|(account, _)| account)
    {
        blocks.push(Block::Muted(
            text::CONNECT_DEFAULT.fill(lang, [account_name(label)]),
        ));
    }
    blocks.push(Block::Field {
        label: text::CONNECT_NETWORK.get(lang).to_owned(),
        value: chain_name.to_owned(),
        mono: false,
    });
    ApprovalView {
        lang,
        header: vec![(text::CONNECT_ORIGIN.get(lang).to_owned(), origin.to_owned())],
        badges,
        blocks,
        ..ApprovalView::default()
    }
}

#[cfg(test)]
mod tests {
    use yw_core::approval::{
        ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore, ChainFacts, build_evm_tx_request,
    };
    use yw_core::bip32::path::AccountIndex;
    use yw_core::evm::abi::erc20_transfer_data;
    use yw_core::evm::address::Address;
    use yw_core::evm::amount::U256;
    use yw_core::evm::chain::sepolia;
    use yw_core::evm::decode::{DecodedTx, decode_call};
    use yw_core::evm::display::format_address;
    use yw_core::evm::simulate::SimResult;
    use yw_core::evm::tx::Eip1559Tx;
    use yw_core::vault::EvmKeySource;

    use super::{Block, Tone, attach_address_note, signing_view, summary};

    const NOW: u64 = 1_790_000_000_000;

    /// A Sepolia transaction request from account `0x01…` (no simulation unless `sim`).
    fn tx_request(
        to: Address,
        data: Vec<u8>,
        sim: &SimResult,
    ) -> yw_core::approval::ApprovalRequest {
        let chain = sepolia();
        let tx = Eip1559Tx {
            chain_id: chain.chain_id,
            nonce: 0,
            max_priority_fee_per_gas: U256::from_u64(1),
            max_fee_per_gas: U256::from_u64(2),
            gas_limit: 60_000,
            to,
            value: U256::ZERO,
            data,
            access_list: Vec::new(),
        };
        let decoded = DecodedTx {
            call: decode_call(&chain, &tx.to, &tx.data),
            tx,
        };
        let draft = build_evm_tx_request(
            yw_core::lang::Lang::Ko,
            ApprovalId([1; 16]),
            ApprovalOrigin::App,
            EvmKeySource::Derived(AccountIndex::ZERO),
            Address::from_bytes([0x01; 20]),
            ApprovalKind::EvmTransaction,
            &chain,
            &decoded,
            sim,
            &ChainFacts::default(),
            Vec::new(),
            NOW,
        )
        .unwrap();
        ApprovalStore::new().issue(draft, 1, NOW).unwrap()
    }

    /// A Sepolia typed-data request of `source`.
    fn typed_request(source: &str) -> yw_core::approval::ApprovalRequest {
        let value = yw_json::parse(source.as_bytes(), &yw_json::Limits::REQUEST).unwrap();
        let typed =
            yw_core::evm::eip712::validate_typed_data_v4(source.as_bytes(), &value, 11_155_111)
                .unwrap();
        let draft = yw_core::approval::build_typed_request(
            yw_core::lang::Lang::Ko,
            ApprovalId([2; 16]),
            ApprovalOrigin::App,
            EvmKeySource::Derived(AccountIndex::ZERO),
            Address::from_bytes([0x01; 20]),
            ApprovalKind::EvmTypedData,
            &sepolia(),
            &typed,
            &ChainFacts::default(),
            NOW,
        )
        .unwrap();
        ApprovalStore::new().issue(draft, 1, NOW).unwrap()
    }

    /// spec/04 §3.2 요약 (2026-11-10): a permission says who gets it and how much, and the
    /// address under the sentence is the one receiving it (spender, operator), not the token.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one table row per permission kind")]
    fn permission_summaries_name_who_gets_what() {
        use yw_core::evm::abi::{
            AbiValue, SEL_APPROVE, SEL_INCREASE_ALLOWANCE, SEL_SET_APPROVAL_FOR_ALL, encode_call,
        };
        let chain = sepolia();
        let usdc = chain.tokens[1].address;
        let spender = Address::from_bytes([0x42; 20]);
        let nft = Address::from_bytes([0x77; 20]);
        let usdc_text = usdc.to_checksum();
        let spender_text = spender.to_checksum();
        // approve(spender, max) that the simulation saw as an ERC-20 `Approval` (R4 resolved).
        let approval_log = yw_core::evm::simulate::LogEvent::Erc20Approval {
            token: usdc,
            owner: Address::from_bytes([0x01; 20]),
            spender,
            amount: U256::MAX,
        };
        let simulated = SimResult::Simulated {
            verdict: yw_core::approval::SimVerdict::Ok,
            diff: yw_core::evm::simulate::SimulationDiff {
                block: yw_core::approval::SimBinding {
                    number: 1,
                    parent_hash: [1; 32],
                    timestamp: 1_790_000_000,
                    base_fee: U256::from_u64(1),
                    sim_digest: [2; 32],
                },
                changes: Vec::new(),
                approvals: Vec::new(),
                transfers: Vec::new(),
                other_events: 0,
                gas_used: 46_000,
                events: vec![approval_log],
                omitted_rows: 0,
                native_emitter_mismatch: false,
            },
            warnings: Vec::new(),
        };
        let approve = tx_request(
            usdc,
            encode_call(
                SEL_APPROVE,
                &[AbiValue::Address(spender), AbiValue::Uint(U256::MAX)],
            ),
            &simulated,
        );
        let for_all = |approved| {
            tx_request(
                nft,
                encode_call(
                    SEL_SET_APPROVAL_FOR_ALL,
                    &[AbiValue::Address(spender), AbiValue::Bool(approved)],
                ),
                &SimResult::skipped(),
            )
        };
        // increaseAllowance adds to an allowance: the increase, and 0 is never a revoke.
        let increase = |added: u64| {
            tx_request(
                usdc,
                encode_call(
                    SEL_INCREASE_ALLOWANCE,
                    &[
                        AbiValue::Address(spender),
                        AbiValue::Uint(U256::from_u64(added)),
                    ],
                ),
                &SimResult::skipped(),
            )
        };
        let permit = typed_request(&format!(
            r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"version","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],"Permit":[{{"name":"owner","type":"address"}},{{"name":"spender","type":"address"}},{{"name":"value","type":"uint256"}},{{"name":"nonce","type":"uint256"}},{{"name":"deadline","type":"uint256"}}]}},"primaryType":"Permit","domain":{{"name":"USDC","version":"2","chainId":11155111,"verifyingContract":"{usdc_text}"}},"message":{{"owner":"{}","spender":"{spender_text}","value":"1000000","nonce":"0","deadline":"1893456000"}}}}"#,
            Address::from_bytes([0x01; 20]).to_checksum()
        ));
        let permit_single = typed_request(&format!(
            r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],"PermitDetails":[{{"name":"token","type":"address"}},{{"name":"amount","type":"uint160"}},{{"name":"expiration","type":"uint48"}},{{"name":"nonce","type":"uint48"}}],"PermitSingle":[{{"name":"details","type":"PermitDetails"}},{{"name":"spender","type":"address"}},{{"name":"sigDeadline","type":"uint256"}}]}},"primaryType":"PermitSingle","domain":{{"name":"Permit2","chainId":11155111,"verifyingContract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"}},"message":{{"details":{{"token":"{usdc_text}","amount":"1461501637330902918203684832716283019655932542975","expiration":"1790086400","nonce":"0"}},"spender":"{spender_text}","sigDeadline":"1790000600"}}}}"#
        ));
        let rows: [(&yw_core::approval::ApprovalRequest, &str); 7] = [
            (
                &approve,
                "Sepolia 테스트넷에서 아래 주소에 USDC 사용 권한을 줍니다: 무제한.",
            ),
            (
                &permit,
                "Sepolia 테스트넷에서 아래 주소가 1 USDC를 가져갈 수 있게 하는 서명입니다. 거래 없이 서명만으로 쓰일 수 있습니다.",
            ),
            (
                &permit_single,
                "Sepolia 테스트넷에서 아래 주소가 USDC를 무제한으로 2026-09-22 ",
            ),
            (
                &for_all(true),
                "Sepolia 테스트넷에서 아래 주소에 이 컬렉션 NFT 전체를 옮길 권한을 줍니다.",
            ),
            (
                &for_all(false),
                "Sepolia 테스트넷에서 아래 주소의 권한을 거둡니다(승인 해제).",
            ),
            (
                &increase(2_500_000),
                "Sepolia 테스트넷에서 아래 주소의 USDC 사용 권한을 늘립니다: +2.5 USDC (이미 준 권한에 더해집니다).",
            ),
            (
                &increase(0),
                "Sepolia 테스트넷에서 아래 주소의 USDC 사용 권한을 늘리는 거래이지만 늘리는 양이 0이라 이미 준 권한은 그대로입니다(승인 해제가 아닙니다).",
            ),
        ];
        for (request, sentence) in rows {
            let (text, address) = summary(request);
            assert!(
                text.starts_with(sentence),
                "{text:?} does not start with {sentence:?}"
            );
            assert_eq!(address, Some(format_address(&spender)), "{text}");
        }
        let (single, _) = summary(&permit_single);
        assert!(
            single.ends_with("까지 쓸 수 있게 하는 서명입니다."),
            "{single}"
        );
    }

    /// spec/04 §3.2 (2026-11-10): an information line that restates the summary (M04) is one
    /// muted line of the summary card — no box, no tag — and its words are still there; the
    /// other information lines follow the key fields.
    #[test]
    fn restating_lines_join_the_summary_card() {
        let draft = yw_core::sol::msgsign::build_sol_message_request(
            yw_core::lang::Lang::Ko,
            &yw_core::sol::msgsign::SolMessageRequest {
                id: ApprovalId([3; 16]),
                origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
                cluster: yw_core::sol::SolCluster::Devnet,
                source: yw_core::slip10::SolKeySource::Standard(AccountIndex::ZERO),
                public: [7; 32],
                label: "Solana 1".to_owned(),
                message: b"Prove it".to_vec(),
                sign_in: false,
            },
            NOW,
        )
        .unwrap();
        let m04 = yw_core::evm::risk::base_text(yw_core::evm::risk::M04, yw_core::lang::Lang::Ko)
            .unwrap();
        assert!(draft.display.warnings.iter().any(|w| w.text == m04));
        let request = ApprovalStore::new().issue(draft, 1, NOW).unwrap();
        let view = signing_view(&request, false, true, Vec::new(), true).unwrap();
        assert!(
            matches!(
                view.blocks.first(),
                Some(Block::Summary { remark: Some(remark), .. }) if *remark == format!("참고: {m04}")
            ),
            "{:?}",
            view.blocks.first()
        );
        assert!(!view.blocks.iter().any(|block| matches!(
            block,
            Block::Warning { text, .. } if text.contains(m04)
        )));
        assert!(!view.blocks.contains(&Block::Section("참고")));
        // The key fields come right after the summary; `자세히` stays last.
        let sections: Vec<&str> = view
            .blocks
            .iter()
            .filter_map(|block| match block {
                Block::Section(title) => Some(*title),
                _ => None,
            })
            .collect();
        assert_eq!(sections, ["핵심 정보"]);
    }

    /// spec/04 §3.2–§3.3: an ERC-20 `transfer` summary names the token recipient with its book
    /// note (not the token contract), and a W-ADDR-3 note goes right under the summary.
    #[test]
    fn token_transfer_summary_names_the_recipient() {
        const NOW: u64 = 1_790_000_000_000;
        let chain = sepolia();
        let usdc = chain.tokens[1].address;
        let recipient = Address::from_bytes([0x42; 20]);
        let tx = Eip1559Tx {
            chain_id: chain.chain_id,
            nonce: 0,
            max_priority_fee_per_gas: U256::from_u64(1),
            max_fee_per_gas: U256::from_u64(2),
            gas_limit: 60_000,
            to: usdc,
            value: U256::ZERO,
            data: erc20_transfer_data(&recipient, &U256::from_u64(1_000_000)),
            access_list: Vec::new(),
        };
        let facts = ChainFacts {
            address_book: vec![(recipient, "친구".to_owned())],
            ..ChainFacts::default()
        };
        let decoded = DecodedTx {
            call: decode_call(&chain, &tx.to, &tx.data),
            tx,
        };
        let draft = build_evm_tx_request(
            yw_core::lang::Lang::Ko,
            ApprovalId([1; 16]),
            ApprovalOrigin::App,
            EvmKeySource::Derived(AccountIndex::ZERO),
            Address::from_bytes([0x01; 20]),
            ApprovalKind::EvmTransaction,
            &chain,
            &decoded,
            &SimResult::skipped(),
            &facts,
            Vec::new(),
            NOW,
        )
        .unwrap();
        let request = ApprovalStore::new().issue(draft, 1, NOW).unwrap();
        let (sentence, address) = summary(&request);
        assert_eq!(
            sentence,
            "Sepolia 테스트넷에서 1 USDC를 아래 주소로 보냅니다."
        );
        assert_eq!(address, Some(format_address(&recipient)));
        let mut view = signing_view(&request, false, true, Vec::new(), true).unwrap();
        assert!(
            matches!(view.blocks.first(), Some(Block::Summary { notes, .. }) if notes == "주소록: 친구"),
            "{:?}",
            view.blocks.first()
        );
        attach_address_note(
            &mut view,
            yw_core::lang::Lang::Ko,
            "'친구'과 끝 6자가 같지만 다른 주소입니다.",
        );
        assert!(
            matches!(
                view.blocks.get(1),
                Some(Block::Warning { text, tone: Tone::Warn })
                    if text == "받는 주소: '친구'과 끝 6자가 같지만 다른 주소입니다."
            ),
            "{:?}",
            view.blocks.get(1)
        );
    }

    /// A hand-assembled transfer of 1,000 lamports from `abandon`×11 `about` standard 0 (it pays
    /// the fee, its slot still zero).
    fn sol_dapp_request(mode: yw_core::sol::dapp::SolTxMode) -> yw_core::approval::ApprovalRequest {
        use yw_core::sol::SolAddress;
        use yw_core::sol::dapp::display::{SolTxFacts, SolTxItemFacts, SolTxRequest};
        let wallet = SolAddress::parse("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk").unwrap();
        let mut message = vec![1, 0, 1, 3];
        message.extend_from_slice(wallet.as_bytes());
        message.extend_from_slice(&[0x22; 32]);
        message.extend_from_slice(&[0; 32]);
        message.extend_from_slice(&[7; 32]);
        message.extend_from_slice(&[1, 2, 2, 0, 1, 12, 2, 0, 0, 0]);
        message.extend_from_slice(&1_000_u64.to_le_bytes());
        let mut wire = vec![1];
        wire.extend_from_slice(&[0; 64]);
        wire.extend_from_slice(&message);
        let request = SolTxRequest {
            id: ApprovalId([4; 16]),
            origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
            cluster: yw_core::sol::SolCluster::Devnet,
            source: yw_core::slip10::SolKeySource::Standard(AccountIndex::ZERO),
            public: wallet.to_bytes(),
            label: "Solana 1".to_owned(),
            mode,
            options: yw_core::sol::dapp::SolSendOptions::default(),
            txs: vec![wire],
        };
        let facts = SolTxFacts {
            items: vec![SolTxItemFacts {
                tables: Ok((0, Vec::new())),
                pre: Vec::new(),
                post: None,
                sim: yw_core::sol::display::SimSummary::Ok { units: 150 },
                sim_replaced_blockhash: false,
                rpc_fee: Some(5_000),
                blockhash_valid: Some(true),
            }],
            mints: Vec::new(),
            unread_mints: Vec::new(),
            known: Vec::new(),
            fee_cap: 100_000,
        };
        let draft =
            yw_core::sol::dapp::build_sol_tx_request(yw_core::lang::Lang::Ko, &request, &facts)
                .unwrap();
        ApprovalStore::new().issue(draft, 1, NOW).unwrap()
    }

    /// spec/07 §20.6: a dApp Solana transaction says whether the wallet sends it, its changes and
    /// fee take the money area, the instructions are key fields, and the raw message folds into
    /// `자세히` as raw data after the plain details.
    #[test]
    fn sol_dapp_transaction_view() {
        use yw_core::sol::dapp::SolTxMode;
        let request = sol_dapp_request(SolTxMode::SignOnly);
        let (sentence, address) = summary(&request);
        assert_eq!(
            sentence,
            "Solana devnet (테스트)에서 사이트가 만든 Solana 거래 1건에 서명해 사이트에 돌려줍니다. 지갑은 전송하지 않습니다."
        );
        assert_eq!(address, None);
        let view = signing_view(&request, true, true, Vec::new(), true).unwrap();
        let sections: Vec<&str> = view
            .blocks
            .iter()
            .filter_map(|block| match block {
                Block::Section(title) => Some(*title),
                _ => None,
            })
            .collect();
        assert_eq!(
            sections,
            [
                "자산 변화·수수료 (시뮬레이션 참고)",
                "확인할 경고",
                "핵심 정보"
            ]
        );
        let labels: Vec<(&str, bool)> = view
            .blocks
            .iter()
            .filter_map(|block| match block {
                Block::Field { label, mono, .. } => Some((label.as_str(), *mono)),
                _ => None,
            })
            .collect();
        assert_eq!(
            labels,
            [
                ("자산·권한 변화 (시뮬레이션 참고)", false),
                ("수수료", false),
                ("요청", false),
                ("명령", false),
                ("쓰기 가능한 계정", true),
                ("서명자·수수료 지불", true),
                ("조회 테이블 (RPC)", true),
                ("시뮬레이션 (참고)", false),
                ("유효 시간", false),
                ("감사 (메시지 SHA-256)", true),
                ("원본 메시지", true),
            ]
        );
        let send = sol_dapp_request(SolTxMode::SignAndSend);
        assert_eq!(
            summary(&send).0,
            "Solana devnet (테스트)에서 사이트가 만든 Solana 거래에 서명하고 지갑이 바로 전송합니다. 되돌릴 수 없습니다."
        );
        assert!(
            signing_view(&send, false, true, Vec::new(), true)
                .unwrap()
                .blocks
                .iter()
                .any(|block| matches!(block, Block::Field { label, .. } if label == "전송 방식"))
        );
    }
}
