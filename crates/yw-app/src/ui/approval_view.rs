//! The A01 content model (spec/04 §3.2–§3.3): which fields go to the fixed header, the fixed
//! simulation band, the scrolling title/warnings/acknowledgement/asset-change/detail/raw-data
//! areas. Pure, so AP-4/AP-6 are tested without windows; `ui::approval_window` paints it.

use core::fmt::Write as _;

use yw_core::approval::{ApprovalRequest, DisplayField, FieldKey, RiskLevel, Warning};
use yw_core::evm::risk::{E01, E02, E03, E04, E07, E08, E09, E36};

use crate::errors::ErrorCode;
use crate::ui::approval::{field_label, validate_for_display};
use crate::ui::interaction::{
    PrepareStage, PrepareState, ReadyContent, SIM_WAIT_MAX_MS, SimState, ack_needed, sim_state,
};

/// Text tone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// `DANGER_BG`: high risk and blocked.
    Danger,
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
    /// `display.title` (bold 12 pt).
    Title(String),
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
    /// `원본 데이터 ▸/▾`.
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

/// The whole A01 content.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent display flags of one window"
)]
pub struct ApprovalView {
    /// Header rows (`요청 출처`, `네트워크`, `서명 계정`).
    pub header: Vec<(String, String)>,
    /// Header badges (user chain, testnet).
    pub badges: Vec<String>,
    /// Testnet coloring.
    pub testnet: bool,
    /// Simulation band.
    pub band: Option<Band>,
    /// Scrolling blocks.
    pub blocks: Vec<Block>,
    /// Blocked request: approve disabled, "승인할 수 없음".
    pub blocked: bool,
    /// High-risk interaction: 2 s hold.
    pub high: bool,
    /// Raw-data fields exist.
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
    !field.critical && matches!(field.key.0, 0x0140..=0x014F)
}

const fn is_mono(key: FieldKey) -> bool {
    matches!(key.0, 0x0003 | 0x0101 | 0x0125 | 0x0140 | 0x0141)
}

fn label_of(field: &DisplayField) -> String {
    let name = field_label(field.key).unwrap_or("?");
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
        RiskLevel::High | RiskLevel::Blocked => Tone::Danger,
        RiskLevel::Caution => Tone::Warn,
        RiskLevel::Info => Tone::Plain,
    }
}

/// Builds the view of a signing request.
///
/// # Errors
///
/// [`ErrorCode::Ui001`] when the request must not be displayed (spec/04 §3.3, AP-4).
pub fn signing_view(
    request: &ApprovalRequest,
    raw_open: bool,
    wide: bool,
    badges: Vec<String>,
    testnet: bool,
) -> Result<ApprovalView, ErrorCode> {
    validate_for_display(&request.display)?;
    let display = &request.display;
    let state = sim_state(request);
    let mut view = ApprovalView {
        badges,
        testnet,
        blocked: display.risk == RiskLevel::Blocked,
        high: ack_needed(request),
        ..ApprovalView::default()
    };
    for field in display.fields.iter().filter(|field| is_header(field.key)) {
        view.header.push((label_of(field), field.value.clone()));
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
    view.blocks.push(Block::Title(display.title.clone()));
    for (index, warning) in display.warnings.iter().enumerate() {
        if band_index.is_some_and(|(band, _)| band == index) {
            continue;
        }
        view.blocks.push(Block::Warning {
            text: warning.text.clone(),
            tone: tone_of(warning.level),
        });
    }
    if view.high && !view.blocked {
        view.blocks.push(Block::Ack);
    }
    let show_diff = matches!(state, Some(SimState::Ok | SimState::Incomplete));
    view.blocks.push(Block::Section("시뮬레이션 결과"));
    if show_diff {
        for field in display
            .fields
            .iter()
            .filter(|field| is_diff(field.key) || field.key == FieldKey::SIMULATION)
        {
            view.blocks.push(Block::Field {
                label: label_of(field),
                value: field.value.clone(),
                mono: false,
            });
        }
        if state == Some(SimState::Incomplete) {
            view.blocks.push(Block::Muted(
                "시뮬레이션에서 확인된 부분만 표시합니다.".to_owned(),
            ));
        }
    } else {
        view.blocks.push(Block::Muted(
            "시뮬레이션 결과가 없어 자산 변화를 표시할 수 없습니다.".to_owned(),
        ));
    }
    view.blocks.push(Block::Section("상세"));
    for field in &display.fields {
        let shown_above = is_header(field.key)
            || (show_diff && (is_diff(field.key) || field.key == FieldKey::SIMULATION));
        if shown_above || is_raw(field) {
            continue;
        }
        view.blocks.push(Block::Field {
            label: label_of(field),
            value: field.value.clone(),
            mono: is_mono(field.key),
        });
    }
    view.has_raw = display.fields.iter().any(is_raw);
    if view.has_raw {
        view.blocks.push(Block::RawToggle { open: raw_open });
        if raw_open {
            for field in display.fields.iter().filter(|field| is_raw(field)) {
                let value = if field.key == FieldKey::CALLDATA {
                    calldata_rows(&field.value, wide)
                } else {
                    field.value.clone()
                };
                view.blocks.push(Block::Field {
                    label: label_of(field),
                    value,
                    mono: true,
                });
            }
        }
    }
    Ok(view)
}

/// Builds the view of any preparation state. `failure` is the text of a `Failed` state.
///
/// # Errors
///
/// [`ErrorCode::Ui001`] for a request that must not be displayed.
pub fn view(
    state: &PrepareState,
    now_ms: u64,
    raw_open: bool,
    wide: bool,
    badges: Vec<String>,
    testnet: bool,
    failure: Option<&str>,
) -> Result<ApprovalView, ErrorCode> {
    match state {
        PrepareState::Ready(ReadyContent::Signing(request)) => {
            signing_view(request, raw_open, wide, badges, testnet)
        }
        PrepareState::Ready(ReadyContent::Connect(_)) => Ok(ApprovalView {
            badges,
            testnet,
            ..ApprovalView::default()
        }),
        PrepareState::Preparing(PrepareStage::Building) => Ok(ApprovalView {
            badges,
            testnet,
            blocks: vec![Block::Notice("요청을 준비하는 중입니다…".to_owned())],
            ..ApprovalView::default()
        }),
        PrepareState::Preparing(PrepareStage::Simulating { since_ms }) => {
            let seconds = now_ms.saturating_sub(*since_ms).min(SIM_WAIT_MAX_MS) / 1_000;
            Ok(ApprovalView {
                badges,
                testnet,
                blocks: vec![Block::Notice(format!("시뮬레이션 중… ({seconds}/10초)"))],
                ..ApprovalView::default()
            })
        }
        PrepareState::Failed { code, .. } => Ok(ApprovalView {
            badges,
            testnet,
            blocked: true,
            blocks: vec![Block::Warning {
                text: failure.map_or_else(|| code.text(), str::to_owned),
                tone: Tone::Danger,
            }],
            ..ApprovalView::default()
        }),
    }
}

/// The connect window content (spec/05 §4.2): the origin in large type, the http and punycode
/// badges, the fixed guidance, the account checkboxes and the origin chain.
#[must_use]
pub fn connect_view(
    origin: &str,
    http: bool,
    accounts: &[(String, String)],
    selected: &[bool],
    chain_name: &str,
) -> ApprovalView {
    let mut badges = Vec::new();
    if http {
        badges.push("로컬 개발 사이트(http)".to_owned());
    }
    if origin
        .split(['/', '.', ':'])
        .any(|label| label.starts_with("xn--"))
    {
        badges.push("국제화 도메인(punycode) — 주소를 다시 확인하세요".to_owned());
    }
    let mut blocks = vec![
        Block::Title(origin.to_owned()),
        Block::Warning {
            text: "이 사이트는 선택한 계정의 주소, 잔액, 거래 기록을 볼 수 있습니다. 서명과 전송은 매번 따로 승인합니다.".to_owned(),
            tone: Tone::Plain,
        },
        Block::Section("연결할 계정 (1–16개)"),
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
        blocks.push(Block::Muted(
            "한 사이트에 연결할 수 있는 계정은 16개까지입니다.".to_owned(),
        ));
    }
    blocks.push(Block::Field {
        label: "현재 네트워크".to_owned(),
        value: chain_name.to_owned(),
        mono: false,
    });
    ApprovalView {
        header: vec![("요청 출처".to_owned(), origin.to_owned())],
        badges,
        blocks,
        ..ApprovalView::default()
    }
}
