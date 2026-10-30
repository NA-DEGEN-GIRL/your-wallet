//! The A01 content model (spec/04 §3.2–§3.3): which fields go to the fixed header, the fixed
//! simulation band, and the scrolling summary / asset-change / warnings + acknowledgement /
//! critical-field areas and the folded 자세히 (non-critical fields and raw data). Pure, so AP-4/AP-6 are tested without windows; `ui::approval_window` paints it.

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
    },
    /// A large title line (the connect window's origin).
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

    /// The fixed text (spec/08 §2).
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Mainnet => yw_core::btc::BtcNetwork::Mainnet.banner(),
            Self::Testnet4 => yw_core::btc::BtcNetwork::Testnet4.banner(),
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
    /// Header rows (`요청 출처`, `네트워크`, `서명 계정`).
    pub header: Vec<(String, String)>,
    /// Header badges (user chain, testnet).
    pub badges: Vec<String>,
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
    !field.critical && matches!(field.key.0, 0x0140..=0x014F)
}

const fn is_mono(key: FieldKey) -> bool {
    matches!(
        key.0,
        0x0003 | 0x0101 | 0x0125 | 0x0140 | 0x0141 | 0x0501 | 0x0509 | 0x0601
    )
}

/// SOL amount/fee rows shown in the asset-change area (spec/04 §3.2: "SOL·BTC는 해당 문서의
/// 금액·수수료 행").
const fn is_sol_money(key: FieldKey) -> bool {
    matches!(key.0, 0x0502..=0x0505)
}

/// BTC amount, change, inputs, fee and total rows (spec/08 §10: the asset-change area is
/// `0x0603`–`0x0607`).
const fn is_btc_money(key: FieldKey) -> bool {
    matches!(key.0, 0x0603..=0x0607)
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

/// The action of `[{network}] {action}`.
fn title_action(title: &str) -> &str {
    title
        .split_once("] ")
        .map_or(title, |(_, action)| action)
        .trim()
}

/// The one-sentence plain-Korean summary at the top of A01 (spec/04 §3.2 `요약`) and the full
/// address it refers to. Derived only from the validated display model (the digest is
/// unchanged); addresses are never shortened (spec/04 §0): the sentence says `아래 주소` and
/// the full grouped address follows it.
#[must_use]
pub fn summary(request: &ApprovalRequest) -> (String, Option<String>) {
    use yw_core::approval::ApprovalKind;
    let display = &request.display;
    let network = network_name(display);
    let place = if network.is_empty() {
        String::new()
    } else {
        format!("{network}에서 ")
    };
    let send = |amount: &str, to: Option<&str>| {
        let amount = first_line(amount).trim();
        (
            format!(
                "{place}{amount}{} 아래 주소로 보냅니다.",
                crate::ui::theme::object_particle(amount)
            ),
            to.map(address_part).filter(|address| !address.is_empty()),
        )
    };
    match request.kind {
        ApprovalKind::EvmTransaction => {
            // The core names a plain native transfer "{symbol} 보내기" (spec/03 §9) and gives it
            // no call arguments.
            let call = field_value(display, 0x0103).map(first_line);
            let plain = call.is_none_or(|call| call.ends_with(" 보내기"))
                && field_value(display, 0x0104).is_none();
            match (plain, field_value(display, 0x0102)) {
                (true, Some(amount)) => send(amount, field_value(display, 0x0101)),
                _ => (
                    format!(
                        "{place}컨트랙트를 호출합니다: {}. 아래 자산 변화와 경고를 확인하세요.",
                        title_action(&display.title)
                    ),
                    field_value(display, 0x0101)
                        .map(address_part)
                        .filter(|address| !address.is_empty()),
                ),
            }
        }
        ApprovalKind::EvmSpeedUp => (
            format!("{place}아직 확정되지 않은 거래를 더 높은 수수료로 다시 보냅니다(가속)."),
            None,
        ),
        ApprovalKind::EvmCancel => (
            format!("{place}아직 확정되지 않은 거래를 취소합니다(같은 nonce로 0을 보내는 거래)."),
            None,
        ),
        ApprovalKind::EvmPersonalSign => (
            format!(
                "{place}메시지에 서명합니다. 거래를 보내지는 않지만, 서명은 로그인이나 권한 확인에 쓰일 수 있습니다."
            ),
            None,
        ),
        ApprovalKind::EvmTypedData => (
            format!(
                "{place}구조화된 데이터(EIP-712)에 서명합니다. 토큰 사용 권한(permit) 같은 권한을 줄 수 있으니 아래 내용을 확인하세요."
            ),
            None,
        ),
        ApprovalKind::SolTransfer => match field_value(display, 0x0502) {
            Some(amount) => send(amount, field_value(display, 0x0501)),
            None => (format!("{place}SOL을 보냅니다."), None),
        },
        ApprovalKind::BtcSend => match field_value(display, 0x0603) {
            Some(amount) => send(amount, field_value(display, 0x0601)),
            None => (format!("{place}BTC를 보냅니다."), None),
        },
        ApprovalKind::BtcFeeBump => (
            format!("{place}아직 확정되지 않은 거래의 수수료를 올려 다시 보냅니다."),
            None,
        ),
        ApprovalKind::SolMessage | ApprovalKind::BtcMessage => (
            format!(
                "{place}메시지에 서명해 이 주소의 소유를 증명합니다. 거래 서명이나 전송은 하지 않습니다."
            ),
            None,
        ),
        ApprovalKind::SolSignIn => (
            format!(
                "{place}사이트 로그인(Sign-In-With-Solana) 메시지에 서명합니다. 거래 서명이나 전송은 하지 않습니다."
            ),
            None,
        ),
    }
}

fn push_simulation_section(
    view: &mut ApprovalView,
    display: &yw_core::approval::ApprovalDisplay,
    state: Option<SimState>,
    show_diff: bool,
) {
    view.blocks
        .push(Block::Section("자산 변화 (시뮬레이션 결과)"));
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
    let (sentence, address) = summary(request);
    let notes = [0x0101, 0x0501, 0x0601]
        .into_iter()
        .find_map(|key| field_value(display, key))
        .filter(|_| address.is_some())
        .map(address_notes)
        .unwrap_or_default();
    view.blocks.push(Block::Summary {
        sentence,
        address,
        notes,
        title: display.title.clone(),
    });
    let show_diff = matches!(state, Some(SimState::Ok | SimState::Incomplete));
    let sol = request.kind == yw_core::approval::ApprovalKind::SolTransfer;
    let btc = request.kind.is_btc();
    let message = matches!(
        request.kind,
        yw_core::approval::ApprovalKind::EvmPersonalSign
            | yw_core::approval::ApprovalKind::EvmTypedData
    );
    let money = |key: FieldKey| (sol && is_sol_money(key)) || (btc && is_btc_money(key));
    if sol || btc {
        view.blocks.push(Block::Section("금액·수수료"));
        for field in display.fields.iter().filter(|field| money(field.key)) {
            view.blocks.push(Block::Field {
                label: label_of(field),
                value: field.value.clone(),
                mono: false,
            });
        }
    } else if !message {
        push_simulation_section(&mut view, display, state, show_diff);
    }
    let shown_warnings: Vec<&Warning> = display
        .warnings
        .iter()
        .enumerate()
        .filter(|(index, _)| band_index.is_none_or(|(band, _)| band != *index))
        .map(|(_, warning)| warning)
        .collect();
    let acknowledge = view.high && !view.blocked;
    if !shown_warnings.is_empty() || acknowledge {
        view.blocks.push(Block::Section("확인할 경고"));
    }
    if shown_warnings.is_empty() && acknowledge {
        view.blocks.push(Block::Muted(
            "맨 위의 고위험 경고를 읽고, 이해했으면 아래에 체크하세요.".to_owned(),
        ));
    }
    for warning in shown_warnings {
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
    };
    let key_fields: Vec<&DisplayField> = display
        .fields
        .iter()
        .filter(|field| field.critical && !shown_above(field))
        .collect();
    if !key_fields.is_empty() {
        view.blocks.push(Block::Section("핵심 정보"));
    }
    for field in key_fields {
        view.blocks.push(Block::Field {
            label: label_of(field),
            value: field.value.clone(),
            mono: is_mono(field.key),
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
                        label: label_of(field),
                        value,
                        mono: raw || is_mono(field.key),
                    });
                }
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

/// The compatibility-mode badge of the connect and site approval windows (spec/05 §2.12, §4.2):
/// the request came from a page where the extension presented itself as another wallet. The
/// origin shown above it is still the real site origin.
#[must_use]
pub fn compat_mode_badge(mode: crate::browser::envelope::CompatMode) -> String {
    format!("호환 모드: {}", mode.label())
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
    family: yw_core::policy::Family,
) -> ApprovalView {
    use yw_core::policy::Family;
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
            text: match family {
                Family::Evm => "이 사이트는 선택한 계정의 주소, 잔액, 거래 기록을 볼 수 있습니다. 서명과 전송은 매번 따로 승인합니다.",
                Family::Solana | Family::Bitcoin => "이 사이트는 선택한 주소와 공개키를 볼 수 있습니다. 이 지갑은 Solana·Bitcoin에서 메시지 서명(소유 증명)만 지원하며, 거래 서명과 전송은 할 수 없습니다. 메시지 서명은 매번 따로 승인합니다.",
            }
            .to_owned(),
            tone: Tone::Plain,
        },
        Block::Section(match family {
            Family::Evm => "연결할 계정 (1–16개)",
            Family::Solana => "연결할 Solana 계정 (1개)",
            Family::Bitcoin => "연결할 Bitcoin 주소 (용도마다 1개, 받기 주소 0번)",
        }),
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
