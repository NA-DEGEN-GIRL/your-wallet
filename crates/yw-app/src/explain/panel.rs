//! The AI panel of one approval window (spec/06 §3, §6–§7): a pure state machine driven by the
//! window (input ready / changed, 50 ms tick, worker result, `다시 요청`, close) and the display
//! model the window paints. Nothing here is an input of `can_approve`, the risk level, the
//! warnings or the digest (spec/06 §1, E2).

use yw_core::approval::RiskLevel;

use super::input::{CriticalAction, ExplainInput, TrustedSets};
use super::response::{ExplainAction, Explanation, omitted_actions};
use super::{
    ExplainError, HiddenReason, MAX_REQUESTS_PER_APPROVAL, MismatchReason, REQUEST_DEADLINE_MS,
};

/// The panel title (§6).
pub const PANEL_TITLE: &str = "AI 설명 (참고용, 틀릴 수 있음)";
/// The retry button text.
pub const RETRY_LABEL: &str = "다시 요청";
/// Body lines reserved when the window is created (§6: 10 lines, scrolled inside when longer).
pub const BODY_LINES: i32 = 10;
/// The label of an explanation that leaves out an approval, permit, `setApprovalForAll` or
/// outgoing transfer the wallet's own decoding found (its body is folded away).
pub const INCONSISTENT_LABEL: &str = "설명 불일치 — 무시하세요";
/// What a High-risk request's panel shows until `위 경고를 모두 확인했습니다` is checked.
pub const HELD_TEXT: &str =
    "위험도가 높은 요청입니다. 위 경고를 모두 확인했다고 표시하면 AI 설명을 보여줍니다.";

/// Whether the AI panel body waits for the warning acknowledgement: a High-risk request whose
/// `위 경고를 모두 확인했습니다` is not checked (the warnings come first; spec/04 §3.8).
#[must_use]
pub fn held_for_ack(risk: Option<RiskLevel>, ack_checked: bool) -> bool {
    risk == Some(RiskLevel::High) && !ack_checked
}

/// Panel state (§3.2 table). `Debug` shows kinds only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AiPanelState {
    /// Feature off or not a target: no panel.
    Off,
    /// Waiting for the decoding/simulation, or for the busy worker.
    Waiting,
    /// A request is in flight.
    Requesting {
        /// Generation of the request.
        generation: u64,
        /// Monotonic start time.
        started_at_ms: u64,
    },
    /// The validated explanation.
    Shown(Box<Explanation>),
    /// Forbidden content (§5.2).
    Hidden(HiddenReason),
    /// Inconsistent with the input (§5.3).
    Mismatch(MismatchReason),
    /// Any other failure (§7).
    Failed(ExplainError),
    /// Shown but not explained: the request cannot be approved (blocked, or its preparation
    /// failed). The reserved panel keeps its place with this sentence.
    Skipped(&'static str),
}

impl AiPanelState {
    /// Log word of a finished state.
    #[must_use]
    pub const fn result_word(&self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Waiting => "Waiting",
            Self::Requesting { .. } => "Requesting",
            Self::Shown(_) => "Shown",
            Self::Hidden(_) => "Hidden",
            Self::Mismatch(_) => "Mismatch",
            Self::Failed(error) => error.as_str(),
            Self::Skipped(_) => "Skipped",
        }
    }

    /// Log word of the reason (`-` when none).
    #[must_use]
    pub const fn reason_word(&self) -> &'static str {
        match self {
            Self::Hidden(reason) => reason.as_str(),
            Self::Mismatch(reason) => reason.as_str(),
            _ => "-",
        }
    }
}

/// A request the window must hand to the worker.
#[derive(Debug)]
pub struct Dispatch {
    /// Generation (results with another one are dropped).
    pub generation: u64,
    /// The input.
    pub input: ExplainInput,
}

/// A request that ended in the UI's view (one log line each, §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    /// Generation.
    pub generation: u64,
    /// `result=` word (`Discarded` when the input changed or the window closed).
    pub result: &'static str,
    /// `reason=` word.
    pub reason: &'static str,
    /// UI-side elapsed milliseconds.
    pub elapsed_ms: u64,
}

/// The per-window panel.
#[derive(Debug)]
pub struct AiPanel {
    state: AiPanelState,
    generation: u64,
    requests: u8,
    input: Option<ExplainInput>,
    elapsed_ms: Option<u64>,
    /// Effects of the shown explanation's input that it does not mention.
    omitted: Vec<CriticalAction>,
    /// The folded body of an inconsistent explanation was opened by the user.
    expanded: bool,
    /// The body waits for the warning acknowledgement ([`held_for_ack`]).
    held: bool,
}

impl AiPanel {
    /// A panel for a window: `Waiting` when the feature is on and the request is a target
    /// (§3.1), otherwise `Off`.
    #[must_use]
    pub const fn new(target: bool) -> Self {
        Self {
            state: if target {
                AiPanelState::Waiting
            } else {
                AiPanelState::Off
            },
            generation: 0,
            requests: 0,
            input: None,
            elapsed_ms: None,
            omitted: Vec::new(),
            expanded: false,
            held: false,
        }
    }

    /// Effects the shown explanation leaves out (empty unless it is inconsistent).
    #[must_use]
    pub fn omitted(&self) -> &[CriticalAction] {
        &self.omitted
    }

    /// Whether the shown explanation is inconsistent with the request's structure.
    #[must_use]
    pub fn inconsistent(&self) -> bool {
        matches!(self.state, AiPanelState::Shown(_)) && !self.omitted.is_empty()
    }

    /// Whether the folded body of an inconsistent explanation is open.
    #[must_use]
    pub const fn expanded(&self) -> bool {
        self.expanded
    }

    /// Opens or folds the body of an inconsistent explanation (a click on the panel body);
    /// returns whether anything changed.
    pub fn toggle_expanded(&mut self) -> bool {
        if !self.inconsistent() || self.held {
            return false;
        }
        self.expanded = !self.expanded;
        true
    }

    /// Whether the body waits for the warning acknowledgement.
    #[must_use]
    pub const fn held(&self) -> bool {
        self.held
    }

    /// Sets [`held_for_ack`] for the current request; returns whether it changed.
    pub fn set_held(&mut self, held: bool) -> bool {
        let changed = self.held != held;
        self.held = held;
        changed
    }

    fn clear_result(&mut self) {
        self.omitted.clear();
        self.expanded = false;
    }

    /// The state.
    #[must_use]
    pub const fn state(&self) -> &AiPanelState {
        &self.state
    }

    /// Whether the panel is shown at all.
    #[must_use]
    pub const fn visible(&self) -> bool {
        !matches!(self.state, AiPanelState::Off)
    }

    /// Requests made by this window.
    #[must_use]
    pub const fn requests(&self) -> u8 {
        self.requests
    }

    /// The current generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The current input's trusted sets (display of action lines).
    #[must_use]
    pub fn trusted(&self) -> Option<&TrustedSets> {
        self.input.as_ref().map(ExplainInput::trusted)
    }

    /// Elapsed milliseconds of the last finished request.
    #[must_use]
    pub const fn elapsed_ms(&self) -> Option<u64> {
        self.elapsed_ms
    }

    fn end_current(
        &mut self,
        now_ms: u64,
        result: &'static str,
        reason: &'static str,
    ) -> Option<Ended> {
        match self.state {
            AiPanelState::Requesting {
                generation,
                started_at_ms,
            } => Some(Ended {
                generation,
                result,
                reason,
                elapsed_ms: now_ms.saturating_sub(started_at_ms),
            }),
            _ => None,
        }
    }

    /// The decoding (and simulation) finished, or a re-simulation changed the input (§3.2). The
    /// same bytes as before change nothing. A different input clears the old text, drops an
    /// in-flight request (returned as `Ended`) and requests again (or waits for the worker).
    pub fn set_input(
        &mut self,
        now_ms: u64,
        input: ExplainInput,
        busy: bool,
    ) -> (Option<Ended>, Option<Dispatch>) {
        if !self.visible() {
            return (None, None);
        }
        if self
            .input
            .as_ref()
            .is_some_and(|current| current.json() == input.json())
        {
            return (None, None);
        }
        let ended = self.end_current(now_ms, "Discarded", "-");
        self.input = Some(input);
        self.generation = self.generation.saturating_add(1);
        self.state = AiPanelState::Waiting;
        self.clear_result();
        (ended, self.start(now_ms, busy))
    }

    /// The request will not be explained (blocked or failed preparation): no request is made
    /// and an in-flight one is dropped.
    pub fn skip(&mut self, now_ms: u64, text: &'static str) -> Option<Ended> {
        if !self.visible() {
            return None;
        }
        let ended = self.end_current(now_ms, "Discarded", "-");
        self.input = None;
        self.generation = self.generation.saturating_add(1);
        self.state = AiPanelState::Skipped(text);
        self.clear_result();
        ended
    }

    /// The input could not be built (e.g. `InputTooLarge`): no request is made.
    pub fn input_failed(&mut self, now_ms: u64, error: ExplainError) -> Option<Ended> {
        if !self.visible() {
            return None;
        }
        let ended = self.end_current(now_ms, "Discarded", "-");
        self.input = None;
        self.generation = self.generation.saturating_add(1);
        self.state = AiPanelState::Failed(error);
        self.clear_result();
        ended
    }

    fn start(&mut self, now_ms: u64, busy: bool) -> Option<Dispatch> {
        if self.state != AiPanelState::Waiting || busy {
            return None;
        }
        let input = self.input.clone()?;
        if self.requests >= MAX_REQUESTS_PER_APPROVAL {
            self.state = AiPanelState::Failed(ExplainError::LimitReached);
            return None;
        }
        self.requests = self.requests.saturating_add(1);
        self.state = AiPanelState::Requesting {
            generation: self.generation,
            started_at_ms: now_ms,
        };
        Some(Dispatch {
            generation: self.generation,
            input,
        })
    }

    /// The 50 ms tick: the deadline (§3.2, the worker is not waited for) and a waiting request
    /// whose worker became free.
    pub fn tick(&mut self, now_ms: u64, busy: bool) -> (Option<Ended>, Option<Dispatch>) {
        if let AiPanelState::Requesting { started_at_ms, .. } = self.state
            && now_ms.saturating_sub(started_at_ms) >= REQUEST_DEADLINE_MS
        {
            let ended = self.end_current(now_ms, ExplainError::Timeout.as_str(), "-");
            self.elapsed_ms = Some(now_ms.saturating_sub(started_at_ms));
            self.state = AiPanelState::Failed(ExplainError::Timeout);
            return (ended, None);
        }
        (None, self.start(now_ms, busy))
    }

    /// A worker result. Applied only when it answers the request in flight; anything else (an
    /// older generation, a result after the deadline) is dropped.
    pub fn on_result(
        &mut self,
        now_ms: u64,
        generation: u64,
        result: Result<Explanation, ExplainError>,
    ) -> Option<Ended> {
        let AiPanelState::Requesting {
            generation: current,
            started_at_ms,
        } = self.state
        else {
            return None;
        };
        if current != generation {
            return None;
        }
        self.elapsed_ms = Some(now_ms.saturating_sub(started_at_ms));
        self.clear_result();
        self.state = match result {
            Ok(explanation) => {
                if let Some(input) = self.input.as_ref() {
                    self.omitted = omitted_actions(input, &explanation);
                }
                AiPanelState::Shown(Box::new(explanation))
            }
            Err(ExplainError::Hidden(reason)) => AiPanelState::Hidden(reason),
            Err(ExplainError::Mismatch(reason)) => AiPanelState::Mismatch(reason),
            Err(error) => AiPanelState::Failed(error),
        };
        Some(Ended {
            generation,
            result: self.state.result_word(),
            reason: if self.inconsistent() {
                "Inconsistent"
            } else {
                self.state.reason_word()
            },
            elapsed_ms: now_ms.saturating_sub(started_at_ms),
        })
    }

    /// Whether `다시 요청` is offered (not for a consistent `Shown`, `Off`, `Waiting`, in flight
    /// or after the limit) and enabled (the worker is free).
    #[must_use]
    pub fn retry_offered(&self) -> bool {
        (matches!(
            self.state,
            AiPanelState::Hidden(_) | AiPanelState::Mismatch(_) | AiPanelState::Failed(_)
        ) || self.inconsistent())
            && self.state != AiPanelState::Failed(ExplainError::LimitReached)
            && self.input.is_some()
    }

    /// `다시 요청` (§3.2): a new request within the per-approval limit, else `LimitReached`.
    pub fn retry(&mut self, now_ms: u64, busy: bool) -> Option<Dispatch> {
        if !self.retry_offered() || busy {
            return None;
        }
        self.generation = self.generation.saturating_add(1);
        self.state = AiPanelState::Waiting;
        self.clear_result();
        self.start(now_ms, busy)
    }

    /// The window closes (approved, rejected, expired): an in-flight request is dropped.
    pub fn close(&mut self, now_ms: u64) -> Option<Ended> {
        let ended = self.end_current(now_ms, "Discarded", "-");
        self.state = AiPanelState::Off;
        self.input = None;
        self.clear_result();
        ended
    }
}

/// A painted line of the panel body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PanelLine {
    /// Body text (the summary, a status sentence).
    Text(String),
    /// A built action line.
    Action(String),
    /// `AI가 판단하지 못한 것:` heading.
    Heading(String),
    /// A bullet of `unknowns`.
    Bullet(String),
    /// The muted footer `{host} · {model} · {s}초`.
    Footer(String),
    /// An error or notice (one line, §7).
    Notice(String),
    /// Vertical gap.
    Gap,
}

fn seconds_text(ms: u64) -> String {
    format!("{}.{}", ms / 1_000, (ms % 1_000) / 100)
}

fn address_text(bytes: &[u8; 20]) -> String {
    yw_core::evm::address::Address::from_bytes(*bytes).to_checksum()
}

/// `<유형> · <자산> <금액> · <from> → <to>` from validated values only (§6).
#[must_use]
pub fn action_line(action: &ExplainAction, trusted: &TrustedSets) -> String {
    let mut parts = vec![action.kind.label().to_owned()];
    let asset = if action.asset.is_empty() {
        String::new()
    } else if let Some(symbol) = trusted.symbol(&action.asset) {
        symbol.to_owned()
    } else {
        let full = yw_core::evm::address::parse_address(&action.asset).map_or_else(
            |_| action.asset.clone(),
            yw_core::evm::address::Address::to_checksum,
        );
        format!("미확인 토큰 {full}")
    };
    let asset_amount = [asset.as_str(), action.amount.as_str()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !asset_amount.is_empty() {
        parts.push(asset_amount);
    }
    let addresses = match (action.from.as_ref(), action.to.as_ref()) {
        (Some(from), Some(to)) => format!("{} → {}", address_text(from), address_text(to)),
        (Some(from), None) => format!("{} →", address_text(from)),
        (None, Some(to)) => format!("→ {}", address_text(to)),
        (None, None) => String::new(),
    };
    if !addresses.is_empty() {
        parts.push(addresses);
    }
    parts.join(" · ")
}

/// The lines of a validated explanation (summary, action lines, unknowns).
fn explanation_lines(panel: &AiPanel, explanation: &Explanation, lines: &mut Vec<PanelLine>) {
    lines.push(PanelLine::Text(explanation.summary.replace('\n', " ")));
    if let Some(trusted) = panel.trusted()
        && !explanation.actions.is_empty()
    {
        lines.push(PanelLine::Gap);
        for action in &explanation.actions {
            lines.push(PanelLine::Action(action_line(action, trusted)));
        }
    }
    if !explanation.unknowns.is_empty() {
        lines.push(PanelLine::Gap);
        lines.push(PanelLine::Heading("AI가 판단하지 못한 것:".to_owned()));
        for unknown in &explanation.unknowns {
            lines.push(PanelLine::Bullet(format!(
                "• {}",
                unknown.replace('\n', " ")
            )));
        }
    }
}

/// The body lines of the panel (§6–§7). `host` is the `{host}` phrase, `model` the model name.
/// A held panel ([`held_for_ack`]) shows only [`HELD_TEXT`]; an inconsistent explanation shows
/// [`INCONSISTENT_LABEL`] and stays folded until the user opens it.
#[must_use]
pub fn body_lines(panel: &AiPanel, now_ms: u64, host: &str, model: &str) -> Vec<PanelLine> {
    let footer = |ms: Option<u64>| {
        PanelLine::Footer(match ms {
            Some(ms) => format!("{host} · {model} · {}초", seconds_text(ms)),
            None => format!("{host} · {model}"),
        })
    };
    if panel.held() && !matches!(panel.state(), AiPanelState::Off | AiPanelState::Skipped(_)) {
        return vec![PanelLine::Notice(HELD_TEXT.to_owned()), footer(None)];
    }
    match panel.state() {
        AiPanelState::Off => Vec::new(),
        AiPanelState::Waiting => vec![
            PanelLine::Notice("요청 해석과 시뮬레이션이 끝나면 AI 설명을 요청합니다.".to_owned()),
            footer(None),
        ],
        AiPanelState::Requesting { started_at_ms, .. } => vec![
            PanelLine::Notice(format!(
                "AI 설명을 요청하는 중… ({}초)",
                now_ms.saturating_sub(*started_at_ms) / 1_000
            )),
            PanelLine::Text("설명을 기다리지 않고 바로 승인하거나 거부해도 됩니다.".to_owned()),
            footer(None),
        ],
        AiPanelState::Shown(explanation) => {
            let mut lines = Vec::new();
            if panel.inconsistent() {
                let names = panel
                    .omitted()
                    .iter()
                    .map(|critical| critical.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(PanelLine::Notice(INCONSISTENT_LABEL.to_owned()));
                lines.push(PanelLine::Text(format!(
                    "AI 설명이 이 요청의 {names}을(를) 언급하지 않습니다. 위의 지갑 해석과 경고를 따르세요."
                )));
                lines.push(PanelLine::Text(if panel.expanded() {
                    "▾ 접기 (이 영역을 클릭)".to_owned()
                } else {
                    "▸ 무시할 설명 펼쳐 보기 (이 영역을 클릭)".to_owned()
                }));
                if panel.expanded() {
                    lines.push(PanelLine::Gap);
                    explanation_lines(panel, explanation, &mut lines);
                }
            } else {
                explanation_lines(panel, explanation, &mut lines);
            }
            lines.push(PanelLine::Gap);
            lines.push(footer(panel.elapsed_ms()));
            lines
        }
        AiPanelState::Hidden(reason) => vec![
            PanelLine::Notice(ExplainError::Hidden(*reason).panel_text()),
            footer(panel.elapsed_ms()),
        ],
        AiPanelState::Mismatch(reason) => vec![
            PanelLine::Notice(ExplainError::Mismatch(*reason).panel_text()),
            footer(panel.elapsed_ms()),
        ],
        AiPanelState::Failed(error) => vec![
            PanelLine::Notice(error.panel_text()),
            footer(panel.elapsed_ms()),
        ],
        AiPanelState::Skipped(text) => vec![PanelLine::Notice((*text).to_owned())],
    }
}
