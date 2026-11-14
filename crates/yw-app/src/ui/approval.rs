//! Approval queue and display pre-checks (spec/04 §3.1–§3.3, §3.5, §3.7). The A01 window itself
//! is drawn from M4; this module holds the pure rules it relies on: the field label table, the
//! defensive re-validation of every displayed string (E-UI-001), and the FIFO queue with its
//! limits, deadlines and outcomes (AP-3).

use std::collections::VecDeque;

use yw_core::approval::{
    ApprovalDisplay, FieldKey, MAX_DISPLAY_VALUE_BYTES, MAX_TITLE_BYTES, is_valid_display_text,
};
use yw_core::lang::{Lang, Text};

use crate::errors::ErrorCode;
use crate::ui::interaction::MIN_REMAINING_TO_SHOW_MS;

/// Per-origin queue bound (spec/05 §8.4).
pub const MAX_APPROVALS_PER_ORIGIN: usize = 16;
/// Global queue bound (shown item included).
pub const MAX_APPROVALS_GLOBAL: usize = 64;
/// Ready display lifetime (D23).
pub const APPROVAL_DISPLAY_MS: u64 = 120_000;

/// yw-app's field label table (spec/03 §11.2, spec/07 §13.3 and §20.6, spec/08 §10 names; English
/// spec/14 §2) in the display's own language. Keys outside it are not displayed.
#[must_use]
pub const fn field_label(key: FieldKey, lang: Lang) -> Option<&'static str> {
    match field_label_text(key) {
        Some(text) => Some(text.get(lang)),
        None => None,
    }
}

/// Both languages of a field label (tests, spec/14 §2).
#[must_use]
pub const fn field_label_text(key: FieldKey) -> Option<Text> {
    Some(match key.0 {
        0x0001 => labels::ORIGIN,
        0x0002 => labels::NETWORK,
        0x0003 => labels::ACCOUNT,
        0x0101 => labels::TO,
        0x0102 => labels::VALUE,
        0x0103 => labels::CALL,
        0x0104 => labels::CALL_ARG,
        0x0110 => labels::SENT,
        0x0111 => labels::RECEIVED,
        0x0112 => labels::APPROVAL,
        0x0113 => labels::OTHER_EVENTS,
        0x0120 => labels::MAX_FEE,
        0x0121 => labels::EXPECTED_FEE,
        0x0122 => labels::FEE_PARAMS,
        0x0123 => labels::GAS_LIMIT,
        0x0124 => labels::NONCE,
        0x0125 => labels::REPLACES_TX,
        0x0130 => labels::SIMULATION,
        0x0140 => labels::ACCESS_LIST,
        0x0141 => labels::CALLDATA,
        0x0301 => labels::DOMAIN,
        0x0302 => labels::SCHEMA,
        0x0303 => labels::TD_FIELD,
        0x0304 => labels::TD_TREE,
        0x0401 => labels::MESSAGE_TEXT,
        0x0402 => labels::MESSAGE_HEX,
        0x0403 => labels::MESSAGE_BYTES,
        0x0404 => labels::SIWE_FIELD,
        0x0405 => labels::SIWS_FIELD,
        0x0406 => labels::MESSAGE_FORMAT,
        0x0501 | 0x0601 | 0x0702 | 0x0801 => labels::RECIPIENT,
        0x0502 => labels::ASSET_AMOUNT,
        0x0503 => labels::ATA,
        0x0504 | 0x0516 | 0x0606 | 0x0704 | 0x0805 => labels::FEE,
        0x0505 => labels::MAX_TOTAL,
        0x0506 => labels::BALANCE_RPC,
        0x0507 | 0x0517 => labels::SIMULATION_REFERENCE,
        0x0508 | 0x0518 => labels::VALIDITY,
        0x0509 => labels::AUDIT,
        0x0510 => labels::REQUEST,
        0x0511 => labels::SIGNERS,
        0x0512 => labels::INSTRUCTIONS,
        0x0513 => labels::WRITABLE,
        0x0514 => labels::LOOKUPS,
        0x0515 => labels::CHANGES,
        0x0519 => labels::SEND_OPTIONS,
        0x051A => labels::AUDIT_MESSAGE,
        0x0540 => labels::RAW_MESSAGE,
        0x0602 | 0x0802 => labels::ADDRESS_TYPE,
        0x0603 | 0x0803 => labels::AMOUNT,
        0x0604 | 0x0804 => labels::CHANGE,
        0x0605 | 0x0808 => labels::INPUTS,
        0x0607 | 0x0806 => labels::TOTAL,
        0x0807 => labels::EXPIRY_HEIGHT,
        0x0608 => labels::BALANCE_AFTER,
        0x0609 => labels::REPLACES,
        0x0640 | 0x0840 => labels::ADVANCED,
        0x0701 => labels::ACTION,
        0x0703 => labels::TOKEN_AMOUNT,
        0x0705 => labels::HC_NONCE,
        0x0706 => labels::HC_TYPED,
        _ => return None,
    })
}

/// The field labels (spec/03 §11.2; English spec/14 §2).
pub mod labels {
    yw_core::texts! {
        ORIGIN = "요청 출처" / "Requested by";
        NETWORK = "네트워크" / "Network";
        ACCOUNT = "서명 계정" / "Signing account";
        TO = "받는 주소/컨트랙트" / "To (address/contract)";
        VALUE = "보내는 금액" / "Amount sent";
        CALL = "호출 내용" / "Call";
        CALL_ARG = "호출 인수" / "Call argument";
        SENT = "보냄" / "You send";
        RECEIVED = "받음" / "You receive";
        APPROVAL = "승인 변경" / "Approval change";
        OTHER_EVENTS = "기타 이벤트" / "Other events";
        MAX_FEE = "최대 수수료" / "Max fee";
        EXPECTED_FEE = "예상 수수료" / "Expected fee";
        FEE_PARAMS = "maxFee/tip" / "maxFee/tip";
        GAS_LIMIT = "가스 한도" / "Gas limit";
        NONCE = "nonce" / "nonce";
        REPLACES_TX = "대체 대상 거래" / "Replaces transaction";
        SIMULATION = "시뮬레이션 기준" / "Simulated at";
        ACCESS_LIST = "액세스 리스트" / "Access list";
        CALLDATA = "calldata" / "calldata";
        DOMAIN = "도메인" / "Domain";
        SCHEMA = "형식" / "Format";
        TD_FIELD = "구조화 필드" / "Field";
        TD_TREE = "필드 트리" / "Field tree";
        MESSAGE_TEXT = "메시지 텍스트" / "Message text";
        MESSAGE_HEX = "메시지 hex" / "Message hex";
        MESSAGE_BYTES = "바이트 수" / "Bytes";
        SIWE_FIELD = "SIWE 필드" / "SIWE field";
        SIWS_FIELD = "SIWS 필드" / "SIWS field";
        MESSAGE_FORMAT = "서명 방식" / "Signature format";
        RECIPIENT = "받는 주소" / "Recipient";
        ASSET_AMOUNT = "자산·금액" / "Asset · amount";
        ATA = "ATA 생성" / "Create token account (ATA)";
        FEE = "수수료" / "Fee";
        MAX_TOTAL = "최대 총 차감" / "Max total deducted";
        BALANCE_RPC = "잔액 (RPC 참고)" / "Balance (RPC, reference)";
        SIMULATION_REFERENCE = "시뮬레이션 (참고)" / "Simulation (reference)";
        VALIDITY = "유효 시간" / "Valid until";
        AUDIT = "감사" / "Audit";
        REQUEST = "요청" / "Request";
        SIGNERS = "서명자·수수료 지불" / "Signers · fee payer";
        INSTRUCTIONS = "명령" / "Instructions";
        WRITABLE = "쓰기 가능한 계정" / "Writable accounts";
        LOOKUPS = "조회 테이블 (RPC)" / "Lookup tables (RPC)";
        CHANGES = "자산·권한 변화 (시뮬레이션 참고)" / "Asset and authority changes (simulation, reference)";
        SEND_OPTIONS = "전송 방식" / "Send options";
        AUDIT_MESSAGE = "감사 (메시지 SHA-256)" / "Audit (message SHA-256)";
        RAW_MESSAGE = "원본 메시지" / "Raw message";
        ADDRESS_TYPE = "주소 종류" / "Address type";
        AMOUNT = "금액" / "Amount";
        CHANGE = "잔돈" / "Change";
        INPUTS = "입력" / "Inputs";
        TOTAL = "총 차감" / "Total deducted";
        EXPIRY_HEIGHT = "만료 높이" / "Expiry height";
        BALANCE_AFTER = "승인 후 잔액" / "Balance after approval";
        REPLACES = "교체 대상" / "Replaces";
        ADVANCED = "고급" / "Advanced";
        ACTION = "작업" / "Action";
        TOKEN_AMOUNT = "토큰·금액" / "Token · amount";
        HC_NONCE = "nonce (time)" / "nonce (time)";
        HC_TYPED = "원본 typed data (EIP-712)" / "Raw typed data (EIP-712)";
    }
}

/// Re-checks a display before drawing (spec/04 §3.3, defence in depth): every key must be in the
/// label table and every title, label, value and warning text must pass the display-character
/// rules. Failure means: show nothing, `Rejected` + E-UI-001.
///
/// # Errors
///
/// [`ErrorCode::Ui001`].
pub fn validate_for_display(display: &ApprovalDisplay) -> Result<(), ErrorCode> {
    let ok = is_valid_display_text(&display.title, MAX_TITLE_BYTES, false)
        && display.fields.iter().all(|field| {
            field_label(field.key, display.lang).is_some()
                && is_valid_display_text(&field.sub_label, MAX_DISPLAY_VALUE_BYTES, true)
                && is_valid_display_text(&field.value, MAX_DISPLAY_VALUE_BYTES, false)
        })
        && display
            .warnings
            .iter()
            .all(|warning| is_valid_display_text(&warning.text, MAX_DISPLAY_VALUE_BYTES, false));
    if ok { Ok(()) } else { Err(ErrorCode::Ui001) }
}

/// Process-local monotonic queue id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QueueId(pub u64);

/// Where a queued request comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueueSource {
    /// This app's own flows (send, speed-up, cancel).
    App,
    /// A dApp request.
    Site {
        /// Serialized browser origin.
        origin: String,
        /// Request deadline (spec/05 §6.4), monotonic ms.
        deadline_ms: u64,
    },
}

/// Final outcome of a queued request (spec/04 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueOutcome {
    /// Approved.
    Approved,
    /// Rejected, closed, locked while shown, unlock window "later".
    Rejected,
    /// Ready display + 120 s passed.
    Expired,
    /// The dApp request deadline passed.
    TimedOut,
    /// Cancelled by the extension.
    Cancelled,
    /// The origin was disconnected while waiting.
    Revoked,
    /// Queue limits exceeded.
    TooManyPending,
    /// `BackupPending` site request.
    NotReady,
    /// Site connect/signing request while `App::passphrase_unverified` (spec/02 §7.5).
    PassphraseUnverified,
    /// App shutdown.
    Shutdown,
}

/// A queued request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueItem<T> {
    /// Id.
    pub id: QueueId,
    /// Source.
    pub source: QueueSource,
    /// Payload (request, connect view).
    pub payload: T,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Shown<T> {
    item: QueueItem<T>,
    ready_at_ms: Option<u64>,
}

/// The approval queue: one window at a time, FIFO, app items right after the current one.
#[derive(Debug)]
pub struct ApprovalQueue<T> {
    waiting: VecDeque<QueueItem<T>>,
    shown: Option<Shown<T>>,
    next_id: u64,
}

impl<T> Default for ApprovalQueue<T> {
    fn default() -> Self {
        Self {
            waiting: VecDeque::new(),
            shown: None,
            next_id: 1,
        }
    }
}

fn origin_of(source: &QueueSource) -> Option<&str> {
    match source {
        QueueSource::App => None,
        QueueSource::Site { origin, .. } => Some(origin),
    }
}

impl<T> ApprovalQueue<T> {
    /// Number of items (shown included).
    #[must_use]
    pub fn len(&self) -> usize {
        self.waiting.len() + usize::from(self.shown.is_some())
    }

    /// Whether nothing is queued or shown.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn count_origin(&self, origin: &str) -> usize {
        self.waiting
            .iter()
            .chain(self.shown.as_ref().map(|shown| &shown.item))
            .filter(|item| origin_of(&item.source) == Some(origin))
            .count()
    }

    /// Adds a request; site items go last, app items right after the shown one.
    ///
    /// # Errors
    ///
    /// [`QueueOutcome::TooManyPending`] beyond 16 per origin or 64 overall.
    pub fn enqueue(&mut self, source: QueueSource, payload: T) -> Result<QueueId, QueueOutcome> {
        if self.len() >= MAX_APPROVALS_GLOBAL
            || origin_of(&source)
                .is_some_and(|origin| self.count_origin(origin) >= MAX_APPROVALS_PER_ORIGIN)
        {
            return Err(QueueOutcome::TooManyPending);
        }
        let id = QueueId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let item = QueueItem {
            id,
            source,
            payload,
        };
        if matches!(item.source, QueueSource::App) {
            self.waiting.push_front(item);
        } else {
            self.waiting.push_back(item);
        }
        Ok(id)
    }

    /// Takes the next item to show. Site items with less than 5 s left finish as `TimedOut`
    /// without a window (returned in `finished`).
    pub fn show_next(
        &mut self,
        now_ms: u64,
        finished: &mut Vec<(QueueItem<T>, QueueOutcome)>,
    ) -> Option<QueueId> {
        if self.shown.is_some() {
            return None;
        }
        while let Some(item) = self.waiting.pop_front() {
            if let QueueSource::Site { deadline_ms, .. } = item.source
                && deadline_ms.saturating_sub(now_ms) < MIN_REMAINING_TO_SHOW_MS
            {
                finished.push((item, QueueOutcome::TimedOut));
                continue;
            }
            let id = item.id;
            self.shown = Some(Shown {
                item,
                ready_at_ms: None,
            });
            return Some(id);
        }
        None
    }

    /// The shown item.
    #[must_use]
    pub fn shown(&self) -> Option<&QueueItem<T>> {
        self.shown.as_ref().map(|shown| &shown.item)
    }

    /// Records the first Ready display (the `ApprovalStore::issue` moment).
    pub fn mark_ready(&mut self, now_ms: u64) {
        if let Some(shown) = self.shown.as_mut()
            && shown.ready_at_ms.is_none()
        {
            shown.ready_at_ms = Some(now_ms);
        }
    }

    /// The shown item's deadline: `min(site deadline, Ready + 120 s)`; while preparing only the
    /// site deadline applies (app items have none until Ready).
    #[must_use]
    pub fn shown_deadline(&self) -> Option<u64> {
        let shown = self.shown.as_ref()?;
        let display = shown
            .ready_at_ms
            .map(|ready| ready.saturating_add(APPROVAL_DISPLAY_MS));
        match (&shown.item.source, display) {
            (QueueSource::Site { deadline_ms, .. }, Some(display)) => {
                Some(display.min(*deadline_ms))
            }
            (QueueSource::Site { deadline_ms, .. }, None) => Some(*deadline_ms),
            (QueueSource::App, display) => display,
        }
    }

    /// Ends the shown item with `outcome`.
    pub fn finish_shown(&mut self, outcome: QueueOutcome) -> Option<(QueueItem<T>, QueueOutcome)> {
        self.shown.take().map(|shown| (shown.item, outcome))
    }

    /// Deadline checks (on show and every main timer tick).
    pub fn tick(&mut self, now_ms: u64) -> Vec<(QueueItem<T>, QueueOutcome)> {
        let mut finished = Vec::new();
        if let Some(shown) = &self.shown {
            let site_deadline = match shown.item.source {
                QueueSource::Site { deadline_ms, .. } => Some(deadline_ms),
                QueueSource::App => None,
            };
            let display_deadline = shown
                .ready_at_ms
                .map(|ready| ready.saturating_add(APPROVAL_DISPLAY_MS));
            let outcome = match (site_deadline, display_deadline) {
                (Some(site), Some(display)) if now_ms >= site.min(display) => {
                    Some(if site <= display {
                        QueueOutcome::TimedOut
                    } else {
                        QueueOutcome::Expired
                    })
                }
                (Some(site), None) if now_ms >= site => Some(QueueOutcome::TimedOut),
                (None, Some(display)) if now_ms >= display => Some(QueueOutcome::Expired),
                _ => None,
            };
            if let Some(outcome) = outcome
                && let Some(done) = self.finish_shown(outcome)
            {
                finished.push(done);
            }
        }
        let mut keep = VecDeque::with_capacity(self.waiting.len());
        while let Some(item) = self.waiting.pop_front() {
            match item.source {
                QueueSource::Site { deadline_ms, .. } if now_ms >= deadline_ms => {
                    finished.push((item, QueueOutcome::TimedOut));
                }
                _ => keep.push_back(item),
            }
        }
        self.waiting = keep;
        finished
    }

    /// Wallet lock: the shown item ends `Rejected`; waiting items stay (deadlines continue).
    pub fn lock(&mut self) -> Vec<(QueueItem<T>, QueueOutcome)> {
        self.finish_shown(QueueOutcome::Rejected)
            .into_iter()
            .collect()
    }

    fn drain_waiting(
        &mut self,
        keep: impl Fn(&QueueItem<T>) -> bool,
        outcome: QueueOutcome,
    ) -> Vec<(QueueItem<T>, QueueOutcome)> {
        let mut finished = Vec::new();
        let mut kept = VecDeque::with_capacity(self.waiting.len());
        while let Some(item) = self.waiting.pop_front() {
            if keep(&item) {
                kept.push_back(item);
            } else {
                finished.push((item, outcome));
            }
        }
        self.waiting = kept;
        finished
    }

    /// Disconnecting `origin`: its waiting items end `Revoked`.
    pub fn revoke(&mut self, origin: &str) -> Vec<(QueueItem<T>, QueueOutcome)> {
        self.drain_waiting(
            |item| origin_of(&item.source) != Some(origin),
            QueueOutcome::Revoked,
        )
    }

    /// `이 사이트의 대기 요청 모두 거부`: the shown item and the same origin's waiting items.
    pub fn reject_origin_of_shown(&mut self) -> Vec<(QueueItem<T>, QueueOutcome)> {
        let Some(origin) = self
            .shown
            .as_ref()
            .and_then(|shown| origin_of(&shown.item.source))
            .map(str::to_owned)
        else {
            return Vec::new();
        };
        let mut finished: Vec<_> = self
            .finish_shown(QueueOutcome::Rejected)
            .into_iter()
            .collect();
        finished.extend(self.drain_waiting(
            |item| origin_of(&item.source) != Some(origin.as_str()),
            QueueOutcome::Rejected,
        ));
        finished
    }

    /// The id of the first item (shown or waiting) matching `predicate`.
    pub fn find(&self, predicate: impl Fn(&T) -> bool) -> Option<QueueId> {
        self.shown
            .as_ref()
            .map(|shown| &shown.item)
            .into_iter()
            .chain(self.waiting.iter())
            .find(|item| predicate(&item.payload))
            .map(|item| item.id)
    }

    /// Waiting items matching `predicate` end with `outcome` (connection revoked: signing items
    /// of that origin, spec/05 §4.5; a deleted chain; `BackupPending`).
    pub fn drain_waiting_matching(
        &mut self,
        predicate: impl Fn(&T) -> bool,
        outcome: QueueOutcome,
    ) -> Vec<(QueueItem<T>, QueueOutcome)> {
        self.drain_waiting(|item| !predicate(&item.payload), outcome)
    }

    /// Payloads of the waiting items (status texts).
    pub fn waiting_payloads(&self) -> impl Iterator<Item = &T> {
        self.waiting.iter().map(|item| &item.payload)
    }

    /// Extension cancel: removes a waiting item or closes the shown one.
    pub fn cancel(&mut self, id: QueueId) -> Option<(QueueItem<T>, QueueOutcome)> {
        if self.shown.as_ref().is_some_and(|shown| shown.item.id == id) {
            return self.finish_shown(QueueOutcome::Cancelled);
        }
        let position = self.waiting.iter().position(|item| item.id == id)?;
        self.waiting
            .remove(position)
            .map(|item| (item, QueueOutcome::Cancelled))
    }

    /// Shutdown: everything ends `Shutdown`.
    pub fn shutdown(&mut self) -> Vec<(QueueItem<T>, QueueOutcome)> {
        let mut finished: Vec<_> = self
            .finish_shown(QueueOutcome::Shutdown)
            .into_iter()
            .collect();
        finished.extend(self.drain_waiting(|_| false, QueueOutcome::Shutdown));
        finished
    }
}
