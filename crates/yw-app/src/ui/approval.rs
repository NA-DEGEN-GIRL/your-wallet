//! Approval queue and display pre-checks (spec/04 §3.1–§3.3, §3.5, §3.7). The A01 window itself
//! is drawn from M4; this module holds the pure rules it relies on: the field label table, the
//! defensive re-validation of every displayed string (E-UI-001), and the FIFO queue with its
//! limits, deadlines and outcomes (AP-3).

use std::collections::VecDeque;

use yw_core::approval::{
    ApprovalDisplay, FieldKey, MAX_DISPLAY_VALUE_BYTES, MAX_TITLE_BYTES, is_valid_display_text,
};

use crate::errors::ErrorCode;
use crate::ui::interaction::MIN_REMAINING_TO_SHOW_MS;

/// Per-origin queue bound (spec/05 §8.4).
pub const MAX_APPROVALS_PER_ORIGIN: usize = 16;
/// Global queue bound (shown item included).
pub const MAX_APPROVALS_GLOBAL: usize = 64;
/// Ready display lifetime (D23).
pub const APPROVAL_DISPLAY_MS: u64 = 120_000;

/// yw-app's field label table (spec/03 §11.2, spec/07 §13.3 and spec/08 §10 names). Keys
/// outside it are not displayed.
#[must_use]
pub const fn field_label(key: FieldKey) -> Option<&'static str> {
    Some(match key.0 {
        0x0001 => "요청 출처",
        0x0002 => "네트워크",
        0x0003 => "서명 계정",
        0x0101 => "받는 주소/컨트랙트",
        0x0102 => "보내는 금액",
        0x0103 => "호출 내용",
        0x0104 => "호출 인수",
        0x0110 => "보냄",
        0x0111 => "받음",
        0x0112 => "승인 변경",
        0x0113 => "기타 이벤트",
        0x0120 => "최대 수수료",
        0x0121 => "예상 수수료",
        0x0122 => "maxFee/tip",
        0x0123 => "가스 한도",
        0x0124 => "nonce",
        0x0125 => "대체 대상 거래",
        0x0130 => "시뮬레이션 기준",
        0x0140 => "액세스 리스트",
        0x0141 => "calldata",
        0x0301 => "도메인",
        0x0302 => "형식",
        0x0303 => "구조화 필드",
        0x0304 => "필드 트리",
        0x0401 => "메시지 텍스트",
        0x0402 => "메시지 hex",
        0x0403 => "바이트 수",
        0x0404 => "SIWE 필드",
        0x0405 => "SIWS 필드",
        0x0406 => "서명 방식",
        0x0501 | 0x0601 => "받는 주소",
        0x0502 => "자산·금액",
        0x0503 => "ATA 생성",
        0x0504 | 0x0606 => "수수료",
        0x0505 => "최대 총 차감",
        0x0506 => "잔액 (RPC 참고)",
        0x0507 => "시뮬레이션 (참고)",
        0x0508 => "유효 시간",
        0x0509 => "감사",
        0x0602 => "주소 종류",
        0x0603 => "금액",
        0x0604 => "잔돈",
        0x0605 => "입력",
        0x0607 => "총 차감",
        0x0608 => "승인 후 잔액",
        0x0609 => "교체 대상",
        0x0640 => "고급",
        _ => return None,
    })
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
            field_label(field.key).is_some()
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
