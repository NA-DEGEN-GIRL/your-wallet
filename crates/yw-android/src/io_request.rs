//! Platform I/O requests (spec/15 §3.2, §18 42 N9; 2026-11-25 A2-4b): how Rust work that needs a
//! Java service (the Keystore device key, the memory facts) gets it without Rust ever calling
//! Java. A Rust thread asks [`IoBroker::request`] and blocks; Java's I/O thread takes the request
//! with `next` ([`IoBroker::take`]), does the work and answers with `ioComplete`
//! ([`IoBroker::complete`]).
//!
//! - Request ids count up from 1 and are never reused (a broker that would wrap refuses).
//! - A request has a deadline. When it passes, the request fails (fail closed: that read or write
//!   did not happen) and is taken out of the queue if Java has not taken it yet.
//! - An answer for an id that is not waiting (late, unknown, answered twice) is dropped and its
//!   body wiped ([`Zeroizing`]).
//! - A request body and an answer body are wiped when dropped: the wrap request carries the plain
//!   32-byte file key (the one exception to "no secret in `next`", spec/15 §3.2), the unwrap
//!   answer carries it back.
//!
//! The frame `next` returns (little-endian): `0x01` (an I/O request) ‖ op ‖ kind ‖ id (8) ‖ body.
//! 2026-11-25 A2-6: or `0x02` ‖ a UI frame (yw-json, UTF-8: the screen model and the effects Java
//! applies, `crate::ui_host`), posted with [`IoBroker::post_ui`]. Java's I/O thread hands a UI
//! frame to the main thread. An I/O request goes first (a Rust thread waits for it); at most
//! [`UI_MAX`] UI frames wait. A full queue first drops what a later queued model makes useless
//! (an older model, and the field writes and reveals of a model before it, [`UiKind`]); when that
//! frees nothing, it drops every waiting UI frame and tells the poster, who sends the state again
//! (`crate::ui_host::UiHost::resync`). 2026-11-25 A2-6 review: before, a full queue dropped its
//! oldest frame of any kind, so a lost field write, timer or copy left the screen silently wrong.
//! Platform-neutral (std only, no `unsafe`): the gate's Windows build tests it, and Java's
//! `IoFrame` reads the same layout (`JvmTests`).
#![forbid(unsafe_code)]

use core::fmt;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use yw_core::secret::Zeroizing;

/// The first byte of an I/O request frame.
pub const FRAME_IO: u8 = 0x01;
/// The first byte of a UI frame (2026-11-25 A2-6).
pub const FRAME_UI: u8 = 0x02;
/// The most UI frames waiting for Java (2026-11-25 A2-6).
pub const UI_MAX: usize = 256;
/// The frame header: kind byte, op, kind, id.
pub const FRAME_HEADER: usize = 1 + 1 + 1 + 8;
/// The largest body Rust reads from an `ioComplete` (the ops' answers are at most 60 bytes).
pub const ANSWER_MAX: usize = 256;
/// The most requests waiting at once (more fail at once: nothing queues without bound).
pub const QUEUE_MAX: usize = 16;

/// What a UI frame is to the queue (2026-11-25 A2-6 review; module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiKind {
    /// A screen model: a later model replaces it.
    Model,
    /// A field write or a reveal: it names a slot of the model before it, so a later model makes
    /// it useless too (Java drops a frame of another model).
    OfModel,
    /// Anything else (the scroll to the top, a timer, a copy): never dropped while room can be
    /// made.
    Other,
}

/// A platform service op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Wrap a 32-byte file key with the device key (body: the key; answer: 60 bytes).
    Wrap,
    /// Unwrap a wrapped file key (body: 60 bytes; answer: the 32-byte key).
    Unwrap,
    /// The memory facts before an Argon2 run (body: none; answer: [`crate::kdf_gate`]'s 25 bytes).
    Memory,
    /// Make the device key when there is none, never replacing one (body: none, kind 0; answer:
    /// none). The only op that makes the key: a wrap and an unwrap never do (spec/15 §5.2;
    /// 2026-11-25 A2-4b review, before a wrap made a missing key).
    Create,
}

impl Op {
    /// The frame's op byte.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Wrap => 1,
            Self::Unwrap => 2,
            Self::Memory => 3,
            Self::Create => 4,
        }
    }
}

/// The answer statuses Java sends (fixed numbers, never an exception text, spec/15 §3.3).
pub mod status {
    /// Done; the body is the answer.
    pub const OK: i32 = 0;
    /// The device key does not exist (wrap and unwrap; 2026-11-25 A2-4b review: before, only an
    /// unwrap answered it, a wrap made the key).
    pub const KEY_MISSING: i32 = 1;
    /// The device key could not be made or loaded.
    pub const KEY_FAILED: i32 = 2;
    /// The cipher refused (a bad tag, a wrong key).
    pub const CRYPTO_FAILED: i32 = 3;
    /// The device is locked (`setUnlockedDeviceRequired`).
    pub const DEVICE_LOCKED: i32 = 4;
    /// Java could not read the request.
    pub const BAD_REQUEST: i32 = 5;
    /// Anything else.
    pub const OTHER: i32 = 6;
}

/// Why a request got no answer. Codes only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    /// No answer before the deadline.
    Timeout,
    /// Java answered with this non-OK status.
    Status(i32),
    /// Too many requests waiting, or the id counter is spent.
    Busy,
    /// A lock was poisoned (another thread panicked; the process is ending).
    Poisoned,
}

impl fmt::Display for IoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("platform request timed out"),
            Self::Status(code) => write!(formatter, "platform request failed ({code})"),
            Self::Busy => formatter.write_str("platform requests busy"),
            Self::Poisoned => formatter.write_str("platform requests unavailable"),
        }
    }
}

impl std::error::Error for IoError {}

/// One queued request: the frame Java will get (wiped on drop).
struct Queued {
    id: u64,
    frame: Zeroizing<Vec<u8>>,
}

/// What a waiting id has.
enum Answer {
    Waiting,
    Done(i32, Zeroizing<Vec<u8>>),
}

struct State {
    last_id: u64,
    queue: VecDeque<Queued>,
    /// UI frames for Java, tagged, with their kind (2026-11-25 A2-6).
    ui: VecDeque<(UiKind, Vec<u8>)>,
    waiting: BTreeMap<u64, Answer>,
}

/// The request broker (module doc). One per process (`IoBroker::new` is `const`).
pub struct IoBroker {
    state: Mutex<State>,
    /// Signalled when a request is queued (Java's `next` waits on it).
    queued: Condvar,
    /// Signalled when an answer arrives (the requesters wait on it).
    answered: Condvar,
}

impl fmt::Debug for IoBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IoBroker")
    }
}

impl Default for IoBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl IoBroker {
    /// An empty broker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                last_id: 0,
                queue: VecDeque::new(),
                ui: VecDeque::new(),
                waiting: BTreeMap::new(),
            }),
            queued: Condvar::new(),
            answered: Condvar::new(),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, IoError> {
        self.state.lock().map_err(|_| IoError::Poisoned)
    }

    /// Queues `op` for `kind` with `body` and waits up to `timeout` for Java's answer.
    ///
    /// # Errors
    ///
    /// [`IoError`]: no answer in time, a non-OK status, too many waiting, or a poisoned lock.
    pub fn request(
        &self,
        op: Op,
        kind: u8,
        body: &[u8],
        timeout: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, IoError> {
        let deadline = Instant::now().checked_add(timeout).ok_or(IoError::Busy)?;
        let mut state = self.lock()?;
        if state.waiting.len() >= QUEUE_MAX {
            return Err(IoError::Busy);
        }
        let id = state.last_id.checked_add(1).ok_or(IoError::Busy)?;
        state.last_id = id;
        let mut frame = Zeroizing::new(Vec::with_capacity(FRAME_HEADER.saturating_add(body.len())));
        frame.push(FRAME_IO);
        frame.push(op.number());
        frame.push(kind);
        frame.extend_from_slice(&id.to_le_bytes());
        frame.extend_from_slice(body);
        state.queue.push_back(Queued { id, frame });
        state.waiting.insert(id, Answer::Waiting);
        self.queued.notify_one();
        loop {
            if let Some(Answer::Done(..)) = state.waiting.get(&id) {
                return match state.waiting.remove(&id) {
                    Some(Answer::Done(status::OK, body)) => Ok(body),
                    Some(Answer::Done(code, _body)) => Err(IoError::Status(code)),
                    _ => Err(IoError::Poisoned),
                };
            }
            let now = Instant::now();
            let Some(left) = deadline
                .checked_duration_since(now)
                .filter(|left| !left.is_zero())
            else {
                // Fail closed: forget the id (a late answer is dropped) and the request too if Java
                // has not taken it.
                state.waiting.remove(&id);
                state.queue.retain(|queued| queued.id != id);
                return Err(IoError::Timeout);
            };
            state = self
                .answered
                .wait_timeout(state, left)
                .map_err(|_| IoError::Poisoned)?
                .0;
        }
    }

    /// Java's `next`: the oldest request's frame, waiting up to `timeout` for one; `None` when
    /// none came. The frame leaves the broker (the caller copies it to Java and drops it).
    #[must_use]
    pub fn take(&self, timeout: Duration) -> Option<Zeroizing<Vec<u8>>> {
        let deadline = Instant::now().checked_add(timeout)?;
        let mut state = self.lock().ok()?;
        loop {
            if let Some(queued) = state.queue.pop_front() {
                return Some(queued.frame);
            }
            if let Some((_, frame)) = state.ui.pop_front() {
                return Some(Zeroizing::new(frame));
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())?;
            state = self.queued.wait_timeout(state, left).ok()?.0;
        }
    }

    /// Queues one UI frame (`json` of `kind`, tagged here with [`FRAME_UI`]) for Java's `next`
    /// (2026-11-25 A2-6). A full queue first drops what a later queued model makes useless; when
    /// that frees nothing, every waiting UI frame is dropped, this one is not queued, and the
    /// answer is `false`: the caller must send the screen's state again (module doc; 2026-11-25
    /// A2-6 review). Nothing happens on a poisoned lock (`true`: the process is ending).
    #[must_use]
    pub fn post_ui(&self, kind: UiKind, json: &[u8]) -> bool {
        let Ok(mut state) = self.lock() else {
            return true;
        };
        if state.ui.len() >= UI_MAX {
            // Keep the last model, everything after it, and every frame no model replaces.
            if let Some(last) = state
                .ui
                .iter()
                .rposition(|(kind, _)| *kind == UiKind::Model)
            {
                let mut at = 0_usize;
                state.ui.retain(|(kind, _)| {
                    let keep = at >= last || *kind == UiKind::Other;
                    at = at.saturating_add(1);
                    keep
                });
            }
            if state.ui.len() >= UI_MAX {
                state.ui.clear();
                return false;
            }
        }
        let mut frame = Vec::with_capacity(json.len().saturating_add(1));
        frame.push(FRAME_UI);
        frame.extend_from_slice(json);
        state.ui.push_back((kind, frame));
        self.queued.notify_one();
        true
    }

    /// Java's `ioComplete`: the answer of `id`. Dropped (and `body` wiped) unless `id` is waiting
    /// and unanswered. Returns whether it was taken.
    pub fn complete(&self, id: u64, status: i32, body: Zeroizing<Vec<u8>>) -> bool {
        let Ok(mut state) = self.lock() else {
            return false;
        };
        match state.waiting.get_mut(&id) {
            Some(answer @ Answer::Waiting) => {
                *answer = Answer::Done(status, body);
                self.answered.notify_all();
                true
            }
            _ => false,
        }
    }

    /// How many requests wait for an answer (tests and the panic-free shutdown check).
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.lock().map_or(0, |state| state.waiting.len())
    }
}

/// The parts of a request frame (what Java's `IoFrame` reads), for tests and checks.
#[must_use]
pub fn parse_frame(frame: &[u8]) -> Option<(u8, u8, u64, &[u8])> {
    let (head, body) = frame.split_at_checked(FRAME_HEADER)?;
    let [tag, op, kind, id @ ..] = head else {
        return None;
    };
    if *tag != FRAME_IO {
        return None;
    }
    let id = u64::from_le_bytes(<[u8; 8]>::try_from(id).ok()?);
    Some((*op, *kind, id, body))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use yw_core::secret::Zeroizing;

    use super::{
        FRAME_IO, FRAME_UI, IoBroker, IoError, Op, QUEUE_MAX, UI_MAX, UiKind, parse_frame, status,
    };

    const LONG: Duration = Duration::from_secs(5);
    const SHORT: Duration = Duration::from_millis(50);

    /// A Java stand-in: answers every request with `answer(op, body)`.
    fn serve(
        broker: Arc<IoBroker>,
        count: usize,
        answer: impl Fn(u8, &[u8]) -> (i32, Vec<u8>) + Send + 'static,
    ) -> std::thread::JoinHandle<Vec<u64>> {
        std::thread::spawn(move || {
            let mut ids = Vec::new();
            while ids.len() < count {
                let Some(frame) = broker.take(LONG) else {
                    break;
                };
                let (op, _kind, id, body) = parse_frame(&frame).unwrap();
                let (code, reply) = answer(op, body);
                ids.push(id);
                broker.complete(id, code, Zeroizing::new(reply));
            }
            ids
        })
    }

    #[test]
    fn a_request_gets_its_answer_and_ids_count_up() {
        let broker = Arc::new(IoBroker::new());
        let java = serve(Arc::clone(&broker), 3, |op, body| {
            (status::OK, [&[op][..], body].concat())
        });
        for round in 1..=3_u8 {
            let answer = broker.request(Op::Wrap, 2, &[round; 32], LONG).unwrap();
            assert_eq!(answer[0], 1);
            assert_eq!(&answer[1..], &[round; 32]);
        }
        assert_eq!(java.join().unwrap(), [1, 2, 3]);
        assert_eq!(broker.waiting(), 0);
    }

    #[test]
    fn the_frame_layout() {
        let broker = Arc::new(IoBroker::new());
        let java = std::thread::spawn({
            let broker = Arc::clone(&broker);
            move || {
                let frame = broker.take(LONG).unwrap();
                let copy = frame.to_vec();
                let (_, _, id, _) = parse_frame(&frame).unwrap();
                broker.complete(id, status::OK, Zeroizing::new(Vec::new()));
                copy
            }
        });
        broker.request(Op::Unwrap, 3, &[0xab, 0xcd], LONG).unwrap();
        let frame = java.join().unwrap();
        assert_eq!(frame, [FRAME_IO, 2, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd]);
        assert_eq!(parse_frame(&[0x02; 12]), None);
        assert_eq!(parse_frame(&[FRAME_IO; 10]), None);
        assert_eq!(Op::Memory.number(), 3);
        assert_eq!(Op::Create.number(), 4);
    }

    #[test]
    fn a_status_is_an_error_and_the_body_is_dropped() {
        let broker = Arc::new(IoBroker::new());
        let java = serve(Arc::clone(&broker), 1, |_, _| {
            (status::KEY_MISSING, vec![9; 32])
        });
        assert_eq!(
            broker.request(Op::Unwrap, 1, &[0; 60], LONG).map(|_| ()),
            Err(IoError::Status(status::KEY_MISSING))
        );
        java.join().unwrap();
    }

    #[test]
    fn timeout_fails_closed_and_late_answers_are_dropped() {
        let broker = IoBroker::new();
        // Nobody serves: the request times out and leaves the queue.
        assert_eq!(
            broker.request(Op::Memory, 0, &[], SHORT).map(|_| ()),
            Err(IoError::Timeout)
        );
        assert_eq!(broker.waiting(), 0);
        assert!(
            broker.take(Duration::ZERO).is_none(),
            "the timed-out request was withdrawn"
        );
        // The late answer for id 1 is dropped; the next request is id 2, never 1 again.
        assert!(!broker.complete(1, status::OK, Zeroizing::new(vec![1; 32])));
        let broker = Arc::new(broker);
        let java = serve(Arc::clone(&broker), 1, |_, _| (status::OK, Vec::new()));
        broker.request(Op::Memory, 0, &[], LONG).unwrap();
        assert_eq!(java.join().unwrap(), [2]);
        assert!(
            !broker.complete(2, status::OK, Zeroizing::new(Vec::new())),
            "answered twice"
        );
    }

    #[test]
    fn a_taken_request_that_times_out_drops_its_answer() {
        let broker = Arc::new(IoBroker::new());
        let java = std::thread::spawn({
            let broker = Arc::clone(&broker);
            move || {
                let frame = broker.take(LONG).unwrap();
                let (_, _, id, _) = parse_frame(&frame).unwrap();
                std::thread::sleep(Duration::from_millis(200));
                broker.complete(id, status::OK, Zeroizing::new(vec![7; 32]))
            }
        });
        assert_eq!(
            broker.request(Op::Unwrap, 1, &[0; 60], SHORT).map(|_| ()),
            Err(IoError::Timeout)
        );
        assert!(!java.join().unwrap(), "the late answer was not taken");
        assert_eq!(broker.waiting(), 0);
    }

    #[test]
    fn the_queue_is_bounded() {
        let broker = Arc::new(IoBroker::new());
        let waiters: Vec<_> = (0..QUEUE_MAX)
            .map(|_| {
                let broker = Arc::clone(&broker);
                std::thread::spawn(move || broker.request(Op::Memory, 0, &[], LONG).map(|_| ()))
            })
            .collect();
        while broker.waiting() < QUEUE_MAX {
            std::thread::yield_now();
        }
        assert_eq!(
            broker.request(Op::Memory, 0, &[], LONG).map(|_| ()),
            Err(IoError::Busy)
        );
        let java = serve(Arc::clone(&broker), QUEUE_MAX, |_, _| {
            (status::OK, Vec::new())
        });
        for waiter in waiters {
            assert_eq!(waiter.join().unwrap(), Ok(()));
        }
        java.join().unwrap();
    }

    #[test]
    fn take_waits_and_gives_up() {
        let broker = IoBroker::new();
        assert!(broker.take(SHORT).is_none());
    }

    /// 2026-11-25 A2-6: UI frames are tagged and come after a waiting I/O request, in order.
    #[test]
    fn ui_frames_follow_requests_in_order() {
        let broker = Arc::new(IoBroker::new());
        assert!(broker.post_ui(UiKind::Other, b"{\"t\":\"top\"}"));
        let requester = std::thread::spawn({
            let broker = Arc::clone(&broker);
            move || broker.request(Op::Memory, 0, &[], LONG).is_ok()
        });
        // Java's side: whichever comes first, the request is never behind a UI frame queued later.
        let first = broker.take(LONG).unwrap();
        let first = if first[0] == FRAME_UI {
            assert_eq!(&first[1..], b"{\"t\":\"top\"}");
            broker.take(LONG).unwrap()
        } else {
            first
        };
        let (_, _, id, _) = parse_frame(&first).unwrap();
        assert!(broker.complete(id, status::OK, Zeroizing::new(Vec::new())));
        assert!(requester.join().unwrap());
    }

    fn drain_ui(broker: &IoBroker) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| broker.take(Duration::ZERO))
            .map(|frame| frame[1..].to_vec())
            .collect()
    }

    /// 2026-11-25 A2-6 review: a full queue drops only what a later model replaces (older models
    /// and their field writes and reveals), never a timer, copy or scroll frame.
    #[test]
    fn a_full_ui_queue_drops_only_replaced_frames() {
        let broker = IoBroker::new();
        assert!(broker.post_ui(UiKind::Other, b"timer"));
        for at in 0..UI_MAX - 3 {
            let kind = if at % 2 == 0 {
                UiKind::Model
            } else {
                UiKind::OfModel
            };
            assert!(broker.post_ui(kind, format!("m{at}").as_bytes()));
        }
        assert!(broker.post_ui(UiKind::Other, b"copy"));
        assert!(broker.post_ui(UiKind::OfModel, b"field"));
        // Full: the next frame drops every model and write before the last model.
        assert!(broker.post_ui(UiKind::Other, b"top"));
        // The last model is `m{UI_MAX - 4}` (an even index): it and what follows it stay.
        let last = UI_MAX - 4;
        assert_eq!(
            drain_ui(&broker),
            [
                b"timer".to_vec(),
                format!("m{last}").into_bytes(),
                b"copy".to_vec(),
                b"field".to_vec(),
                b"top".to_vec(),
            ]
        );
    }

    /// 2026-11-25 A2-6 review: when nothing can be dropped, every waiting frame goes and the
    /// poster is told (it sends the state again); the queue takes frames again at once.
    #[test]
    fn a_full_ui_queue_with_nothing_replaced_asks_for_a_resync() {
        let broker = IoBroker::new();
        for at in 0..UI_MAX {
            assert!(broker.post_ui(UiKind::Other, at.to_string().as_bytes()));
        }
        assert!(!broker.post_ui(UiKind::Model, b"late"));
        assert!(broker.take(Duration::ZERO).is_none(), "all dropped");
        assert!(broker.post_ui(UiKind::Model, b"fresh"));
        assert_eq!(drain_ui(&broker), [b"fresh".to_vec()]);
    }
}
