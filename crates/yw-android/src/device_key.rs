//! The Keystore device key `yw.device.v1` as yw-core's [`DeviceKey`] (spec/15 §5.2, §3.2, §18 42
//! N9, §18 44; 2026-11-25 A2-4b), and the memory facts of [`crate::kdf_gate`], both through
//! [`IoBroker`] requests that Java's I/O thread serves. Rust never calls Java.
//!
//! The wrap request's body is the plain 32-byte file key and the unwrap answer's body is that key
//! again; both are wiped by the broker when dropped, and the copy here is a `Zeroizing` array.
//! Java fills its arrays with zeros right after `Cipher.doFinal` (spec/15 §3.2; the residual of
//! copies Java cannot wipe is spec/15 §5.2's).
//!
//! Every failure is an error code ([`DeviceCode`]), never a damaged file: a missing or unusable
//! key, a Keystore refusal, a locked device or no answer in time must not lead to a quarantine.
//! Platform-neutral: tested on the Windows gate with a Java stand-in thread.
#![forbid(unsafe_code)]

use std::time::Duration;

use yw_core::secret::Zeroizing;
use yw_core::vault::envelope::{DeviceKey, EnvelopeError, SealKind, WRAPPED_KEY_LEN};

use crate::io_request::{IoBroker, IoError, Op};
use crate::kdf_gate::{self, MemoryFacts};

/// How long a Keystore request may take before it fails (a cold key operation measured 15–52 ms
/// on the test device, P0-10; a generous bound, since a timed-out write is a failed write).
pub const KEY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the memory facts may take.
pub const FACTS_TIMEOUT: Duration = Duration::from_secs(5);

/// The storage error codes of the device key (`StorageError::Io`, spec/15 §5.2): `0x7977_00ss` for
/// Java's status `ss`, and the Rust-side failures below. Codes only, no text (D28).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceCode;

impl DeviceCode {
    /// The common prefix (`"yw"`).
    pub const BASE: u32 = 0x7977_0000;
    /// No answer in time.
    pub const TIMEOUT: u32 = Self::BASE + 0x100;
    /// Too many requests waiting.
    pub const BUSY: u32 = Self::BASE + 0x101;
    /// A poisoned lock.
    pub const POISONED: u32 = Self::BASE + 0x102;
    /// An answer of the wrong length.
    pub const BAD_ANSWER: u32 = Self::BASE + 0x103;

    /// The code of a request error.
    #[must_use]
    pub fn of(error: IoError) -> u32 {
        match error {
            IoError::Timeout => Self::TIMEOUT,
            IoError::Busy => Self::BUSY,
            IoError::Poisoned => Self::POISONED,
            IoError::Status(status) => {
                Self::BASE + u32::try_from(status).map_or(0xff, |status| status.min(0xff))
            }
        }
    }
}

/// [`DeviceKey`] over the broker.
#[derive(Debug, Clone, Copy)]
pub struct BrokerKey<'a> {
    broker: &'a IoBroker,
    timeout: Duration,
}

impl<'a> BrokerKey<'a> {
    /// The device key served through `broker`.
    #[must_use]
    pub const fn new(broker: &'a IoBroker) -> Self {
        Self {
            broker,
            timeout: KEY_TIMEOUT,
        }
    }

    /// The same with another timeout (tests).
    #[must_use]
    pub const fn with_timeout(broker: &'a IoBroker, timeout: Duration) -> Self {
        Self { broker, timeout }
    }
}

impl DeviceKey for BrokerKey<'_> {
    fn wrap(
        &self,
        kind: SealKind,
        file_key: &[u8; 32],
    ) -> Result<[u8; WRAPPED_KEY_LEN], EnvelopeError> {
        let answer = self
            .broker
            .request(Op::Wrap, kind.number(), file_key, self.timeout)
            .map_err(|error| EnvelopeError::Device(DeviceCode::of(error)))?;
        <[u8; WRAPPED_KEY_LEN]>::try_from(answer.as_slice())
            .map_err(|_| EnvelopeError::Device(DeviceCode::BAD_ANSWER))
    }

    fn unwrap(
        &self,
        kind: SealKind,
        wrapped: &[u8; WRAPPED_KEY_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
        let answer = self
            .broker
            .request(Op::Unwrap, kind.number(), wrapped, self.timeout)
            .map_err(|error| EnvelopeError::Device(DeviceCode::of(error)))?;
        let mut key = Zeroizing::new([0_u8; 32]);
        let bytes = <&[u8; 32]>::try_from(answer.as_slice())
            .map_err(|_| EnvelopeError::Device(DeviceCode::BAD_ANSWER))?;
        key.copy_from_slice(bytes);
        Ok(key)
    }
}

/// The memory facts now, or `None` (no answer, a malformed one): the caller then runs no Argon2.
#[must_use]
pub fn memory_facts(broker: &IoBroker, timeout: Duration) -> Option<MemoryFacts> {
    let answer = broker.request(Op::Memory, 0, &[], timeout).ok()?;
    kdf_gate::parse(&answer)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use yw_core::secret::Zeroizing;
    use yw_core::vault::envelope::{self, DeviceKey, EnvelopeError, SealKind};

    use super::{BrokerKey, DeviceCode, memory_facts};
    use crate::io_request::{IoBroker, parse_frame, status};
    use crate::kdf_gate::{Gate, gate};

    /// A Java stand-in: wraps by XOR with a pad (60 bytes: 12 "iv", 32, 16 "tag"); `fail` answers
    /// every unwrap with that status.
    fn java(broker: Arc<IoBroker>, count: usize, fail: Option<i32>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for _ in 0..count {
                let Some(frame) = broker.take(Duration::from_secs(5)) else {
                    return;
                };
                let (op, kind, id, body) = parse_frame(&frame).unwrap();
                let (code, answer) = match (op, fail) {
                    (1, _) => {
                        let mut out = vec![0x11_u8; 60];
                        for (at, byte) in body.iter().enumerate() {
                            out[12 + at] = byte ^ 0x5a ^ kind;
                        }
                        (status::OK, out)
                    }
                    (2, None) => (
                        status::OK,
                        body[12..44].iter().map(|byte| byte ^ 0x5a ^ kind).collect(),
                    ),
                    (2, Some(code)) => (code, Vec::new()),
                    (3, _) => {
                        let mut out = Vec::new();
                        out.extend_from_slice(&(4_u64 << 30).to_le_bytes());
                        out.extend_from_slice(&(2_u64 << 30).to_le_bytes());
                        out.extend_from_slice(&(300_u64 << 20).to_le_bytes());
                        out.push(0);
                        (status::OK, out)
                    }
                    _ => (status::BAD_REQUEST, Vec::new()),
                };
                broker.complete(id, code, Zeroizing::new(answer));
            }
        })
    }

    #[test]
    fn seal_and_open_through_the_broker() {
        let broker = Arc::new(IoBroker::new());
        let server = java(Arc::clone(&broker), 2, None);
        let key = BrokerKey::new(&broker);
        let sealed = envelope::seal(SealKind::Journal, b"journal", &key).unwrap();
        assert_eq!(
            envelope::open(SealKind::Journal, &sealed, &key)
                .unwrap()
                .as_slice(),
            b"journal"
        );
        server.join().unwrap();
    }

    #[test]
    fn statuses_and_timeouts_are_device_codes() {
        let broker = Arc::new(IoBroker::new());
        let server = java(Arc::clone(&broker), 2, Some(status::KEY_MISSING));
        let key = BrokerKey::new(&broker);
        let sealed = envelope::seal(SealKind::Vault, b"v", &key).unwrap();
        assert_eq!(
            envelope::open(SealKind::Vault, &sealed, &key).map(|_| ()),
            Err(EnvelopeError::Device(DeviceCode::BASE + 1))
        );
        server.join().unwrap();
        let quick = BrokerKey::with_timeout(&broker, Duration::from_millis(30));
        assert_eq!(
            quick.wrap(SealKind::Vault, &[0; 32]).map(|_| ()),
            Err(EnvelopeError::Device(DeviceCode::TIMEOUT))
        );
        assert_eq!(
            DeviceCode::of(crate::io_request::IoError::Status(-1)),
            DeviceCode::BASE + 0xff
        );
    }

    #[test]
    fn a_wrong_length_answer_is_refused() {
        let broker = Arc::new(IoBroker::new());
        let server = std::thread::spawn({
            let broker = Arc::clone(&broker);
            move || {
                let frame = broker.take(Duration::from_secs(5)).unwrap();
                let (_, _, id, _) = parse_frame(&frame).unwrap();
                broker.complete(id, status::OK, Zeroizing::new(vec![0; 59]));
            }
        });
        assert_eq!(
            BrokerKey::new(&broker)
                .wrap(SealKind::Meta, &[1; 32])
                .map(|_| ()),
            Err(EnvelopeError::Device(DeviceCode::BAD_ANSWER))
        );
        server.join().unwrap();
    }

    #[test]
    fn memory_facts_through_the_broker() {
        let broker = Arc::new(IoBroker::new());
        let server = java(Arc::clone(&broker), 1, None);
        let facts = memory_facts(&broker, Duration::from_secs(5)).unwrap();
        assert_eq!(facts.total, 4 << 30);
        assert_eq!(gate(facts), Gate::Go);
        server.join().unwrap();
        assert_eq!(memory_facts(&broker, Duration::from_millis(20)), None);
    }
}
