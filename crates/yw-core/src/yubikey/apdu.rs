//! ISO 7816-4 command/response APDUs (spec/10 §5.1): short and extended encoding, command
//! chaining (`CLA | 0x10`), `61xx` GET RESPONSE collection and `6Cxx` re-send.
//!
//! The byte layer is pure; [`exchange`] drives a [`CardTransport`] (PC/SC in yw-win, the APDU
//! emulator in tests). Data buffers that may carry PINs or private keys are `Zeroizing`.
#![deny(clippy::indexing_slicing)]

use zeroize::Zeroizing;

use super::{CardError, CardTransport};

/// Largest data field of one short command APDU.
pub const SHORT_MAX_DATA: usize = 255;
/// Largest data field of one extended command APDU accepted here (YubiKey 4.3+ accepts APDUs of
/// up to 3,062 bytes; header, Lc and Le take 9).
pub const EXTENDED_MAX_DATA: usize = 3_000;
/// Largest response collected through `61xx` GET RESPONSE (the longest real answer, a PIV
/// certificate or RSA-4096 key, is below 4 KiB; this is an upper bound against a looping card).
pub const MAX_RESPONSE: usize = 16_384;
/// Most GET RESPONSE rounds per command.
const MAX_GET_RESPONSE_ROUNDS: usize = 80;

/// Status word `9000`.
pub const SW_OK: u16 = 0x9000;
/// Security status not satisfied (PIN / management key / touch not satisfied).
pub const SW_SECURITY_STATUS: u16 = 0x6982;
/// Authentication method blocked (PIN blocked).
pub const SW_AUTH_BLOCKED: u16 = 0x6983;
/// Reference data not usable / conditions of use not satisfied.
pub const SW_CONDITIONS: u16 = 0x6985;
/// Incorrect parameters in the data field.
pub const SW_WRONG_DATA: u16 = 0x6A80;
/// Function not supported.
pub const SW_FUNC_NOT_SUPPORTED: u16 = 0x6A81;
/// File or application not found.
pub const SW_NOT_FOUND: u16 = 0x6A82;
/// Incorrect P1/P2.
pub const SW_WRONG_P1P2: u16 = 0x6A86;
/// Referenced data not found.
pub const SW_REF_NOT_FOUND: u16 = 0x6A88;
/// Instruction not supported.
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
/// Class not supported.
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;
/// Wrong length.
pub const SW_WRONG_LENGTH: u16 = 0x6700;

/// How command APDUs are framed on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApduMode {
    /// Short APDUs (Lc ≤ 255) with command chaining for longer data; works on every reader,
    /// including NFC readers without extended-length support. The default.
    Short,
    /// Extended APDUs (3-byte Lc/Le) for data up to [`EXTENDED_MAX_DATA`].
    Extended,
}

/// One command APDU. `data` is wiped on drop (it may hold a PIN or a private key).
pub struct Command {
    /// Class byte (the chaining bit is added by the encoder).
    pub cla: u8,
    /// Instruction.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Data field.
    pub data: Zeroizing<Vec<u8>>,
    /// Whether a response body is expected (`Le = 00` / `00 00`, i.e. "up to the maximum").
    pub expect_response: bool,
}

impl core::fmt::Debug for Command {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The data may be a PIN or a key: only the header and the length are shown.
        write!(
            formatter,
            "Command({:02X} {:02X} {:02X} {:02X}, {} bytes)",
            self.cla,
            self.ins,
            self.p1,
            self.p2,
            self.data.len()
        )
    }
}

impl Command {
    /// A command with data and an expected response.
    #[must_use]
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Zeroizing::new(data),
            expect_response: true,
        }
    }

    /// A command without a response body (`Le` absent).
    #[must_use]
    pub fn no_response(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            expect_response: false,
            ..Self::new(cla, ins, p1, p2, data)
        }
    }
}

/// A response APDU: body and status word.
pub struct Response {
    /// Response data (wiped on drop: may hold a signature, harmless, but uniform handling).
    pub data: Zeroizing<Vec<u8>>,
    /// `SW1 SW2`.
    pub sw: u16,
}

impl core::fmt::Debug for Response {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "Response({:04X}, {} bytes)",
            self.sw,
            self.data.len()
        )
    }
}

impl Response {
    /// Splits raw bytes `data ‖ SW1 ‖ SW2`.
    ///
    /// # Errors
    ///
    /// [`CardError::Malformed`] for fewer than two bytes.
    pub fn parse(raw: &[u8]) -> Result<Self, CardError> {
        let (data, sw) = raw.split_last_chunk::<2>().ok_or(CardError::Malformed)?;
        Ok(Self {
            data: Zeroizing::new(data.to_vec()),
            sw: u16::from_be_bytes(*sw),
        })
    }

    /// `Ok(data)` for `9000`, otherwise the status mapped by [`CardError::from_status`].
    ///
    /// # Errors
    ///
    /// The mapped status error.
    pub fn ok(self) -> Result<Zeroizing<Vec<u8>>, CardError> {
        if self.sw == SW_OK {
            Ok(self.data)
        } else {
            Err(CardError::from_status(self.sw))
        }
    }
}

fn push_header(out: &mut Vec<u8>, cla: u8, command: &Command) {
    out.extend_from_slice(&[cla, command.ins, command.p1, command.p2]);
}

/// Encodes one short APDU (`data.len() ≤ 255`), cases 1–4.
fn encode_short(cla: u8, command: &Command, data: &[u8], expect: bool) -> Option<Vec<u8>> {
    let lc = u8::try_from(data.len()).ok()?;
    let mut out = Vec::with_capacity(data.len().checked_add(6)?);
    push_header(&mut out, cla, command);
    if !data.is_empty() {
        out.push(lc);
        out.extend_from_slice(data);
    }
    if expect {
        out.push(0x00);
    }
    Some(out)
}

/// Encodes one extended APDU (`data.len() ≤ EXTENDED_MAX_DATA`), cases 1, 2E, 3E, 4E.
fn encode_extended(command: &Command) -> Option<Vec<u8>> {
    let data = command.data.as_slice();
    if data.len() > EXTENDED_MAX_DATA {
        return None;
    }
    let lc = u16::try_from(data.len()).ok()?;
    let mut out = Vec::with_capacity(data.len().checked_add(9)?);
    push_header(&mut out, command.cla, command);
    if data.is_empty() {
        if command.expect_response {
            out.extend_from_slice(&[0x00, 0x00, 0x00]);
        }
    } else {
        out.push(0x00);
        out.extend_from_slice(&lc.to_be_bytes());
        out.extend_from_slice(data);
        if command.expect_response {
            out.extend_from_slice(&[0x00, 0x00]);
        }
    }
    Some(out)
}

/// The wire frames of `command` in `mode`: one frame, or for short mode with more than 255 data
/// bytes a chain whose frames but the last carry `CLA | 0x10` and no `Le`. Frames are wiped on
/// drop.
///
/// # Errors
///
/// [`CardError::TooLarge`] when the data exceeds [`EXTENDED_MAX_DATA`].
pub fn encode(command: &Command, mode: ApduMode) -> Result<Vec<Zeroizing<Vec<u8>>>, CardError> {
    if command.data.len() > EXTENDED_MAX_DATA {
        return Err(CardError::TooLarge);
    }
    match mode {
        ApduMode::Extended => Ok(vec![Zeroizing::new(
            encode_extended(command).ok_or(CardError::TooLarge)?,
        )]),
        ApduMode::Short => {
            let data = command.data.as_slice();
            if data.len() <= SHORT_MAX_DATA {
                return Ok(vec![Zeroizing::new(
                    encode_short(command.cla, command, data, command.expect_response)
                        .ok_or(CardError::TooLarge)?,
                )]);
            }
            let mut frames = Vec::new();
            let mut chunks = data.chunks(SHORT_MAX_DATA).peekable();
            while let Some(chunk) = chunks.next() {
                let last = chunks.peek().is_none();
                let cla = if last {
                    command.cla
                } else {
                    command.cla | 0x10
                };
                let expect = last && command.expect_response;
                frames.push(Zeroizing::new(
                    encode_short(cla, command, chunk, expect).ok_or(CardError::TooLarge)?,
                ));
            }
            Ok(frames)
        }
    }
}

fn transmit(transport: &mut dyn CardTransport, frame: &[u8]) -> Result<Response, CardError> {
    let raw = Zeroizing::new(transport.transmit(frame)?);
    Response::parse(&raw)
}

/// Sends `command` and returns the complete response: chained frames must each answer `9000`;
/// `61xx` is followed by GET RESPONSE (`00 C0 00 00 xx`) until the card stops, `6Cxx` re-sends
/// the last frame with `Le = xx`. The final status word is returned unchanged (callers map it).
///
/// # Errors
///
/// [`CardError::TooLarge`], transport errors, a chained frame refused (mapped status),
/// [`CardError::Malformed`] for a response above [`MAX_RESPONSE`] or too many rounds.
pub fn exchange(
    transport: &mut dyn CardTransport,
    command: &Command,
    mode: ApduMode,
) -> Result<Response, CardError> {
    let frames = encode(command, mode)?;
    let mut response = None;
    let count = frames.len();
    for (position, frame) in frames.iter().enumerate() {
        let answer = transmit(transport, frame)?;
        if position.checked_add(1) == Some(count) {
            response = Some((answer, frame));
        } else if answer.sw != SW_OK {
            return Err(CardError::from_status(answer.sw));
        }
    }
    let (mut answer, last_frame) = response.ok_or(CardError::Malformed)?;
    // `6Cxx` = wrong Le: re-send with Le = xx (only frames that carry an Le byte).
    if answer.sw & 0xFF00 == 0x6C00 && command.expect_response && mode == ApduMode::Short {
        let mut again = Zeroizing::new(last_frame.to_vec());
        if let Some(le) = again.last_mut() {
            *le = u8::try_from(answer.sw & 0x00FF).map_err(|_| CardError::Malformed)?;
        }
        answer = transmit(transport, &again)?;
    }
    let mut data = Zeroizing::new(Vec::new());
    let mut rounds = 0_usize;
    loop {
        data.extend_from_slice(&answer.data);
        if data.len() > MAX_RESPONSE {
            return Err(CardError::Malformed);
        }
        if answer.sw & 0xFF00 != 0x6100 {
            return Ok(Response {
                data,
                sw: answer.sw,
            });
        }
        rounds = rounds.checked_add(1).ok_or(CardError::Malformed)?;
        if rounds > MAX_GET_RESPONSE_ROUNDS {
            return Err(CardError::Malformed);
        }
        let le = u8::try_from(answer.sw & 0x00FF).map_err(|_| CardError::Malformed)?;
        answer = transmit(transport, &[0x00, 0xC0, 0x00, 0x00, le])?;
    }
}

/// [`exchange`] and require `9000`.
///
/// # Errors
///
/// As [`exchange`], or the mapped status error.
pub fn exchange_ok(
    transport: &mut dyn CardTransport,
    command: &Command,
    mode: ApduMode,
) -> Result<Zeroizing<Vec<u8>>, CardError> {
    exchange(transport, command, mode)?.ok()
}

/// Splits one received frame into `(header, data, expects_response)` for the emulator: accepts
/// short and extended cases 1–4. `None` for a malformed frame.
pub(crate) fn decode_frame(frame: &[u8]) -> Option<([u8; 4], Vec<u8>, bool)> {
    let (header, rest) = frame.split_first_chunk::<4>()?;
    match rest {
        // Case 1, case 2S.
        [] => Some((*header, Vec::new(), false)),
        [_le] => Some((*header, Vec::new(), true)),
        // Case 2E: 00 Le(2).
        [0x00, _, _] => Some((*header, Vec::new(), true)),
        // Cases 3E / 4E: 00 Lc(2) data [Le(2)].
        [0x00, hi, lo, body @ ..] => {
            let lc = usize::from(u16::from_be_bytes([*hi, *lo]));
            if lc == 0 {
                None
            } else if body.len() == lc {
                Some((*header, body.to_vec(), false))
            } else if body.len() == lc.checked_add(2)? {
                Some((*header, body.get(..lc)?.to_vec(), true))
            } else {
                None
            }
        }
        // Cases 3S / 4S: Lc(1, non-zero) data [Le(1)].
        [lc, body @ ..] => {
            let lc = usize::from(*lc);
            if body.len() == lc {
                Some((*header, body.to_vec(), false))
            } else if body.len() == lc.checked_add(1)? {
                Some((*header, body.get(..lc)?.to_vec(), true))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions on fixed frames")]
mod tests {
    use super::*;

    struct Script {
        answers: Vec<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl CardTransport for Script {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, CardError> {
            self.sent.push(command.to_vec());
            if self.answers.is_empty() {
                return Err(CardError::Malformed);
            }
            Ok(self.answers.remove(0))
        }
    }

    #[test]
    fn short_cases() {
        let case1 = Command::no_response(0x00, 0xA4, 0x04, 0x00, Vec::new());
        assert_eq!(
            *encode(&case1, ApduMode::Short).unwrap()[0],
            [0, 0xA4, 4, 0]
        );
        let case2 = Command::new(0x00, 0xCA, 0x00, 0x6E, Vec::new());
        assert_eq!(
            *encode(&case2, ApduMode::Short).unwrap()[0],
            [0, 0xCA, 0, 0x6E, 0]
        );
        let case3 = Command::no_response(0x00, 0x20, 0x00, 0x81, b"123456".to_vec());
        assert_eq!(
            *encode(&case3, ApduMode::Short).unwrap()[0],
            [0, 0x20, 0, 0x81, 6, b'1', b'2', b'3', b'4', b'5', b'6']
        );
        let case4 = Command::new(0x00, 0x2A, 0x9E, 0x9A, vec![0xAB; 32]);
        let frame = &encode(&case4, ApduMode::Short).unwrap()[0];
        assert_eq!(frame.len(), 4 + 1 + 32 + 1);
        assert_eq!(frame[4], 32);
        assert_eq!(frame[37], 0);
    }

    #[test]
    fn extended_cases() {
        let case2 = Command::new(0x00, 0xCA, 0x00, 0x6E, Vec::new());
        assert_eq!(
            *encode(&case2, ApduMode::Extended).unwrap()[0],
            [0, 0xCA, 0, 0x6E, 0, 0, 0]
        );
        let case4 = Command::new(0x00, 0xDB, 0x3F, 0xFF, vec![7; 300]);
        let frame = &encode(&case4, ApduMode::Extended).unwrap()[0];
        assert_eq!(&frame[..7], &[0, 0xDB, 0x3F, 0xFF, 0, 0x01, 0x2C]);
        assert_eq!(frame.len(), 7 + 300 + 2);
        let (header, data, expect) = decode_frame(frame).unwrap();
        assert_eq!(header, [0, 0xDB, 0x3F, 0xFF]);
        assert_eq!(data, vec![7; 300]);
        assert!(expect);
        let too_big = Command::new(0, 0xDB, 0x3F, 0xFF, vec![0; EXTENDED_MAX_DATA + 1]);
        assert!(matches!(
            encode(&too_big, ApduMode::Extended),
            Err(CardError::TooLarge)
        ));
    }

    #[test]
    fn short_chaining_splits_at_255() {
        let command = Command::no_response(0x00, 0xDB, 0x3F, 0xFF, vec![1; 600]);
        let frames = encode(&command, ApduMode::Short).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0][0], 0x10);
        assert_eq!(frames[1][0], 0x10);
        assert_eq!(frames[2][0], 0x00);
        assert_eq!(frames[0][4], 255);
        assert_eq!(frames[2][4], 90);
        assert_eq!(frames[2].len(), 5 + 90);
        let mut joined = Vec::new();
        for frame in &frames {
            let (_, data, _) = decode_frame(frame).unwrap();
            joined.extend(data);
        }
        assert_eq!(joined, vec![1; 600]);
    }

    #[test]
    fn get_response_and_resend() {
        let mut script = Script {
            answers: vec![vec![1, 2, 0x61, 0x02], vec![3, 4, 0x90, 0x00]],
            sent: Vec::new(),
        };
        let response = exchange(
            &mut script,
            &Command::new(0, 0xCA, 0, 0x6E, Vec::new()),
            ApduMode::Short,
        )
        .unwrap();
        assert_eq!(response.sw, SW_OK);
        assert_eq!(*response.data, [1, 2, 3, 4]);
        assert_eq!(script.sent[1], [0x00, 0xC0, 0x00, 0x00, 0x02]);

        let mut script = Script {
            answers: vec![vec![0x6C, 0x10], vec![9, 0x90, 0x00]],
            sent: Vec::new(),
        };
        let response = exchange(
            &mut script,
            &Command::new(0, 0xCA, 0, 0x6E, Vec::new()),
            ApduMode::Short,
        )
        .unwrap();
        assert_eq!(*response.data, [9]);
        assert_eq!(script.sent[1], [0, 0xCA, 0, 0x6E, 0x10]);
    }

    #[test]
    fn chained_frame_refusal_stops() {
        let mut script = Script {
            answers: vec![vec![0x6A, 0x80]],
            sent: Vec::new(),
        };
        let command = Command::no_response(0x00, 0xDB, 0x3F, 0xFF, vec![1; 300]);
        assert!(matches!(
            exchange(&mut script, &command, ApduMode::Short),
            Err(CardError::WrongData)
        ));
        assert_eq!(script.sent.len(), 1);
    }

    #[test]
    fn endless_get_response_is_cut() {
        let mut script = Script {
            answers: vec![vec![0xAA; 200]; 200]
                .into_iter()
                .map(|mut answer| {
                    answer.extend_from_slice(&[0x61, 0x00]);
                    answer
                })
                .collect(),
            sent: Vec::new(),
        };
        assert!(matches!(
            exchange(
                &mut script,
                &Command::new(0, 0xCA, 0, 0x6E, Vec::new()),
                ApduMode::Short
            ),
            Err(CardError::Malformed)
        ));
    }

    #[test]
    fn debug_hides_data() {
        let command = Command::no_response(0x00, 0x20, 0x00, 0x81, b"123456".to_vec());
        let text = format!("{command:?}");
        assert!(!text.contains("123456") && !text.contains("31"));
    }
}
