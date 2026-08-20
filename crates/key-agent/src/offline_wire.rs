//! Bounded binary protocol for the inherited Broker-to-Key-Agent channel.
//!
//! This protocol deliberately contains only offline lifecycle commands.  It has
//! no field capable of carrying a password, mnemonic, private key, signing
//! payload, import/export material, or network request.  The production channel
//! adapter is not wired yet; this module only defines the strict codec that the
//! eventual inherited private channel must use.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;
use std::io::{Read, Write};

use thiserror::Error;

const REQUEST_MAGIC: &[u8; 8] = b"YWOFREQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"YWOFRES1";
const VERSION: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 44;
const RESPONSE_HEADER_BYTES: usize = 36;
const ADDRESS_PAYLOAD_BYTES: usize = 24;
const STATUS_PAYLOAD_BYTES: usize = 4;

/// Hard upper bound for one complete offline request frame.
pub(crate) const MAX_OFFLINE_REQUEST_BYTES: usize = 64;
/// Hard upper bound for one complete offline response frame.
pub(crate) const MAX_OFFLINE_RESPONSE_BYTES: usize = 64;

/// The only account selectors admitted by the offline lifecycle protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineAccount {
    /// BIP-44 account at managed derivation index zero.
    Index0,
    /// BIP-44 account at managed derivation index one.
    Index1,
}

impl OfflineAccount {
    const fn code(self) -> u8 {
        match self {
            Self::Index0 => 0,
            Self::Index1 => 1,
        }
    }

    const fn from_code(code: u8) -> Result<Self, OfflineWireError> {
        match code {
            0 => Ok(Self::Index0),
            1 => Ok(Self::Index1),
            _ => Err(OfflineWireError::Payload),
        }
    }
}

/// Secret-free commands admitted on the inherited offline channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineCommand {
    /// Return the coarse vault lifecycle status.
    Status,
    /// Start creation of a 12-word vault through trusted secret UI.
    Create12,
    /// Start creation of a 24-word vault through trusted secret UI.
    Create24,
    /// Start the authenticated one-shot backup display stage.
    BeginBackupDisplay,
    /// Start the separate authenticated backup confirmation stage.
    SubmitBackupConfirmation,
    /// Open the vault through trusted secret UI.
    Open,
    /// Immediately discard decrypted vault state.
    Lock,
    /// Return one address, but only after durable backup confirmation.
    GetConfirmedAddress(OfflineAccount),
}

impl OfflineCommand {
    const fn kind(self) -> u16 {
        match self {
            Self::Status => 1,
            Self::Create12 => 2,
            Self::Create24 => 3,
            Self::BeginBackupDisplay => 4,
            Self::SubmitBackupConfirmation => 5,
            Self::Open => 6,
            Self::Lock => 7,
            Self::GetConfirmedAddress(_) => 8,
        }
    }
}

/// One structurally validated request from the inherited private channel.
#[derive(Eq, PartialEq)]
pub(crate) struct OfflineRequest {
    command: OfflineCommand,
    request_id: u64,
    sequence: u64,
    deadline_unix_ms: u64,
}

impl OfflineRequest {
    /// Constructs an internal request for an encoder or test transport.
    pub(crate) const fn new(
        command: OfflineCommand,
        request_id: u64,
        sequence: u64,
        deadline_unix_ms: u64,
    ) -> Result<Self, OfflineWireError> {
        if request_id == 0 || sequence == 0 || deadline_unix_ms == 0 {
            return Err(OfflineWireError::Identifier);
        }
        Ok(Self {
            command,
            request_id,
            sequence,
            deadline_unix_ms,
        })
    }

    #[must_use]
    pub(crate) const fn command(&self) -> OfflineCommand {
        self.command
    }

    #[must_use]
    pub(crate) const fn request_id(&self) -> u64 {
        self.request_id
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
}

impl fmt::Debug for OfflineRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineRequest")
            .field("command", &self.command)
            .field("request_id", &"[REDACTED]")
            .field("sequence", &"[REDACTED]")
            .field("deadline_unix_ms", &"[REDACTED]")
            .finish()
    }
}

/// Coarse, non-secret status returned to the Broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineStatus {
    /// No decrypted vault state is resident.
    Locked,
    /// Recovery backup confirmation is still required.
    BackupPending,
    /// Backup confirmation is durable and the vault is open.
    Unlocked,
}

impl OfflineStatus {
    const fn code(self) -> u8 {
        match self {
            Self::Locked => 1,
            Self::BackupPending => 2,
            Self::Unlocked => 3,
        }
    }

    const fn from_code(code: u8) -> Result<Self, OfflineWireError> {
        match code {
            1 => Ok(Self::Locked),
            2 => Ok(Self::BackupPending),
            3 => Ok(Self::Unlocked),
            _ => Err(OfflineWireError::Payload),
        }
    }
}

/// Stable outer errors.  They intentionally do not disclose paths, secrets, or
/// cryptographic failure details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineResponseCode {
    /// The authenticated secret/recovery frontend is not installed.
    Unavailable,
    /// The request deadline elapsed before dispatch.
    Expired,
    /// The request identifier was already consumed on this channel.
    Duplicate,
    /// The sequence is older than the next expected value.
    Replay,
    /// The sequence skipped ahead of the next expected value.
    OutOfSequence,
    /// The fixed per-channel request budget was exhausted.
    ChannelExhausted,
    /// The command is not valid in the current vault state.
    InvalidState,
    /// The user cancelled trusted UI.
    Cancelled,
    /// Trusted UI exceeded its deadline.
    TimedOut,
    /// Trusted UI or vault policy rejected the operation.
    Rejected,
    /// A non-disclosive internal failure occurred.
    Internal,
}

impl fmt::Display for OfflineResponseCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "offline frontend unavailable",
            Self::Expired => "offline request expired",
            Self::Duplicate => "duplicate offline request",
            Self::Replay => "replayed offline request",
            Self::OutOfSequence => "offline request out of sequence",
            Self::ChannelExhausted => "offline channel request budget exhausted",
            Self::InvalidState => "offline lifecycle state rejected request",
            Self::Cancelled => "offline interaction cancelled",
            Self::TimedOut => "offline interaction timed out",
            Self::Rejected => "offline operation rejected",
            Self::Internal => "offline operation failed",
        })
    }
}

impl std::error::Error for OfflineResponseCode {}

/// Typed response payloads.  Address bytes are public only after durable backup
/// confirmation; Debug output still redacts them.
#[derive(Eq, PartialEq)]
pub(crate) enum OfflineOutcome {
    /// A state-changing command completed.
    Acknowledged,
    /// Coarse vault state.
    Status(OfflineStatus),
    /// One confirmed managed account address.
    ConfirmedAddress {
        /// Requested managed account.
        account: OfflineAccount,
        /// Canonical Ethereum address bytes.
        address: [u8; 20],
    },
    /// Stable non-secret rejection.
    Error(OfflineResponseCode),
}

impl fmt::Debug for OfflineOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acknowledged => formatter.write_str("OfflineOutcome::Acknowledged"),
            Self::Status(status) => formatter
                .debug_tuple("OfflineOutcome::Status")
                .field(status)
                .finish(),
            Self::ConfirmedAddress { account, .. } => formatter
                .debug_struct("OfflineOutcome::ConfirmedAddress")
                .field("account", account)
                .field("address", &"[REDACTED]")
                .finish(),
            Self::Error(code) => formatter
                .debug_tuple("OfflineOutcome::Error")
                .field(code)
                .finish(),
        }
    }
}

/// One response bound to the exact accepted request metadata.
#[derive(Eq, PartialEq)]
pub(crate) struct OfflineResponse {
    request_id: u64,
    sequence: u64,
    outcome: OfflineOutcome,
}

impl OfflineResponse {
    #[must_use]
    pub(crate) const fn new(request_id: u64, sequence: u64, outcome: OfflineOutcome) -> Self {
        Self {
            request_id,
            sequence,
            outcome,
        }
    }

    #[must_use]
    pub(crate) const fn request_id(&self) -> u64 {
        self.request_id
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn outcome(&self) -> &OfflineOutcome {
        &self.outcome
    }
}

impl fmt::Debug for OfflineResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineResponse")
            .field("request_id", &"[REDACTED]")
            .field("sequence", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Stable, data-free codec failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum OfflineWireError {
    /// A frame exceeded its compile-time cap.
    #[error("offline frame exceeded its bound")]
    TooLarge,
    /// A frame ended before all declared fields were present.
    #[error("offline frame was truncated")]
    Truncated,
    /// A frame contained trailing or inconsistent length data.
    #[error("offline frame length was not canonical")]
    Length,
    /// Magic did not identify the expected direction.
    #[error("offline frame magic was invalid")]
    Magic,
    /// Protocol version was not exactly supported.
    #[error("offline frame version was unsupported")]
    Version,
    /// Message type was outside the closed enum.
    #[error("offline frame type was unsupported")]
    Type,
    /// A reserved byte was nonzero.
    #[error("offline frame reserved field was nonzero")]
    Reserved,
    /// A command-specific payload was malformed.
    #[error("offline frame payload was malformed")]
    Payload,
    /// Required request metadata was zero.
    #[error("offline frame identifier was invalid")]
    Identifier,
    /// Channel I/O failed; the underlying error is intentionally discarded.
    #[error("offline channel I/O failed")]
    Io,
}

/// Encodes one canonical request.
pub(crate) fn encode_request(request: &OfflineRequest) -> Result<Vec<u8>, OfflineWireError> {
    let payload_length = match request.command {
        OfflineCommand::GetConfirmedAddress(_) => 4_usize,
        _ => 0,
    };
    let total = REQUEST_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(OfflineWireError::TooLarge)?;
    if total > MAX_OFFLINE_REQUEST_BYTES {
        return Err(OfflineWireError::TooLarge);
    }
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(REQUEST_MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&request.command.kind().to_be_bytes());
    output.extend_from_slice(&[0_u8; 4]);
    output.extend_from_slice(&request.request_id.to_be_bytes());
    output.extend_from_slice(&request.sequence.to_be_bytes());
    output.extend_from_slice(&request.deadline_unix_ms.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(payload_length)
            .map_err(|_| OfflineWireError::TooLarge)?
            .to_be_bytes(),
    );
    if let OfflineCommand::GetConfirmedAddress(account) = request.command {
        output.push(account.code());
        output.extend_from_slice(&[0_u8; 3]);
    }
    if output.len() != total {
        return Err(OfflineWireError::Length);
    }
    Ok(output)
}

/// Decodes one complete request and rejects every noncanonical byte.
pub(crate) fn decode_request(bytes: &[u8]) -> Result<OfflineRequest, OfflineWireError> {
    if bytes.len() > MAX_OFFLINE_REQUEST_BYTES {
        return Err(OfflineWireError::TooLarge);
    }
    if bytes.len() < REQUEST_HEADER_BYTES {
        return Err(OfflineWireError::Truncated);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take::<8>()? != *REQUEST_MAGIC {
        return Err(OfflineWireError::Magic);
    }
    if cursor.read_u16()? != VERSION {
        return Err(OfflineWireError::Version);
    }
    let kind = cursor.read_u16()?;
    if cursor.take::<4>()? != [0_u8; 4] {
        return Err(OfflineWireError::Reserved);
    }
    let request_id = cursor.read_u64()?;
    let sequence = cursor.read_u64()?;
    let deadline_unix_ms = cursor.read_u64()?;
    if request_id == 0 || sequence == 0 || deadline_unix_ms == 0 {
        return Err(OfflineWireError::Identifier);
    }
    let payload_length =
        usize::try_from(cursor.read_u32()?).map_err(|_| OfflineWireError::Length)?;
    if cursor.remaining() != payload_length {
        return Err(if cursor.remaining() < payload_length {
            OfflineWireError::Truncated
        } else {
            OfflineWireError::Length
        });
    }
    let command = match kind {
        1 => empty_command(&cursor, OfflineCommand::Status)?,
        2 => empty_command(&cursor, OfflineCommand::Create12)?,
        3 => empty_command(&cursor, OfflineCommand::Create24)?,
        4 => empty_command(&cursor, OfflineCommand::BeginBackupDisplay)?,
        5 => empty_command(&cursor, OfflineCommand::SubmitBackupConfirmation)?,
        6 => empty_command(&cursor, OfflineCommand::Open)?,
        7 => empty_command(&cursor, OfflineCommand::Lock)?,
        8 => {
            if payload_length != 4 {
                return Err(OfflineWireError::Payload);
            }
            let account = OfflineAccount::from_code(cursor.read_u8()?)?;
            if cursor.take::<3>()? != [0_u8; 3] {
                return Err(OfflineWireError::Reserved);
            }
            OfflineCommand::GetConfirmedAddress(account)
        }
        _ => return Err(OfflineWireError::Type),
    };
    if cursor.remaining() != 0 {
        return Err(OfflineWireError::Length);
    }
    OfflineRequest::new(command, request_id, sequence, deadline_unix_ms)
}

fn empty_command(
    cursor: &Cursor<'_>,
    command: OfflineCommand,
) -> Result<OfflineCommand, OfflineWireError> {
    if cursor.remaining() == 0 {
        Ok(command)
    } else {
        Err(OfflineWireError::Payload)
    }
}

/// Reads one complete request through EOF without allocating beyond the cap.
pub(crate) fn read_request(reader: &mut impl Read) -> Result<OfflineRequest, OfflineWireError> {
    let limit = u64::try_from(MAX_OFFLINE_REQUEST_BYTES).map_err(|_| OfflineWireError::TooLarge)?;
    let mut bytes = Vec::with_capacity(MAX_OFFLINE_REQUEST_BYTES + 1);
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OfflineWireError::Io)?;
    if bytes.len() > MAX_OFFLINE_REQUEST_BYTES {
        return Err(OfflineWireError::TooLarge);
    }
    decode_request(&bytes)
}

/// Encodes one canonical response.
pub(crate) fn encode_response(response: &OfflineResponse) -> Result<Vec<u8>, OfflineWireError> {
    if response.request_id == 0 || response.sequence == 0 {
        return Err(OfflineWireError::Identifier);
    }
    let (kind, payload_length) = response_shape(&response.outcome);
    let total = RESPONSE_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(OfflineWireError::TooLarge)?;
    if total > MAX_OFFLINE_RESPONSE_BYTES {
        return Err(OfflineWireError::TooLarge);
    }
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&[0_u8; 4]);
    output.extend_from_slice(&response.request_id.to_be_bytes());
    output.extend_from_slice(&response.sequence.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(payload_length)
            .map_err(|_| OfflineWireError::TooLarge)?
            .to_be_bytes(),
    );
    match &response.outcome {
        OfflineOutcome::Acknowledged | OfflineOutcome::Error(_) => {}
        OfflineOutcome::Status(status) => {
            output.push(status.code());
            output.extend_from_slice(&[0_u8; 3]);
        }
        OfflineOutcome::ConfirmedAddress { account, address } => {
            output.push(account.code());
            output.extend_from_slice(&[0_u8; 3]);
            output.extend_from_slice(address);
        }
    }
    if output.len() != total {
        return Err(OfflineWireError::Length);
    }
    Ok(output)
}

/// Decodes one complete response and rejects every noncanonical byte.
pub(crate) fn decode_response(bytes: &[u8]) -> Result<OfflineResponse, OfflineWireError> {
    if bytes.len() > MAX_OFFLINE_RESPONSE_BYTES {
        return Err(OfflineWireError::TooLarge);
    }
    if bytes.len() < RESPONSE_HEADER_BYTES {
        return Err(OfflineWireError::Truncated);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take::<8>()? != *RESPONSE_MAGIC {
        return Err(OfflineWireError::Magic);
    }
    if cursor.read_u16()? != VERSION {
        return Err(OfflineWireError::Version);
    }
    let kind = cursor.read_u16()?;
    if cursor.take::<4>()? != [0_u8; 4] {
        return Err(OfflineWireError::Reserved);
    }
    let request_id = cursor.read_u64()?;
    let sequence = cursor.read_u64()?;
    if request_id == 0 || sequence == 0 {
        return Err(OfflineWireError::Identifier);
    }
    let payload_length =
        usize::try_from(cursor.read_u32()?).map_err(|_| OfflineWireError::Length)?;
    if cursor.remaining() != payload_length {
        return Err(if cursor.remaining() < payload_length {
            OfflineWireError::Truncated
        } else {
            OfflineWireError::Length
        });
    }
    let outcome = match kind {
        1 => {
            require_payload_length(payload_length, 0)?;
            OfflineOutcome::Acknowledged
        }
        2 => {
            require_payload_length(payload_length, STATUS_PAYLOAD_BYTES)?;
            let status = OfflineStatus::from_code(cursor.read_u8()?)?;
            if cursor.take::<3>()? != [0_u8; 3] {
                return Err(OfflineWireError::Reserved);
            }
            OfflineOutcome::Status(status)
        }
        3 => {
            require_payload_length(payload_length, ADDRESS_PAYLOAD_BYTES)?;
            let account = OfflineAccount::from_code(cursor.read_u8()?)?;
            if cursor.take::<3>()? != [0_u8; 3] {
                return Err(OfflineWireError::Reserved);
            }
            let address = cursor.take::<20>()?;
            OfflineOutcome::ConfirmedAddress { account, address }
        }
        0x0100..=0x010a => {
            require_payload_length(payload_length, 0)?;
            OfflineOutcome::Error(response_code(kind)?)
        }
        _ => return Err(OfflineWireError::Type),
    };
    if cursor.remaining() != 0 {
        return Err(OfflineWireError::Length);
    }
    Ok(OfflineResponse::new(request_id, sequence, outcome))
}

/// Writes one exact response frame and flushes it.
pub(crate) fn write_response(
    writer: &mut impl Write,
    response: &OfflineResponse,
) -> Result<(), OfflineWireError> {
    let encoded = encode_response(response)?;
    writer
        .write_all(&encoded)
        .map_err(|_| OfflineWireError::Io)?;
    writer.flush().map_err(|_| OfflineWireError::Io)
}

fn response_shape(outcome: &OfflineOutcome) -> (u16, usize) {
    match outcome {
        OfflineOutcome::Acknowledged => (1, 0),
        OfflineOutcome::Status(_) => (2, STATUS_PAYLOAD_BYTES),
        OfflineOutcome::ConfirmedAddress { .. } => (3, ADDRESS_PAYLOAD_BYTES),
        OfflineOutcome::Error(code) => (response_code_value(*code), 0),
    }
}

const fn response_code_value(code: OfflineResponseCode) -> u16 {
    match code {
        OfflineResponseCode::Unavailable => 0x0100,
        OfflineResponseCode::Expired => 0x0101,
        OfflineResponseCode::Duplicate => 0x0102,
        OfflineResponseCode::Replay => 0x0103,
        OfflineResponseCode::OutOfSequence => 0x0104,
        OfflineResponseCode::ChannelExhausted => 0x0105,
        OfflineResponseCode::InvalidState => 0x0106,
        OfflineResponseCode::Cancelled => 0x0107,
        OfflineResponseCode::TimedOut => 0x0108,
        OfflineResponseCode::Rejected => 0x0109,
        OfflineResponseCode::Internal => 0x010a,
    }
}

const fn response_code(value: u16) -> Result<OfflineResponseCode, OfflineWireError> {
    match value {
        0x0100 => Ok(OfflineResponseCode::Unavailable),
        0x0101 => Ok(OfflineResponseCode::Expired),
        0x0102 => Ok(OfflineResponseCode::Duplicate),
        0x0103 => Ok(OfflineResponseCode::Replay),
        0x0104 => Ok(OfflineResponseCode::OutOfSequence),
        0x0105 => Ok(OfflineResponseCode::ChannelExhausted),
        0x0106 => Ok(OfflineResponseCode::InvalidState),
        0x0107 => Ok(OfflineResponseCode::Cancelled),
        0x0108 => Ok(OfflineResponseCode::TimedOut),
        0x0109 => Ok(OfflineResponseCode::Rejected),
        0x010a => Ok(OfflineResponseCode::Internal),
        _ => Err(OfflineWireError::Type),
    }
}

fn require_payload_length(actual: usize, expected: usize) -> Result<(), OfflineWireError> {
    if actual == expected {
        Ok(())
    } else {
        Err(OfflineWireError::Payload)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], OfflineWireError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(OfflineWireError::Truncated)?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or(OfflineWireError::Truncated)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(source);
        self.position = end;
        Ok(output)
    }

    fn read_u8(&mut self) -> Result<u8, OfflineWireError> {
        Ok(self.take::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, OfflineWireError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn read_u32(&mut self) -> Result<u32, OfflineWireError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn read_u64(&mut self) -> Result<u64, OfflineWireError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor as IoCursor;

    use super::{
        MAX_OFFLINE_REQUEST_BYTES, OfflineAccount, OfflineCommand, OfflineOutcome, OfflineRequest,
        OfflineResponse, OfflineResponseCode, OfflineStatus, OfflineWireError, decode_request,
        decode_response, encode_request, encode_response, read_request, write_response,
    };

    const DEADLINE: u64 = 1_900_000_000_000;

    fn request(command: OfflineCommand) -> Result<OfflineRequest, OfflineWireError> {
        OfflineRequest::new(command, 7, 3, DEADLINE)
    }

    #[test]
    fn every_closed_command_round_trips() -> Result<(), OfflineWireError> {
        for command in [
            OfflineCommand::Status,
            OfflineCommand::Create12,
            OfflineCommand::Create24,
            OfflineCommand::BeginBackupDisplay,
            OfflineCommand::SubmitBackupConfirmation,
            OfflineCommand::Open,
            OfflineCommand::Lock,
            OfflineCommand::GetConfirmedAddress(OfflineAccount::Index0),
            OfflineCommand::GetConfirmedAddress(OfflineAccount::Index1),
        ] {
            let value = request(command)?;
            assert_eq!(decode_request(&encode_request(&value)?)?, value);
        }
        Ok(())
    }

    #[test]
    fn every_secret_ui_command_has_an_empty_wire_payload() -> Result<(), OfflineWireError> {
        for command in [
            OfflineCommand::Create12,
            OfflineCommand::Create24,
            OfflineCommand::BeginBackupDisplay,
            OfflineCommand::SubmitBackupConfirmation,
            OfflineCommand::Open,
        ] {
            let encoded = encode_request(&request(command)?)?;
            assert_eq!(encoded.len(), super::REQUEST_HEADER_BYTES);
            assert_eq!(&encoded[40..44], &[0_u8; 4]);
        }
        Ok(())
    }

    #[test]
    fn request_rejects_every_truncation_and_trailing_byte() -> Result<(), OfflineWireError> {
        let encoded = encode_request(&request(OfflineCommand::GetConfirmedAddress(
            OfflineAccount::Index1,
        ))?)?;
        for length in 0..encoded.len() {
            assert!(decode_request(&encoded[..length]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn request_rejects_header_and_payload_mutations() -> Result<(), OfflineWireError> {
        let canonical = encode_request(&request(OfflineCommand::GetConfirmedAddress(
            OfflineAccount::Index0,
        ))?)?;
        for index in [0_usize, 8, 10, 12, 43, 44, 45] {
            let mut mutated = canonical.clone();
            mutated[index] ^= 0x80;
            assert!(decode_request(&mutated).is_err(), "mutation {index}");
        }
        for range in [16..24, 24..32, 32..40] {
            let mut zero = canonical.clone();
            zero[range].fill(0);
            assert_eq!(decode_request(&zero), Err(OfflineWireError::Identifier));
        }
        Ok(())
    }

    #[test]
    fn bounded_reader_refuses_oversized_input() {
        let mut reader = IoCursor::new(vec![0_u8; MAX_OFFLINE_REQUEST_BYTES + 1]);
        assert_eq!(read_request(&mut reader), Err(OfflineWireError::TooLarge));
    }

    #[test]
    fn all_response_shapes_round_trip_and_redact() -> Result<(), OfflineWireError> {
        let outcomes = [
            OfflineOutcome::Acknowledged,
            OfflineOutcome::Status(OfflineStatus::BackupPending),
            OfflineOutcome::ConfirmedAddress {
                account: OfflineAccount::Index0,
                address: [0xabu8; 20],
            },
            OfflineOutcome::Error(OfflineResponseCode::Unavailable),
            OfflineOutcome::Error(OfflineResponseCode::Expired),
            OfflineOutcome::Error(OfflineResponseCode::Duplicate),
            OfflineOutcome::Error(OfflineResponseCode::Replay),
            OfflineOutcome::Error(OfflineResponseCode::OutOfSequence),
            OfflineOutcome::Error(OfflineResponseCode::ChannelExhausted),
            OfflineOutcome::Error(OfflineResponseCode::InvalidState),
            OfflineOutcome::Error(OfflineResponseCode::Cancelled),
            OfflineOutcome::Error(OfflineResponseCode::TimedOut),
            OfflineOutcome::Error(OfflineResponseCode::Rejected),
            OfflineOutcome::Error(OfflineResponseCode::Internal),
        ];
        for outcome in outcomes {
            let response = OfflineResponse::new(9, 4, outcome);
            let encoded = encode_response(&response)?;
            let decoded = decode_response(&encoded)?;
            assert_eq!(decoded.request_id(), 9);
            assert_eq!(decoded.sequence(), 4);
            assert_eq!(decoded, response);
            assert!(!format!("{response:?}").contains("abab"));
        }
        Ok(())
    }

    #[test]
    fn response_rejects_every_truncation_trailing_and_reserved_mutation()
    -> Result<(), OfflineWireError> {
        let response = OfflineResponse::new(
            9,
            4,
            OfflineOutcome::ConfirmedAddress {
                account: OfflineAccount::Index1,
                address: [0x11; 20],
            },
        );
        let encoded = encode_response(&response)?;
        for length in 0..encoded.len() {
            assert!(decode_response(&encoded[..length]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_response(&trailing).is_err());
        for index in [12_usize, 37] {
            let mut mutated = encoded.clone();
            mutated[index] = 1;
            assert_eq!(decode_response(&mutated), Err(OfflineWireError::Reserved));
        }
        Ok(())
    }

    #[test]
    fn writer_emits_exactly_one_canonical_frame() -> Result<(), OfflineWireError> {
        let response = OfflineResponse::new(9, 4, OfflineOutcome::Acknowledged);
        let mut bytes = Vec::new();
        write_response(&mut bytes, &response)?;
        assert_eq!(bytes, encode_response(&response)?);
        Ok(())
    }

    #[test]
    fn debug_and_errors_never_reproduce_request_metadata() -> Result<(), OfflineWireError> {
        let value = OfflineRequest::new(OfflineCommand::Status, 4_242, 93, DEADLINE)?;
        let debug = format!("{value:?}");
        assert!(!debug.contains("4242"));
        assert!(!debug.contains("1900000000000"));
        assert_eq!(
            OfflineWireError::Io.to_string(),
            "offline channel I/O failed"
        );
        Ok(())
    }
}
