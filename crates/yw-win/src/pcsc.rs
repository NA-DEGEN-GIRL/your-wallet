#![allow(unsafe_code)]
//! PC/SC smart-card access (spec/10 §4, §5.1): `SCardEstablishContext` (user scope),
//! `SCardListReadersW`, `SCardConnectW` (shared, T=1), `SCardBeginTransaction`,
//! `SCardTransmit`, `SCardEndTransaction` / `SCardDisconnect` with `SCARD_LEAVE_CARD` (never
//! reset or unpower the card). USB (CCID) and NFC readers use the same path.
//!
//! This module only moves bytes. Which APDUs are sent is decided by `yw_core::yubikey`; yw-app
//! adapts [`Card`] to its `CardTransport` trait. Handles close on drop; no raw handle escapes.
//! Received buffers are wiped after they are copied out (a response never carries a secret, but
//! a mis-addressed command might echo data).

use core::marker::PhantomData;

use windows_sys::Win32::Security::Credentials::{
    SCARD_IO_REQUEST, SCARD_LEAVE_CARD, SCARD_PROTOCOL_T1, SCARD_SCOPE_USER, SCARD_SHARE_SHARED,
    SCardBeginTransaction, SCardConnectW, SCardDisconnect, SCardEndTransaction,
    SCardEstablishContext, SCardListReadersW, SCardReleaseContext, SCardTransmit,
};

use crate::error::WinError;
use crate::mem::wipe;
use crate::wide::to_wide;

/// Largest response buffer: 64 KiB data (extended `Le = 00 00`) + SW.
const MAX_RESPONSE: usize = 65_538;
/// Largest command accepted (extended APDU with 3,000 data bytes and headers fits well below).
const MAX_COMMAND: usize = 4_096;
/// Longest reader list in UTF-16 units.
const MAX_READERS_CHARS: u32 = 16_384;

const SCARD_S_SUCCESS: i32 = 0;
#[expect(
    clippy::cast_possible_wrap,
    reason = "PC/SC returns these HRESULT-style codes as LONG"
)]
const fn code(value: u32) -> i32 {
    value as i32
}
const E_NO_SMARTCARD: i32 = code(0x8010_000C);
const E_NO_READERS_AVAILABLE: i32 = code(0x8010_002E);
const E_NO_SERVICE: i32 = code(0x8010_001D);
const E_SERVICE_STOPPED: i32 = code(0x8010_001E);
const E_SHARING_VIOLATION: i32 = code(0x8010_000B);
const E_TIMEOUT: i32 = code(0x8010_000A);
const E_READER_UNAVAILABLE: i32 = code(0x8010_0017);
const E_UNKNOWN_READER: i32 = code(0x8010_0009);
const W_REMOVED_CARD: i32 = code(0x8010_0069);
const W_RESET_CARD: i32 = code(0x8010_0068);
const E_NOT_TRANSACTED: i32 = code(0x8010_0016);
const W_UNRESPONSIVE_CARD: i32 = code(0x8010_0066);
const W_UNPOWERED_CARD: i32 = code(0x8010_0067);

/// Reader-side failure class of a PC/SC error code (the code itself goes to the log only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcscFault {
    /// The Smart Card service is not running (`SCARD_E_NO_SERVICE`, `SCARD_E_SERVICE_STOPPED`).
    NoService,
    /// No reader is attached (`SCARD_E_NO_READERS_AVAILABLE`, unknown/unavailable reader).
    NoReader,
    /// The reader has no card (`SCARD_E_NO_SMARTCARD`, unpowered/unresponsive card).
    NoCard,
    /// Another program holds the card exclusively (`SCARD_E_SHARING_VIOLATION`, timeout).
    Busy,
    /// The card was removed or reset during the operation.
    Removed,
    /// Any other code.
    Other,
}

/// Classifies a [`WinError`] code from this module.
#[must_use]
pub const fn fault(error: &WinError) -> PcscFault {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "PC/SC returns these HRESULT-style codes as LONG"
    )]
    let value = error.code as i32;
    match value {
        E_NO_SERVICE | E_SERVICE_STOPPED => PcscFault::NoService,
        E_NO_READERS_AVAILABLE | E_UNKNOWN_READER | E_READER_UNAVAILABLE => PcscFault::NoReader,
        E_NO_SMARTCARD | W_UNPOWERED_CARD | W_UNRESPONSIVE_CARD => PcscFault::NoCard,
        E_SHARING_VIOLATION | E_TIMEOUT => PcscFault::Busy,
        W_REMOVED_CARD | W_RESET_CARD | E_NOT_TRANSACTED => PcscFault::Removed,
        _ => PcscFault::Other,
    }
}

#[expect(
    clippy::cast_sign_loss,
    reason = "the LONG return value is kept bit for bit in WinError::code"
)]
const fn failure(api: &'static str, status: i32) -> WinError {
    WinError::new(api, status as u32)
}

/// Splits a `REG_MULTI_SZ`-style buffer (`a\0b\0\0`) into strings (lossy UTF-16).
#[must_use]
pub fn parse_multi_string(buffer: &[u16]) -> Vec<String> {
    buffer
        .split(|unit| *unit == 0)
        .take_while(|part| !part.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// A PC/SC resource manager context (user scope). Released on drop.
#[derive(Debug)]
pub struct Context {
    handle: usize,
}

impl Context {
    /// `SCardEstablishContext(SCARD_SCOPE_USER)`.
    ///
    /// # Errors
    ///
    /// The PC/SC code ([`fault`] gives the class).
    pub fn establish() -> Result<Self, WinError> {
        let mut handle = 0_usize;
        // SAFETY: Both reserved pointers are null as documented; `handle` is a valid out pointer.
        let status = unsafe {
            SCardEstablishContext(
                SCARD_SCOPE_USER,
                core::ptr::null(),
                core::ptr::null(),
                &raw mut handle,
            )
        };
        if status != SCARD_S_SUCCESS {
            return Err(failure("SCardEstablishContext", status));
        }
        Ok(Self { handle })
    }

    /// Reader names (`SCardListReadersW`, all groups). An empty list when no reader is attached.
    ///
    /// # Errors
    ///
    /// The PC/SC code (other than "no readers").
    pub fn readers(&self) -> Result<Vec<String>, WinError> {
        let mut len = 0_u32;
        // SAFETY: Size query: a null buffer with a valid length out pointer, groups null (all).
        let status = unsafe {
            SCardListReadersW(
                self.handle,
                core::ptr::null(),
                core::ptr::null_mut(),
                &raw mut len,
            )
        };
        if status == E_NO_READERS_AVAILABLE {
            return Ok(Vec::new());
        }
        if status != SCARD_S_SUCCESS {
            return Err(failure("SCardListReadersW", status));
        }
        if len == 0 || len > MAX_READERS_CHARS {
            return Err(WinError::invalid_argument("SCardListReadersW"));
        }
        let mut buffer = vec![0_u16; usize::try_from(len).unwrap_or(0)];
        // SAFETY: `buffer` holds `len` writable UTF-16 units and `len` tells the API so.
        let status = unsafe {
            SCardListReadersW(
                self.handle,
                core::ptr::null(),
                buffer.as_mut_ptr(),
                &raw mut len,
            )
        };
        if status == E_NO_READERS_AVAILABLE {
            return Ok(Vec::new());
        }
        if status != SCARD_S_SUCCESS {
            return Err(failure("SCardListReadersW", status));
        }
        buffer.truncate(usize::try_from(len).unwrap_or(0));
        Ok(parse_multi_string(&buffer))
    }

    /// Connects to the card in `reader` (shared, T=1).
    ///
    /// # Errors
    ///
    /// The PC/SC code (`NoCard`, `Busy`, …), or an argument error for an interior NUL.
    pub fn connect(&self, reader: &str) -> Result<Card<'_>, WinError> {
        let name = to_wide(reader, "SCardConnectW")?;
        let mut handle = 0_usize;
        let mut protocol = 0_u32;
        // SAFETY: `name` is NUL-terminated UTF-16 that outlives the call; the out pointers are
        // valid.
        let status = unsafe {
            SCardConnectW(
                self.handle,
                name.as_ptr(),
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T1,
                &raw mut handle,
                &raw mut protocol,
            )
        };
        if status != SCARD_S_SUCCESS {
            return Err(failure("SCardConnectW", status));
        }
        Ok(Card {
            handle,
            protocol,
            transaction: false,
            _context: PhantomData,
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: `handle` came from `SCardEstablishContext` and is released exactly once.
        unsafe { SCardReleaseContext(self.handle) };
    }
}

/// A connected card. Ends the transaction and disconnects with `SCARD_LEAVE_CARD` on drop.
#[derive(Debug)]
pub struct Card<'c> {
    handle: usize,
    protocol: u32,
    transaction: bool,
    _context: PhantomData<&'c Context>,
}

impl Card<'_> {
    /// `SCardBeginTransaction`: exclusive use for the operation (other programs wait).
    ///
    /// # Errors
    ///
    /// The PC/SC code.
    pub fn begin_transaction(&mut self) -> Result<(), WinError> {
        if self.transaction {
            return Ok(());
        }
        // SAFETY: `handle` is a connected card handle owned by `self`.
        let status = unsafe { SCardBeginTransaction(self.handle) };
        if status != SCARD_S_SUCCESS {
            return Err(failure("SCardBeginTransaction", status));
        }
        self.transaction = true;
        Ok(())
    }

    /// Sends one command frame and returns `data ‖ SW1 ‖ SW2`.
    ///
    /// # Errors
    ///
    /// The PC/SC code, or an argument error for an empty or oversize command.
    pub fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, WinError> {
        if command.len() < 4 || command.len() > MAX_COMMAND {
            return Err(WinError::invalid_argument("SCardTransmit"));
        }
        let send_len = u32::try_from(command.len())
            .map_err(|_| WinError::invalid_argument("SCardTransmit"))?;
        let pci = SCARD_IO_REQUEST {
            dwProtocol: self.protocol,
            cbPciLength: u32::try_from(core::mem::size_of::<SCARD_IO_REQUEST>()).unwrap_or(8),
        };
        let mut response = vec![0_u8; MAX_RESPONSE];
        let mut received = u32::try_from(MAX_RESPONSE).unwrap_or(0);
        // SAFETY: `pci` describes the active protocol, `command` is readable for `send_len`
        // bytes, `response` is writable for `received` bytes and `received` is a valid in/out
        // pointer; the receive PCI is null (not requested).
        let status = unsafe {
            SCardTransmit(
                self.handle,
                &raw const pci,
                command.as_ptr(),
                send_len,
                core::ptr::null_mut(),
                response.as_mut_ptr(),
                &raw mut received,
            )
        };
        if status != SCARD_S_SUCCESS {
            wipe(&mut response);
            return Err(failure("SCardTransmit", status));
        }
        let len = usize::try_from(received).unwrap_or(0).min(response.len());
        let out = response.get(..len).unwrap_or_default().to_vec();
        wipe(&mut response);
        Ok(out)
    }
}

impl Drop for Card<'_> {
    fn drop(&mut self) {
        if self.transaction {
            // SAFETY: A transaction begun on this handle is ended once; the card is left as is.
            unsafe { SCardEndTransaction(self.handle, SCARD_LEAVE_CARD) };
        }
        // SAFETY: `handle` came from `SCardConnectW` and is disconnected exactly once, leaving
        // the card powered and unreset.
        unsafe { SCardDisconnect(self.handle, SCARD_LEAVE_CARD) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_string_parsing() {
        let wide: Vec<u16> = "Yubico YubiKey OTP+FIDO+CCID 0\0ACS ACR122 0\0\0"
            .encode_utf16()
            .collect();
        assert_eq!(
            parse_multi_string(&wide),
            ["Yubico YubiKey OTP+FIDO+CCID 0", "ACS ACR122 0"]
        );
        assert!(parse_multi_string(&[0, 0]).is_empty());
        assert!(parse_multi_string(&[]).is_empty());
    }

    #[test]
    fn fault_classes() {
        let of = |value: u32| fault(&WinError::new("SCardTransmit", value));
        assert_eq!(of(0x8010_001D), PcscFault::NoService);
        assert_eq!(of(0x8010_002E), PcscFault::NoReader);
        assert_eq!(of(0x8010_000C), PcscFault::NoCard);
        assert_eq!(of(0x8010_000B), PcscFault::Busy);
        assert_eq!(of(0x8010_0069), PcscFault::Removed);
        assert_eq!(of(0x8010_0068), PcscFault::Removed);
        assert_eq!(of(5), PcscFault::Other);
    }

    /// Read-only diagnostic for a real reader (spec/10 §12.2). Never run by the gate (`ignored`,
    /// and its name does not match the gate's `fuzz_lite` filter). It sends only SELECT, GET
    /// VERSION, GET SERIAL, GET DATA `6E`/`F9` and GET METADATA `9B`/`80` — no command that
    /// writes, imports, generates, resets, changes a PIN/key or signs.
    #[test]
    #[ignore = "talks to a real reader; run by hand: cargo test -p yw-win pcsc_readonly_probe -- --ignored --nocapture"]
    #[allow(clippy::print_stdout, reason = "manual diagnostic output")]
    fn pcsc_readonly_probe() {
        const READ_ONLY: [&[u8]; 9] = [
            &[
                0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00,
            ],
            &[0x00, 0xFD, 0x00, 0x00, 0x00],
            &[0x00, 0xF8, 0x00, 0x00, 0x00],
            &[0x00, 0xF7, 0x00, 0x9B, 0x00],
            &[0x00, 0xF7, 0x00, 0x80, 0x00],
            &[
                0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00,
            ],
            &[0x00, 0xF1, 0x00, 0x00, 0x00],
            &[0x00, 0xCA, 0x00, 0x6E, 0x00],
            &[0x00, 0xCA, 0x00, 0xF9, 0x00],
        ];
        let context = match Context::establish() {
            Ok(context) => context,
            Err(error) => {
                println!("no PC/SC: {error} ({:?})", fault(&error));
                return;
            }
        };
        for reader in context.readers().unwrap_or_default() {
            println!("reader: {reader}");
            let Ok(mut card) = context.connect(&reader) else {
                println!("  (no card)");
                continue;
            };
            let _ = card.begin_transaction();
            for command in READ_ONLY {
                // Defence in depth: only the read-only instructions above may leave.
                let ins = command.get(1).copied().unwrap_or(0);
                assert!(matches!(ins, 0xA4 | 0xFD | 0xF8 | 0xF7 | 0xF1 | 0xCA));
                match card.transmit(command) {
                    Ok(answer) => println!(
                        "  {:02X?} -> {} bytes, SW {:02X?}",
                        &command[..4],
                        answer.len(),
                        answer.get(answer.len().saturating_sub(2)..)
                    ),
                    Err(error) => println!("  {:02X?} -> {error}", &command[..4]),
                }
            }
        }
    }
}
