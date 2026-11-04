//! `YubiKey` glue for the key worker (spec/10 §4, §7, §9.2): adapters from yw-win's PC/SC card
//! and CNG cipher to the yw-core `CardTransport` / `MgmtCipher` traits, the [`CardSource`]
//! that visits the inserted cards (the emulator in tests), and the two operations the worker
//! runs on a card: enrolment and EVM digest signing.
//!
//! Every PIN, admin PIN and management key reaches these functions as a borrowed buffer that
//! the job owns and wipes when it finishes (no caching between operations, spec/10 §9.1).

use yw_core::bip32::path::AccountIndex;
use yw_core::secret::Zeroizing;
use yw_core::yubikey::apdu::ApduMode;
use yw_core::yubikey::enrol::{EnrolAuth, EnrolError, Enrolled, enrol_card, identify};
use yw_core::yubikey::piv::{MgmtAlgorithm, MgmtCipher};
use yw_core::yubikey::plan::{KeyRole, PlannedSlot, slot_on_card};
use yw_core::yubikey::record::HwKeyRecord;
use yw_core::yubikey::sign::{CardKey, sign_evm_checked};
use yw_core::yubikey::{CardError, CardTransport, TransportFault};
use yw_win::pcsc::{self, PcscFault};

/// The framing used with every reader: short APDUs with chaining work on USB and NFC alike
/// (spec/10 §5.1).
pub const MODE: ApduMode = ApduMode::Short;

const fn transport_error(fault: PcscFault) -> CardError {
    match fault {
        PcscFault::NoService => CardError::Transport(TransportFault::NoService),
        PcscFault::NoReader => CardError::Transport(TransportFault::NoReader),
        PcscFault::NoCard => CardError::Transport(TransportFault::NoCard),
        PcscFault::Busy => CardError::Transport(TransportFault::Busy),
        PcscFault::Removed => CardError::CardRemoved,
        PcscFault::Other => CardError::Transport(TransportFault::Io),
    }
}

/// A connected PC/SC card as a [`CardTransport`].
#[derive(Debug)]
pub struct PcscTransport<'c> {
    card: pcsc::Card<'c>,
}

impl CardTransport for PcscTransport<'_> {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, CardError> {
        self.card
            .transmit(command)
            .map_err(|error| transport_error(pcsc::fault(&error)))
    }
}

/// Windows CNG as the PIV management-key cipher.
#[derive(Clone, Copy, Debug, Default)]
pub struct CngCipher;

impl CngCipher {
    fn run(
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
        encrypt: bool,
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        let cipher = match algorithm {
            MgmtAlgorithm::TripleDes => yw_win::cng::BlockCipher::TripleDes,
            MgmtAlgorithm::Aes128 | MgmtAlgorithm::Aes192 | MgmtAlgorithm::Aes256 => {
                yw_win::cng::BlockCipher::Aes
            }
        };
        if key.len() != algorithm.key_len() {
            return Err(CardError::Internal);
        }
        yw_win::cng::ecb_block(cipher, key, block, encrypt)
            .map(Zeroizing::new)
            .map_err(|_| CardError::Internal)
    }
}

impl MgmtCipher for CngCipher {
    fn encrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        Self::run(algorithm, key, block, true)
    }

    fn decrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        Self::run(algorithm, key, block, false)
    }
}

/// The visitor of [`CardSource::each_card`]: a transport to one card and the management-key
/// cipher; returns `true` to stop.
pub type CardVisit<'a> = dyn FnMut(&mut dyn CardTransport, &dyn MgmtCipher) -> bool + 'a;

/// Visits the inserted cards.
pub trait CardSource: Send {
    /// Calls `visit` with each present card (one exclusive transaction each) until it returns
    /// `true`.
    ///
    /// # Errors
    ///
    /// Reader errors before any card was visited (no service, no reader).
    fn each_card(&mut self, visit: &mut CardVisit<'_>) -> Result<(), CardError>;
}

/// The real readers (PC/SC, user scope).
#[derive(Debug, Default)]
pub struct PcscSource;

impl CardSource for PcscSource {
    fn each_card(&mut self, visit: &mut CardVisit<'_>) -> Result<(), CardError> {
        let context =
            pcsc::Context::establish().map_err(|error| transport_error(pcsc::fault(&error)))?;
        let readers = context
            .readers()
            .map_err(|error| transport_error(pcsc::fault(&error)))?;
        if readers.is_empty() {
            return Err(CardError::Transport(TransportFault::NoReader));
        }
        for reader in readers {
            // A reader without a card (or held by another program) is skipped.
            let Ok(mut card) = context.connect(&reader) else {
                continue;
            };
            if card.begin_transaction().is_err() {
                continue;
            }
            let mut transport = PcscTransport { card };
            if visit(&mut transport, &CngCipher) {
                break;
            }
        }
        Ok(())
    }
}

/// Why a card operation of the worker failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardJobError {
    /// No card answered (no reader, no card, or no card with the key).
    NoCard,
    /// Cards were present but none holds the key (`WrongCard`) — the most specific error seen.
    Card(CardError),
    /// Enrolment refused or failed.
    Enrol(EnrolError),
}

impl core::fmt::Display for CardJobError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoCard => CardError::Transport(TransportFault::NoCard).fmt(formatter),
            Self::Card(error) => error.fmt(formatter),
            Self::Enrol(error) => error.fmt(formatter),
        }
    }
}

/// Signs `digest` with `YubiKey` EVM account `index` on the first inserted card that holds it
/// (`yubikey::sign::sign_evm`: serial and public key checked before the PIN is sent, low-s,
/// recovery id against the recorded key).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`] (PIN, touch, wrong card, bad signature).
pub fn sign_evm_digest(
    source: &mut dyn CardSource,
    records: &[HwKeyRecord],
    index: AccountIndex,
    pin: &[u8],
    digest: [u8; 32],
) -> Result<(u8, [u8; 64]), CardJobError> {
    let role = KeyRole::Evm { index, btc: None };
    let mut result: Option<Result<(u8, [u8; 64]), CardError>> = None;
    let mut seen_other = false;
    source
        .each_card(&mut |transport, _| {
            let Ok((serial, _)) = identify(transport, MODE, true, false) else {
                return false;
            };
            let Some(holder) = slot_on_card(records, role, serial) else {
                seen_other = true;
                return false;
            };
            let Some(public) = records
                .iter()
                .find(|record| record.serial == serial)
                .and_then(|record| record.slots.iter().find(|slot| slot.slot == holder.slot))
                .map(|slot| slot.public)
            else {
                return false;
            };
            let key = CardKey {
                serial,
                slot: holder.slot,
                public,
            };
            result = Some(sign_evm_checked(transport, MODE, &key, pin, digest));
            true
        })
        .map_err(CardJobError::Card)?;
    match result {
        Some(outcome) => outcome.map_err(CardJobError::Card),
        None if seen_other => Err(CardJobError::Card(CardError::WrongCard)),
        None => Err(CardJobError::NoCard),
    }
}

/// Card credentials for [`enrol_first_card`] (borrowed from the job's wiped buffers).
pub struct EnrolSecrets<'a> {
    /// `OpenPGP` admin PIN.
    pub admin_pin: &'a [u8],
    /// PIV management key (empty when the plan has no PIV slot).
    pub management_key: &'a [u8],
}

impl core::fmt::Debug for EnrolSecrets<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("EnrolSecrets([REDACTED])")
    }
}

/// Enrols the first inserted card that answers with `slots` (spec/10 §7.3).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Enrol`].
pub fn enrol_first_card(
    source: &mut dyn CardSource,
    seed: &[u8; 64],
    slots: &[PlannedSlot],
    records: &[HwKeyRecord],
    secrets: &EnrolSecrets<'_>,
) -> Result<Enrolled, CardJobError> {
    let mut challenge = [0_u8; 16];
    yw_core::entropy::fill_random(&mut challenge)
        .map_err(|error| CardJobError::Enrol(EnrolError::Key(error)))?;
    let mut result: Option<Result<Enrolled, EnrolError>> = None;
    source
        .each_card(&mut |transport, cipher| {
            let auth = EnrolAuth {
                admin_pin: secrets.admin_pin,
                management_key: secrets.management_key,
                cipher: Some(cipher),
                challenge,
            };
            result = Some(enrol_card(transport, MODE, seed, slots, records, &auth));
            true
        })
        .map_err(CardJobError::Card)?;
    result
        .ok_or(CardJobError::NoCard)?
        .map_err(CardJobError::Enrol)
}

/// The emulator as a card source (tests of the key worker and the app).
#[cfg(test)]
pub(crate) struct MockSource {
    /// The inserted emulated cards.
    pub(crate) cards: std::sync::Arc<std::sync::Mutex<Vec<yw_core::yubikey::mock::MockCard>>>,
}

#[cfg(test)]
impl CardSource for MockSource {
    fn each_card(&mut self, visit: &mut CardVisit<'_>) -> Result<(), CardError> {
        let mut cards = self.cards.lock().map_err(|_| CardError::Internal)?;
        if cards.is_empty() {
            return Err(CardError::Transport(TransportFault::NoCard));
        }
        for card in cards.iter_mut() {
            if visit(card, &yw_core::yubikey::mock::ToyCipher) {
                break;
            }
        }
        Ok(())
    }
}
