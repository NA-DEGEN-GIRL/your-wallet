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
use yw_core::yubikey::piv::{ManagementState, MgmtAlgorithm, MgmtCipher};
use yw_core::yubikey::plan::{Curve, KeyRole, PlannedSlot, slot_on_card};
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

/// Runs `operation` once on the first inserted card that holds the key of `role` (found by the
/// serial the card reports and the vault slot map), with that card's [`CardKey`] (recorded
/// public key). Cards that do not hold the key are skipped; when only such cards answered the
/// error is [`CardError::WrongCard`].
fn on_card<T>(
    source: &mut dyn CardSource,
    records: &[HwKeyRecord],
    role: KeyRole,
    operation: &mut dyn FnMut(&mut dyn CardTransport, &CardKey) -> Result<T, CardError>,
) -> Result<T, CardJobError> {
    let (pgp, piv) = match role.curve() {
        Curve::Secp256k1 => (true, false),
        Curve::Ed25519 => (false, true),
    };
    let mut result: Option<Result<T, CardError>> = None;
    let mut seen_other = false;
    source
        .each_card(&mut |transport, _| {
            let Ok((serial, _)) = identify(transport, MODE, pgp, piv) else {
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
            result = Some(operation(transport, &key));
            true
        })
        .map_err(CardJobError::Card)?;
    match result {
        Some(outcome) => outcome.map_err(CardJobError::Card),
        None if seen_other => Err(CardJobError::Card(CardError::WrongCard)),
        None => Err(CardJobError::NoCard),
    }
}

/// The PIN check before an approved operation is spent (spec/10 §9.2,
/// `yubikey::sign::check_pin`: serial, recorded key, one VERIFY; no write, no touch). A wrong
/// PIN, another card or no card is reported while the approval is still unused, so the app can
/// ask for the PIN again.
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`].
pub fn check_pin(
    source: &mut dyn CardSource,
    records: &[HwKeyRecord],
    role: KeyRole,
    pin: &[u8],
) -> Result<(), CardJobError> {
    on_card(source, records, role, &mut |transport, key| {
        yw_core::yubikey::sign::check_pin(transport, MODE, key, pin)
    })
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
    on_card(source, records, role, &mut |transport, key| {
        sign_evm_checked(transport, MODE, key, pin, digest)
    })
}

/// Signs the Solana `message` bytes with `YubiKey` Solana account `index` (PIV Ed25519,
/// `yubikey::sign::sign_sol`: serial and slot key checked first, `verify_strict` against the
/// recorded key).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`].
pub fn sign_sol_message(
    source: &mut dyn CardSource,
    records: &[HwKeyRecord],
    index: AccountIndex,
    pin: &[u8],
    message: &[u8],
) -> Result<[u8; 64], CardJobError> {
    on_card(
        source,
        records,
        KeyRole::Sol { index },
        &mut |transport, key| yw_core::yubikey::sign::sign_sol(transport, MODE, key, pin, message),
    )
}

/// Signs one Bitcoin sighash with the `YubiKey` key of `role` (`yubikey::sign::sign_btc`: DER,
/// low-s, verified against the recorded key).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`].
pub fn sign_btc_sighash(
    source: &mut dyn CardSource,
    records: &[HwKeyRecord],
    role: KeyRole,
    pin: &[u8],
    sighash: [u8; 32],
) -> Result<Vec<u8>, CardJobError> {
    on_card(source, records, role, &mut |transport, key| {
        yw_core::yubikey::sign::sign_btc_checked(transport, MODE, key, pin, sighash)
    })
}

/// The serials of the enrolled cards holding the key of `role`, in record order (the PIN
/// window lists them).
#[must_use]
pub fn holders(records: &[HwKeyRecord], role: KeyRole) -> Vec<u32> {
    let identity = role.key_identity();
    records
        .iter()
        .filter(|record| {
            record
                .slots
                .iter()
                .any(|slot| slot.role.key_identity() == identity)
        })
        .map(|record| record.serial)
        .collect()
}

/// The PIN length bounds of the applet holding a key of `role` (spec/10 §9.1): `OpenPGP` PW1
/// 6–127, PIV PIN 6–8.
#[must_use]
pub const fn pin_bounds(role: KeyRole) -> (u8, u8) {
    match role.curve() {
        Curve::Secp256k1 => (6, 127),
        Curve::Ed25519 => (6, 8),
    }
}

/// The card key role of an approval signed on a `YubiKey` (spec/10 §10): an EVM approval of
/// `EvmKeySource::Hardware`, a Solana transfer or message of `SolKeySource::Hardware`, a Bitcoin
/// message of `BtcKeySource::Hardware`. `None` for a software approval (and for a Bitcoin send,
/// whose key is the plan's account: [`btc_plan_role`]).
#[must_use]
pub fn approval_role(approved: &yw_core::approval::Approved) -> Option<KeyRole> {
    role_of(&approved.signer(), approved.payload())
}

/// [`approval_role`] of a request's signer and payload (before it is approved: the approval
/// window's `YubiKey로 서명` badge, which is app chrome outside the digested display).
#[must_use]
pub fn role_of(
    signer: &yw_core::approval::Signer,
    payload: &yw_core::approval::SigningPayload,
) -> Option<KeyRole> {
    use yw_core::approval::{Signer, SigningPayload};
    use yw_core::slip10::SolKeySource;
    use yw_core::vault::EvmKeySource;
    if let Signer::Evm(EvmKeySource::Hardware(index)) = *signer {
        return Some(KeyRole::Evm { index, btc: None });
    }
    match payload {
        SigningPayload::SolTransfer(intent) => match intent.source {
            SolKeySource::Hardware(index) => Some(KeyRole::Sol { index }),
            _ => None,
        },
        SigningPayload::SolMessage(payload) => match payload.source {
            SolKeySource::Hardware(index) => Some(KeyRole::Sol { index }),
            _ => None,
        },
        SigningPayload::BtcMessage(payload) => match payload.source {
            yw_core::btc::account::BtcKeySource::Hardware { key, script_type } => {
                key.role(payload.network, script_type)
            }
            _ => None,
        },
        _ => None,
    }
}

/// The card key role of a Bitcoin plan of a `YubiKey` account (every input uses the account's
/// one key); `None` for a software account.
#[must_use]
pub fn btc_plan_role(plan: &yw_core::btc::SendPlan) -> Option<KeyRole> {
    match *plan.account() {
        yw_core::btc::account::BtcAccountKey::Hardware {
            key, script_type, ..
        } => key.role(plan.network(), script_type),
        _ => None,
    }
}

/// Card credentials for [`enrol_first_card`] (borrowed from the job's wiped buffers).
pub struct EnrolSecrets<'a> {
    /// `OpenPGP` admin PIN.
    pub admin_pin: &'a [u8],
    /// PIV management key (empty when the plan has no PIV slot or the key is PIN-protected).
    pub management_key: &'a [u8],
    /// PIV PIN (only for a PIN-protected management key; otherwise empty).
    pub piv_pin: &'a [u8],
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
                piv_pin: secrets.piv_pin,
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

/// "가져오기 없이 등록" (spec/10 §7.5) on the first inserted card that answers: the record of
/// keys already on the card, built with read-only commands only (`enrol::adopt_card`).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Enrol`].
pub fn adopt_first_card(
    source: &mut dyn CardSource,
    seed: &[u8; 64],
    slots: &[PlannedSlot],
    records: &[HwKeyRecord],
) -> Result<Enrolled, CardJobError> {
    let mut result: Option<Result<Enrolled, EnrolError>> = None;
    source
        .each_card(&mut |transport, _| {
            result = Some(yw_core::yubikey::enrol::adopt_card(
                transport, MODE, seed, slots, records,
            ));
            true
        })
        .map_err(CardJobError::Card)?;
    result
        .ok_or(CardJobError::NoCard)?
        .map_err(CardJobError::Enrol)
}

/// Which card secret a defaults change replaces (spec/10 §9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinTarget {
    /// `OpenPGP` user PIN PW1 (6–127, factory `123456`).
    OpenPgpUser,
    /// `OpenPGP` admin PIN PW3 (8–127, factory `12345678`).
    OpenPgpAdmin,
    /// PIV PIN (6–8, factory `123456`).
    PivPin,
    /// PIV PUK (6–8, factory `12345678`).
    PivPuk,
}

impl PinTarget {
    /// Length bounds (spec/10 §9.1).
    #[must_use]
    pub const fn bounds(self) -> (u8, u8) {
        match self {
            Self::OpenPgpUser => (6, 127),
            Self::OpenPgpAdmin => (8, 127),
            Self::PivPin | Self::PivPuk => (6, 8),
        }
    }

    /// The secret's name in sentences.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OpenPgpUser => "OpenPGP PIN",
            Self::OpenPgpAdmin => "OpenPGP 관리자 PIN",
            Self::PivPin => "PIV PIN",
            Self::PivPuk => "PIV PUK",
        }
    }

    /// The W12 title.
    #[must_use]
    pub const fn change_title(self) -> &'static str {
        match self {
            Self::OpenPgpUser => "OpenPGP PIN 바꾸기",
            Self::OpenPgpAdmin => "OpenPGP 관리자 PIN 바꾸기",
            Self::PivPin => "PIV PIN 바꾸기",
            Self::PivPuk => "PIV PUK 바꾸기",
        }
    }

    /// The length rule and the factory value.
    #[must_use]
    pub const fn rule(self) -> &'static str {
        match self {
            Self::OpenPgpUser => "영문·숫자·기호(ASCII) 6–127자입니다(공장 기본값 123456).",
            Self::OpenPgpAdmin => "영문·숫자·기호(ASCII) 8–127자입니다(공장 기본값 12345678).",
            Self::PivPin => "영문·숫자·기호(ASCII) 6–8자입니다(공장 기본값 123456).",
            Self::PivPuk => "영문·숫자·기호(ASCII) 6–8자입니다(공장 기본값 12345678).",
        }
    }

    const fn applets(self) -> (bool, bool) {
        match self {
            Self::OpenPgpUser | Self::OpenPgpAdmin => (true, false),
            Self::PivPin | Self::PivPuk => (false, true),
        }
    }
}

/// A card operation of [`on_serial`].
type CardOperation<'a, T> =
    dyn FnMut(&mut dyn CardTransport, &dyn MgmtCipher) -> Result<T, CardError> + 'a;

/// Runs `operation` once on the inserted card whose serial is `serial` (read with the applets
/// `pgp` / `piv`); other cards are skipped ([`CardError::WrongCard`] when only they answered).
fn on_serial<T>(
    source: &mut dyn CardSource,
    serial: u32,
    (pgp, piv): (bool, bool),
    operation: &mut CardOperation<'_, T>,
) -> Result<T, CardJobError> {
    let mut result: Option<Result<T, CardError>> = None;
    let mut seen_other = false;
    source
        .each_card(&mut |transport, cipher| {
            match identify(transport, MODE, pgp, piv) {
                Ok((found, _)) if found == serial => {}
                _ => {
                    seen_other = true;
                    return false;
                }
            }
            result = Some(operation(transport, cipher));
            true
        })
        .map_err(CardJobError::Card)?;
    match result {
        Some(outcome) => outcome.map_err(CardJobError::Card),
        None if seen_other => Err(CardJobError::Card(CardError::WrongCard)),
        None => Err(CardJobError::NoCard),
    }
}

/// Changes a PIN or PUK of card `serial` (spec/10 §9.3: `OpenPGP` CHANGE REFERENCE DATA `81` /
/// `83`, PIV `80` / `81`).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`] (wrong current value with the tries left,
/// blocked, format, another card).
pub fn change_card_pin(
    source: &mut dyn CardSource,
    serial: u32,
    target: PinTarget,
    old: &[u8],
    new: &[u8],
) -> Result<(), CardJobError> {
    on_serial(
        source,
        serial,
        target.applets(),
        &mut |transport, _| match target {
            PinTarget::OpenPgpUser | PinTarget::OpenPgpAdmin => {
                yw_core::yubikey::openpgp::OpenPgp::open(transport, MODE)?.change_pin(
                    target == PinTarget::OpenPgpAdmin,
                    old,
                    new,
                )
            }
            PinTarget::PivPin | PinTarget::PivPuk => yw_core::yubikey::piv::Piv::open(
                transport, MODE,
            )?
            .change_reference(target == PinTarget::PivPuk, old, new),
        },
    )
}

fn fresh_challenge() -> Result<[u8; 16], CardJobError> {
    let mut challenge = [0_u8; 16];
    yw_core::entropy::fill_random(&mut challenge)
        .map_err(|_| CardJobError::Card(CardError::Internal))?;
    Ok(challenge)
}

/// The PIV management key state of the first inserted card (read-only: GET METADATA `9B`,
/// GET DATA ADMIN DATA), for the wizard's credentials step (spec/10 §7.3).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`].
pub fn probe_management(source: &mut dyn CardSource) -> Result<ManagementState, CardJobError> {
    let mut result: Option<Result<ManagementState, CardError>> = None;
    source
        .each_card(&mut |transport, _| {
            result = Some(
                yw_core::yubikey::piv::Piv::open(transport, MODE)
                    .and_then(|mut session| session.management_state()),
            );
            true
        })
        .map_err(CardJobError::Card)?;
    result
        .ok_or(CardJobError::NoCard)?
        .map_err(CardJobError::Card)
}

/// "PIV 관리 키 자동 보호" of card `serial` (spec/10 §9.3, `Piv::protect_management_key`, the
/// equivalent of `ykman piv access change-management-key --generate --protect`): a random
/// AES-192 key made on this PC, stored PIN-protected on the card, never shown.
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`] (wrong PIN, a custom key the wallet does
/// not know, another card).
pub fn protect_management_key(
    source: &mut dyn CardSource,
    serial: u32,
    pin: &[u8],
) -> Result<(), CardJobError> {
    let challenge = fresh_challenge()?;
    on_serial(source, serial, (false, true), &mut |transport, cipher| {
        yw_core::yubikey::piv::Piv::open(transport, MODE)?
            .protect_management_key(pin, cipher, &challenge)
    })
}

/// One step of "PIN 설정" (spec/10 §9.3), in the order they run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultsStep {
    /// PIV PIN.
    PivPin,
    /// PIV PUK.
    PivPuk,
    /// PIV management key: generated and stored PIN-protected (needs the new PIN).
    PivManagement,
    /// `OpenPGP` admin PIN (PW3).
    OpenPgpAdmin,
    /// `OpenPGP` user PIN (PW1).
    OpenPgpUser,
}

impl DefaultsStep {
    /// The name in sentences.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PivPin => "PIV PIN",
            Self::PivPuk => "PIV PUK",
            Self::PivManagement => "PIV 관리 키(PIN 보호)",
            Self::OpenPgpAdmin => "OpenPGP 관리자 PIN",
            Self::OpenPgpUser => "OpenPGP PIN",
        }
    }

    const fn factory(self) -> &'static [u8] {
        match self {
            Self::PivPin | Self::OpenPgpUser | Self::PivManagement => b"123456",
            Self::PivPuk | Self::OpenPgpAdmin => b"12345678",
        }
    }
}

/// What "PIN 설정" did: the steps done in order, the ones skipped (applet missing or already
/// PIN-protected), and the step that failed (nothing after it ran).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinReport {
    /// Done, in order.
    pub done: Vec<DefaultsStep>,
    /// Skipped.
    pub skipped: Vec<DefaultsStep>,
    /// The failed step and why.
    pub failed: Option<(DefaultsStep, CardError)>,
}

impl PinReport {
    fn step(&mut self, step: DefaultsStep, result: Result<(), CardError>) -> bool {
        match result {
            Ok(()) => {
                self.done.push(step);
                true
            }
            Err(error) => {
                self.failed = Some((step, error));
                false
            }
        }
    }

    fn piv(
        &mut self,
        session: &mut yw_core::yubikey::piv::Piv<'_>,
        (old_pin, old_puk): (&[u8], &[u8]),
        new: &[u8],
        cipher: &dyn MgmtCipher,
        challenge: &[u8; 16],
    ) {
        if !self.step(
            DefaultsStep::PivPin,
            session.change_reference(false, old_pin, new),
        ) || !self.step(
            DefaultsStep::PivPuk,
            session.change_reference(true, old_puk, new),
        ) {
            return;
        }
        match session.management_state() {
            Ok(state) if state.protected && !state.default => {
                self.skipped.push(DefaultsStep::PivManagement);
            }
            Ok(_) => {
                self.step(
                    DefaultsStep::PivManagement,
                    session.protect_management_key(new, cipher, challenge),
                );
            }
            Err(error) => self.failed = Some((DefaultsStep::PivManagement, error)),
        }
    }
}

/// "PIN 하나로 통일" of card `serial` (spec/10 §9.3): one `new` value (8 characters, valid for
/// every applet) replaces, in this order, the PIV PIN, the PIV PUK, the management key
/// (generated and stored PIN-protected with the new PIN), the `OpenPGP` admin PIN and the
/// `OpenPGP` user PIN. `current` empty = the factory values; otherwise the one current value of
/// all four. The first failure stops the sequence; the report says what changed. An applet the
/// card lacks is skipped. `applets` are the ones used to identify the card (its record's).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`] (`WrongCard`, the serial could not be read).
pub fn set_pins(
    source: &mut dyn CardSource,
    serial: u32,
    applets: (bool, bool),
    current: &[u8],
    new: &[u8],
) -> Result<PinReport, CardJobError> {
    let challenge = fresh_challenge()?;
    let old = |step: DefaultsStep| -> &[u8] {
        if current.is_empty() {
            step.factory()
        } else {
            current
        }
    };
    on_serial(source, serial, applets, &mut |transport, cipher| {
        let mut report = PinReport::default();
        match yw_core::yubikey::piv::Piv::open(transport, MODE) {
            Ok(mut session) => report.piv(
                &mut session,
                (old(DefaultsStep::PivPin), old(DefaultsStep::PivPuk)),
                new,
                cipher,
                &challenge,
            ),
            Err(CardError::AppletMissing | CardError::FirmwareTooOld) => report.skipped.extend([
                DefaultsStep::PivPin,
                DefaultsStep::PivPuk,
                DefaultsStep::PivManagement,
            ]),
            Err(error) => report.failed = Some((DefaultsStep::PivPin, error)),
        }
        if report.failed.is_some() {
            return Ok(report);
        }
        match yw_core::yubikey::openpgp::OpenPgp::open(transport, MODE) {
            Ok(mut session) => {
                let _ = report.step(
                    DefaultsStep::OpenPgpAdmin,
                    session.change_pin(true, old(DefaultsStep::OpenPgpAdmin), new),
                ) && report.step(
                    DefaultsStep::OpenPgpUser,
                    session.change_pin(false, old(DefaultsStep::OpenPgpUser), new),
                );
            }
            Err(CardError::AppletMissing | CardError::FirmwareTooOld) => report
                .skipped
                .extend([DefaultsStep::OpenPgpAdmin, DefaultsStep::OpenPgpUser]),
            Err(error) => report.failed = Some((DefaultsStep::OpenPgpAdmin, error)),
        }
        Ok(report)
    })
}

/// "다시 확인" (spec/10 §7.3-6): on card `record.serial`, every recorded slot's public key is read
/// again (`sign::check_key`, read-only). One result per slot, in record order.
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`] (no card with that serial answered).
pub fn check_record(
    source: &mut dyn CardSource,
    record: &HwKeyRecord,
) -> Result<Vec<Result<(), CardError>>, CardJobError> {
    let pgp = record
        .slots
        .iter()
        .any(|slot| slot.role.curve() == Curve::Secp256k1);
    let piv = record
        .slots
        .iter()
        .any(|slot| slot.role.curve() == Curve::Ed25519);
    on_serial(source, record.serial, (pgp, piv), &mut |transport, _| {
        Ok(record
            .slots
            .iter()
            .map(|slot| {
                yw_core::yubikey::sign::check_key(
                    transport,
                    MODE,
                    &CardKey {
                        serial: record.serial,
                        slot: slot.slot,
                        public: slot.public,
                    },
                )
            })
            .collect())
    })
}

/// An enrolment-style operation of [`on_serial_enrol`].
type EnrolOperation<'a, T> =
    dyn FnMut(&mut dyn CardTransport, &dyn MgmtCipher) -> Result<T, EnrolError> + 'a;

/// [`on_serial`] for operations that fail with an [`EnrolError`] (re-slot, clear).
fn on_serial_enrol<T>(
    source: &mut dyn CardSource,
    serial: u32,
    (pgp, piv): (bool, bool),
    operation: &mut EnrolOperation<'_, T>,
) -> Result<T, CardJobError> {
    let mut result: Option<Result<T, EnrolError>> = None;
    let mut seen_other = false;
    source
        .each_card(&mut |transport, cipher| {
            match identify(transport, MODE, pgp, piv) {
                Ok((found, _)) if found == serial => {}
                _ => {
                    seen_other = true;
                    return false;
                }
            }
            result = Some(operation(transport, cipher));
            true
        })
        .map_err(CardJobError::Card)?;
    match result {
        Some(outcome) => outcome.map_err(CardJobError::Enrol),
        None if seen_other => Err(CardJobError::Card(CardError::WrongCard)),
        None => Err(CardJobError::NoCard),
    }
}

/// "슬롯 구성 바꾸기" of the inserted card `record.serial` (spec/10 §15.1,
/// `yubikey::manage::reslot_card`): the new `OpenPGP` keys from `seed`, read back and compared.
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`] (`WrongCard`), [`CardJobError::Enrol`].
pub fn reslot_card(
    source: &mut dyn CardSource,
    seed: &[u8; 64],
    record: &HwKeyRecord,
    openpgp: &[PlannedSlot],
    others: &[HwKeyRecord],
    admin_pin: &[u8],
) -> Result<HwKeyRecord, CardJobError> {
    on_serial_enrol(source, record.serial, (true, false), &mut |transport, _| {
        yw_core::yubikey::manage::reslot_card(
            transport, MODE, seed, record, openpgp, others, admin_pin,
        )
    })
}

/// "`YubiKey` 비우기" of the inserted card `record.serial` (spec/10 §15.2–§15.3,
/// `yubikey::manage::clear_card`).
///
/// # Errors
///
/// [`CardJobError::NoCard`], [`CardJobError::Card`] (`WrongCard`), [`CardJobError::Enrol`]
/// (identification).
pub fn clear_card(
    source: &mut dyn CardSource,
    record: &HwKeyRecord,
    plan: yw_core::yubikey::manage::ClearPlan,
    admin_pin: &[u8],
    piv_pin: &[u8],
) -> Result<yw_core::yubikey::manage::ClearReport, CardJobError> {
    let challenge = fresh_challenge()?;
    on_serial_enrol(
        source,
        record.serial,
        (plan.openpgp.is_some(), plan.piv.is_some()),
        &mut |transport, cipher| {
            let auth = yw_core::yubikey::manage::ClearAuth {
                admin_pin,
                piv_pin,
                cipher: Some(cipher),
                challenge,
            };
            yw_core::yubikey::manage::clear_card(transport, MODE, record, plan, &auth)
        },
    )
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
