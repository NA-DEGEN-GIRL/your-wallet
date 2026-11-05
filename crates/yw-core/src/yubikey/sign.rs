//! Signing on the card (spec/10 §6): select the applet, require the enrolled serial and the
//! recorded public key in the slot (an overwritten slot is refused before the PIN is sent),
//! VERIFY the PIN, sign, and post-process/verify against the recorded key.
//!
//! The PIN is borrowed for the one operation; callers keep it in a `Zeroizing` buffer and wipe
//! it right after (spec/10 §9.2). A Bitcoin send calls [`sign_secp256k1`] once per input with
//! the same borrowed PIN (and one touch each, or one touch per 15 s with a cached policy).

use secp256k1::{Secp256k1, Verification};
use zeroize::Zeroizing;

use super::apdu::ApduMode;
use super::openpgp::OpenPgp;
use super::piv::Piv;
use super::plan::{CardSlot, PgpKey, PivSlot};
use super::record::HwPublicKey;
use super::{CardError, CardTransport, sig};

/// What the app needs to sign with one key on one card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardKey {
    /// Expected serial.
    pub serial: u32,
    /// Slot.
    pub slot: CardSlot,
    /// Recorded public key.
    pub public: HwPublicKey,
}

/// Opens OpenPGP, checks serial and key, verifies PW1 and returns the raw `r ‖ s`.
///
/// # Errors
///
/// [`CardError::WrongCard`], [`CardError::KeyMismatch`], PIN/touch/status errors.
pub fn sign_secp256k1(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    key: &CardKey,
    pin: &[u8],
    digest: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, CardError> {
    let (CardSlot::OpenPgp(pgp_key), HwPublicKey::Secp256k1(public)) = (key.slot, key.public)
    else {
        return Err(CardError::Internal);
    };
    let mut session = open_pgp(transport, mode, key.serial, pgp_key, &public)?;
    session.sign_digest(pgp_key, pin, digest)
}

fn open_pgp<'t>(
    transport: &'t mut dyn CardTransport,
    mode: ApduMode,
    serial: u32,
    key: PgpKey,
    public: &[u8; 33],
) -> Result<OpenPgp<'t>, CardError> {
    let mut session = OpenPgp::open(transport, mode)?;
    if session.app.serial != serial {
        return Err(CardError::WrongCard);
    }
    if session.public_key(key)? != *public {
        return Err(CardError::KeyMismatch);
    }
    Ok(session)
}

/// EVM: signs `digest` and returns `(y_parity, r ‖ s)` low-s, verified and recovered against the
/// recorded key.
///
/// # Errors
///
/// As [`sign_secp256k1`], [`CardError::BadSignature`].
pub fn sign_evm<C: Verification>(
    ctx: &Secp256k1<C>,
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    key: &CardKey,
    pin: &[u8],
    digest: [u8; 32],
) -> Result<(u8, [u8; 64]), CardError> {
    let HwPublicKey::Secp256k1(public) = key.public else {
        return Err(CardError::Internal);
    };
    let raw = sign_secp256k1(transport, mode, key, pin, &digest)?;
    sig::evm_recoverable(ctx, digest, &raw, &public)
}

/// [`sign_evm`] with its own verification-only context (for callers without a secp256k1
/// dependency, e.g. yw-app).
///
/// # Errors
///
/// As [`sign_evm`].
pub fn sign_evm_checked(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    key: &CardKey,
    pin: &[u8],
    digest: [u8; 32],
) -> Result<(u8, [u8; 64]), CardError> {
    sign_evm(
        &Secp256k1::verification_only(),
        transport,
        mode,
        key,
        pin,
        digest,
    )
}

/// Bitcoin: signs a sighash and returns the verified low-s DER (without the sighash byte).
///
/// # Errors
///
/// As [`sign_secp256k1`], [`CardError::BadSignature`].
pub fn sign_btc<C: Verification>(
    ctx: &Secp256k1<C>,
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    key: &CardKey,
    pin: &[u8],
    sighash: [u8; 32],
) -> Result<Vec<u8>, CardError> {
    let HwPublicKey::Secp256k1(public) = key.public else {
        return Err(CardError::Internal);
    };
    let raw = sign_secp256k1(transport, mode, key, pin, &sighash)?;
    sig::btc_der(ctx, sighash, &raw, &public)
}

/// [`sign_btc`] with its own verification-only context (for callers without a secp256k1
/// dependency, e.g. yw-app).
///
/// # Errors
///
/// As [`sign_btc`].
pub fn sign_btc_checked(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    key: &CardKey,
    pin: &[u8],
    sighash: [u8; 32],
) -> Result<Vec<u8>, CardError> {
    sign_btc(
        &Secp256k1::verification_only(),
        transport,
        mode,
        key,
        pin,
        sighash,
    )
}

/// Solana: signs `message` (the exact bytes the Solana signature covers) with the PIV Ed25519
/// key and verifies the signature strictly against the recorded key.
///
/// # Errors
///
/// [`CardError::WrongCard`], [`CardError::KeyMismatch`], PIN/touch/status errors,
/// [`CardError::BadSignature`].
pub fn sign_sol(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    key: &CardKey,
    pin: &[u8],
    message: &[u8],
) -> Result<[u8; 64], CardError> {
    let (CardSlot::Piv(slot), HwPublicKey::Ed25519(public)) = (key.slot, key.public) else {
        return Err(CardError::Internal);
    };
    let mut session = open_piv(transport, mode, key.serial, slot, &public)?;
    let signature = session.sign_ed25519(slot, pin, message)?;
    sig::verify_ed25519(&public, message, &signature)
}

fn open_piv<'t>(
    transport: &'t mut dyn CardTransport,
    mode: ApduMode,
    serial: u32,
    slot: PivSlot,
    public: &[u8; 32],
) -> Result<Piv<'t>, CardError> {
    let mut session = Piv::open(transport, mode)?;
    if session.serial != serial {
        return Err(CardError::WrongCard);
    }
    if session.slot_metadata(slot)?.public != Some(*public) {
        return Err(CardError::KeyMismatch);
    }
    Ok(session)
}

/// Checks the PIN before anything is signed (spec/10 §9.2): the same serial and recorded-key
/// checks as signing, then one VERIFY (PW1 of the slot's operation, or the PIV PIN). Sends no
/// write instruction and asks for no touch, so a wrong PIN, another card or a missing card is
/// known before the approved operation is spent. The signing call verifies the PIN again (PW1
/// `81` is valid for one signature, a PIV "always" PIN policy for one operation).
///
/// # Errors
///
/// [`CardError::WrongCard`], [`CardError::KeyMismatch`], [`CardError::WrongPin`],
/// [`CardError::PinBlocked`], [`CardError::PinFormat`], status errors.
pub fn check_pin(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    key: &CardKey,
    pin: &[u8],
) -> Result<(), CardError> {
    match (key.slot, key.public) {
        (CardSlot::OpenPgp(pgp_key), HwPublicKey::Secp256k1(public)) => {
            open_pgp(transport, mode, key.serial, pgp_key, &public)?.verify(pgp_key.pw(), pin)
        }
        (CardSlot::Piv(slot), HwPublicKey::Ed25519(public)) => {
            open_piv(transport, mode, key.serial, slot, &public)?.verify_pin(pin)
        }
        _ => Err(CardError::Internal),
    }
}

/// Read-only check that the inserted card holds `key` (serial and public key): used by the
/// wizard's final "다시 확인" step and the acceptance checklist. Sends only SELECT, GET VERSION,
/// GET DATA / GET SERIAL, and the public-key read (`00 47 81 00` / GET METADATA).
///
/// # Errors
///
/// [`CardError::WrongCard`], [`CardError::KeyMismatch`], status errors.
pub fn check_key(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    key: &CardKey,
) -> Result<(), CardError> {
    match (key.slot, key.public) {
        (CardSlot::OpenPgp(pgp_key), HwPublicKey::Secp256k1(public)) => {
            open_pgp(transport, mode, key.serial, pgp_key, &public).map(drop)
        }
        (CardSlot::Piv(slot), HwPublicKey::Ed25519(public)) => {
            open_piv(transport, mode, key.serial, slot, &public).map(drop)
        }
        _ => Err(CardError::Internal),
    }
}
