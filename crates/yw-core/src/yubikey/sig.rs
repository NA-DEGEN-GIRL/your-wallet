//! Signature post-processing for card signatures (spec/10 §6).
//!
//! The card returns ECDSA as raw `r ‖ s` (OpenPGP §7.2.10: 2 × field size) with a random nonce,
//! so `s` may be high and `r` may be ≥ 2^255. We:
//!
//! 1. parse `r ‖ s` strictly (both in `1..n`),
//! 2. normalise to low-s (`s ← n − s` when `s > n/2`; BIP62/BIP146, EIP-2),
//! 3. verify against the **recorded** public key (never trusting the card),
//! 4. for EVM, find the recovery id by trying 0 and 1 and comparing with the known key,
//! 5. for Bitcoin, DER-encode (up to 72 bytes: high-R is allowed for card signatures, §6.3).
//!
//! Ed25519 (PIV) signatures are verified with `ed25519-dalek` `verify_strict` against the
//! recorded public key.
#![deny(clippy::indexing_slicing)]

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use secp256k1::{Message, PublicKey, Secp256k1, Verification};

use super::CardError;

/// Longest DER ECDSA signature (high-R and high-s cannot both remain after low-s, but the DER of
/// a high-R low-s signature is up to 71 bytes; 72 is the BIP66 maximum and our bound).
pub const MAX_CARD_DER_LEN: usize = 72;

/// Parses card `r ‖ s` and normalises it to low-s.
///
/// # Errors
///
/// [`CardError::BadSignature`] for a value outside `1..n`.
pub fn low_s(raw: &[u8]) -> Result<Signature, CardError> {
    let compact: &[u8; 64] = raw.try_into().map_err(|_| CardError::BadSignature)?;
    if compact.get(..32).is_some_and(|r| r.iter().all(|b| *b == 0))
        || compact.get(32..).is_some_and(|s| s.iter().all(|b| *b == 0))
    {
        return Err(CardError::BadSignature);
    }
    let mut signature = Signature::from_compact(compact).map_err(|_| CardError::BadSignature)?;
    signature.normalize_s();
    Ok(signature)
}

/// Verifies a (normalised) signature of `digest` for `public` (33-byte compressed).
///
/// # Errors
///
/// [`CardError::KeyMismatch`] for an invalid recorded key, [`CardError::BadSignature`].
pub fn verify_secp<C: Verification>(
    ctx: &Secp256k1<C>,
    digest: [u8; 32],
    signature: &Signature,
    public: &[u8; 33],
) -> Result<(), CardError> {
    let key = PublicKey::from_slice(public).map_err(|_| CardError::KeyMismatch)?;
    ctx.verify_ecdsa(Message::from_digest(digest), signature, &key)
        .map_err(|_| CardError::BadSignature)
}

/// EVM form of a card signature: low-s `r ‖ s` and the `y_parity` (0 or 1) whose recovered key is
/// `public`. The signature must verify first.
///
/// # Errors
///
/// [`CardError::BadSignature`] when it does not verify or neither recovery id gives `public`.
pub fn evm_recoverable<C: Verification>(
    ctx: &Secp256k1<C>,
    digest: [u8; 32],
    raw: &[u8],
    public: &[u8; 33],
) -> Result<(u8, [u8; 64]), CardError> {
    let signature = low_s(raw)?;
    verify_secp(ctx, digest, &signature, public)?;
    let compact = signature.serialize_compact();
    let expected = PublicKey::from_slice(public).map_err(|_| CardError::KeyMismatch)?;
    for parity in [0_u8, 1] {
        let id = RecoveryId::try_from(i32::from(parity)).map_err(|_| CardError::Internal)?;
        let recoverable = RecoverableSignature::from_compact(&compact, id)
            .map_err(|_| CardError::BadSignature)?;
        if ctx
            .recover_ecdsa(Message::from_digest(digest), &recoverable)
            .is_ok_and(|key| key == expected)
        {
            return Ok((parity, compact));
        }
    }
    Err(CardError::BadSignature)
}

/// Bitcoin form of a card signature over `sighash`: verified low-s DER (≤ 72 bytes).
///
/// # Errors
///
/// [`CardError::BadSignature`].
pub fn btc_der<C: Verification>(
    ctx: &Secp256k1<C>,
    sighash: [u8; 32],
    raw: &[u8],
    public: &[u8; 33],
) -> Result<Vec<u8>, CardError> {
    let signature = low_s(raw)?;
    verify_secp(ctx, sighash, &signature, public)?;
    let der = signature.serialize_der();
    if der.len() > MAX_CARD_DER_LEN {
        return Err(CardError::BadSignature);
    }
    Ok(der.to_vec())
}

/// Verifies an Ed25519 card signature over `message` for `public` (strict: canonical `S`, no
/// small-order key).
///
/// # Errors
///
/// [`CardError::KeyMismatch`] for an invalid recorded key, [`CardError::BadSignature`].
pub fn verify_ed25519(
    public: &[u8; 32],
    message: &[u8],
    raw: &[u8],
) -> Result<[u8; 64], CardError> {
    let bytes: [u8; 64] = raw.try_into().map_err(|_| CardError::BadSignature)?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(public).map_err(|_| CardError::KeyMismatch)?;
    let signature = ed25519_dalek::Signature::from_bytes(&bytes);
    key.verify_strict(message, &signature)
        .map_err(|_| CardError::BadSignature)?;
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions on fixed frames")]
mod tests {
    use secp256k1::SecretKey;

    use super::*;

    fn high_s(signature: &Signature) -> [u8; 64] {
        // n − s through the scalar negation of a secret key with the same value.
        let compact = signature.serialize_compact();
        let mut s = [0_u8; 32];
        s.copy_from_slice(&compact[32..]);
        let negated = SecretKey::from_byte_array(s).unwrap().negate();
        let mut out = compact;
        out[32..].copy_from_slice(&negated.secret_bytes());
        out
    }

    #[test]
    fn high_s_is_normalised_and_recovered() {
        let ctx = Secp256k1::new();
        let secret = SecretKey::from_byte_array([0x11; 32]).unwrap();
        let public = PublicKey::from_secret_key(&ctx, &secret).serialize();
        for byte in 0..16_u8 {
            let digest = [byte; 32];
            let signature = ctx.sign_ecdsa(Message::from_digest(digest), &secret);
            let high = high_s(&signature);
            assert_ne!(high, signature.serialize_compact());
            assert_eq!(low_s(&high).unwrap(), signature);
            let (parity, compact) = evm_recoverable(&ctx, digest, &high, &public).unwrap();
            assert_eq!(compact, signature.serialize_compact());
            let recoverable = RecoverableSignature::from_compact(
                &compact,
                RecoveryId::try_from(i32::from(parity)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                ctx.recover_ecdsa(Message::from_digest(digest), &recoverable)
                    .unwrap()
                    .serialize(),
                public
            );
            let der = btc_der(&ctx, digest, &high, &public).unwrap();
            assert!(der.len() <= MAX_CARD_DER_LEN);
            assert_eq!(Signature::from_der(&der).unwrap(), signature);
        }
    }

    #[test]
    fn wrong_key_or_digest_is_rejected() {
        let ctx = Secp256k1::new();
        let secret = SecretKey::from_byte_array([0x11; 32]).unwrap();
        let other =
            PublicKey::from_secret_key(&ctx, &SecretKey::from_byte_array([0x12; 32]).unwrap())
                .serialize();
        let signature = ctx
            .sign_ecdsa(Message::from_digest([1; 32]), &secret)
            .serialize_compact();
        assert_eq!(
            evm_recoverable(&ctx, [1; 32], &signature, &other),
            Err(CardError::BadSignature)
        );
        let public = PublicKey::from_secret_key(&ctx, &secret).serialize();
        assert_eq!(
            evm_recoverable(&ctx, [2; 32], &signature, &public),
            Err(CardError::BadSignature)
        );
        assert_eq!(low_s(&[0; 64]), Err(CardError::BadSignature));
        assert_eq!(low_s(&[1; 63]), Err(CardError::BadSignature));
        assert_eq!(low_s(&[0xFF; 64]), Err(CardError::BadSignature));
    }

    #[test]
    fn ed25519_strict() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key().to_bytes();
        let signature = key.sign(b"hello").to_bytes();
        assert_eq!(
            verify_ed25519(&public, b"hello", &signature).unwrap(),
            signature
        );
        assert_eq!(
            verify_ed25519(&public, b"hellp", &signature),
            Err(CardError::BadSignature)
        );
        assert_eq!(
            verify_ed25519(&public, b"hello", &signature[..63]),
            Err(CardError::BadSignature)
        );
    }
}
