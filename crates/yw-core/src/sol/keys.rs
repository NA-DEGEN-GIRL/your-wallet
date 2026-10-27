//! Ed25519 key handling (spec/07 §3.1, §4): only `SigningKey::from_bytes`,
//! `SigningKey::verifying_key`, `Signer::sign`, `VerifyingKey::from_bytes`,
//! `VerifyingKey::verify_strict`, `VerifyingKey::to_bytes` and `Signature::{from_bytes,to_bytes}`
//! are used. The secret seed is an RFC 8032 seed; it is never used as a scalar here.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// The signing key of an RFC 8032 secret seed. Call only inside `Vault::with_ed25519_seed`;
/// the key is zeroized on drop (feature `zeroize`).
pub(crate) fn signing_key(secret: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(secret)
}

/// The public key of an RFC 8032 secret seed.
pub(crate) fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    signing_key(secret).verifying_key().to_bytes()
}

/// `verify_strict(public, message, signature)`: rejects small-order keys and non-canonical
/// signature components.
#[must_use]
pub fn verify_strict(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}
