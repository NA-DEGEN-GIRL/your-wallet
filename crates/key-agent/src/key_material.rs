//! Canonical device-key bundle and hardware-protection envelope model.
//!
//! This module is intentionally crate-private and has no production PCP/TPM
//! implementation. It defines the bytes that a future Windows provisioning
//! adapter must protect and the sealed operations that adapter must provide.
//!
//! The plaintext bundle is exactly:
//!
//! `YWKBND01 || version:u16be || flags:u16be || installation_id:[u8;32] ||
//! key_epoch:u64be || six independent [u8;32] values`
//!
//! The six values have the fixed order anchor-registry HMAC, storage-MAC root,
//! journal AEAD, local-settings AEAD, nonce-ledger AEAD, and TPM NV auth. The
//! bundle and every transient plaintext/KEK allocation are zeroizing.
//!
//! The signed envelope fixes XChaCha20-Poly1305, RSA-3072 OAEP with SHA-256 and
//! MGF1-SHA-256, and low-S ECDSA P-256/SHA-256 in 64-byte IEEE-P1363 form. It also
//! binds canonical RFC 5280 SubjectPublicKeyInfo identities and the Microsoft
//! Platform Crypto Provider TPM/non-exportable provenance profile. A future
//! Windows adapter may read CNG public blobs only as an internal transport: it
//! must strictly normalize and round-trip them into the one required SPKI form.
//! Its complete canonical header
//! is the `XChaCha` AAD. The stored signer digest is SHA-256 over a
//! domain-separated transcript containing that same complete header, the
//! ciphertext and tag, and the OAEP-wrapped KEK; the signature covers that
//! digest. Unknown algorithms, lengths, flags, or trailing bytes are rejected.
//!
//! Integrity is not freshness. Opening therefore additionally requires an
//! opaque [`VerifiedKeyBundleAnchor`] loaded from a rollback-resistant external
//! authority. The anchor commits the exact canonical envelope bytes, installation
//! identifier, and key epoch before any PCP unwrap occurs.

#![allow(dead_code)] // The production PCP/TPM adapter is intentionally not wired yet.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const BUNDLE_MAGIC: &[u8; 8] = b"YWKBND01";
const BUNDLE_VERSION: u16 = 1;
const BUNDLE_FLAGS: u16 = 0;
const INITIAL_KEY_EPOCH: u64 = 1;
const INSTALLATION_ID_BYTES: usize = 32;
const KEY_BYTES: usize = 32;
const KEY_COUNT: usize = 6;
const MATERIAL_SLOT_COUNT: usize = KEY_COUNT + 1;
const INSTALLATION_SLOT: usize = 0;
const ANCHOR_REGISTRY_HMAC_SLOT: usize = 1;
const STORAGE_MAC_ROOT_SLOT: usize = 2;
const JOURNAL_AEAD_SLOT: usize = 3;
const SETTINGS_AEAD_SLOT: usize = 4;
const NONCE_AEAD_SLOT: usize = 5;
const TPM_NV_AUTH_SLOT: usize = 6;
const BUNDLE_HEADER_BYTES: usize = 8 + 2 + 2 + INSTALLATION_ID_BYTES + 8;
const BUNDLE_BYTES: usize = BUNDLE_HEADER_BYTES + (KEY_BYTES * KEY_COUNT);

const ENVELOPE_MAGIC: &[u8; 8] = b"YWKBENV1";
const ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_FLAGS: u16 = 0;
const XCHACHA20_POLY1305_V1_ALGORITHM_ID: u16 = 1;
const RSA3072_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL_ALGORITHM_ID: u16 = 1;
const ECDSA_P256_SHA256_P1363_ALGORITHM_ID: u16 = 1;
const PCP_RSA3072_KEY_KIND_ID: u16 = 1;
const PCP_ECDSA_P256_KEY_KIND_ID: u16 = 1;
#[repr(u16)]
enum WrappingPublicKeyEncodingId {
    /// SHA-256 input is the exact RFC 5280 DER `SubjectPublicKeyInfo` using the
    /// `rsaEncryption` OID with explicit NULL parameters, a 3072-bit modulus,
    /// and its minimally encoded positive public exponent.
    RsaSpkiDerSha256V1 = 1,
}

#[repr(u16)]
enum SigningPublicKeyEncodingId {
    /// SHA-256 input is the exact RFC 5280 DER `SubjectPublicKeyInfo` whose
    /// `AlgorithmIdentifier` is `id-ecPublicKey` with the named-curve parameter
    /// `prime256v1`; its BIT STRING is `0x04 || X[32] || Y[32]`.
    P256SpkiDerSha256V1 = 1,
}
/// Both keys are dedicated current-user, non-exportable private keys reported
/// as hardware-backed by the exact Microsoft Platform Crypto Provider. A future
/// adapter must re-query these properties from held handles for every operation.
const MICROSOFT_PCP_TPM_NONEXPORTABLE_V1_PROVENANCE_ID: u16 = 1;
const XCHACHA_NONCE_BYTES: usize = 24;
const AEAD_TAG_BYTES: usize = 16;
const CIPHERTEXT_AND_TAG_BYTES: usize = BUNDLE_BYTES + AEAD_TAG_BYTES;
const OAEP_WRAPPED_KEK_BYTES: usize = 384;
const SIGNER_DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MAX_PCP_KEY_ID_BYTES: usize = 128;
const ENVELOPE_FIXED_HEADER_BYTES: usize = 176;
const ENVELOPE_FIXED_BODY_BYTES: usize =
    CIPHERTEXT_AND_TAG_BYTES + OAEP_WRAPPED_KEK_BYTES + SIGNER_DIGEST_BYTES + SIGNATURE_BYTES;
const MAX_ENVELOPE_BYTES: usize =
    ENVELOPE_FIXED_HEADER_BYTES + (MAX_PCP_KEY_ID_BYTES * 2) + ENVELOPE_FIXED_BODY_BYTES;
const RANDOM_ATTEMPTS: usize = 16;
const SIGNATURE_DOMAIN: &[u8] = b"your-wallet/key-agent/device-key-envelope/signature/v1\0";
const ANCHOR_DOMAIN: &[u8] = b"your-wallet/key-agent/device-key-envelope/anchor/v1\0";

const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Stable, path-free failures for device-key generation and envelope handling.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum KeyMaterialError {
    /// Operating-system cryptographic randomness was unavailable or unusable.
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    /// A plaintext bundle violated its exact version, bounds, or independence.
    #[error("device key bundle is invalid")]
    InvalidBundle,
    /// An encrypted envelope was malformed, non-canonical, or internally stale.
    #[error("device key envelope is invalid")]
    InvalidEnvelope,
    /// An algorithm or key-kind identifier was not the compiled profile.
    #[error("device key envelope algorithm is unsupported")]
    UnsupportedAlgorithm,
    /// A PCP wrapping operation did not complete exactly.
    #[error("device key wrapping failed")]
    WrapFailed,
    /// A PCP signing operation did not complete exactly.
    #[error("device key envelope signing failed")]
    SignFailed,
    /// A PCP unwrapping operation did not complete exactly.
    #[error("device key unwrapping failed")]
    UnwrapFailed,
    /// The envelope signer identity or signature was not valid.
    #[error("device key envelope signature is invalid")]
    SignatureInvalid,
    /// The configured PCP identity did not match the envelope identity.
    #[error("device key envelope identity does not match")]
    IdentityMismatch,
    /// External rollback-resistant state did not name this exact envelope.
    #[error("device key anchor does not match")]
    AnchorMismatch,
    /// Bootstrap, rotation, or anchor commit state was not safe to continue.
    #[error("device key anchor transition is invalid")]
    InvalidAnchorTransition,
    /// A persistence result was ambiguous, so key use remains locked.
    #[error("device key anchor state is locked")]
    AnchorLocked,
    /// The monotonic key epoch cannot be incremented.
    #[error("device key epoch is exhausted")]
    EpochExhausted,
    /// XChaCha20-Poly1305 authentication failed.
    #[error("device key envelope did not authenticate")]
    AuthenticationFailed,
}

/// Opaque backend failure. It deliberately carries no provider text or key ID.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("hardware key operation failed")]
pub(crate) struct KeyProtectionBackendError;

/// Independent installation-scoped key material.
///
/// The object is non-cloneable, its debug representation is redacted, and it
/// exposes no raw key accessor. Encoding is available only inside this private
/// module so that wrapping owns the complete plaintext lifetime.
pub(crate) struct DeviceKeyBundle {
    key_epoch: u64,
    material: Zeroizing<[[u8; KEY_BYTES]; MATERIAL_SLOT_COUNT]>,
}

macro_rules! define_role_key_view {
    ($name:ident, $debug_name:literal) => {
        /// Borrowed, role-specific access to one bundle secret.
        ///
        /// The view is deliberately non-cloneable and cannot select a different
        /// role or outlive its bundle.
        pub(crate) struct $name<'a> {
            bytes: &'a [u8; KEY_BYTES],
        }

        impl<'a> $name<'a> {
            /// Exposes this one role's bytes to its dedicated cryptographic
            /// consumer. There is no generic slot/role selector.
            pub(crate) const fn expose_secret(&self) -> &'a [u8; KEY_BYTES] {
                self.bytes
            }
        }

        impl fmt::Debug for $name<'_> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($debug_name)
            }
        }
    };
}

define_role_key_view!(
    AnchorRegistryHmacKey,
    "AnchorRegistryHmacKey([REDACTED KEY MATERIAL])"
);
define_role_key_view!(
    StorageMacRootKey,
    "StorageMacRootKey([REDACTED KEY MATERIAL])"
);
define_role_key_view!(JournalAeadKey, "JournalAeadKey([REDACTED KEY MATERIAL])");
define_role_key_view!(
    LocalSettingsAeadKey,
    "LocalSettingsAeadKey([REDACTED KEY MATERIAL])"
);
define_role_key_view!(
    NonceLedgerAeadKey,
    "NonceLedgerAeadKey([REDACTED KEY MATERIAL])"
);
define_role_key_view!(TpmNvAuthValue, "TpmNvAuthValue([REDACTED KEY MATERIAL])");

impl DeviceKeyBundle {
    fn from_material(
        key_epoch: u64,
        material: Zeroizing<[[u8; KEY_BYTES]; MATERIAL_SLOT_COUNT]>,
    ) -> Result<Self, KeyMaterialError> {
        if key_epoch == 0 || !valid_material(&material) {
            return Err(KeyMaterialError::InvalidBundle);
        }
        Ok(Self {
            key_epoch,
            material,
        })
    }

    fn encode(&self) -> Zeroizing<[u8; BUNDLE_BYTES]> {
        let mut encoded = Zeroizing::new([0_u8; BUNDLE_BYTES]);
        encoded[..8].copy_from_slice(BUNDLE_MAGIC);
        encoded[8..10].copy_from_slice(&BUNDLE_VERSION.to_be_bytes());
        encoded[10..12].copy_from_slice(&BUNDLE_FLAGS.to_be_bytes());
        encoded[12..44].copy_from_slice(&self.material[INSTALLATION_SLOT]);
        encoded[44..52].copy_from_slice(&self.key_epoch.to_be_bytes());
        let mut offset = BUNDLE_HEADER_BYTES;
        for slot in ANCHOR_REGISTRY_HMAC_SLOT..=TPM_NV_AUTH_SLOT {
            encoded[offset..offset + KEY_BYTES].copy_from_slice(&self.material[slot]);
            offset += KEY_BYTES;
        }
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, KeyMaterialError> {
        if encoded.len() != BUNDLE_BYTES
            || &encoded[..8] != BUNDLE_MAGIC
            || u16::from_be_bytes([encoded[8], encoded[9]]) != BUNDLE_VERSION
            || u16::from_be_bytes([encoded[10], encoded[11]]) != BUNDLE_FLAGS
        {
            return Err(KeyMaterialError::InvalidBundle);
        }

        let mut material = Zeroizing::new([[0_u8; KEY_BYTES]; MATERIAL_SLOT_COUNT]);
        material[INSTALLATION_SLOT].copy_from_slice(&encoded[12..44]);
        let key_epoch = u64::from_be_bytes(
            encoded[44..52]
                .try_into()
                .map_err(|_| KeyMaterialError::InvalidBundle)?,
        );
        let mut offset = BUNDLE_HEADER_BYTES;
        for slot in ANCHOR_REGISTRY_HMAC_SLOT..=TPM_NV_AUTH_SLOT {
            material[slot].copy_from_slice(&encoded[offset..offset + KEY_BYTES]);
            offset += KEY_BYTES;
        }
        Self::from_material(key_epoch, material)
    }

    /// Returns only the anchor-registry HMAC role.
    pub(crate) fn anchor_registry_hmac_key(&self) -> AnchorRegistryHmacKey<'_> {
        AnchorRegistryHmacKey {
            bytes: &self.material[ANCHOR_REGISTRY_HMAC_SLOT],
        }
    }

    /// Returns only the storage-MAC root role.
    pub(crate) fn storage_mac_root_key(&self) -> StorageMacRootKey<'_> {
        StorageMacRootKey {
            bytes: &self.material[STORAGE_MAC_ROOT_SLOT],
        }
    }

    /// Returns only the journal AEAD role.
    pub(crate) fn journal_aead_key(&self) -> JournalAeadKey<'_> {
        JournalAeadKey {
            bytes: &self.material[JOURNAL_AEAD_SLOT],
        }
    }

    /// Returns only the local-settings AEAD role.
    pub(crate) fn local_settings_aead_key(&self) -> LocalSettingsAeadKey<'_> {
        LocalSettingsAeadKey {
            bytes: &self.material[SETTINGS_AEAD_SLOT],
        }
    }

    /// Returns only the nonce-ledger AEAD role.
    pub(crate) fn nonce_ledger_aead_key(&self) -> NonceLedgerAeadKey<'_> {
        NonceLedgerAeadKey {
            bytes: &self.material[NONCE_AEAD_SLOT],
        }
    }

    /// Returns only the TPM NV authorization-value role.
    pub(crate) fn tpm_nv_auth_value(&self) -> TpmNvAuthValue<'_> {
        TpmNvAuthValue {
            bytes: &self.material[TPM_NV_AUTH_SLOT],
        }
    }

    /// Creates a pending rotation that preserves this installation identifier
    /// and advances the epoch exactly once. The new material is unusable until
    /// its exact envelope commitment is externally committed.
    pub(crate) fn begin_rotation(&self) -> Result<PendingDeviceKeyBundle, KeyMaterialError> {
        let next_epoch = self
            .key_epoch
            .checked_add(1)
            .ok_or(KeyMaterialError::EpochExhausted)?;
        let mut material = Zeroizing::new([[0_u8; KEY_BYTES]; MATERIAL_SLOT_COUNT]);
        material[INSTALLATION_SLOT].copy_from_slice(&self.material[INSTALLATION_SLOT]);
        for slot in ANCHOR_REGISTRY_HMAC_SLOT..=TPM_NV_AUTH_SLOT {
            fill_rotated_material_slot(&mut material, slot, &self.material)?;
        }
        Ok(PendingDeviceKeyBundle {
            bundle: Self::from_material(next_epoch, material)?,
        })
    }
}

/// Fresh key material that has not yet been committed by an external anchor.
/// It can be sealed, but it exposes no role key and cannot be returned by the
/// anchored open path.
pub(crate) struct PendingDeviceKeyBundle {
    bundle: DeviceKeyBundle,
}

impl PendingDeviceKeyBundle {
    /// Samples the only valid bootstrap bundle: a new installation at epoch 1.
    pub(crate) fn generate_initial() -> Result<Self, KeyMaterialError> {
        let mut material = Zeroizing::new([[0_u8; KEY_BYTES]; MATERIAL_SLOT_COUNT]);
        for slot in 0..MATERIAL_SLOT_COUNT {
            fill_distinct_material_slot(&mut material, slot)?;
        }
        Ok(Self {
            bundle: DeviceKeyBundle::from_material(INITIAL_KEY_EPOCH, material)?,
        })
    }

    fn encode(&self) -> Zeroizing<[u8; BUNDLE_BYTES]> {
        self.bundle.encode()
    }

    /// Protects this pending bundle with the fixed software AEAD plus separately
    /// held PCP wrapping and signing keys.
    pub(crate) fn seal<W: PcpOaepKeyWrapper, S: PcpDigestSigner>(
        &self,
        wrapper: &mut W,
        signer: &mut S,
    ) -> Result<SignedKeyBundleEnvelope, KeyMaterialError> {
        let mut nonce = [0_u8; XCHACHA_NONCE_BYTES];
        fill_nonzero(&mut nonce)?;

        let header = EnvelopeHeader::new(
            &self.bundle,
            wrapper.wrapping_identity(),
            signer.signing_identity(),
            nonce,
        )?;
        let aad = header.encode()?;
        let plaintext = self.bundle.encode();
        let mut kek = Zeroizing::new([0_u8; KEY_BYTES]);
        fill_nonzero(&mut kek)?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
        let ciphertext_and_tag = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| KeyMaterialError::AuthenticationFailed)?;
        if ciphertext_and_tag.len() != CIPHERTEXT_AND_TAG_BYTES {
            return Err(KeyMaterialError::InvalidEnvelope);
        }

        let wrapped_kek = wrapper
            .wrap_kek(&kek)
            .map_err(|_| KeyMaterialError::WrapFailed)?;
        if wrapped_kek.len() != OAEP_WRAPPED_KEK_BYTES {
            return Err(KeyMaterialError::WrapFailed);
        }
        if !header
            .wrapping_identity
            .matches(wrapper.wrapping_identity())
        {
            return Err(KeyMaterialError::IdentityMismatch);
        }

        let signer_digest = signature_digest(&aad, &ciphertext_and_tag, &wrapped_kek)?;
        let signature = signer
            .sign_digest(&signer_digest)
            .map_err(|_| KeyMaterialError::SignFailed)?;
        if !header.signing_identity.matches(signer.signing_identity()) {
            return Err(KeyMaterialError::IdentityMismatch);
        }

        let envelope = SignedKeyBundleEnvelope {
            header,
            ciphertext_and_tag,
            wrapped_kek,
            signer_digest,
            signature,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

impl fmt::Debug for PendingDeviceKeyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingDeviceKeyBundle([REDACTED KEY MATERIAL])")
    }
}

impl fmt::Debug for DeviceKeyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceKeyBundle([REDACTED KEY MATERIAL])")
    }
}

/// Validated identity for the dedicated PCP RSA-3072 wrapping key.
pub(crate) struct PcpWrappingKeyIdentity {
    identifier: String,
    public_key_sha256: [u8; 32],
}

impl PcpWrappingKeyIdentity {
    /// Builds a wrapping-key identity from a provider key name and SHA-256 over
    /// the exact RSA-3072 SPKI-DER profile identified in the envelope header.
    ///
    /// A production caller may invoke this only after a held-key query proves
    /// the dedicated key is current-user, TPM hardware-backed, non-exportable,
    /// and owned by the exact Microsoft Platform Crypto Provider. If Windows
    /// supplies a `BCRYPT_RSAPUBLIC_BLOB`, the future adapter must strictly
    /// validate its 3072-bit modulus/exponent, normalize it to the one required
    /// `rsaEncryption` + NULL SPKI, and round-trip the same held key before
    /// hashing. Raw CNG-blob digests are never envelope identities. The sealed
    /// operation trait requires that proof to stay live across each operation.
    fn new(identifier: String, public_key_sha256: [u8; 32]) -> Result<Self, KeyMaterialError> {
        validate_pcp_key_identity(&identifier, &public_key_sha256)?;
        Ok(Self {
            identifier,
            public_key_sha256,
        })
    }

    fn matches(&self, other: &Self) -> bool {
        self.identifier == other.identifier
            && bool::from(self.public_key_sha256.ct_eq(&other.public_key_sha256))
    }
}

impl fmt::Debug for PcpWrappingKeyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PcpWrappingKeyIdentity([REDACTED])")
    }
}

impl Drop for PcpWrappingKeyIdentity {
    fn drop(&mut self) {
        self.identifier.zeroize();
        self.public_key_sha256.zeroize();
    }
}

/// Validated identity for the dedicated PCP ECDSA-P256 signing key.
pub(crate) struct PcpSigningKeyIdentity {
    identifier: String,
    public_key_sha256: [u8; 32],
}

impl PcpSigningKeyIdentity {
    /// Builds a signing-key identity from a provider key name and SHA-256 over
    /// the exact canonical P-256 SPKI-DER profile identified in the header.
    ///
    /// A production caller may invoke this only after a held-key query proves
    /// the dedicated key is current-user, TPM hardware-backed, non-exportable,
    /// and owned by the exact Microsoft Platform Crypto Provider. If Windows
    /// supplies a `BCRYPT_ECCPUBLIC_BLOB`, the future adapter must strictly
    /// validate its P-256 magic/coordinates, normalize it to the one required
    /// `id-ecPublicKey` + `prime256v1` SPKI, and round-trip the same held key
    /// before hashing. Raw CNG-blob digests are never envelope identities. The
    /// sealed operation trait requires that proof to stay live across each
    /// operation.
    fn new(identifier: String, public_key_sha256: [u8; 32]) -> Result<Self, KeyMaterialError> {
        validate_pcp_key_identity(&identifier, &public_key_sha256)?;
        Ok(Self {
            identifier,
            public_key_sha256,
        })
    }

    fn matches(&self, other: &Self) -> bool {
        self.identifier == other.identifier
            && bool::from(self.public_key_sha256.ct_eq(&other.public_key_sha256))
    }
}

impl fmt::Debug for PcpSigningKeyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PcpSigningKeyIdentity([REDACTED])")
    }
}

impl Drop for PcpSigningKeyIdentity {
    fn drop(&mut self) {
        self.identifier.zeroize();
        self.public_key_sha256.zeroize();
    }
}

/// Sealed RSA-OAEP operation supplied only by the future PCP adapter.
///
/// Implementations must hold the exact RSA key while reporting its canonical
/// SPKI identity, re-query the compiled provenance properties, and use RSA-3072
/// OAEP with SHA-256, MGF1-SHA-256, and an empty label. Merely returning 384
/// bytes is not evidence of this contract; the production adapter needs strict
/// CNG-to-SPKI normalization, round-trip platform-property, and known-answer
/// evidence before activation.
pub(crate) trait PcpOaepKeyWrapper: fmt::Debug + sealed::PcpOaepKeyWrapperSealed {
    /// Returns the held RSA-3072 key identity for this operation.
    fn wrapping_identity(&self) -> &PcpWrappingKeyIdentity;

    /// Wraps exactly one 32-byte KEK with RSA-3072 OAEP using SHA-256 for both
    /// OAEP and MGF1, an empty label, and exactly 384 ciphertext bytes.
    fn wrap_kek(&mut self, kek: &[u8; KEY_BYTES]) -> Result<Vec<u8>, KeyProtectionBackendError>;
}

/// Sealed ECDSA operation supplied only by the future PCP adapter.
///
/// Implementations must hold the exact P-256 key and its canonical SPKI
/// identity, re-query the compiled provenance properties, sign the supplied
/// digest as a prehash exactly once, return big-endian IEEE-P1363 `r || s`, and
/// normalize `s` to low-S. A CNG blob is only an adapter-internal transport.
pub(crate) trait PcpDigestSigner: fmt::Debug + sealed::PcpDigestSignerSealed {
    /// Returns the held ECDSA-P256 key identity for this operation.
    fn signing_identity(&self) -> &PcpSigningKeyIdentity;

    /// Signs the exact 32-byte SHA-256 digest and returns a 64-byte IEEE-P1363
    /// `r || s` signature.
    fn sign_digest(
        &mut self,
        digest: &[u8; SIGNER_DIGEST_BYTES],
    ) -> Result<[u8; SIGNATURE_BYTES], KeyProtectionBackendError>;
}

/// Sealed RSA-OAEP operation supplied only by the future PCP adapter. The same
/// exact provider, key-property, OAEP, MGF1, label, and held-identity contract as
/// [`PcpOaepKeyWrapper`] applies.
pub(crate) trait PcpOaepKeyUnwrapper:
    fmt::Debug + sealed::PcpOaepKeyUnwrapperSealed
{
    /// Returns the held RSA-3072 key identity for this operation.
    fn wrapping_identity(&self) -> &PcpWrappingKeyIdentity;

    /// Unwraps one exact RSA-3072 OAEP/SHA-256 ciphertext with an empty label
    /// into a zeroizing KEK.
    fn unwrap_kek(
        &mut self,
        wrapped_kek: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_BYTES]>, KeyProtectionBackendError>;
}

/// Sealed ECDSA verification operation supplied only by the future PCP adapter.
/// It must reject non-P-256, non-P1363, out-of-range, or high-S signatures and
/// verify the supplied digest as a prehash exactly once.
pub(crate) trait PcpDigestVerifier: fmt::Debug + sealed::PcpDigestVerifierSealed {
    /// Returns the expected ECDSA-P256 key identity for this operation.
    fn signing_identity(&self) -> &PcpSigningKeyIdentity;

    /// Verifies the exact 32-byte SHA-256 digest against a 64-byte IEEE-P1363
    /// signature.
    fn verify_digest(
        &mut self,
        digest: &[u8; SIGNER_DIGEST_BYTES],
        signature: &[u8; SIGNATURE_BYTES],
    ) -> Result<(), KeyProtectionBackendError>;
}

/// Crate-only sealing markers. No production implementation exists yet.
mod sealed {
    /// Prevents external wrapping implementations.
    pub trait PcpOaepKeyWrapperSealed {}
    /// Prevents external signing implementations.
    pub trait PcpDigestSignerSealed {}
    /// Prevents external unwrapping implementations.
    pub trait PcpOaepKeyUnwrapperSealed {}
    /// Prevents external verification implementations.
    pub trait PcpDigestVerifierSealed {}
}

/// Canonical exact-byte commitment offered to an external rollback-resistant
/// anchor during bootstrap or rotation. This is not proof that the commitment
/// was accepted.
pub(crate) struct KeyBundleAnchorCommitment {
    installation_id: [u8; INSTALLATION_ID_BYTES],
    key_epoch: u64,
    envelope_digest: [u8; 32],
}

impl KeyBundleAnchorCommitment {
    fn validate(&self) -> Result<(), KeyMaterialError> {
        if self.installation_id == [0; INSTALLATION_ID_BYTES]
            || self.key_epoch == 0
            || self.envelope_digest == [0; 32]
        {
            return Err(KeyMaterialError::InvalidAnchorTransition);
        }
        Ok(())
    }

    fn matches(&self, other: &Self) -> bool {
        self.key_epoch == other.key_epoch
            && bool::from(self.installation_id.ct_eq(&other.installation_id))
            && bool::from(self.envelope_digest.ct_eq(&other.envelope_digest))
    }
}

impl fmt::Debug for KeyBundleAnchorCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyBundleAnchorCommitment([REDACTED])")
    }
}

impl Drop for KeyBundleAnchorCommitment {
    fn drop(&mut self) {
        self.installation_id.zeroize();
        self.envelope_digest.zeroize();
    }
}

/// Opaque evidence that an independent rollback-resistant authority committed
/// one exact envelope at a nonzero anchor generation. Rotation evidence also
/// names the exact previously committed installation, epoch, and envelope
/// digest, so a shared physical counter may skip numbers without admitting an
/// unproven history gap or alternate branch. There is deliberately no production
/// constructor: only a future sealed TPM/anchor adapter may add one after
/// verifying the held anchor and its predecessor link.
pub(crate) struct VerifiedKeyBundleAnchor {
    commitment: KeyBundleAnchorCommitment,
    predecessor: VerifiedAnchorPredecessor,
    anchor_generation: u64,
    _verification_seal: AnchorVerificationSeal,
}

struct AnchorVerificationSeal;

enum VerifiedAnchorPredecessor {
    Bootstrap,
    Rotation { previous: KeyBundleAnchorCommitment },
}

impl VerifiedKeyBundleAnchor {
    fn validate(&self) -> Result<(), KeyMaterialError> {
        self.commitment.validate()?;
        if self.anchor_generation == 0 {
            return Err(KeyMaterialError::InvalidAnchorTransition);
        }
        match &self.predecessor {
            VerifiedAnchorPredecessor::Bootstrap
                if self.commitment.key_epoch == INITIAL_KEY_EPOCH => {}
            VerifiedAnchorPredecessor::Rotation { previous } => {
                previous.validate()?;
                if !bool::from(
                    previous
                        .installation_id
                        .ct_eq(&self.commitment.installation_id),
                ) || self.commitment.key_epoch
                    != previous
                        .key_epoch
                        .checked_add(1)
                        .ok_or(KeyMaterialError::EpochExhausted)?
                    || bool::from(
                        previous
                            .envelope_digest
                            .ct_eq(&self.commitment.envelope_digest),
                    )
                {
                    return Err(KeyMaterialError::InvalidAnchorTransition);
                }
            }
            VerifiedAnchorPredecessor::Bootstrap => {
                return Err(KeyMaterialError::InvalidAnchorTransition);
            }
        }
        Ok(())
    }

    fn matches(&self, commitment: &KeyBundleAnchorCommitment) -> bool {
        self.commitment.matches(commitment)
    }

    fn is_bootstrap(&self) -> bool {
        matches!(self.predecessor, VerifiedAnchorPredecessor::Bootstrap)
    }

    fn follows(&self, previous: &KeyBundleAnchorCommitment) -> bool {
        match &self.predecessor {
            VerifiedAnchorPredecessor::Rotation {
                previous: verified_previous,
            } => verified_previous.matches(previous),
            VerifiedAnchorPredecessor::Bootstrap => false,
        }
    }

    #[cfg(test)]
    fn new_bootstrap_for_test(
        commitment: KeyBundleAnchorCommitment,
        anchor_generation: u64,
    ) -> Result<Self, KeyMaterialError> {
        let anchor = Self {
            commitment,
            predecessor: VerifiedAnchorPredecessor::Bootstrap,
            anchor_generation,
            _verification_seal: AnchorVerificationSeal,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    #[cfg(test)]
    fn new_rotation_for_test(
        previous: KeyBundleAnchorCommitment,
        commitment: KeyBundleAnchorCommitment,
        anchor_generation: u64,
    ) -> Result<Self, KeyMaterialError> {
        let anchor = Self {
            commitment,
            predecessor: VerifiedAnchorPredecessor::Rotation { previous },
            anchor_generation,
            _verification_seal: AnchorVerificationSeal,
        };
        anchor.validate()?;
        Ok(anchor)
    }
}

impl fmt::Debug for VerifiedKeyBundleAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedKeyBundleAnchor([REDACTED])")
    }
}

/// Explicit fail-closed bootstrap/rotation seam. Only `Committed` permits key
/// opening; either pending state and every ambiguous outcome remain locked.
pub(crate) enum KeyBundleAnchorState {
    Empty,
    BootstrapPending {
        next: KeyBundleAnchorCommitment,
    },
    Committed {
        current: VerifiedKeyBundleAnchor,
    },
    RotationPending {
        current: VerifiedKeyBundleAnchor,
        next: KeyBundleAnchorCommitment,
    },
    Locked,
}

impl KeyBundleAnchorState {
    pub(crate) const fn empty() -> Self {
        Self::Empty
    }

    pub(crate) fn stage_bootstrap(
        &mut self,
        next: KeyBundleAnchorCommitment,
    ) -> Result<(), KeyMaterialError> {
        next.validate()?;
        if !matches!(self, Self::Empty) || next.key_epoch != INITIAL_KEY_EPOCH {
            return Err(KeyMaterialError::InvalidAnchorTransition);
        }
        *self = Self::BootstrapPending { next };
        Ok(())
    }

    pub(crate) fn stage_rotation(
        &mut self,
        next: KeyBundleAnchorCommitment,
    ) -> Result<(), KeyMaterialError> {
        next.validate()?;
        let previous = std::mem::replace(self, Self::Locked);
        match previous {
            Self::Committed { current }
                if next.installation_id == current.commitment.installation_id
                    && next.key_epoch
                        == current
                            .commitment
                            .key_epoch
                            .checked_add(1)
                            .ok_or(KeyMaterialError::EpochExhausted)?
                    && !bool::from(
                        next.envelope_digest
                            .ct_eq(&current.commitment.envelope_digest),
                    ) =>
            {
                *self = Self::RotationPending { current, next };
                Ok(())
            }
            Self::Committed { current } => {
                *self = Self::Committed { current };
                Err(KeyMaterialError::InvalidAnchorTransition)
            }
            other => {
                *self = other;
                Err(KeyMaterialError::InvalidAnchorTransition)
            }
        }
    }

    pub(crate) fn accept_verified(
        &mut self,
        verified: VerifiedKeyBundleAnchor,
    ) -> Result<(), KeyMaterialError> {
        verified.validate()?;
        let accepted = match self {
            Self::BootstrapPending { next } => verified.is_bootstrap() && verified.matches(next),
            Self::RotationPending { current, next } => {
                verified.matches(next)
                    && verified.follows(&current.commitment)
                    && verified.anchor_generation > current.anchor_generation
                    && verified.commitment.key_epoch
                        == current
                            .commitment
                            .key_epoch
                            .checked_add(1)
                            .ok_or(KeyMaterialError::EpochExhausted)?
            }
            _ => false,
        };
        if !accepted {
            *self = Self::Locked;
            return Err(KeyMaterialError::AnchorMismatch);
        }
        *self = Self::Committed { current: verified };
        Ok(())
    }

    pub(crate) fn current(&self) -> Result<&VerifiedKeyBundleAnchor, KeyMaterialError> {
        match self {
            Self::Committed { current } => Ok(current),
            Self::Empty | Self::BootstrapPending { .. } | Self::RotationPending { .. } => {
                Err(KeyMaterialError::InvalidAnchorTransition)
            }
            Self::Locked => Err(KeyMaterialError::AnchorLocked),
        }
    }

    pub(crate) fn lock_ambiguous(&mut self) {
        *self = Self::Locked;
    }
}

impl fmt::Debug for KeyBundleAnchorState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyBundleAnchorState([REDACTED])")
    }
}

struct EnvelopeHeader {
    installation_id: [u8; INSTALLATION_ID_BYTES],
    key_epoch: u64,
    wrapping_identity: PcpWrappingKeyIdentity,
    signing_identity: PcpSigningKeyIdentity,
    nonce: [u8; XCHACHA_NONCE_BYTES],
}

impl EnvelopeHeader {
    fn new(
        bundle: &DeviceKeyBundle,
        wrapping_identity: &PcpWrappingKeyIdentity,
        signing_identity: &PcpSigningKeyIdentity,
        nonce: [u8; XCHACHA_NONCE_BYTES],
    ) -> Result<Self, KeyMaterialError> {
        let header = Self {
            installation_id: bundle.material[INSTALLATION_SLOT],
            key_epoch: bundle.key_epoch,
            wrapping_identity: PcpWrappingKeyIdentity::new(
                wrapping_identity.identifier.clone(),
                wrapping_identity.public_key_sha256,
            )?,
            signing_identity: PcpSigningKeyIdentity::new(
                signing_identity.identifier.clone(),
                signing_identity.public_key_sha256,
            )?,
            nonce,
        };
        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<(), KeyMaterialError> {
        validate_pcp_key_identity(
            &self.wrapping_identity.identifier,
            &self.wrapping_identity.public_key_sha256,
        )?;
        validate_pcp_key_identity(
            &self.signing_identity.identifier,
            &self.signing_identity.public_key_sha256,
        )?;
        if self.installation_id == [0; INSTALLATION_ID_BYTES]
            || self.key_epoch == 0
            || self.nonce == [0; XCHACHA_NONCE_BYTES]
            || self.wrapping_identity.identifier == self.signing_identity.identifier
            || bool::from(
                self.wrapping_identity
                    .public_key_sha256
                    .ct_eq(&self.signing_identity.public_key_sha256),
            )
        {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        Ok(())
    }

    fn encoded_len(&self) -> Result<usize, KeyMaterialError> {
        let length = ENVELOPE_FIXED_HEADER_BYTES
            .checked_add(self.wrapping_identity.identifier.len())
            .and_then(|value| value.checked_add(self.signing_identity.identifier.len()))
            .ok_or(KeyMaterialError::InvalidEnvelope)?;
        if length > ENVELOPE_FIXED_HEADER_BYTES + (MAX_PCP_KEY_ID_BYTES * 2)
            || u16::try_from(length).is_err()
        {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        Ok(length)
    }

    fn encode(&self) -> Result<Vec<u8>, KeyMaterialError> {
        self.validate()?;
        let header_len = self.encoded_len()?;
        let header_len_u16 =
            u16::try_from(header_len).map_err(|_| KeyMaterialError::InvalidEnvelope)?;
        let wrapping_id_len = u16::try_from(self.wrapping_identity.identifier.len())
            .map_err(|_| KeyMaterialError::InvalidEnvelope)?;
        let signing_id_len = u16::try_from(self.signing_identity.identifier.len())
            .map_err(|_| KeyMaterialError::InvalidEnvelope)?;
        let ciphertext_len = u32::try_from(CIPHERTEXT_AND_TAG_BYTES)
            .map_err(|_| KeyMaterialError::InvalidEnvelope)?;
        let wrapped_kek_len =
            u16::try_from(OAEP_WRAPPED_KEK_BYTES).map_err(|_| KeyMaterialError::InvalidEnvelope)?;
        let signer_digest_len =
            u16::try_from(SIGNER_DIGEST_BYTES).map_err(|_| KeyMaterialError::InvalidEnvelope)?;
        let signature_len =
            u16::try_from(SIGNATURE_BYTES).map_err(|_| KeyMaterialError::InvalidEnvelope)?;
        let nonce_len =
            u16::try_from(XCHACHA_NONCE_BYTES).map_err(|_| KeyMaterialError::InvalidEnvelope)?;
        let mut encoded = Vec::with_capacity(header_len);
        encoded.extend_from_slice(ENVELOPE_MAGIC);
        extend_u16(&mut encoded, ENVELOPE_VERSION);
        extend_u16(&mut encoded, ENVELOPE_FLAGS);
        extend_u16(&mut encoded, header_len_u16);
        extend_u16(&mut encoded, BUNDLE_VERSION);
        extend_u16(&mut encoded, XCHACHA20_POLY1305_V1_ALGORITHM_ID);
        extend_u16(
            &mut encoded,
            RSA3072_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL_ALGORITHM_ID,
        );
        extend_u16(&mut encoded, ECDSA_P256_SHA256_P1363_ALGORITHM_ID);
        extend_u16(&mut encoded, PCP_RSA3072_KEY_KIND_ID);
        extend_u16(&mut encoded, PCP_ECDSA_P256_KEY_KIND_ID);
        extend_u16(
            &mut encoded,
            WrappingPublicKeyEncodingId::RsaSpkiDerSha256V1 as u16,
        );
        extend_u16(
            &mut encoded,
            SigningPublicKeyEncodingId::P256SpkiDerSha256V1 as u16,
        );
        extend_u16(
            &mut encoded,
            MICROSOFT_PCP_TPM_NONEXPORTABLE_V1_PROVENANCE_ID,
        );
        encoded.extend_from_slice(&self.installation_id);
        encoded.extend_from_slice(&self.key_epoch.to_be_bytes());
        extend_u16(&mut encoded, wrapping_id_len);
        extend_u16(&mut encoded, signing_id_len);
        encoded.extend_from_slice(&ciphertext_len.to_be_bytes());
        extend_u16(&mut encoded, wrapped_kek_len);
        extend_u16(&mut encoded, signer_digest_len);
        extend_u16(&mut encoded, signature_len);
        extend_u16(&mut encoded, nonce_len);
        encoded.extend_from_slice(&self.wrapping_identity.public_key_sha256);
        encoded.extend_from_slice(&self.signing_identity.public_key_sha256);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(self.wrapping_identity.identifier.as_bytes());
        encoded.extend_from_slice(self.signing_identity.identifier.as_bytes());
        if encoded.len() != header_len {
            encoded.zeroize();
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        Ok(encoded)
    }
}

impl Drop for EnvelopeHeader {
    fn drop(&mut self) {
        self.installation_id.zeroize();
        self.nonce.zeroize();
    }
}

/// Canonical encrypted and signed DTO suitable for durable storage.
///
/// The DTO is deliberately non-cloneable and has no field or raw-byte
/// accessor. Persistence uses [`Self::encode`], and recovery uses only
/// [`Self::open_anchored`], which checks external freshness and verifies the
/// signature before invoking the unwrapper.
pub(crate) struct SignedKeyBundleEnvelope {
    header: EnvelopeHeader,
    ciphertext_and_tag: Vec<u8>,
    wrapped_kek: Vec<u8>,
    signer_digest: [u8; SIGNER_DIGEST_BYTES],
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedKeyBundleEnvelope {
    fn validate(&self) -> Result<(), KeyMaterialError> {
        self.header.validate()?;
        if self.ciphertext_and_tag.len() != CIPHERTEXT_AND_TAG_BYTES
            || self.wrapped_kek.len() != OAEP_WRAPPED_KEK_BYTES
            || !canonical_p256_p1363_signature(&self.signature)
        {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        let aad = self.header.encode()?;
        let expected = signature_digest(&aad, &self.ciphertext_and_tag, &self.wrapped_kek)?;
        if !bool::from(expected.ct_eq(&self.signer_digest)) {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        Ok(())
    }

    /// Serializes this DTO into its one canonical bounded representation.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, KeyMaterialError> {
        self.validate()?;
        let header = self.header.encode()?;
        let total_len = header
            .len()
            .checked_add(ENVELOPE_FIXED_BODY_BYTES)
            .ok_or(KeyMaterialError::InvalidEnvelope)?;
        if total_len > MAX_ENVELOPE_BYTES {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        let mut encoded = Vec::with_capacity(total_len);
        encoded.extend_from_slice(&header);
        encoded.extend_from_slice(&self.ciphertext_and_tag);
        encoded.extend_from_slice(&self.wrapped_kek);
        encoded.extend_from_slice(&self.signer_digest);
        encoded.extend_from_slice(&self.signature);
        if encoded.len() != total_len {
            encoded.zeroize();
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        Ok(encoded)
    }

    /// Computes the exact commitment that a rollback-resistant authority must
    /// durably accept before this envelope can be opened.
    pub(crate) fn anchor_commitment(&self) -> Result<KeyBundleAnchorCommitment, KeyMaterialError> {
        let encoded = self.encode()?;
        let envelope_digest = envelope_anchor_digest(&encoded)?;
        let commitment = KeyBundleAnchorCommitment {
            installation_id: self.header.installation_id,
            key_epoch: self.header.key_epoch,
            envelope_digest,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    /// Parses an exact envelope, rejecting truncation, trailing bytes, unknown
    /// algorithms and every non-canonical length.
    pub(crate) fn parse(encoded: &[u8]) -> Result<Self, KeyMaterialError> {
        if encoded.len() > MAX_ENVELOPE_BYTES || encoded.len() < ENVELOPE_FIXED_BODY_BYTES {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        let mut cursor = Cursor::new(encoded);
        if cursor.take(8)? != ENVELOPE_MAGIC
            || cursor.u16()? != ENVELOPE_VERSION
            || cursor.u16()? != ENVELOPE_FLAGS
        {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        let header_len = usize::from(cursor.u16()?);
        if !(ENVELOPE_FIXED_HEADER_BYTES..=ENVELOPE_FIXED_HEADER_BYTES + (MAX_PCP_KEY_ID_BYTES * 2))
            .contains(&header_len)
            || cursor.u16()? != BUNDLE_VERSION
        {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        validate_algorithm(cursor.u16()?, XCHACHA20_POLY1305_V1_ALGORITHM_ID)?;
        validate_algorithm(
            cursor.u16()?,
            RSA3072_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL_ALGORITHM_ID,
        )?;
        validate_algorithm(cursor.u16()?, ECDSA_P256_SHA256_P1363_ALGORITHM_ID)?;
        validate_algorithm(cursor.u16()?, PCP_RSA3072_KEY_KIND_ID)?;
        validate_algorithm(cursor.u16()?, PCP_ECDSA_P256_KEY_KIND_ID)?;
        validate_algorithm(
            cursor.u16()?,
            WrappingPublicKeyEncodingId::RsaSpkiDerSha256V1 as u16,
        )?;
        validate_algorithm(
            cursor.u16()?,
            SigningPublicKeyEncodingId::P256SpkiDerSha256V1 as u16,
        )?;
        validate_algorithm(
            cursor.u16()?,
            MICROSOFT_PCP_TPM_NONEXPORTABLE_V1_PROVENANCE_ID,
        )?;

        let installation_id = cursor.array()?;
        let key_epoch = cursor.u64()?;
        let wrapping_id_len = usize::from(cursor.u16()?);
        let signing_id_len = usize::from(cursor.u16()?);
        if usize::try_from(cursor.u32()?).map_err(|_| KeyMaterialError::InvalidEnvelope)?
            != CIPHERTEXT_AND_TAG_BYTES
            || usize::from(cursor.u16()?) != OAEP_WRAPPED_KEK_BYTES
            || usize::from(cursor.u16()?) != SIGNER_DIGEST_BYTES
            || usize::from(cursor.u16()?) != SIGNATURE_BYTES
            || usize::from(cursor.u16()?) != XCHACHA_NONCE_BYTES
        {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        let wrapping_public_key_sha256 = cursor.array()?;
        let signing_public_key_sha256 = cursor.array()?;
        let nonce = cursor.array()?;
        let identifiers_end = cursor
            .position()
            .checked_add(wrapping_id_len)
            .and_then(|value| value.checked_add(signing_id_len))
            .ok_or(KeyMaterialError::InvalidEnvelope)?;
        if identifiers_end != header_len {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        let wrapping_identifier = parse_identifier(cursor.take(wrapping_id_len)?)?;
        let signing_identifier = parse_identifier(cursor.take(signing_id_len)?)?;
        if cursor.position() != header_len {
            return Err(KeyMaterialError::InvalidEnvelope);
        }

        let ciphertext_and_tag = cursor.take(CIPHERTEXT_AND_TAG_BYTES)?.to_vec();
        let wrapped_kek = cursor.take(OAEP_WRAPPED_KEK_BYTES)?.to_vec();
        let signer_digest = cursor.array()?;
        let signature = cursor.array()?;
        cursor.finish()?;

        let envelope = Self {
            header: EnvelopeHeader {
                installation_id,
                key_epoch,
                wrapping_identity: PcpWrappingKeyIdentity::new(
                    wrapping_identifier,
                    wrapping_public_key_sha256,
                )?,
                signing_identity: PcpSigningKeyIdentity::new(
                    signing_identifier,
                    signing_public_key_sha256,
                )?,
                nonce,
            },
            ciphertext_and_tag,
            wrapped_kek,
            signer_digest,
            signature,
        };
        envelope.validate()?;
        if envelope.header.encode()?.as_slice() != &encoded[..header_len] {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        Ok(envelope)
    }

    /// Checks an independently verified exact anchor, then verifies, unwraps,
    /// authenticates, and decodes this envelope. The anchor and PCP verifier run
    /// before the private unwrapping operation. No unanchored open path exists.
    pub(crate) fn open_anchored<U: PcpOaepKeyUnwrapper, V: PcpDigestVerifier>(
        &self,
        anchor: &VerifiedKeyBundleAnchor,
        unwrapper: &mut U,
        verifier: &mut V,
    ) -> Result<DeviceKeyBundle, KeyMaterialError> {
        self.validate()?;
        anchor.validate()?;
        let commitment = self.anchor_commitment()?;
        if !anchor.matches(&commitment) {
            return Err(KeyMaterialError::AnchorMismatch);
        }
        if !self
            .header
            .wrapping_identity
            .matches(unwrapper.wrapping_identity())
            || !self
                .header
                .signing_identity
                .matches(verifier.signing_identity())
        {
            return Err(KeyMaterialError::IdentityMismatch);
        }
        verifier
            .verify_digest(&self.signer_digest, &self.signature)
            .map_err(|_| KeyMaterialError::SignatureInvalid)?;
        if !self
            .header
            .signing_identity
            .matches(verifier.signing_identity())
        {
            return Err(KeyMaterialError::IdentityMismatch);
        }

        let kek = unwrapper
            .unwrap_kek(&self.wrapped_kek)
            .map_err(|_| KeyMaterialError::UnwrapFailed)?;
        if is_zero(kek.as_ref()) {
            return Err(KeyMaterialError::UnwrapFailed);
        }
        if !self
            .header
            .wrapping_identity
            .matches(unwrapper.wrapping_identity())
        {
            return Err(KeyMaterialError::IdentityMismatch);
        }
        let aad = self.header.encode()?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&self.header.nonce),
                    Payload {
                        msg: &self.ciphertext_and_tag,
                        aad: &aad,
                    },
                )
                .map_err(|_| KeyMaterialError::AuthenticationFailed)?,
        );
        let bundle = DeviceKeyBundle::decode(&plaintext)?;
        if bundle.key_epoch != self.header.key_epoch
            || !bool::from(bundle.material[INSTALLATION_SLOT].ct_eq(&self.header.installation_id))
        {
            return Err(KeyMaterialError::InvalidBundle);
        }
        Ok(bundle)
    }
}

impl fmt::Debug for SignedKeyBundleEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedKeyBundleEnvelope([REDACTED ENVELOPE])")
    }
}

impl Drop for SignedKeyBundleEnvelope {
    fn drop(&mut self) {
        self.ciphertext_and_tag.zeroize();
        self.wrapped_kek.zeroize();
        self.signer_digest.zeroize();
        self.signature.zeroize();
    }
}

fn fill_distinct_material_slot(
    material: &mut [[u8; KEY_BYTES]; MATERIAL_SLOT_COUNT],
    slot: usize,
) -> Result<(), KeyMaterialError> {
    for _ in 0..RANDOM_ATTEMPTS {
        getrandom::fill(&mut material[slot])
            .map_err(|_| KeyMaterialError::RandomnessUnavailable)?;
        if !is_zero(&material[slot])
            && (0..slot).all(|prior| !ct_equal(&material[slot], &material[prior]))
        {
            return Ok(());
        }
        material[slot].zeroize();
    }
    Err(KeyMaterialError::RandomnessUnavailable)
}

fn fill_rotated_material_slot(
    material: &mut [[u8; KEY_BYTES]; MATERIAL_SLOT_COUNT],
    slot: usize,
    previous: &[[u8; KEY_BYTES]; MATERIAL_SLOT_COUNT],
) -> Result<(), KeyMaterialError> {
    for _ in 0..RANDOM_ATTEMPTS {
        getrandom::fill(&mut material[slot])
            .map_err(|_| KeyMaterialError::RandomnessUnavailable)?;
        if !is_zero(&material[slot])
            && (0..slot).all(|prior| !ct_equal(&material[slot], &material[prior]))
            && previous
                .iter()
                .all(|prior| !ct_equal(&material[slot], prior))
        {
            return Ok(());
        }
        material[slot].zeroize();
    }
    Err(KeyMaterialError::RandomnessUnavailable)
}

fn fill_nonzero<const N: usize>(bytes: &mut [u8; N]) -> Result<(), KeyMaterialError> {
    for _ in 0..RANDOM_ATTEMPTS {
        getrandom::fill(bytes).map_err(|_| KeyMaterialError::RandomnessUnavailable)?;
        if !is_zero(bytes) {
            return Ok(());
        }
        bytes.zeroize();
    }
    Err(KeyMaterialError::RandomnessUnavailable)
}

fn valid_material(material: &[[u8; KEY_BYTES]; MATERIAL_SLOT_COUNT]) -> bool {
    for slot in INSTALLATION_SLOT..=TPM_NV_AUTH_SLOT {
        if is_zero(&material[slot]) {
            return false;
        }
        for prior in INSTALLATION_SLOT..slot {
            if ct_equal(&material[slot], &material[prior]) {
                return false;
            }
        }
    }
    true
}

fn validate_pcp_key_identity(
    identifier: &str,
    public_key_sha256: &[u8; 32],
) -> Result<(), KeyMaterialError> {
    if !valid_pcp_key_identifier(identifier) || is_zero(public_key_sha256) {
        return Err(KeyMaterialError::InvalidEnvelope);
    }
    Ok(())
}

fn parse_identifier(encoded: &[u8]) -> Result<String, KeyMaterialError> {
    let identifier = std::str::from_utf8(encoded).map_err(|_| KeyMaterialError::InvalidEnvelope)?;
    if !valid_pcp_key_identifier(identifier) {
        return Err(KeyMaterialError::InvalidEnvelope);
    }
    Ok(identifier.to_owned())
}

fn valid_pcp_key_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= MAX_PCP_KEY_ID_BYTES
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn signature_digest(
    header: &[u8],
    ciphertext_and_tag: &[u8],
    wrapped_kek: &[u8],
) -> Result<[u8; SIGNER_DIGEST_BYTES], KeyMaterialError> {
    if header.len() > usize::from(u16::MAX)
        || ciphertext_and_tag.len() != CIPHERTEXT_AND_TAG_BYTES
        || wrapped_kek.len() != OAEP_WRAPPED_KEK_BYTES
    {
        return Err(KeyMaterialError::InvalidEnvelope);
    }
    let mut hasher = Sha256::new();
    hasher.update(SIGNATURE_DOMAIN);
    hasher.update(
        u16::try_from(header.len())
            .map_err(|_| KeyMaterialError::InvalidEnvelope)?
            .to_be_bytes(),
    );
    hasher.update(header);
    hasher.update(ciphertext_and_tag);
    hasher.update(wrapped_kek);
    Ok(hasher.finalize().into())
}

fn envelope_anchor_digest(encoded: &[u8]) -> Result<[u8; 32], KeyMaterialError> {
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(KeyMaterialError::InvalidEnvelope);
    }
    let encoded_len =
        u32::try_from(encoded.len()).map_err(|_| KeyMaterialError::InvalidEnvelope)?;
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_DOMAIN);
    hasher.update(encoded_len.to_be_bytes());
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn canonical_p256_p1363_signature(signature: &[u8; SIGNATURE_BYTES]) -> bool {
    valid_p256_scalar(&signature[..32]) && valid_low_s_p256_scalar(&signature[32..])
}

fn valid_p256_scalar(bytes: &[u8]) -> bool {
    bytes.len() == 32 && !is_zero(bytes) && bytes < P256_ORDER.as_slice()
}

fn valid_low_s_p256_scalar(bytes: &[u8]) -> bool {
    valid_p256_scalar(bytes) && bytes <= P256_HALF_ORDER.as_slice()
}

fn is_zero(bytes: &[u8]) -> bool {
    let aggregate = bytes.iter().fold(0_u8, |value, byte| value | byte);
    bool::from(aggregate.ct_eq(&0))
}

fn ct_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn validate_algorithm(actual: u16, expected: u16) -> Result<(), KeyMaterialError> {
    if actual != expected {
        return Err(KeyMaterialError::UnsupportedAlgorithm);
    }
    Ok(())
}

fn extend_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_be_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn position(&self) -> usize {
        self.offset
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], KeyMaterialError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(KeyMaterialError::InvalidEnvelope)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(KeyMaterialError::InvalidEnvelope)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], KeyMaterialError> {
        self.take(N)?
            .try_into()
            .map_err(|_| KeyMaterialError::InvalidEnvelope)
    }

    fn u16(&mut self) -> Result<u16, KeyMaterialError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, KeyMaterialError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, KeyMaterialError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), KeyMaterialError> {
        if self.offset != self.bytes.len() {
            return Err(KeyMaterialError::InvalidEnvelope);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;

    const WRAP_IDENTIFIER: &str = "yw-device-wrap-01";
    const SIGN_IDENTIFIER: &str = "yw-device-sign-01";
    const WRAP_DIGEST: [u8; 32] = [0x31; 32];
    const SIGN_DIGEST: [u8; 32] = [0x72; 32];
    const FAKE_WRAP_MASK: [u8; 32] = [0xa5; 32];
    const FAKE_SIGN_KEY: [u8; 32] = [0x5a; 32];
    const HEADER_LENGTH_OFFSET: usize = 12;
    const INSTALLATION_OFFSET: usize = 32;
    const EPOCH_OFFSET: usize = 64;
    const WRAPPING_ID_LENGTH_OFFSET: usize = 72;
    const SIGNING_ID_LENGTH_OFFSET: usize = 74;
    const CIPHERTEXT_LENGTH_OFFSET: usize = 76;
    const WRAPPED_KEK_LENGTH_OFFSET: usize = 80;
    const SIGNER_DIGEST_LENGTH_OFFSET: usize = 82;
    const SIGNATURE_LENGTH_OFFSET: usize = 84;
    const NONCE_LENGTH_OFFSET: usize = 86;
    const WRAPPING_PUBLIC_DIGEST_OFFSET: usize = 88;
    const SIGNING_PUBLIC_DIGEST_OFFSET: usize = 120;
    const NONCE_OFFSET: usize = 152;

    fn wrapping_identity() -> Result<PcpWrappingKeyIdentity, KeyMaterialError> {
        PcpWrappingKeyIdentity::new(WRAP_IDENTIFIER.to_owned(), WRAP_DIGEST)
    }

    fn signing_identity() -> Result<PcpSigningKeyIdentity, KeyMaterialError> {
        PcpSigningKeyIdentity::new(SIGN_IDENTIFIER.to_owned(), SIGN_DIGEST)
    }

    struct FakeWrapper {
        identity: PcpWrappingKeyIdentity,
        wrong_length: bool,
    }

    impl fmt::Debug for FakeWrapper {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeWrapper([REDACTED])")
        }
    }

    impl sealed::PcpOaepKeyWrapperSealed for FakeWrapper {}

    impl PcpOaepKeyWrapper for FakeWrapper {
        fn wrapping_identity(&self) -> &PcpWrappingKeyIdentity {
            &self.identity
        }

        fn wrap_kek(
            &mut self,
            kek: &[u8; KEY_BYTES],
        ) -> Result<Vec<u8>, KeyProtectionBackendError> {
            let length = if self.wrong_length {
                OAEP_WRAPPED_KEK_BYTES - 1
            } else {
                OAEP_WRAPPED_KEK_BYTES
            };
            let mut wrapped = vec![0x81; length];
            for (output, (secret, mask)) in wrapped
                .iter_mut()
                .take(KEY_BYTES)
                .zip(kek.iter().zip(FAKE_WRAP_MASK))
            {
                *output = secret ^ mask;
            }
            Ok(wrapped)
        }
    }

    struct FakeUnwrapper {
        identity: PcpWrappingKeyIdentity,
        wrong_key: bool,
    }

    impl fmt::Debug for FakeUnwrapper {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeUnwrapper([REDACTED])")
        }
    }

    impl sealed::PcpOaepKeyUnwrapperSealed for FakeUnwrapper {}

    impl PcpOaepKeyUnwrapper for FakeUnwrapper {
        fn wrapping_identity(&self) -> &PcpWrappingKeyIdentity {
            &self.identity
        }

        fn unwrap_kek(
            &mut self,
            wrapped_kek: &[u8],
        ) -> Result<Zeroizing<[u8; KEY_BYTES]>, KeyProtectionBackendError> {
            if wrapped_kek.len() != OAEP_WRAPPED_KEK_BYTES {
                return Err(KeyProtectionBackendError);
            }
            let mut kek = Zeroizing::new([0_u8; KEY_BYTES]);
            for (output, (wrapped, mask)) in
                kek.iter_mut().zip(wrapped_kek.iter().zip(FAKE_WRAP_MASK))
            {
                *output = wrapped ^ mask;
            }
            if self.wrong_key {
                kek[0] ^= 1;
            }
            Ok(kek)
        }
    }

    struct FakeSigner {
        identity: PcpSigningKeyIdentity,
    }

    impl fmt::Debug for FakeSigner {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeSigner([REDACTED])")
        }
    }

    impl sealed::PcpDigestSignerSealed for FakeSigner {}

    impl PcpDigestSigner for FakeSigner {
        fn signing_identity(&self) -> &PcpSigningKeyIdentity {
            &self.identity
        }

        fn sign_digest(
            &mut self,
            digest: &[u8; SIGNER_DIGEST_BYTES],
        ) -> Result<[u8; SIGNATURE_BYTES], KeyProtectionBackendError> {
            Ok(fake_signature(digest))
        }
    }

    struct FakeVerifier {
        identity: PcpSigningKeyIdentity,
    }

    impl fmt::Debug for FakeVerifier {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeVerifier([REDACTED])")
        }
    }

    impl sealed::PcpDigestVerifierSealed for FakeVerifier {}

    impl PcpDigestVerifier for FakeVerifier {
        fn signing_identity(&self) -> &PcpSigningKeyIdentity {
            &self.identity
        }

        fn verify_digest(
            &mut self,
            digest: &[u8; SIGNER_DIGEST_BYTES],
            signature: &[u8; SIGNATURE_BYTES],
        ) -> Result<(), KeyProtectionBackendError> {
            if bool::from(fake_signature(digest).ct_eq(signature)) {
                Ok(())
            } else {
                Err(KeyProtectionBackendError)
            }
        }
    }

    struct RecordingUnwrapper {
        identity: PcpWrappingKeyIdentity,
        called: bool,
    }

    impl fmt::Debug for RecordingUnwrapper {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("RecordingUnwrapper([REDACTED])")
        }
    }

    impl sealed::PcpOaepKeyUnwrapperSealed for RecordingUnwrapper {}

    impl PcpOaepKeyUnwrapper for RecordingUnwrapper {
        fn wrapping_identity(&self) -> &PcpWrappingKeyIdentity {
            &self.identity
        }

        fn unwrap_kek(
            &mut self,
            _wrapped_kek: &[u8],
        ) -> Result<Zeroizing<[u8; KEY_BYTES]>, KeyProtectionBackendError> {
            self.called = true;
            Err(KeyProtectionBackendError)
        }
    }

    struct RecordingVerifier {
        identity: PcpSigningKeyIdentity,
        called: bool,
    }

    impl fmt::Debug for RecordingVerifier {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("RecordingVerifier([REDACTED])")
        }
    }

    impl sealed::PcpDigestVerifierSealed for RecordingVerifier {}

    impl PcpDigestVerifier for RecordingVerifier {
        fn signing_identity(&self) -> &PcpSigningKeyIdentity {
            &self.identity
        }

        fn verify_digest(
            &mut self,
            _digest: &[u8; SIGNER_DIGEST_BYTES],
            _signature: &[u8; SIGNATURE_BYTES],
        ) -> Result<(), KeyProtectionBackendError> {
            self.called = true;
            Err(KeyProtectionBackendError)
        }
    }

    fn fake_signature(digest: &[u8; SIGNER_DIGEST_BYTES]) -> [u8; SIGNATURE_BYTES] {
        let mut first = Sha256::new();
        first.update(b"fake-pcp-signature-r\0");
        first.update(FAKE_SIGN_KEY);
        first.update(digest);
        let mut second = Sha256::new();
        second.update(b"fake-pcp-signature-s\0");
        second.update(FAKE_SIGN_KEY);
        second.update(digest);
        let mut signature = [0_u8; SIGNATURE_BYTES];
        signature[..32].copy_from_slice(&first.finalize());
        signature[32..].copy_from_slice(&second.finalize());
        // The fake backend follows the production low-S P1363 contract. Clearing
        // these high bits is sufficient for a deterministic test double; this is
        // not intended to model real ECDSA arithmetic.
        signature[0] &= 0x7f;
        signature[32] &= 0x3f;
        if is_zero(&signature[..32]) {
            signature[31] = 1;
        }
        if is_zero(&signature[32..]) {
            signature[63] = 1;
        }
        signature
    }

    fn seal_fixture() -> Result<(PendingDeviceKeyBundle, SignedKeyBundleEnvelope), KeyMaterialError>
    {
        let bundle = PendingDeviceKeyBundle::generate_initial()?;
        let envelope = seal_pending(&bundle)?;
        Ok((bundle, envelope))
    }

    fn seal_pending(
        bundle: &PendingDeviceKeyBundle,
    ) -> Result<SignedKeyBundleEnvelope, KeyMaterialError> {
        let mut wrapper = FakeWrapper {
            identity: wrapping_identity()?,
            wrong_length: false,
        };
        let mut signer = FakeSigner {
            identity: signing_identity()?,
        };
        bundle.seal(&mut wrapper, &mut signer)
    }

    fn verified_anchor_for(
        envelope: &SignedKeyBundleEnvelope,
        anchor_generation: u64,
    ) -> Result<VerifiedKeyBundleAnchor, KeyMaterialError> {
        VerifiedKeyBundleAnchor::new_bootstrap_for_test(
            envelope.anchor_commitment()?,
            anchor_generation,
        )
    }

    fn verified_rotation_anchor_for(
        previous: &SignedKeyBundleEnvelope,
        envelope: &SignedKeyBundleEnvelope,
        anchor_generation: u64,
    ) -> Result<VerifiedKeyBundleAnchor, KeyMaterialError> {
        VerifiedKeyBundleAnchor::new_rotation_for_test(
            previous.anchor_commitment()?,
            envelope.anchor_commitment()?,
            anchor_generation,
        )
    }

    fn open_fixture(
        envelope: &SignedKeyBundleEnvelope,
    ) -> Result<DeviceKeyBundle, KeyMaterialError> {
        let anchor = verified_anchor_for(envelope, 1)?;
        open_with_anchor(envelope, &anchor)
    }

    fn open_with_anchor(
        envelope: &SignedKeyBundleEnvelope,
        anchor: &VerifiedKeyBundleAnchor,
    ) -> Result<DeviceKeyBundle, KeyMaterialError> {
        let mut unwrapper = FakeUnwrapper {
            identity: wrapping_identity()?,
            wrong_key: false,
        };
        let mut verifier = FakeVerifier {
            identity: signing_identity()?,
        };
        envelope.open_anchored(anchor, &mut unwrapper, &mut verifier)
    }

    fn committed_state_for(
        envelope: &SignedKeyBundleEnvelope,
        anchor_generation: u64,
    ) -> Result<KeyBundleAnchorState, KeyMaterialError> {
        let mut state = KeyBundleAnchorState::empty();
        state.stage_bootstrap(envelope.anchor_commitment()?)?;
        state.accept_verified(verified_anchor_for(envelope, anchor_generation)?)?;
        Ok(state)
    }

    fn assert_anchor_mismatch_before_pcp(
        envelope: &SignedKeyBundleEnvelope,
        anchor: &VerifiedKeyBundleAnchor,
    ) -> Result<(), KeyMaterialError> {
        let mut unwrapper = RecordingUnwrapper {
            identity: wrapping_identity()?,
            called: false,
        };
        let mut verifier = RecordingVerifier {
            identity: signing_identity()?,
            called: false,
        };
        assert_eq!(
            envelope
                .open_anchored(anchor, &mut unwrapper, &mut verifier)
                .err(),
            Some(KeyMaterialError::AnchorMismatch)
        );
        assert!(!verifier.called);
        assert!(!unwrapper.called);
        Ok(())
    }

    #[test]
    fn generated_bundle_is_distinct_canonical_and_zeroizing() -> Result<(), KeyMaterialError> {
        let first = PendingDeviceKeyBundle::generate_initial()?;
        let second = PendingDeviceKeyBundle::generate_initial()?;
        assert!(mem::needs_drop::<DeviceKeyBundle>());
        assert!(mem::needs_drop::<PendingDeviceKeyBundle>());
        assert!(valid_material(&first.bundle.material));
        assert!(valid_material(&second.bundle.material));
        assert!(!ct_equal(first.encode().as_ref(), second.encode().as_ref()));
        assert_eq!(first.encode().len(), BUNDLE_BYTES);
        let decoded = DeviceKeyBundle::decode(first.encode().as_ref())?;
        assert!(ct_equal(first.encode().as_ref(), decoded.encode().as_ref()));
        assert_eq!(decoded.key_epoch, INITIAL_KEY_EPOCH);
        assert_eq!(
            format!("{decoded:?}"),
            "DeviceKeyBundle([REDACTED KEY MATERIAL])"
        );
        assert_eq!(
            format!("{first:?}"),
            "PendingDeviceKeyBundle([REDACTED KEY MATERIAL])"
        );
        Ok(())
    }

    #[test]
    fn bundle_codec_rejects_zero_equal_wrong_version_truncation_and_trailing()
    -> Result<(), KeyMaterialError> {
        let bundle = PendingDeviceKeyBundle::generate_initial()?;
        let canonical = bundle.encode();

        let mut zero = Zeroizing::new(*canonical);
        zero[BUNDLE_HEADER_BYTES..BUNDLE_HEADER_BYTES + KEY_BYTES].zeroize();
        assert_eq!(
            DeviceKeyBundle::decode(zero.as_ref()).err(),
            Some(KeyMaterialError::InvalidBundle)
        );

        let mut equal = Zeroizing::new(*canonical);
        let first_key: [u8; KEY_BYTES] = equal
            [BUNDLE_HEADER_BYTES..BUNDLE_HEADER_BYTES + KEY_BYTES]
            .try_into()
            .map_err(|_| KeyMaterialError::InvalidBundle)?;
        equal[BUNDLE_HEADER_BYTES + KEY_BYTES..BUNDLE_HEADER_BYTES + (KEY_BYTES * 2)]
            .copy_from_slice(&first_key);
        assert_eq!(
            DeviceKeyBundle::decode(equal.as_ref()).err(),
            Some(KeyMaterialError::InvalidBundle)
        );

        let mut equal_to_installation = Zeroizing::new(*canonical);
        let installation: [u8; KEY_BYTES] = equal_to_installation[12..44]
            .try_into()
            .map_err(|_| KeyMaterialError::InvalidBundle)?;
        equal_to_installation[BUNDLE_HEADER_BYTES..BUNDLE_HEADER_BYTES + KEY_BYTES]
            .copy_from_slice(&installation);
        assert_eq!(
            DeviceKeyBundle::decode(equal_to_installation.as_ref()).err(),
            Some(KeyMaterialError::InvalidBundle)
        );

        let mut wrong_version = Zeroizing::new(*canonical);
        wrong_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            DeviceKeyBundle::decode(wrong_version.as_ref()).err(),
            Some(KeyMaterialError::InvalidBundle)
        );
        let mut wrong_magic = Zeroizing::new(*canonical);
        wrong_magic[0] ^= 1;
        assert_eq!(
            DeviceKeyBundle::decode(wrong_magic.as_ref()).err(),
            Some(KeyMaterialError::InvalidBundle)
        );
        let mut wrong_flags = Zeroizing::new(*canonical);
        wrong_flags[10..12].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            DeviceKeyBundle::decode(wrong_flags.as_ref()).err(),
            Some(KeyMaterialError::InvalidBundle)
        );
        let mut zero_installation = Zeroizing::new(*canonical);
        zero_installation[12..44].zeroize();
        assert_eq!(
            DeviceKeyBundle::decode(zero_installation.as_ref()).err(),
            Some(KeyMaterialError::InvalidBundle)
        );
        let mut zero_epoch = Zeroizing::new(*canonical);
        zero_epoch[44..52].zeroize();
        assert_eq!(
            DeviceKeyBundle::decode(zero_epoch.as_ref()).err(),
            Some(KeyMaterialError::InvalidBundle)
        );
        for length in 0..BUNDLE_BYTES {
            assert!(DeviceKeyBundle::decode(&canonical[..length]).is_err());
        }
        let mut trailing = Zeroizing::new(canonical.to_vec());
        trailing.push(0);
        assert!(DeviceKeyBundle::decode(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn envelope_round_trip_is_canonical_and_debug_redacted() -> Result<(), KeyMaterialError> {
        let (bundle, envelope) = seal_fixture()?;
        assert!(mem::needs_drop::<SignedKeyBundleEnvelope>());
        let encoded = envelope.encode()?;
        let parsed = SignedKeyBundleEnvelope::parse(&encoded)?;
        assert_eq!(parsed.encode()?, encoded);
        let opened = open_fixture(&parsed)?;
        assert!(ct_equal(bundle.encode().as_ref(), opened.encode().as_ref()));
        assert_eq!(
            format!("{parsed:?}"),
            "SignedKeyBundleEnvelope([REDACTED ENVELOPE])"
        );
        assert_eq!(
            format!("{:?}", wrapping_identity()?),
            "PcpWrappingKeyIdentity([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", signing_identity()?),
            "PcpSigningKeyIdentity([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn every_unknown_algorithm_id_is_rejected() -> Result<(), KeyMaterialError> {
        let (_, envelope) = seal_fixture()?;
        let canonical = envelope.encode()?;
        for offset in [16_usize, 18, 20, 22, 24, 26, 28, 30] {
            let mut altered = canonical.clone();
            altered[offset..offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
            assert_eq!(
                SignedKeyBundleEnvelope::parse(&altered).err(),
                Some(KeyMaterialError::UnsupportedAlgorithm)
            );
        }
        Ok(())
    }

    #[test]
    fn envelope_rejects_every_truncation_and_trailing_bytes() -> Result<(), KeyMaterialError> {
        let (_, envelope) = seal_fixture()?;
        let canonical = envelope.encode()?;
        for length in 0..canonical.len() {
            assert!(SignedKeyBundleEnvelope::parse(&canonical[..length]).is_err());
        }
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            SignedKeyBundleEnvelope::parse(&trailing).err(),
            Some(KeyMaterialError::InvalidEnvelope)
        );
        Ok(())
    }

    #[test]
    fn header_tamper_cannot_survive_both_signature_and_aead() -> Result<(), KeyMaterialError> {
        let (_, mut envelope) = seal_fixture()?;
        let previous_envelope = SignedKeyBundleEnvelope::parse(&envelope.encode()?)?;
        envelope.header.key_epoch = envelope
            .header
            .key_epoch
            .checked_add(1)
            .ok_or(KeyMaterialError::InvalidEnvelope)?;
        let aad = envelope.header.encode()?;
        envelope.signer_digest =
            signature_digest(&aad, &envelope.ciphertext_and_tag, &envelope.wrapped_kek)?;
        envelope.signature = fake_signature(&envelope.signer_digest);
        let anchor = verified_rotation_anchor_for(&previous_envelope, &envelope, 2)?;
        assert_eq!(
            open_with_anchor(&envelope, &anchor).err(),
            Some(KeyMaterialError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn ciphertext_digest_signature_identity_and_kek_tamper_fail_closed()
    -> Result<(), KeyMaterialError> {
        let (_, mut ciphertext_tamper) = seal_fixture()?;
        ciphertext_tamper.ciphertext_and_tag[0] ^= 1;
        assert_eq!(
            open_fixture(&ciphertext_tamper).err(),
            Some(KeyMaterialError::InvalidEnvelope)
        );

        let (_, mut signature_tamper) = seal_fixture()?;
        signature_tamper.signature[0] ^= 1;
        assert_eq!(
            open_fixture(&signature_tamper).err(),
            Some(KeyMaterialError::SignatureInvalid)
        );

        let (_, identity_tamper) = seal_fixture()?;
        let mut wrong_unwrapper = FakeUnwrapper {
            identity: PcpWrappingKeyIdentity::new("different-wrap-key".to_owned(), [0x44; 32])?,
            wrong_key: false,
        };
        let mut verifier = FakeVerifier {
            identity: signing_identity()?,
        };
        let anchor = verified_anchor_for(&identity_tamper, 1)?;
        assert_eq!(
            identity_tamper
                .open_anchored(&anchor, &mut wrong_unwrapper, &mut verifier)
                .err(),
            Some(KeyMaterialError::IdentityMismatch)
        );

        let (_, wrong_kek) = seal_fixture()?;
        let mut unwrapper = FakeUnwrapper {
            identity: wrapping_identity()?,
            wrong_key: true,
        };
        let mut verifier = FakeVerifier {
            identity: signing_identity()?,
        };
        let anchor = verified_anchor_for(&wrong_kek, 1)?;
        assert_eq!(
            wrong_kek
                .open_anchored(&anchor, &mut unwrapper, &mut verifier)
                .err(),
            Some(KeyMaterialError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn equal_or_malformed_pcp_identities_and_wrong_wrap_length_are_rejected()
    -> Result<(), KeyMaterialError> {
        assert!(PcpWrappingKeyIdentity::new(String::new(), WRAP_DIGEST).is_err());
        assert!(PcpWrappingKeyIdentity::new("bad/key".to_owned(), WRAP_DIGEST).is_err());
        assert!(PcpWrappingKeyIdentity::new("valid-key".to_owned(), [0; 32]).is_err());

        let bundle = PendingDeviceKeyBundle::generate_initial()?;
        let mut equal_wrapper = FakeWrapper {
            identity: PcpWrappingKeyIdentity::new(SIGN_IDENTIFIER.to_owned(), SIGN_DIGEST)?,
            wrong_length: false,
        };
        let mut signer = FakeSigner {
            identity: signing_identity()?,
        };
        assert_eq!(
            bundle.seal(&mut equal_wrapper, &mut signer).err(),
            Some(KeyMaterialError::InvalidEnvelope)
        );

        let mut wrong_length = FakeWrapper {
            identity: wrapping_identity()?,
            wrong_length: true,
        };
        let mut signer = FakeSigner {
            identity: signing_identity()?,
        };
        assert_eq!(
            bundle.seal(&mut wrong_length, &mut signer).err(),
            Some(KeyMaterialError::WrapFailed)
        );
        Ok(())
    }

    #[test]
    fn opened_bundle_exposes_only_distinct_role_typed_views() -> Result<(), KeyMaterialError> {
        let (_, envelope) = seal_fixture()?;
        let bundle = open_fixture(&envelope)?;
        let role_secrets = [
            bundle.anchor_registry_hmac_key().expose_secret(),
            bundle.storage_mac_root_key().expose_secret(),
            bundle.journal_aead_key().expose_secret(),
            bundle.local_settings_aead_key().expose_secret(),
            bundle.nonce_ledger_aead_key().expose_secret(),
            bundle.tpm_nv_auth_value().expose_secret(),
        ];

        for (index, secret) in role_secrets.iter().enumerate() {
            assert!(!is_zero(secret.as_slice()));
            assert!(!ct_equal(
                secret.as_slice(),
                &bundle.material[INSTALLATION_SLOT]
            ));
            for prior in &role_secrets[..index] {
                assert!(!ct_equal(secret.as_slice(), prior.as_slice()));
            }
        }
        assert_eq!(
            format!("{:?}", bundle.anchor_registry_hmac_key()),
            "AnchorRegistryHmacKey([REDACTED KEY MATERIAL])"
        );
        assert_eq!(
            format!("{:?}", bundle.tpm_nv_auth_value()),
            "TpmNvAuthValue([REDACTED KEY MATERIAL])"
        );
        Ok(())
    }

    #[test]
    fn rotation_preserves_installation_advances_once_and_rekeys_every_role()
    -> Result<(), KeyMaterialError> {
        let (_, initial_envelope) = seal_fixture()?;
        let initial = open_fixture(&initial_envelope)?;
        let rotation = initial.begin_rotation()?;

        assert_eq!(rotation.bundle.key_epoch, INITIAL_KEY_EPOCH + 1);
        assert!(ct_equal(
            &rotation.bundle.material[INSTALLATION_SLOT],
            &initial.material[INSTALLATION_SLOT]
        ));
        assert!(valid_material(&rotation.bundle.material));
        for rotated_slot in ANCHOR_REGISTRY_HMAC_SLOT..=TPM_NV_AUTH_SLOT {
            for previous_slot in INSTALLATION_SLOT..=TPM_NV_AUTH_SLOT {
                assert!(!ct_equal(
                    &rotation.bundle.material[rotated_slot],
                    &initial.material[previous_slot]
                ));
            }
        }

        let exhausted =
            DeviceKeyBundle::from_material(u64::MAX, Zeroizing::new(*initial.material))?;
        assert_eq!(
            exhausted.begin_rotation().err(),
            Some(KeyMaterialError::EpochExhausted)
        );
        Ok(())
    }

    #[test]
    fn canonical_spki_algorithm_and_provenance_ids_are_exact() -> Result<(), KeyMaterialError> {
        let (_, envelope) = seal_fixture()?;
        let encoded = envelope.encode()?;
        let u16_at = |offset: usize| u16::from_be_bytes([encoded[offset], encoded[offset + 1]]);

        assert_eq!(u16_at(16), XCHACHA20_POLY1305_V1_ALGORITHM_ID);
        assert_eq!(
            u16_at(18),
            RSA3072_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL_ALGORITHM_ID
        );
        assert_eq!(u16_at(20), ECDSA_P256_SHA256_P1363_ALGORITHM_ID);
        assert_eq!(u16_at(22), PCP_RSA3072_KEY_KIND_ID);
        assert_eq!(u16_at(24), PCP_ECDSA_P256_KEY_KIND_ID);
        assert_eq!(
            u16_at(26),
            WrappingPublicKeyEncodingId::RsaSpkiDerSha256V1 as u16
        );
        assert_eq!(
            u16_at(28),
            SigningPublicKeyEncodingId::P256SpkiDerSha256V1 as u16
        );
        assert_eq!(u16_at(30), MICROSOFT_PCP_TPM_NONEXPORTABLE_V1_PROVENANCE_ID);
        Ok(())
    }

    #[test]
    fn p256_p1363_scalar_boundaries_and_low_s_are_enforced() {
        let mut signature = [0_u8; SIGNATURE_BYTES];
        signature[31] = 1;
        signature[63] = 1;
        assert!(canonical_p256_p1363_signature(&signature));

        let mut zero_r = signature;
        zero_r[..32].zeroize();
        assert!(!canonical_p256_p1363_signature(&zero_r));

        let mut order_r = signature;
        order_r[..32].copy_from_slice(&P256_ORDER);
        assert!(!canonical_p256_p1363_signature(&order_r));

        let mut order_minus_one_r = signature;
        let mut order_minus_one = P256_ORDER;
        order_minus_one[31] -= 1;
        order_minus_one_r[..32].copy_from_slice(&order_minus_one);
        assert!(canonical_p256_p1363_signature(&order_minus_one_r));

        let mut zero_s = signature;
        zero_s[32..].zeroize();
        assert!(!canonical_p256_p1363_signature(&zero_s));

        let mut half_order_s = signature;
        half_order_s[32..].copy_from_slice(&P256_HALF_ORDER);
        assert!(canonical_p256_p1363_signature(&half_order_s));

        let mut high_s = signature;
        let mut half_order_plus_one = P256_HALF_ORDER;
        half_order_plus_one[31] += 1;
        high_s[32..].copy_from_slice(&half_order_plus_one);
        assert!(!canonical_p256_p1363_signature(&high_s));

        let mut order_s = signature;
        order_s[32..].copy_from_slice(&P256_ORDER);
        assert!(!canonical_p256_p1363_signature(&order_s));
    }

    #[test]
    fn parser_rejects_noncanonical_p256_signatures() -> Result<(), KeyMaterialError> {
        let (_, envelope) = seal_fixture()?;
        let canonical = envelope.encode()?;
        let signature_offset = canonical
            .len()
            .checked_sub(SIGNATURE_BYTES)
            .ok_or(KeyMaterialError::InvalidEnvelope)?;

        for invalid_signature in {
            let mut signatures = Vec::new();
            let mut zero_r = envelope.signature;
            zero_r[..32].zeroize();
            signatures.push(zero_r);
            let mut order_r = envelope.signature;
            order_r[..32].copy_from_slice(&P256_ORDER);
            signatures.push(order_r);
            let mut zero_s = envelope.signature;
            zero_s[32..].zeroize();
            signatures.push(zero_s);
            let mut high_s = envelope.signature;
            let mut half_order_plus_one = P256_HALF_ORDER;
            half_order_plus_one[31] += 1;
            high_s[32..].copy_from_slice(&half_order_plus_one);
            signatures.push(high_s);
            signatures
        } {
            let mut altered = canonical.clone();
            altered[signature_offset..].copy_from_slice(&invalid_signature);
            assert_eq!(
                SignedKeyBundleEnvelope::parse(&altered).err(),
                Some(KeyMaterialError::InvalidEnvelope)
            );
        }
        Ok(())
    }

    #[test]
    fn every_single_byte_envelope_mutation_fails_exact_anchor_open() -> Result<(), KeyMaterialError>
    {
        let (_, envelope) = seal_fixture()?;
        let anchor = verified_anchor_for(&envelope, 7)?;
        let canonical = envelope.encode()?;
        for index in 0..canonical.len() {
            let mut altered = canonical.clone();
            altered[index] ^= 1;
            if let Ok(parsed) = SignedKeyBundleEnvelope::parse(&altered) {
                assert_anchor_mismatch_before_pcp(&parsed, &anchor)?;
            }
        }
        Ok(())
    }

    #[test]
    fn anchor_digest_is_domain_separated_and_covers_the_complete_signed_envelope()
    -> Result<(), KeyMaterialError> {
        let (_, mut envelope) = seal_fixture()?;
        let original = envelope.anchor_commitment()?;
        let raw_digest: [u8; 32] = Sha256::digest(envelope.encode()?).into();
        assert!(!ct_equal(&original.envelope_digest, &raw_digest));

        envelope.signature[31] ^= 1;
        assert!(canonical_p256_p1363_signature(&envelope.signature));
        let signature_mutated = envelope.anchor_commitment()?;
        assert!(!ct_equal(
            &original.envelope_digest,
            &signature_mutated.envelope_digest
        ));
        Ok(())
    }

    #[test]
    fn stale_future_wrong_install_and_different_reseal_anchors_are_rejected_before_pcp()
    -> Result<(), KeyMaterialError> {
        let (initial_pending, initial_envelope) = seal_fixture()?;
        let initial = open_fixture(&initial_envelope)?;
        let rotation_pending = initial.begin_rotation()?;
        let rotated_envelope = seal_pending(&rotation_pending)?;
        let rotated_anchor =
            verified_rotation_anchor_for(&initial_envelope, &rotated_envelope, 11)?;
        let opened_rotation = open_with_anchor(&rotated_envelope, &rotated_anchor)?;
        assert!(ct_equal(
            rotation_pending.encode().as_ref(),
            opened_rotation.encode().as_ref()
        ));

        let stale_anchor = verified_anchor_for(&initial_envelope, 10)?;
        assert_anchor_mismatch_before_pcp(&rotated_envelope, &stale_anchor)?;

        let future_pending = opened_rotation.begin_rotation()?;
        let future_envelope = seal_pending(&future_pending)?;
        let future_anchor = verified_rotation_anchor_for(&rotated_envelope, &future_envelope, 15)?;
        assert_anchor_mismatch_before_pcp(&rotated_envelope, &future_anchor)?;

        let (_, different_install_envelope) = seal_fixture()?;
        let wrong_install_anchor = verified_anchor_for(&different_install_envelope, 10)?;
        assert_anchor_mismatch_before_pcp(&initial_envelope, &wrong_install_anchor)?;

        let different_reseal = seal_pending(&initial_pending)?;
        let different_reseal_anchor = verified_anchor_for(&different_reseal, 10)?;
        assert_anchor_mismatch_before_pcp(&initial_envelope, &different_reseal_anchor)?;
        Ok(())
    }

    #[test]
    fn pending_anchor_state_blocks_use_and_accepts_only_linked_commit_evidence()
    -> Result<(), KeyMaterialError> {
        let (_, initial_envelope) = seal_fixture()?;
        let mut state = KeyBundleAnchorState::empty();
        assert_eq!(
            state.current().err(),
            Some(KeyMaterialError::InvalidAnchorTransition)
        );
        state.stage_bootstrap(initial_envelope.anchor_commitment()?)?;
        assert_eq!(
            state.current().err(),
            Some(KeyMaterialError::InvalidAnchorTransition)
        );
        state.accept_verified(verified_anchor_for(&initial_envelope, 3)?)?;

        let initial = open_with_anchor(&initial_envelope, state.current()?)?;
        let rotation_pending = initial.begin_rotation()?;
        let rotated_envelope = seal_pending(&rotation_pending)?;
        state.stage_rotation(rotated_envelope.anchor_commitment()?)?;
        assert_eq!(
            state.current().err(),
            Some(KeyMaterialError::InvalidAnchorTransition)
        );
        state.accept_verified(verified_rotation_anchor_for(
            &initial_envelope,
            &rotated_envelope,
            9,
        )?)?;
        let opened = open_with_anchor(&rotated_envelope, state.current()?)?;
        assert!(ct_equal(
            rotation_pending.encode().as_ref(),
            opened.encode().as_ref()
        ));
        Ok(())
    }

    #[test]
    fn stale_generation_rollback_equivocation_and_ambiguous_commit_lock_state()
    -> Result<(), KeyMaterialError> {
        let (initial_pending, initial_envelope) = seal_fixture()?;
        let initial = open_fixture(&initial_envelope)?;
        let rotation_pending = initial.begin_rotation()?;
        let rotated_envelope = seal_pending(&rotation_pending)?;

        let mut stale_generation = committed_state_for(&initial_envelope, 8)?;
        stale_generation.stage_rotation(rotated_envelope.anchor_commitment()?)?;
        assert_eq!(
            stale_generation
                .accept_verified(verified_rotation_anchor_for(
                    &initial_envelope,
                    &rotated_envelope,
                    8,
                )?)
                .err(),
            Some(KeyMaterialError::AnchorMismatch)
        );
        assert_eq!(
            stale_generation.current().err(),
            Some(KeyMaterialError::AnchorLocked)
        );

        let alternate_initial_envelope = seal_pending(&initial_pending)?;
        let mut predecessor_equivocation = committed_state_for(&initial_envelope, 8)?;
        predecessor_equivocation.stage_rotation(rotated_envelope.anchor_commitment()?)?;
        let alternate_branch_evidence = VerifiedKeyBundleAnchor::new_rotation_for_test(
            alternate_initial_envelope.anchor_commitment()?,
            rotated_envelope.anchor_commitment()?,
            12,
        )?;
        assert_eq!(
            predecessor_equivocation
                .accept_verified(alternate_branch_evidence)
                .err(),
            Some(KeyMaterialError::AnchorMismatch)
        );
        assert_eq!(
            predecessor_equivocation.current().err(),
            Some(KeyMaterialError::AnchorLocked)
        );

        let alternate_rotated_envelope = seal_pending(&rotation_pending)?;
        let mut successor_equivocation = committed_state_for(&initial_envelope, 8)?;
        successor_equivocation.stage_rotation(rotated_envelope.anchor_commitment()?)?;
        assert_eq!(
            successor_equivocation
                .accept_verified(verified_rotation_anchor_for(
                    &initial_envelope,
                    &alternate_rotated_envelope,
                    12,
                )?)
                .err(),
            Some(KeyMaterialError::AnchorMismatch)
        );
        assert_eq!(
            successor_equivocation.current().err(),
            Some(KeyMaterialError::AnchorLocked)
        );

        let new_anchor = verified_rotation_anchor_for(&initial_envelope, &rotated_envelope, 12)?;
        assert_anchor_mismatch_before_pcp(&initial_envelope, &new_anchor)?;
        let old_anchor = verified_anchor_for(&initial_envelope, 8)?;
        assert_anchor_mismatch_before_pcp(&rotated_envelope, &old_anchor)?;

        let mut ambiguous = committed_state_for(&initial_envelope, 8)?;
        ambiguous.lock_ambiguous();
        assert_eq!(
            ambiguous.current().err(),
            Some(KeyMaterialError::AnchorLocked)
        );
        Ok(())
    }

    #[test]
    fn verified_anchor_evidence_rejects_unlinked_or_nonconsecutive_history()
    -> Result<(), KeyMaterialError> {
        let (_, initial_envelope) = seal_fixture()?;
        let initial = open_fixture(&initial_envelope)?;
        let rotation = initial.begin_rotation()?;
        let rotated_envelope = seal_pending(&rotation)?;

        assert_eq!(
            VerifiedKeyBundleAnchor::new_bootstrap_for_test(
                rotated_envelope.anchor_commitment()?,
                2,
            )
            .err(),
            Some(KeyMaterialError::InvalidAnchorTransition)
        );

        let (_, other_initial_envelope) = seal_fixture()?;
        assert_eq!(
            VerifiedKeyBundleAnchor::new_rotation_for_test(
                other_initial_envelope.anchor_commitment()?,
                rotated_envelope.anchor_commitment()?,
                2,
            )
            .err(),
            Some(KeyMaterialError::InvalidAnchorTransition)
        );
        Ok(())
    }

    #[test]
    fn fixed_slot_order_covers_every_independent_key_role() {
        assert_eq!(ANCHOR_REGISTRY_HMAC_SLOT, 1);
        assert_eq!(STORAGE_MAC_ROOT_SLOT, 2);
        assert_eq!(JOURNAL_AEAD_SLOT, 3);
        assert_eq!(SETTINGS_AEAD_SLOT, 4);
        assert_eq!(NONCE_AEAD_SLOT, 5);
        assert_eq!(TPM_NV_AUTH_SLOT, 6);
        assert_eq!(MATERIAL_SLOT_COUNT, 7);
    }
}
