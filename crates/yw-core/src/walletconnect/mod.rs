//! `WalletConnect` v2 (Reown) wallet-side primitives (spec/13): the pairing URI (EIP-1328 v2),
//! the typed envelopes (type 0/1, `ChaCha20-Poly1305`), the X25519 + HKDF-SHA256 session key
//! agreement with `topic = sha256(symKey)`, and the relay client-auth did-JWT (Ed25519
//! `did:key`).
//!
//! Sources (2026-11-06): `WalletConnect/walletconnect-specs` `clients/core/pairing/pairing-uri.md`,
//! `clients/core/crypto/crypto-envelopes.md`, `crypto-keys.md`, `crypto-authentication.md`,
//! `clients/core/relay/relay-client-auth.md`, and the reference implementation
//! `walletconnect-monorepo` `packages/utils/src/crypto.ts` (`deriveSymKey`: `hkdf(sha256,
//! shared, undefined, undefined, 32)`, `hashKey`, `serialize`/`deserialize` base64-pad).
//!
//! No network, clock or threads: yw-app supplies times and randomness-derived keys and does I/O.
#![deny(clippy::indexing_slicing)]

pub mod crypto;
pub mod jwt;
pub mod uri;

#[cfg(test)]
mod tests;

pub use crypto::{
    Envelope, KEY_LEN, X25519Secret, derive_sym_key, open_envelope, seal_envelope, topic_of,
};
pub use jwt::{base64url_decode, base64url_encode, did_key, relay_auth_jwt};
pub use uri::{PairingUri, UriError, parse_pairing_uri};

/// The relay protocol the wallet speaks (`relay-protocol=irn`).
pub const RELAY_PROTOCOL: &str = "irn";
/// The default relay URL (`RELAYER_DEFAULT_RELAY_URL`), also the JWT `aud`.
pub const RELAY_URL: &str = "wss://relay.walletconnect.org";
