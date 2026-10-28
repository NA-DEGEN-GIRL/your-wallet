//! Bitcoin WIF (wallet import format, spec/02 §8.4): `Base58Check(version ‖ secret[32] ‖ 01?)`.
//!
//! Version `0x80` is mainnet, `0xef` the test networks (this wallet maps it to testnet4). The
//! optional `0x01` suffix marks a key whose public key is used compressed. The decoded secret
//! lives only in `Zeroizing` buffers; errors carry no input.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::SecretKey;
use zeroize::Zeroizing;

use super::base58::{decode_check_secret, encode_check_into, max_encoded_len};
use crate::btc::network::BtcNetwork;
use crate::error::KeyError;
use crate::secret::SecretString;

/// WIF version byte of mainnet keys.
pub const WIF_MAINNET: u8 = 0x80;
/// WIF version byte of test-network keys (testnet3/testnet4/signet/regtest share it).
pub const WIF_TESTNET: u8 = 0xef;
/// Text length of an uncompressed WIF (33-byte payload + checksum).
pub const WIF_UNCOMPRESSED_LEN: usize = 51;
/// Text length of a compressed WIF (34-byte payload + checksum).
pub const WIF_COMPRESSED_LEN: usize = 52;

/// A decoded WIF key. The secret is a valid secp256k1 scalar.
pub struct WifKey {
    secret: Zeroizing<[u8; 32]>,
    compressed: bool,
    network: BtcNetwork,
}

impl fmt::Debug for WifKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WifKey([REDACTED])")
    }
}

impl WifKey {
    /// The 32-byte secret (crate-internal: only the vault stores it).
    pub(crate) const fn secret(&self) -> &Zeroizing<[u8; 32]> {
        &self.secret
    }

    /// Whether the public key is used compressed (`0x01` suffix).
    #[must_use]
    pub const fn compressed(&self) -> bool {
        self.compressed
    }

    /// The network of the version byte (`0xef` → testnet4).
    #[must_use]
    pub const fn network(&self) -> BtcNetwork {
        self.network
    }
}

fn valid_scalar(secret: &[u8; 32]) -> bool {
    SecretKey::from_byte_array(*secret).is_ok_and(|mut key| {
        key.non_secure_erase();
        true
    })
}

/// Parses WIF text: surrounding ASCII whitespace is ignored, everything else must be ASCII
/// base58 of exactly 51 (uncompressed) or 52 (compressed) characters with a valid checksum, a
/// known version byte, a `0x01` compression marker when 34 bytes long, and a scalar in [1, n−1].
///
/// # Errors
///
/// [`KeyError::WifFormat`] for any violation (the input is never echoed).
pub fn parse_wif(text: &str) -> Result<WifKey, KeyError> {
    let text = text.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if !text.is_ascii() || !matches!(text.len(), WIF_UNCOMPRESSED_LEN | WIF_COMPRESSED_LEN) {
        return Err(KeyError::WifFormat);
    }
    let payload = decode_check_secret(text).map_err(|_| KeyError::WifFormat)?;
    let (version, rest) = payload.split_first().ok_or(KeyError::WifFormat)?;
    let network = match *version {
        WIF_MAINNET => BtcNetwork::Mainnet,
        WIF_TESTNET => BtcNetwork::Testnet4,
        _ => return Err(KeyError::WifFormat),
    };
    let (body, compressed) = match rest.len() {
        32 => (rest, false),
        33 => match rest.split_last() {
            Some((0x01, body)) => (body, true),
            _ => return Err(KeyError::WifFormat),
        },
        _ => return Err(KeyError::WifFormat),
    };
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret.copy_from_slice(body);
    if !valid_scalar(&secret) {
        return Err(KeyError::WifFormat);
    }
    Ok(WifKey {
        secret,
        compressed,
        network,
    })
}

/// Encodes a secret as WIF (reveal of an imported Bitcoin key, spec/02 §9).
pub(crate) fn encode_wif(secret: &[u8; 32], compressed: bool, network: BtcNetwork) -> SecretString {
    let version = match network {
        BtcNetwork::Mainnet => WIF_MAINNET,
        BtcNetwork::Testnet4 => WIF_TESTNET,
    };
    let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(34));
    payload.push(version);
    payload.extend_from_slice(secret);
    if compressed {
        payload.push(0x01);
    }
    let mut out = Zeroizing::new(String::with_capacity(max_encoded_len(38)));
    encode_check_into(&payload, &mut out);
    SecretString::from_zeroizing(out)
}

/// Test access to [`encode_wif`] (vectors only).
#[cfg(test)]
pub(crate) fn encode_wif_for_tests(
    secret: &[u8; 32],
    compressed: bool,
    network: BtcNetwork,
) -> String {
    encode_wif(secret, compressed, network).expose().to_owned()
}
