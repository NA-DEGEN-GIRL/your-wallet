use core::fmt;
use core::str::FromStr;

use hmac::{Hmac, Mac};
use secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey, ecdsa::RecoverableSignature};
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, Zeroizing};

use crate::SecretError;

const HARDENED_OFFSET: u32 = 1 << 31;
const MAX_PATH_DEPTH: usize = 10;
const DEFAULT_PURPOSE: u32 = 0x002C | HARDENED_OFFSET;
const DEFAULT_COIN_TYPE: u32 = 0x003C | HARDENED_OFFSET;
const DEFAULT_ACCOUNT: u32 = HARDENED_OFFSET;
const DEFAULT_CHANGE: u32 = 0;
const BIP32_ROOT_KEY: &[u8] = b"Bitcoin seed";

type HmacSha512 = Hmac<Sha512>;

/// A non-hardened default derivation index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountIndex(u32);

impl AccountIndex {
    /// Creates a non-hardened account index.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidDerivationPath`] for a hardened value.
    pub const fn new(value: u32) -> Result<Self, SecretError> {
        if value < HARDENED_OFFSET {
            Ok(Self(value))
        } else {
            Err(SecretError::InvalidDerivationPath)
        }
    }

    /// Returns the raw non-hardened index.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// A strictly parsed absolute BIP-32 derivation path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    components: Vec<u32>,
}

impl DerivationPath {
    /// Constructs a path from encoded BIP-32 child numbers.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidDerivationPath`] when depth exceeds the
    /// frozen wallet maximum.
    pub fn new(components: Vec<u32>) -> Result<Self, SecretError> {
        if components.len() > MAX_PATH_DEPTH {
            return Err(SecretError::InvalidDerivationPath);
        }
        Ok(Self { components })
    }

    /// Constructs `m/44'/60'/0'/0/index` using the actual derived index.
    #[must_use]
    pub fn default_ethereum(index: AccountIndex) -> Self {
        Self {
            components: vec![
                DEFAULT_PURPOSE,
                DEFAULT_COIN_TYPE,
                DEFAULT_ACCOUNT,
                DEFAULT_CHANGE,
                index.value(),
            ],
        }
    }

    /// Returns encoded child numbers; bit 31 denotes hardened derivation.
    #[must_use]
    pub fn components(&self) -> &[u32] {
        &self.components
    }
}

impl FromStr for DerivationPath {
    type Err = SecretError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input == "m" {
            return Self::new(Vec::new());
        }
        let suffix = input
            .strip_prefix("m/")
            .ok_or(SecretError::InvalidDerivationPath)?;
        let components: Result<Vec<_>, _> = suffix.split('/').map(parse_path_component).collect();
        Self::new(components?)
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("m")?;
        for component in &self.components {
            let hardened = component & HARDENED_OFFSET != 0;
            let value = component & !HARDENED_OFFSET;
            if hardened {
                write!(formatter, "/{value}'")?;
            } else {
                write!(formatter, "/{value}")?;
            }
        }
        Ok(())
    }
}

/// An Ethereum address derived from an uncompressed secp256k1 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthereumAddress([u8; 20]);

impl fmt::Debug for EthereumAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EthereumAddress([REDACTED])")
    }
}

impl EthereumAddress {
    /// Constructs an address from canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Returns canonical 20-byte address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

/// A validated raw private key that is zeroized on drop.
pub struct RawPrivateKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RawPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawPrivateKey([REDACTED])")
    }
}

/// Scoped `secp256k1` key material that is best-effort erased even while
/// unwinding. Keeping this wrapper private prevents a reconstructed key from
/// escaping the operation that needs it.
struct EphemeralSecpSecret(SecretKey);

impl EphemeralSecpSecret {
    fn new(source: &RawPrivateKey) -> Result<Self, SecretError> {
        SecretKey::from_byte_array(*source.bytes)
            .map(Self)
            .map_err(|_| SecretError::InvalidPrivateKey)
    }

    const fn as_secret(&self) -> &SecretKey {
        &self.0
    }
}

impl Drop for EphemeralSecpSecret {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

impl RawPrivateKey {
    /// Strictly imports exactly 32 bytes and rejects zero/out-of-range scalars.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidPrivateKey`] unless input is exactly one
    /// valid `secp256k1` scalar.
    pub fn import(bytes: &[u8]) -> Result<Self, SecretError> {
        let mut bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SecretError::InvalidPrivateKey)?;
        let mut validation = SecretKey::from_byte_array(bytes).map_err(|_| {
            bytes.zeroize();
            SecretError::InvalidPrivateKey
        })?;
        validation.non_secure_erase();
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Computes the corresponding Ethereum address.
    ///
    /// # Errors
    ///
    /// Returns an error if the private-key invariant cannot be reconstructed.
    pub fn ethereum_address(&self) -> Result<EthereumAddress, SecretError> {
        let secret = EphemeralSecpSecret::new(self)?;
        let serialized = PublicKey::from_secret_key(&Secp256k1::new(), secret.as_secret())
            .serialize_uncompressed();
        let digest = Keccak256::digest(&serialized[1..]);
        let mut address = [0_u8; 20];
        address.copy_from_slice(&digest[12..]);
        Ok(EthereumAddress(address))
    }

    pub(crate) fn expose_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub(crate) fn sign_recoverable_prehash(
        &self,
        prehash: [u8; 32],
    ) -> Result<RecoverableSignature, SecretError> {
        let secret = EphemeralSecpSecret::new(self)?;
        Ok(Secp256k1::new()
            .sign_ecdsa_recoverable(Message::from_digest(prehash), secret.as_secret()))
    }
}

/// A derived account and its actual persisted path.
pub struct DerivedAccount {
    private_key: RawPrivateKey,
    address: EthereumAddress,
    path: DerivationPath,
    actual_index: AccountIndex,
}

impl fmt::Debug for DerivedAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedAccount")
            .field("private_key", &"[REDACTED]")
            .field("address", &self.address)
            .field("path", &self.path)
            .field("actual_index", &self.actual_index)
            .finish()
    }
}

impl DerivedAccount {
    /// Returns the derived address.
    #[must_use]
    pub const fn address(&self) -> EthereumAddress {
        self.address
    }

    /// Returns the actual path after invalid-child skipping.
    #[must_use]
    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    /// Returns the actual final index after invalid-child skipping.
    #[must_use]
    pub const fn actual_index(&self) -> AccountIndex {
        self.actual_index
    }

    /// Borrows the private key for key-agent-internal signing.
    #[must_use]
    pub const fn private_key(&self) -> &RawPrivateKey {
        &self.private_key
    }
}

pub(crate) struct ExtendedPrivateKey {
    secret: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
}

impl ExtendedPrivateKey {
    pub(crate) fn from_seed(seed: &[u8]) -> Result<Self, SecretError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(SecretError::InvalidMnemonic);
        }
        let mut output = hmac_sha512(BIP32_ROOT_KEY, seed)?;
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(&output[..32]);
        let mut validation = SecretKey::from_byte_array(secret).map_err(|_| {
            secret.zeroize();
            SecretError::CryptographicFailure
        })?;
        validation.non_secure_erase();
        let mut chain_code = [0_u8; 32];
        chain_code.copy_from_slice(&output[32..]);
        output.zeroize();
        Ok(Self {
            secret: Zeroizing::new(secret),
            chain_code: Zeroizing::new(chain_code),
        })
    }

    pub(crate) fn derive_default_ethereum_account(
        &self,
        requested: AccountIndex,
    ) -> Result<DerivedAccount, SecretError> {
        let (purpose, current) = self.derive_next_valid_child(DEFAULT_PURPOSE)?;
        let (coin_type, current) = current.derive_next_valid_child(DEFAULT_COIN_TYPE)?;
        let (account, current) = current.derive_next_valid_child(DEFAULT_ACCOUNT)?;
        let (change, current) = current.derive_next_valid_child(DEFAULT_CHANGE)?;

        let (actual_index, derived) = find_next_valid_child(requested, |candidate| {
            current.derive_child(candidate.value())
        })?;
        let private_key = RawPrivateKey::import(derived.secret.as_slice())?;
        let address = private_key.ethereum_address()?;
        let path = DerivationPath::new(vec![
            purpose,
            coin_type,
            account,
            change,
            actual_index.value(),
        ])?;
        Ok(DerivedAccount {
            private_key,
            address,
            path,
            actual_index,
        })
    }

    fn derive_next_valid_child(&self, requested: u32) -> Result<(u32, Self), SecretError> {
        let requested_hardened = requested & HARDENED_OFFSET != 0;
        let mut candidate = requested;
        loop {
            if let Some(child) = self.derive_child(candidate)? {
                return Ok((candidate, child));
            }
            candidate = candidate
                .checked_add(1)
                .filter(|next| (*next & HARDENED_OFFSET != 0) == requested_hardened)
                .ok_or(SecretError::DerivationExhausted)?;
        }
    }

    fn derive_child(&self, child_number: u32) -> Result<Option<Self>, SecretError> {
        let mut data = Zeroizing::new(Vec::with_capacity(37));
        if child_number & HARDENED_OFFSET != 0 {
            data.push(0);
            data.extend_from_slice(self.secret.as_slice());
        } else {
            let mut parent_secret = SecretKey::from_byte_array(*self.secret)
                .map_err(|_| SecretError::CryptographicFailure)?;
            let public = PublicKey::from_secret_key(&Secp256k1::new(), &parent_secret);
            parent_secret.non_secure_erase();
            data.extend_from_slice(&public.serialize());
        }
        data.extend_from_slice(&child_number.to_be_bytes());

        let mut output = hmac_sha512(self.chain_code.as_slice(), data.as_slice())?;
        let mut left = [0_u8; 32];
        left.copy_from_slice(&output[..32]);
        if left == [0_u8; 32] {
            output.zeroize();
            return Ok(None);
        }
        let Ok(mut scalar) = Scalar::from_be_bytes(left) else {
            left.zeroize();
            output.zeroize();
            return Ok(None);
        };
        left.zeroize();

        let mut parent_secret = SecretKey::from_byte_array(*self.secret)
            .map_err(|_| SecretError::CryptographicFailure)?;
        let child_result = parent_secret.add_tweak(&scalar);
        parent_secret.non_secure_erase();
        scalar.non_secure_erase();
        let Ok(mut child_secret) = child_result else {
            output.zeroize();
            return Ok(None);
        };
        let child_bytes = child_secret.secret_bytes();
        child_secret.non_secure_erase();
        let mut chain_code = [0_u8; 32];
        chain_code.copy_from_slice(&output[32..]);
        output.zeroize();
        Ok(Some(Self {
            secret: Zeroizing::new(child_bytes),
            chain_code: Zeroizing::new(chain_code),
        }))
    }
}

fn parse_path_component(component: &str) -> Result<u32, SecretError> {
    if component.is_empty() {
        return Err(SecretError::InvalidDerivationPath);
    }
    let (digits, hardened) = component
        .strip_suffix('\'')
        .map_or((component, false), |digits| (digits, true));
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(SecretError::InvalidDerivationPath);
    }
    let value = digits
        .parse::<u32>()
        .map_err(|_| SecretError::InvalidDerivationPath)?;
    if value >= HARDENED_OFFSET {
        return Err(SecretError::InvalidDerivationPath);
    }
    Ok(if hardened {
        value | HARDENED_OFFSET
    } else {
        value
    })
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64], SecretError> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| SecretError::CryptographicFailure)?;
    mac.update(data);
    let mut bytes = mac.finalize().into_bytes();
    let mut output = [0_u8; 64];
    output.copy_from_slice(bytes.as_slice());
    bytes.zeroize();
    Ok(output)
}

fn find_next_valid_child<F>(
    requested: AccountIndex,
    mut derive: F,
) -> Result<(AccountIndex, ExtendedPrivateKey), SecretError>
where
    F: FnMut(AccountIndex) -> Result<Option<ExtendedPrivateKey>, SecretError>,
{
    let mut value = requested.value();
    loop {
        let candidate = AccountIndex(value);
        if let Some(child) = derive(candidate)? {
            return Ok((candidate, child));
        }
        value = value
            .checked_add(1)
            .filter(|next| *next < HARDENED_OFFSET)
            .ok_or(SecretError::DerivationExhausted)?;
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    use super::{
        AccountIndex, DerivationPath, ExtendedPrivateKey, RawPrivateKey, find_next_valid_child,
    };
    use crate::SecretError;

    #[test]
    fn strict_path_parser_round_trips() -> Result<(), SecretError> {
        let path = DerivationPath::from_str("m/44'/60'/0'/0/12")?;
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/12");
        assert_eq!(path.components().len(), 5);
        Ok(())
    }

    #[test]
    fn strict_path_parser_rejects_ambiguous_forms() {
        for invalid in [
            "",
            "M/44'/60'",
            "m//0",
            "m/01",
            "m/+1",
            "m/1h",
            "m/2147483648",
            " m/0",
            "m/0 ",
        ] {
            assert!(DerivationPath::from_str(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn raw_key_address_derivation_is_deterministic() -> Result<(), SecretError> {
        let key = RawPrivateKey::import(&[7_u8; 32])?;
        let first = key.ethereum_address()?;
        let second = key.ethereum_address()?;
        assert_eq!(first, second);
        assert_ne!(first.as_bytes(), &[0_u8; 20]);
        Ok(())
    }

    #[test]
    fn raw_key_validation_rejects_wrong_length_and_zero() {
        assert!(RawPrivateKey::import(&[1_u8; 31]).is_err());
        assert!(RawPrivateKey::import(&[0_u8; 32]).is_err());
    }

    #[test]
    fn invalid_child_search_persists_actual_index() -> Result<(), SecretError> {
        let root = ExtendedPrivateKey::from_seed(&[17_u8; 32])?;
        let requested = AccountIndex::new(9)?;
        let mut first = true;
        let (actual, _) = find_next_valid_child(requested, |index| {
            if first {
                first = false;
                Ok(None)
            } else {
                root.derive_child(index.value())
            }
        })?;
        assert_eq!(actual.value(), 10);
        Ok(())
    }

    #[test]
    fn official_bip32_vector_one_matches_public_derivation() -> Result<(), SecretError> {
        // BIP-32 test vector 1 uses the 16 bytes 0x00 through 0x0f. Comparing
        // public keys exercises the standard without committing private-key
        // fixtures to the repository.
        let seed: Vec<u8> = (0_u8..=15).collect();
        let master = ExtendedPrivateKey::from_seed(&seed)?;
        assert_eq!(
            compressed_public_hex(&master)?,
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );

        let child = master
            .derive_child(0x8000_0000)?
            .ok_or(SecretError::CryptographicFailure)?;
        assert_eq!(
            compressed_public_hex(&child)?,
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
        );
        Ok(())
    }

    fn compressed_public_hex(key: &ExtendedPrivateKey) -> Result<String, SecretError> {
        let secret = SecretKey::from_byte_array(*key.secret)
            .map_err(|_| SecretError::CryptographicFailure)?;
        Ok(PublicKey::from_secret_key(&Secp256k1::new(), &secret).to_string())
    }
}
