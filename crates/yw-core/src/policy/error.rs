//! Provider error codes and messages (spec/05 §5, canonical per D31).
//!
//! The fixed codes and wording follow `archive/spec-v2.4:crates/wallet-protocol/src/error.rs:5-178`
//! (4001/4100/4200/-32602/-32603 mapping with fixed phrases) extended with the v3 rows. Errors
//! made by yw-app carry no `data`; only [`ProviderError::Upstream`] (sanitized read errors,
//! spec/05 §3.5) may.
//!
//! An `eth_sendTransaction` refused before any window says which rule it broke
//! ([`ProviderError::InvalidTxParams`], 2026-11-11): every message is a compiled-in ASCII string
//! that names a field or a rule and never a value from the request.

macro_rules! unsupported_tx_keys {
    ($($variant:ident = $key:literal),* $(,)?) => {
        /// A known Ethereum transaction key this wallet does not accept (spec/03 §3.2). Its name
        /// is compiled in, so a -32602 may quote it; any other unknown key is
        /// [`TxRule::UnknownKey`] and is never echoed.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum UnsupportedTxKey {
            $(
                #[doc = concat!("`", $key, "`")]
                $variant,
            )*
        }

        impl UnsupportedTxKey {
            /// The key named exactly `key` (case-sensitive), if it is one of the known keys.
            #[must_use]
            pub fn parse(key: &str) -> Option<Self> {
                match key {
                    $($key => Some(Self::$variant),)*
                    _ => None,
                }
            }

            /// The JSON key.
            #[must_use]
            pub const fn key(self) -> &'static str {
                match self {
                    $(Self::$variant => $key,)*
                }
            }

            const fn rule(self) -> &'static str {
                match self {
                    $(Self::$variant => concat!("key_", $key),)*
                }
            }

            const fn message(self) -> &'static str {
                match self {
                    $(Self::$variant => concat!("Invalid params: unsupported key \"", $key, "\"."),)*
                }
            }

            #[cfg(test)]
            const ALL: &'static [Self] = &[$(Self::$variant),*];
        }
    };
}

unsupported_tx_keys![
    AuthorizationList = "authorizationList",
    BlobVersionedHashes = "blobVersionedHashes",
    Blobs = "blobs",
    MaxFeePerBlobGas = "maxFeePerBlobGas",
    Sidecars = "sidecars",
    Commitments = "commitments",
    Proofs = "proofs",
    Kzg = "kzg",
    CustomData = "customData",
    CcipReadEnabled = "ccipReadEnabled",
    EnableCcipRead = "enableCcipRead",
    BlockTag = "blockTag",
    FeeCurrency = "feeCurrency",
    Paymaster = "paymaster",
    PaymasterInput = "paymasterInput",
    GasPerPubdata = "gasPerPubdata",
    FactoryDeps = "factoryDeps",
    CustomSignature = "customSignature",
    SourceHash = "sourceHash",
    Mint = "mint",
    IsSystemTx = "isSystemTx",
    Hash = "hash",
    V = "v",
    R = "r",
    S = "s",
    YParity = "yParity",
];

/// A member of an `eth_sendTransaction` object whose value has the wrong form (spec/03 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxField {
    /// `from` (address).
    From,
    /// `to` (address).
    To,
    /// `value` (quantity).
    Value,
    /// `data` (hex bytes).
    Data,
    /// `input` (hex bytes).
    Input,
    /// `gas` (quantity).
    Gas,
    /// `gasLimit` (quantity, alias of `gas`).
    GasLimit,
    /// `gasPrice` (quantity).
    GasPrice,
    /// `maxFeePerGas` (quantity).
    MaxFeePerGas,
    /// `maxPriorityFeePerGas` (quantity).
    MaxPriorityFeePerGas,
    /// `nonce` (u64 quantity).
    Nonce,
    /// `type` (quantity).
    Type,
    /// `chainId` (u64 quantity or JSON integer).
    ChainId,
    /// `accessList`.
    AccessList,
}

impl TxField {
    const fn rule(self) -> &'static str {
        match self {
            Self::From => "bad_from",
            Self::To => "bad_to",
            Self::Value => "bad_value",
            Self::Data => "bad_data",
            Self::Input => "bad_input",
            Self::Gas => "bad_gas",
            Self::GasLimit => "bad_gasLimit",
            Self::GasPrice => "bad_gasPrice",
            Self::MaxFeePerGas => "bad_maxFeePerGas",
            Self::MaxPriorityFeePerGas => "bad_maxPriorityFeePerGas",
            Self::Nonce => "bad_nonce",
            Self::Type => "bad_type",
            Self::ChainId => "bad_chainId",
            Self::AccessList => "bad_accessList",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::From => {
                "Invalid params: \"from\" is not a valid address (0x + 40 hex; mixed case must be EIP-55)."
            }
            Self::To => {
                "Invalid params: \"to\" is not a valid address (0x + 40 hex; mixed case must be EIP-55)."
            }
            Self::Value => "Invalid params: \"value\" is not a hex quantity.",
            Self::Data => "Invalid params: \"data\" is not hex bytes.",
            Self::Input => "Invalid params: \"input\" is not hex bytes.",
            Self::Gas => "Invalid params: \"gas\" is not a hex quantity.",
            Self::GasLimit => "Invalid params: \"gasLimit\" is not a hex quantity.",
            Self::GasPrice => "Invalid params: \"gasPrice\" is not a hex quantity.",
            Self::MaxFeePerGas => "Invalid params: \"maxFeePerGas\" is not a hex quantity.",
            Self::MaxPriorityFeePerGas => {
                "Invalid params: \"maxPriorityFeePerGas\" is not a hex quantity."
            }
            Self::Nonce => "Invalid params: \"nonce\" is not a 64-bit hex quantity.",
            Self::Type => "Invalid params: \"type\" is not a hex quantity.",
            Self::ChainId => "Invalid params: \"chainId\" is not a 64-bit hex quantity or integer.",
            Self::AccessList => {
                "Invalid params: \"accessList\" is not a valid access list (at most 256 entries of exactly {address, storageKeys}, at most 256 keys each, no repeated address)."
            }
        }
    }
}

/// The rule an `eth_sendTransaction` object broke before any window (spec/03 §3.2, spec/05 §5,
/// 2026-11-11). Each rule has a fixed log word ([`TxRule::id`]) and a fixed ASCII message of at
/// most 256 characters; neither ever carries a value from the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRule {
    /// `params` is not exactly one transaction object.
    Shape,
    /// A key outside spec/03 §3.2 that is not a known one (never named).
    UnknownKey,
    /// A known Ethereum transaction key this wallet does not accept (named).
    UnsupportedKey(UnsupportedTxKey),
    /// A member with the wrong form.
    Invalid(TxField),
    /// `from` is missing.
    FromRequired,
    /// `to` is missing.
    ToRequired,
    /// `to` is `null` (contract deployment, D19).
    ToNull,
    /// `type` other than 0 or 2 (D19).
    Type,
    /// `gas`/`gasLimit` above 16,777,216 (D20).
    GasCap,
    /// `gas` and `gasLimit` are both present with different values.
    GasLimitDiffers,
    /// `data` and `input` are both present with different bytes.
    DataInputDiffer,
    /// `data`/`input` longer than 131,072 bytes.
    DataTooLarge,
    /// `chainId` is not the site's chain (D17).
    ChainId,
    /// `nonce` is not the account's next nonce (spec/03 §3.6–§3.7 step 4).
    Nonce,
}

impl TxRule {
    /// The log word of this rule (a static identifier, no values).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Shape => "shape",
            Self::UnknownKey => "unknown_key",
            Self::UnsupportedKey(key) => key.rule(),
            Self::Invalid(field) => field.rule(),
            Self::FromRequired => "from_required",
            Self::ToRequired => "to_required",
            Self::ToNull => "to_null",
            Self::Type => "type",
            Self::GasCap => "gas_cap",
            Self::GasLimitDiffers => "gas_limit_differs",
            Self::DataInputDiffer => "data_input_differ",
            Self::DataTooLarge => "data_too_large",
            Self::ChainId => "chain_id",
            Self::Nonce => "nonce",
        }
    }

    /// The exact dApp-facing message.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Shape => "Invalid params: expected exactly one transaction object.",
            Self::UnknownKey => "Invalid params: unsupported transaction key.",
            Self::UnsupportedKey(key) => key.message(),
            Self::Invalid(field) => field.message(),
            Self::FromRequired => "Invalid params: \"from\" is required.",
            Self::ToRequired => "Invalid params: \"to\" is required.",
            Self::ToNull => {
                "Invalid params: \"to\" must not be null (contract deployment is not supported)."
            }
            Self::Type => "Invalid params: transaction type is not supported (only 0 and 2).",
            Self::GasCap => "Invalid params: gas exceeds 16777216.",
            Self::GasLimitDiffers => "Invalid params: \"gas\" and \"gasLimit\" differ.",
            Self::DataInputDiffer => "Invalid params: \"data\" and \"input\" differ.",
            Self::DataTooLarge => "Invalid params: transaction data exceeds 131072 bytes.",
            Self::ChainId => "Invalid params: chainId does not match the site's network.",
            Self::Nonce => "Invalid params: nonce does not match the account's next nonce.",
        }
    }
}

/// A dApp-facing error (spec/05 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderError {
    /// 4001 `User rejected the request.`
    UserRejected,
    /// 4001 `Request expired.`
    Expired,
    /// 4100 `Unauthorized.`
    Unauthorized,
    /// 4100 with the reason: the wallet was opened with a BIP39 passphrase that failed its check
    /// value (`Unlocked { alt_passphrase: true }`, spec/02 §7.5). Connect and signing requests
    /// are refused; reads continue.
    PassphraseUnverified,
    /// 4100 with the reason: the wallet has no EVM account (a key-only wallet started from a
    /// Solana or Bitcoin key, spec/02 §8.5). Connect is refused until an EVM key is imported.
    NoEvmAccount,
    /// 4100 with the reason: no Solana account to connect (spec/05 §4.9).
    NoSolAccount,
    /// 4100 with the reason: no Bitcoin account of a requested kind on the settings network
    /// (spec/05 §4.9); the message names the address types of each purpose.
    NoBtcAccount,
    /// 4100 with the reason: Bitcoin is turned off in the app's settings (spec/05 §3.6, §4.9).
    BtcDisabled,
    /// 4100 with the reason: the signing account's recovery phrase has no confirmed backup, so
    /// the vault would refuse its key (spec/02 §8.6, spec/05 §4.5).
    BackupUnconfirmed,
    /// 4100 with the reason: a new Solana/Bitcoin connection would exceed the 256 grants of that
    /// chain (meta `sol_sites`/`btc_sites`, spec/05 §4.9).
    TooManySites,
    /// 4200 `Unsupported method.`
    UnsupportedMethod,
    /// 4900 `Wallet is unavailable.`
    Unavailable,
    /// 4900 `Wallet connection closed.`
    ConnectionClosed,
    /// 4900 `Wallet extension was reloaded.`
    ExtensionReloaded,
    /// 4901 `Chain RPC is unavailable.`
    ChainUnavailable,
    /// 4902 `Unrecognized chain.`
    UnrecognizedChain,
    /// -32002 `Request already pending.`
    RequestPending,
    /// -32002 `Transaction already pending.`
    TransactionPending,
    /// -32005 `Rate limit exceeded.`
    RateLimited,
    /// -32005 `Too many pending requests.`
    TooManyPending,
    /// -32600 `Invalid request.`
    InvalidRequest,
    /// -32600 `Request too large.`
    RequestTooLarge,
    /// -32602 `Invalid params.`
    InvalidParams,
    /// -32602 with the rule an `eth_sendTransaction` object broke (`Invalid params: …`,
    /// [`TxRule::message`]). Other methods keep [`ProviderError::InvalidParams`].
    InvalidTxParams(TxRule),
    /// -32603 `Internal error.`
    Internal,
    /// -32603 `Request timed out.`
    TimedOut,
    /// -32603 `Response too large.`
    ResponseTooLarge,
    /// -32603 `Transaction broadcast failed.`
    BroadcastFailed,
    /// A sanitized upstream JSON-RPC error of a read (spec/05 §3.5).
    Upstream {
        /// Kept code (3, -32099…-32000, -32600…-32603) or -32603.
        code: i64,
        /// 0x20–0x7E, 1–256 characters, or `RPC error.`.
        message: String,
        /// Lowercase `0x` hex, ≤ 131,074 characters, if kept.
        data: Option<String>,
    },
}

impl ProviderError {
    /// The numeric code.
    #[must_use]
    pub const fn code(&self) -> i64 {
        match self {
            Self::UserRejected | Self::Expired => 4001,
            Self::Unauthorized
            | Self::PassphraseUnverified
            | Self::NoEvmAccount
            | Self::NoSolAccount
            | Self::NoBtcAccount
            | Self::BtcDisabled
            | Self::BackupUnconfirmed
            | Self::TooManySites => 4100,
            Self::UnsupportedMethod => 4200,
            Self::Unavailable | Self::ConnectionClosed | Self::ExtensionReloaded => 4900,
            Self::ChainUnavailable => 4901,
            Self::UnrecognizedChain => 4902,
            Self::RequestPending | Self::TransactionPending => -32_002,
            Self::RateLimited | Self::TooManyPending => -32_005,
            Self::InvalidRequest | Self::RequestTooLarge => -32_600,
            Self::InvalidParams | Self::InvalidTxParams(_) => -32_602,
            Self::Internal | Self::TimedOut | Self::ResponseTooLarge | Self::BroadcastFailed => {
                -32_603
            }
            Self::Upstream { code, .. } => *code,
        }
    }

    /// The exact message.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::UserRejected => "User rejected the request.",
            Self::Expired => "Request expired.",
            Self::Unauthorized => "Unauthorized.",
            Self::PassphraseUnverified => {
                "Unauthorized: the wallet was opened with an unverified passphrase, so connecting and signing are disabled. Lock the wallet and unlock it with the correct passphrase."
            }
            Self::NoEvmAccount => {
                "Unauthorized: this wallet has no EVM account. Import an EVM private key in the Your Wallet app first."
            }
            Self::NoSolAccount => {
                "Unauthorized: this wallet has no Solana account. Add or import one in the Your Wallet app first."
            }
            Self::NoBtcAccount => {
                "Unauthorized: this wallet has no Bitcoin account of the requested type on the selected network (payment: native or nested SegWit, P2WPKH or P2SH-P2WPKH; ordinals: Taproot, P2TR). Add one in the Your Wallet app first."
            }
            Self::BtcDisabled => {
                "Unauthorized: Bitcoin is turned off in the Your Wallet app. Turn it on in the app's settings first."
            }
            Self::BackupUnconfirmed => {
                "Unauthorized: the recovery phrase of this account is not backed up yet, so it can receive but not sign. Confirm its backup in the Your Wallet app first."
            }
            Self::TooManySites => {
                "Unauthorized: too many sites are connected on this chain (256). Disconnect one in the Your Wallet app first."
            }
            Self::UnsupportedMethod => "Unsupported method.",
            Self::Unavailable => "Wallet is unavailable.",
            Self::ConnectionClosed => "Wallet connection closed.",
            Self::ExtensionReloaded => "Wallet extension was reloaded.",
            Self::ChainUnavailable => "Chain RPC is unavailable.",
            Self::UnrecognizedChain => "Unrecognized chain.",
            Self::RequestPending => "Request already pending.",
            Self::TransactionPending => "Transaction already pending.",
            Self::RateLimited => "Rate limit exceeded.",
            Self::TooManyPending => "Too many pending requests.",
            Self::InvalidRequest => "Invalid request.",
            Self::RequestTooLarge => "Request too large.",
            Self::InvalidParams => "Invalid params.",
            Self::InvalidTxParams(rule) => rule.message(),
            Self::Internal => "Internal error.",
            Self::TimedOut => "Request timed out.",
            Self::ResponseTooLarge => "Response too large.",
            Self::BroadcastFailed => "Transaction broadcast failed.",
            Self::Upstream { message, .. } => message,
        }
    }

    /// The `data` member (only sanitized upstream errors carry one).
    #[must_use]
    pub fn data(&self) -> Option<&str> {
        match self {
            Self::Upstream { data, .. } => data.as_deref(),
            _ => None,
        }
    }

    /// The log word of the broken `eth_sendTransaction` rule ([`TxRule::id`]), if any.
    #[must_use]
    pub const fn rule(&self) -> Option<&'static str> {
        match self {
            Self::InvalidTxParams(rule) => Some(rule.id()),
            _ => None,
        }
    }

    /// Builds the sanitized upstream error of spec/05 §3.5 from a JSON-RPC `error` member:
    /// the code is kept for 3, -32099…-32000 and -32600…-32603 (else -32603); the message is
    /// kept when it is 1–256 characters of 0x20–0x7E (else `RPC error.`); `data` is kept, in
    /// lowercase, only when it is `0x` + whole bytes of hex and at most 131,074 characters.
    #[must_use]
    pub fn upstream(code: Option<i64>, message: Option<&str>, data: Option<&str>) -> Self {
        let code = code
            .filter(|code| matches!(code, 3 | -32_099..=-32_000 | -32_603..=-32_600))
            .unwrap_or(-32_603);
        let message = match message {
            Some(text)
                if (1..=256).contains(&text.len())
                    && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) =>
            {
                text.to_owned()
            }
            _ => "RPC error.".to_owned(),
        };
        let data = data.and_then(|text| {
            let hex = text.strip_prefix("0x")?;
            (text.len() <= 131_074
                && hex.len() % 2 == 0
                && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| text.to_ascii_lowercase())
        });
        Self::Upstream {
            code,
            message,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProviderError, TxField, TxRule, UnsupportedTxKey};

    #[test]
    fn tx_rules_are_fixed_short_ascii_and_distinct() {
        let fields = [
            TxField::From,
            TxField::To,
            TxField::Value,
            TxField::Data,
            TxField::Input,
            TxField::Gas,
            TxField::GasLimit,
            TxField::GasPrice,
            TxField::MaxFeePerGas,
            TxField::MaxPriorityFeePerGas,
            TxField::Nonce,
            TxField::Type,
            TxField::ChainId,
            TxField::AccessList,
        ];
        let mut rules = vec![
            TxRule::Shape,
            TxRule::UnknownKey,
            TxRule::FromRequired,
            TxRule::ToRequired,
            TxRule::ToNull,
            TxRule::Type,
            TxRule::GasCap,
            TxRule::GasLimitDiffers,
            TxRule::DataInputDiffer,
            TxRule::DataTooLarge,
            TxRule::ChainId,
            TxRule::Nonce,
        ];
        rules.extend(fields.iter().map(|field| TxRule::Invalid(*field)));
        rules.extend(
            UnsupportedTxKey::ALL
                .iter()
                .map(|key| TxRule::UnsupportedKey(*key)),
        );
        let mut ids = std::collections::BTreeSet::new();
        let mut messages = std::collections::BTreeSet::new();
        for rule in &rules {
            let error = ProviderError::InvalidTxParams(*rule);
            assert_eq!(error.code(), -32_602);
            assert_eq!(error.data(), None);
            assert_eq!(error.rule(), Some(rule.id()));
            assert_eq!(error.message(), rule.message());
            let message = rule.message();
            assert!(message.starts_with("Invalid params: "), "{message}");
            assert!(message.ends_with('.'), "{message}");
            assert!((1..=256).contains(&message.len()), "{message}");
            assert!(
                message.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
                "{message}"
            );
            assert!(
                rule.id()
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "{}",
                rule.id()
            );
            assert!(ids.insert(rule.id()), "duplicate id {}", rule.id());
            assert!(messages.insert(message), "duplicate message {message}");
        }
        for key in UnsupportedTxKey::ALL {
            assert_eq!(UnsupportedTxKey::parse(key.key()), Some(*key));
            assert_eq!(
                TxRule::UnsupportedKey(*key).message(),
                format!("Invalid params: unsupported key \"{}\".", key.key())
            );
        }
        assert_eq!(UnsupportedTxKey::parse("AuthorizationList"), None);
        assert_eq!(UnsupportedTxKey::parse("gasLimit"), None);
        assert_eq!(ProviderError::InvalidParams.rule(), None);
        assert_eq!(ProviderError::InvalidParams.message(), "Invalid params.");
    }

    #[test]
    fn upstream_sanitizing_rules() {
        let kept = ProviderError::upstream(Some(3), Some("execution reverted"), Some("0xDEADbeef"));
        assert_eq!(kept.code(), 3);
        assert_eq!(kept.message(), "execution reverted");
        assert_eq!(kept.data(), Some("0xdeadbeef"));
        for code in [-32_000, -32_099, -32_600, -32_603] {
            assert_eq!(ProviderError::upstream(Some(code), None, None).code(), code);
        }
        for code in [-32_100, -31_999, -32_604, -32_700, 4001, 1, 0] {
            assert_eq!(
                ProviderError::upstream(Some(code), None, None).code(),
                -32_603
            );
        }
        assert_eq!(ProviderError::upstream(None, None, None).code(), -32_603);
        for bad in ["", "tab\there", "é", &"a".repeat(257)] {
            assert_eq!(
                ProviderError::upstream(Some(3), Some(bad), None).message(),
                "RPC error."
            );
        }
        assert_eq!(
            ProviderError::upstream(Some(3), Some(&"a".repeat(256)), None).message(),
            "a".repeat(256)
        );
        for bad in ["0x0", "deadbeef", "0xzz", "0X00"] {
            assert_eq!(
                ProviderError::upstream(Some(3), None, Some(bad)).data(),
                None
            );
        }
        let long = format!("0x{}", "00".repeat(65_536));
        assert_eq!(long.len(), 131_074);
        assert!(
            ProviderError::upstream(Some(3), None, Some(&long))
                .data()
                .is_some()
        );
        let longer = format!("0x{}", "00".repeat(65_537));
        assert_eq!(
            ProviderError::upstream(Some(3), None, Some(&longer)).data(),
            None
        );
        assert_eq!(ProviderError::Internal.data(), None);
    }
}
