//! Provider error codes and messages (spec/05 §5, canonical per D31).
//!
//! The fixed codes and wording follow `archive/spec-v2.4:crates/wallet-protocol/src/error.rs:5-178`
//! (4001/4100/4200/-32602/-32603 mapping with fixed phrases) extended with the v3 rows. Errors
//! made by yw-app carry no `data`; only [`ProviderError::Upstream`] (sanitized read errors,
//! spec/05 §3.5) may.

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
            Self::InvalidParams => -32_602,
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
    use super::ProviderError;

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
