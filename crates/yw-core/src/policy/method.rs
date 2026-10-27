//! The dApp method allowlist and routes (spec/05 §3.1–§3.2). Rust canon of the single method
//! table; the JavaScript canon is `extension/src/shared.js` `METHOD_ROUTE`, and both are compared
//! with `extension/native-host/v1-methods.golden.json` (S1, R-M1).
//!
//! Ported from `archive/spec-v2.4:crates/broker/src/lib.rs:50-225` (`ProviderMethod`,
//! `ProviderRoute`) narrowed to the 27 v3 methods: `wallet_addEthereumChain`,
//! `wallet_watchAsset` and `wallet_getCapabilities` are gone (D14, spec/05 §3.2) and
//! `wallet_revokePermissions`, `web3_clientVersion` are added.

/// The envelope v1 route (spec/05 §6.1). `Permission` = answered by yw-app without RPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    /// Answered from memory state or a connect/unlock window.
    Permission,
    /// Forwarded to the origin chain's RPC endpoint.
    Read,
    /// Approval window and signing.
    Signing,
}

impl Route {
    /// Parses the exact lowercase wire label.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "permission" => Some(Self::Permission),
            "read" => Some(Self::Read),
            "signing" => Some(Self::Signing),
            _ => None,
        }
    }

    /// The wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permission => "permission",
            Self::Read => "read",
            Self::Signing => "signing",
        }
    }
}

macro_rules! methods {
    ($($variant:ident => $name:literal, $route:ident;)*) => {
        /// The 27 allowed dApp methods (spec/05 §3.1). Anything else is 4200.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Method {
            $(
                #[doc = concat!("`", $name, "`")]
                $variant,
            )*
        }

        impl Method {
            /// Every method in spec/05 §3.1 order (permission, read, signing).
            pub const ALL: [Self; 27] = [$(Self::$variant,)*];

            /// Exact, case-sensitive name lookup.
            #[must_use]
            pub fn parse(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Self::$variant),)*
                    _ => None,
                }
            }

            /// The wire name.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                }
            }

            /// The only route allowed for the method.
            #[must_use]
            pub const fn route(self) -> Route {
                match self {
                    $(Self::$variant => Route::$route,)*
                }
            }
        }
    };
}

methods! {
    RequestAccounts => "eth_requestAccounts", Permission;
    Accounts => "eth_accounts", Permission;
    ChainId => "eth_chainId", Permission;
    NetVersion => "net_version", Permission;
    SwitchEthereumChain => "wallet_switchEthereumChain", Permission;
    RequestPermissions => "wallet_requestPermissions", Permission;
    GetPermissions => "wallet_getPermissions", Permission;
    RevokePermissions => "wallet_revokePermissions", Permission;
    ClientVersion => "web3_clientVersion", Permission;
    BlockNumber => "eth_blockNumber", Read;
    Call => "eth_call", Read;
    EstimateGas => "eth_estimateGas", Read;
    FeeHistory => "eth_feeHistory", Read;
    GasPrice => "eth_gasPrice", Read;
    MaxPriorityFeePerGas => "eth_maxPriorityFeePerGas", Read;
    GetBalance => "eth_getBalance", Read;
    GetBlockByHash => "eth_getBlockByHash", Read;
    GetBlockByNumber => "eth_getBlockByNumber", Read;
    GetCode => "eth_getCode", Read;
    GetLogs => "eth_getLogs", Read;
    GetStorageAt => "eth_getStorageAt", Read;
    GetTransactionByHash => "eth_getTransactionByHash", Read;
    GetTransactionCount => "eth_getTransactionCount", Read;
    GetTransactionReceipt => "eth_getTransactionReceipt", Read;
    SendTransaction => "eth_sendTransaction", Signing;
    PersonalSign => "personal_sign", Signing;
    SignTypedDataV4 => "eth_signTypedData_v4", Signing;
}

/// Whether `text` matches the method-name grammar `^[A-Za-z0-9_]{1,96}$` (spec/05 §2.5).
#[must_use]
pub fn is_method_name(text: &str) -> bool {
    (1..=96).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::{Method, Route, is_method_name};

    #[test]
    fn names_round_trip_and_are_case_sensitive() {
        for method in Method::ALL {
            assert_eq!(Method::parse(method.as_str()), Some(method));
            assert!(is_method_name(method.as_str()));
        }
        assert_eq!(Method::parse("Eth_chainId"), None);
        assert_eq!(Method::parse("eth_chainId "), None);
        assert_eq!(Route::parse("read"), Some(Route::Read));
        assert_eq!(Route::parse("Read"), None);
        assert!(!is_method_name(""));
        assert!(!is_method_name(&"a".repeat(97)));
        assert!(!is_method_name("eth-chainId"));
    }
}
