//! spec/05 §10.2 R-M1 (method table against the shared golden) and R-ERR (yw-core part: every
//! `ProviderError` code and message against the spec/05 §5 table; `BrowserOrigin` rules are the
//! unit tests of `policy`).

use yw_core::policy::{BrowserOrigin, Method, ProviderError, Route};
use yw_json::{Limits, Value, parse};

const METHODS_GOLDEN: &str = include_str!("../../../extension/native-host/v1-methods.golden.json");
const ORIGINS_GOLDEN: &str = include_str!("../../../extension/native-host/v1-origins.golden.json");

/// Security review L6 (spec/05 §2.4 "같은 규칙을 네 곳"): `BrowserOrigin::parse` accepts exactly the
/// serialized origins of the pages the extension accepts (the same vectors pin `shared.js`,
/// `provider-main.js` and background `deriveSenderContext`).
#[test]
fn r_origin_rule_matches_the_shared_golden() {
    let golden = parse(ORIGINS_GOLDEN.as_bytes(), &Limits::RESPONSE).unwrap();
    let cases = golden
        .as_object()
        .and_then(|object| object.get("cases"))
        .and_then(Value::as_array)
        .unwrap();
    let mut checked = 0;
    for case in cases {
        let case = case.as_object().unwrap();
        let note = case.get("note").and_then(Value::as_str).unwrap();
        let ok = matches!(case.get("ok"), Some(Value::Bool(true)));
        match case.get("origin").and_then(Value::as_str) {
            Some(origin) => {
                assert_eq!(BrowserOrigin::parse(origin).is_some(), ok, "{note}");
                checked += 1;
            }
            None => assert!(!ok, "{note}"),
        }
    }
    assert!(checked >= 20);
}

fn names(golden: &Value, key: &str) -> Vec<String> {
    golden
        .as_object()
        .and_then(|object| object.get(key))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn r_m1_method_table_matches_the_shared_golden() {
    let golden = parse(METHODS_GOLDEN.as_bytes(), &Limits::RESPONSE).unwrap();
    let object = golden.as_object().unwrap();
    assert_eq!(
        object.keys().collect::<Vec<_>>(),
        ["permission", "read", "signing", "rejected"]
    );
    let mut expected = Vec::new();
    for (key, route) in [
        ("permission", Route::Permission),
        ("read", Route::Read),
        ("signing", Route::Signing),
    ] {
        let list = names(&golden, key);
        assert!(!list.is_empty());
        for name in list {
            let method = Method::parse(&name).unwrap();
            assert_eq!(method.route(), route, "{name}");
            expected.push(method);
        }
    }
    assert_eq!(expected.as_slice(), Method::ALL.as_slice());
    let rejected = names(&golden, "rejected");
    assert_eq!(rejected.len(), 38);
    for name in rejected {
        assert_eq!(Method::parse(&name), None, "{name}");
    }
}

#[test]
fn r_err_provider_errors_match_spec_05_section_5() {
    let table: [(ProviderError, i64, &str); 24] = [
        (
            ProviderError::UserRejected,
            4001,
            "User rejected the request.",
        ),
        (ProviderError::Expired, 4001, "Request expired."),
        (ProviderError::Unauthorized, 4100, "Unauthorized."),
        (
            ProviderError::PassphraseUnverified,
            4100,
            "Unauthorized: the wallet was opened with an unverified passphrase, so connecting and signing are disabled. Lock the wallet and unlock it with the correct passphrase.",
        ),
        (
            ProviderError::NoEvmAccount,
            4100,
            "Unauthorized: this wallet has no EVM account. Import an EVM private key in the Your Wallet app first.",
        ),
        (
            ProviderError::NoSolAccount,
            4100,
            "Unauthorized: this wallet has no Solana account. Add or import one in the Your Wallet app first.",
        ),
        (
            ProviderError::NoBtcAccount,
            4100,
            "Unauthorized: this wallet has no Bitcoin account of the requested type on the selected network. Add one in the Your Wallet app first.",
        ),
        (
            ProviderError::UnsupportedMethod,
            4200,
            "Unsupported method.",
        ),
        (ProviderError::Unavailable, 4900, "Wallet is unavailable."),
        (
            ProviderError::ConnectionClosed,
            4900,
            "Wallet connection closed.",
        ),
        (
            ProviderError::ExtensionReloaded,
            4900,
            "Wallet extension was reloaded.",
        ),
        (
            ProviderError::ChainUnavailable,
            4901,
            "Chain RPC is unavailable.",
        ),
        (
            ProviderError::UnrecognizedChain,
            4902,
            "Unrecognized chain.",
        ),
        (
            ProviderError::RequestPending,
            -32_002,
            "Request already pending.",
        ),
        (
            ProviderError::TransactionPending,
            -32_002,
            "Transaction already pending.",
        ),
        (ProviderError::RateLimited, -32_005, "Rate limit exceeded."),
        (
            ProviderError::TooManyPending,
            -32_005,
            "Too many pending requests.",
        ),
        (ProviderError::InvalidRequest, -32_600, "Invalid request."),
        (
            ProviderError::RequestTooLarge,
            -32_600,
            "Request too large.",
        ),
        (ProviderError::InvalidParams, -32_602, "Invalid params."),
        (ProviderError::Internal, -32_603, "Internal error."),
        (ProviderError::TimedOut, -32_603, "Request timed out."),
        (
            ProviderError::ResponseTooLarge,
            -32_603,
            "Response too large.",
        ),
        (
            ProviderError::BroadcastFailed,
            -32_603,
            "Transaction broadcast failed.",
        ),
    ];
    for (error, code, message) in table {
        assert_eq!(error.code(), code, "{message}");
        assert_eq!(error.message(), message);
        assert_eq!(error.data(), None);
    }
    let upstream = ProviderError::upstream(Some(-32_000), Some("nonce too low"), None);
    assert_eq!(upstream.code(), -32_000);
    assert_eq!(upstream.message(), "nonce too low");
}

#[test]
fn r_err_too_many_sites_matches_spec_05_section_5() {
    let error = ProviderError::TooManySites;
    assert_eq!(error.code(), 4100);
    assert_eq!(
        error.message(),
        "Unauthorized: too many sites are connected on this chain (256). Disconnect one in the Your Wallet app first."
    );
    assert_eq!(error.data(), None);
}
