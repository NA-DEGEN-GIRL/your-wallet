//! Solana and Bitcoin dApp requests in the dispatcher (spec/05 §3.6, §4.9): connect and message
//! signing only. Transaction methods are 4200, signing needs the per-chain grant of the origin,
//! grants are forgotten while locked and come back at unlock with their events, the compat mode
//! must match the method family, and a SIWS sign-in gets the origin's domain filled in.

mod common;

use common::browser::{Harness, NOW_UNIX, RequestSpec, activation, events_of, json, request_frame};
use yw_app::browser::envelope::{BrowserEvent, Correlation};
use yw_app::browser::{DappEvent, GrantChange, SiteKind, VaultView};
use yw_app::settings::Settings;
use yw_core::btc::{BtcNetwork, BtcPubKey, ScriptType};
use yw_core::policy::{
    BrowserOrigin, BtcGrant, BtcGrantAddress, BtcPurpose, ProviderError, SolGrant,
};
use yw_json::{Limits, Object, Value};

const SITE: &str = "https://app.example";
const OTHER: &str = "https://other.example:8443";
const SOL_KEY: &str = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";
const P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn origin(text: &str) -> TestResult<BrowserOrigin> {
    BrowserOrigin::parse(text).ok_or_else(|| "origin".into())
}

fn sol_public() -> TestResult<[u8; 32]> {
    Ok(yw_core::codec::base58::base58_decode_32(SOL_KEY)?)
}

fn sol_grant(site: &str) -> TestResult<SolGrant> {
    Ok(SolGrant {
        origin: origin(site)?,
        public: sol_public()?,
        granted_at_unix_ms: NOW_UNIX,
    })
}

fn btc_grant(site: &str, network: BtcNetwork) -> TestResult<BtcGrant> {
    let key = yw_core::hex::decode_array::<33>(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )?;
    BtcGrant::new(
        origin(site)?,
        network,
        vec![BtcGrantAddress {
            purpose: BtcPurpose::Payment,
            address: P2WPKH.to_owned(),
            pubkey: BtcPubKey::Compressed(key),
            script_type: ScriptType::P2wpkh,
        }],
        NOW_UNIX,
    )
    .ok_or_else(|| "grant".into())
}

fn single(h: &Harness, correlation: &Correlation) -> TestResult<Result<Value, ProviderError>> {
    let mut found = h.take_response(correlation);
    if found.len() != 1 {
        return Err(format!("expected one response, got {}", found.len()).into());
    }
    found.pop().ok_or_else(|| "no response".into())
}

fn text(value: &Result<Value, ProviderError>) -> String {
    match value {
        Ok(value) => String::from_utf8_lossy(&yw_json::to_vec(value)).into_owned(),
        Err(error) => format!("error {} {}", error.code(), error.message()),
    }
}

fn sign_params() -> String {
    format!(r#"[{{"publicKey":"{SOL_KEY}","message":"48656c6c6f"}}]"#)
}

#[test]
fn transaction_methods_are_unsupported() -> TestResult {
    let mut h = Harness::new();
    for method in [
        "sol_signTransaction",
        "sol_signAllTransactions",
        "sol_signAndSendTransaction",
        "btc_signPsbt",
        "btc_sendBitcoin",
        "btc_pushTx",
        "btc_sendTransfer",
    ] {
        let sent = h.send_with(SITE, 1, method, json("[]"), "signing", None);
        assert_eq!(
            single(&h, &sent)?,
            Err(ProviderError::UnsupportedMethod),
            "{method}"
        );
    }
    Ok(())
}

#[test]
fn signing_needs_the_origin_grant_and_connect_queues_a_window() -> TestResult {
    let mut h = Harness::new();
    // Not connected: no accounts, signing 4100, connect queues the window.
    let accounts = h.send(SITE, 1, "sol_accounts", json("[]"));
    assert_eq!(text(&single(&h, &accounts)?), "[]");
    let trusted = h.send(SITE, 1, "sol_connect", json(r#"[{"onlyIfTrusted":true}]"#));
    assert_eq!(single(&h, &trusted)?, Err(ProviderError::UserRejected));
    let sign = h.send(SITE, 1, "sol_signMessage", json(&sign_params()));
    assert_eq!(single(&h, &sign)?, Err(ProviderError::Unauthorized));
    let btc_sign = h.send(
        SITE,
        1,
        "btc_signMessage",
        json(&format!(r#"[{{"address":"{P2WPKH}","message":"hi"}}]"#)),
    );
    assert_eq!(single(&h, &btc_sign)?, Err(ProviderError::Unauthorized));
    let connect = h.send(SITE, 1, "sol_connect", json("[]"));
    assert!(h.take_response(&connect).is_empty());
    let requests = h.sink.requests();
    assert!(matches!(requests.as_slice(), [one] if one.kind == SiteKind::SolConnect));
    // A second connect of the same family while the window waits: -32002; EVM is independent.
    let again = h.send(SITE, 1, "sol_connect", json("[]"));
    assert_eq!(single(&h, &again)?, Err(ProviderError::RequestPending));
    let evm = h.send(SITE, 1, "eth_requestAccounts", json("[]"));
    assert!(h.take_response(&evm).is_empty());

    // Connected: immediate answers, and a sign request reaches the queue.
    h.core.upsert_sol_grant(sol_grant(SITE)?);
    h.core
        .upsert_btc_grant(btc_grant(SITE, BtcNetwork::Mainnet)?);
    let events = events_of(&h.out.take(), 1);
    assert!(events.contains(&BrowserEvent::SolAccountsChanged(vec![sol_public()?])));
    assert!(events.contains(&BrowserEvent::BtcAccountsChanged(vec![P2WPKH.to_owned()])));
    let accounts = h.send(SITE, 1, "sol_accounts", json("[]"));
    assert_eq!(text(&single(&h, &accounts)?), format!("[\"{SOL_KEY}\"]"));
    let connect = h.send(SITE, 1, "sol_connect", json("[]"));
    assert_eq!(
        text(&single(&h, &connect)?),
        format!("{{\"publicKey\":\"{SOL_KEY}\"}}")
    );
    let btc = h.send(SITE, 1, "btc_getAccounts", json("[]"));
    let listed = text(&single(&h, &btc)?);
    assert!(
        listed.contains("\"purpose\":\"payment\"") && listed.contains("\"addressType\":\"p2wpkh\"")
    );
    let request = h.send(
        SITE,
        1,
        "btc_requestAccounts",
        json(r#"[{"purposes":["payment"]}]"#),
    );
    assert!(text(&single(&h, &request)?).contains(P2WPKH));
    // Ordinals are not granted: a window.
    let ordinals = h.send(
        SITE,
        1,
        "btc_requestAccounts",
        json(r#"[{"purposes":["payment","ordinals"]}]"#),
    );
    assert!(h.take_response(&ordinals).is_empty());
    h.sink.take();
    let sign = h.send(SITE, 1, "sol_signMessage", json(&sign_params()));
    assert!(h.take_response(&sign).is_empty());
    let queued = h.sink.requests();
    assert!(matches!(
        queued.as_slice(),
        [one] if matches!(&one.kind, SiteKind::SolSign { message, sign_in: false, .. } if message == b"Hello")
    ));
    // The grant is per origin.
    let elsewhere = h.send(OTHER, 2, "sol_signMessage", json(&sign_params()));
    assert_eq!(single(&h, &elsewhere)?, Err(ProviderError::Unauthorized));
    let network = h.send(SITE, 1, "btc_getNetwork", json("[]"));
    assert_eq!(text(&single(&h, &network)?), "\"mainnet\"");
    Ok(())
}

#[test]
fn sign_in_fills_domain_and_address() -> TestResult {
    let mut h = Harness::new();
    h.core.upsert_sol_grant(sol_grant(OTHER)?);
    let sent = h.send(
        OTHER,
        1,
        "sol_signIn",
        json(&format!(
            r#"[{{"publicKey":"{SOL_KEY}","input":{{"statement":"Sign in","chainId":"mainnet"}}}}]"#
        )),
    );
    assert!(h.take_response(&sent).is_empty());
    let requests = h.sink.requests();
    let [request] = requests.as_slice() else {
        return Err("one request".into());
    };
    let SiteKind::SolSign {
        message, sign_in, ..
    } = &request.kind
    else {
        return Err("sign kind".into());
    };
    assert!(*sign_in);
    assert_eq!(
        String::from_utf8(message.clone())?,
        format!(
            "other.example:8443 wants you to sign in with your Solana account:\n{SOL_KEY}\n\nSign in\n\nChain ID: mainnet"
        )
    );
    let unknown = h.send(
        OTHER,
        1,
        "sol_signIn",
        json(&format!(
            r#"[{{"publicKey":"{SOL_KEY}","input":{{"useOffchainMessage":true}}}}]"#
        )),
    );
    assert_eq!(single(&h, &unknown)?, Err(ProviderError::InvalidParams));
    Ok(())
}

#[test]
fn lock_unlock_disconnect_and_states() -> TestResult {
    let mut h = Harness::new();
    // Touch the document so it receives events.
    let first = h.send(SITE, 1, "sol_accounts", json("[]"));
    let _ = single(&h, &first)?;
    h.core.unlock_chains(
        vec![sol_grant(SITE)?],
        vec![btc_grant(SITE, BtcNetwork::Mainnet)?],
    );
    let events = events_of(&h.out.take(), 1);
    assert_eq!(events.len(), 2);
    h.core.lock_wallet();
    let events = events_of(&h.out.take(), 1);
    assert!(events.contains(&BrowserEvent::SolAccountsChanged(Vec::new())));
    assert!(events.contains(&BrowserEvent::BtcAccountsChanged(Vec::new())));
    assert!(h.core.sol_grants().is_empty());
    // Locked: nothing exposed, disconnect answers null and is remembered for the unlock,
    // signing waits for the unlock.
    let mut view = h.core.wallet();
    view.vault = VaultView::Locked;
    h.core.set_wallet(view.clone());
    let accounts = h.send(SITE, 1, "sol_accounts", json("[]"));
    assert_eq!(text(&single(&h, &accounts)?), "[]");
    let disconnect = h.send(SITE, 1, "sol_disconnect", json("[]"));
    assert_eq!(text(&single(&h, &disconnect)?), "null");
    assert_eq!(
        h.core.locked_revocations(),
        vec![(origin(SITE)?, yw_core::policy::Family::Solana)]
    );
    let sign = h.send(SITE, 1, "sol_signMessage", json(&sign_params()));
    assert!(h.take_response(&sign).is_empty());
    assert_eq!(h.sink.requests().len(), 1);
    // A wallet on another network: the Bitcoin grant is not used. The locked-time disconnect
    // removes the Solana grant before any event (meta must be written: `true`).
    view.vault = VaultView::Unlocked;
    view.btc_network = BtcNetwork::Testnet4;
    h.core.set_wallet(view.clone());
    h.out.take();
    assert!(h.core.unlock_chains(
        vec![sol_grant(SITE)?],
        vec![btc_grant(SITE, BtcNetwork::Mainnet)?],
    ));
    assert!(h.core.sol_grants().is_empty());
    assert!(h.core.locked_revocations().is_empty());
    assert!(events_of(&h.out.take(), 1).is_empty());
    let btc = h.send(SITE, 1, "btc_getAccounts", json("[]"));
    assert_eq!(text(&single(&h, &btc)?), "[]");
    let network = h.send(SITE, 1, "btc_getNetwork", json("[]"));
    assert_eq!(text(&single(&h, &network)?), "\"testnet4\"");
    // Unlocked disconnect removes the grant and tells the UI to persist it.
    assert!(h.core.upsert_sol_grant(sol_grant(SITE)?));
    h.sink.take();
    let disconnect = h.send(SITE, 1, "sol_disconnect", json("[]"));
    assert_eq!(text(&single(&h, &disconnect)?), "null");
    assert!(h.core.sol_grants().is_empty());
    assert!(h.sink.take().iter().any(|event| matches!(
        event,
        DappEvent::GrantChanged {
            change: GrantChange::SolRevoked,
            ..
        }
    )));
    // No vault / passphrase-unverified refuse a connect like EVM.
    for (vault, error) in [
        (VaultView::NoVault, ProviderError::Unauthorized),
        (
            VaultView::PassphraseUnverified,
            ProviderError::PassphraseUnverified,
        ),
        (VaultView::BackupPending, ProviderError::Unauthorized),
    ] {
        let mut h = Harness::with(vault, &Settings::default());
        let connect = h.send(SITE, 1, "sol_connect", json("[]"));
        assert_eq!(single(&h, &connect)?, Err(error.clone()));
        let btc = h.send(
            SITE,
            1,
            "btc_requestAccounts",
            json(r#"[{"purposes":["any"]}]"#),
        );
        assert_eq!(single(&h, &btc)?, Err(error));
    }
    Ok(())
}

fn two_address_grant(site: &str) -> TestResult<BtcGrant> {
    let mut grant = btc_grant(site, BtcNetwork::Mainnet)?;
    let key = yw_core::hex::decode_array::<33>(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    )?;
    grant.addresses.push(BtcGrantAddress {
        purpose: BtcPurpose::Ordinals,
        address: "bc1pordinals".to_owned(),
        pubkey: BtcPubKey::Compressed(key),
        script_type: ScriptType::P2tr,
    });
    Ok(grant)
}

#[test]
fn grants_of_accounts_no_longer_usable_answer_nothing() -> TestResult {
    let mut h = Harness::new();
    let first = h.send(SITE, 1, "sol_accounts", json("[]"));
    let _ = single(&h, &first)?;
    // The Solana account was hidden and the Bitcoin address left the wallet (an older meta
    // still lists their grants): unlock sends no account event for them.
    let mut view = h.core.wallet();
    view.sol_accounts.clear();
    view.btc_accounts.clear();
    h.core.set_wallet(view.clone());
    assert!(!h.core.unlock_chains(
        vec![sol_grant(SITE)?],
        vec![btc_grant(SITE, BtcNetwork::Mainnet)?],
    ));
    assert!(events_of(&h.out.take(), 1).is_empty());
    let accounts = h.send(SITE, 1, "sol_accounts", json("[]"));
    assert_eq!(text(&single(&h, &accounts)?), "[]");
    let trusted = h.send(SITE, 1, "sol_connect", json(r#"[{"onlyIfTrusted":true}]"#));
    assert_eq!(single(&h, &trusted)?, Err(ProviderError::UserRejected));
    let btc = h.send(SITE, 1, "btc_getAccounts", json("[]"));
    assert_eq!(text(&single(&h, &btc)?), "[]");
    let sign = h.send(SITE, 1, "sol_signMessage", json(&sign_params()));
    assert_eq!(single(&h, &sign)?, Err(ProviderError::Unauthorized));
    // A connect is not answered from the stale grant: it opens the window.
    let connect = h.send(SITE, 1, "sol_connect", json("[]"));
    assert!(h.take_response(&connect).is_empty());
    let request = h.send(
        SITE,
        1,
        "btc_requestAccounts",
        json(r#"[{"purposes":["payment"]}]"#),
    );
    assert!(h.take_response(&request).is_empty());
    let kinds: Vec<SiteKind> = h.sink.requests().into_iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        vec![
            SiteKind::SolConnect,
            SiteKind::BtcConnect(vec![BtcPurpose::Payment])
        ]
    );
    Ok(())
}

#[test]
fn removed_accounts_drop_their_grants_with_events() -> TestResult {
    let mut h = Harness::new();
    let first = h.send(SITE, 1, "sol_accounts", json("[]"));
    let _ = single(&h, &first)?;
    let other = h.send(OTHER, 2, "sol_accounts", json("[]"));
    let _ = single(&h, &other)?;
    assert!(h.core.upsert_sol_grant(sol_grant(SITE)?));
    assert!(h.core.upsert_sol_grant(SolGrant {
        public: [9; 32],
        ..sol_grant(OTHER)?
    }));
    assert!(h.core.upsert_btc_grant(two_address_grant(SITE)?));
    assert!(
        h.core
            .upsert_btc_grant(btc_grant(OTHER, BtcNetwork::Testnet4)?)
    );
    h.out.take();
    // Only the grants naming the removed key go, with `solAccountsChanged([])`.
    assert_eq!(
        h.core.remove_sol_account(&sol_public()?),
        vec![origin(SITE)?]
    );
    assert_eq!(h.core.sol_grants().len(), 1);
    assert_eq!(
        events_of(&h.out.take(), 1),
        vec![BrowserEvent::SolAccountsChanged(Vec::new())]
    );
    assert!(h.core.remove_sol_account(&sol_public()?).is_empty());
    // A Bitcoin grant listing the address goes as a whole (also its ordinals address), on every
    // network; an unknown address removes nothing.
    assert!(h.core.remove_btc_address("bc1qunknown").is_empty());
    let removed = h.core.remove_btc_address(P2WPKH);
    assert_eq!(removed, vec![origin(SITE)?, origin(OTHER)?]);
    assert!(h.core.btc_grants().is_empty());
    assert_eq!(
        events_of(&h.out.take(), 1),
        vec![BrowserEvent::BtcAccountsChanged(Vec::new())]
    );
    let btc = h.send(SITE, 1, "btc_getAccounts", json("[]"));
    assert_eq!(text(&single(&h, &btc)?), "[]");
    Ok(())
}

#[test]
fn bitcoin_off_refuses_bitcoin_requests() -> TestResult {
    let mut settings = Settings::default();
    settings.bitcoin.enabled = false;
    for vault in [VaultView::Unlocked, VaultView::Locked] {
        let mut h = Harness::with(vault, &settings);
        let mut view = h.core.wallet();
        view.btc_enabled = false;
        h.core.set_wallet(view);
        let _ = h
            .core
            .upsert_btc_grant(btc_grant(SITE, BtcNetwork::Mainnet)?);
        for (method, params) in [
            (
                "btc_requestAccounts",
                r#"[{"purposes":["payment"]}]"#.to_owned(),
            ),
            ("btc_getAccounts", "[]".to_owned()),
            (
                "btc_signMessage",
                format!(r#"[{{"address":"{P2WPKH}","message":"hi"}}]"#),
            ),
        ] {
            let sent = h.send(SITE, 1, method, json(&params));
            assert_eq!(
                single(&h, &sent)?,
                Err(ProviderError::NoBtcAccount),
                "{method} {vault:?}"
            );
        }
        assert!(h.sink.requests().is_empty(), "no window, no unlock prompt");
        let network = h.send(SITE, 1, "btc_getNetwork", json("[]"));
        assert_eq!(text(&single(&h, &network)?), "\"mainnet\"");
        let disconnect = h.send(SITE, 1, "btc_disconnect", json("[]"));
        assert_eq!(text(&single(&h, &disconnect)?), "null");
        // Solana is not affected.
        let accounts = h.send(SITE, 1, "sol_accounts", json("[]"));
        assert!(single(&h, &accounts)?.is_ok());
    }
    Ok(())
}

#[test]
fn chain_grant_limit_holds() -> TestResult {
    let mut h = Harness::new();
    for index in 0..yw_core::policy::MAX_CHAIN_GRANTS {
        let site = format!("https://s{index}.example");
        assert!(h.core.upsert_sol_grant(sol_grant(&site)?));
        assert!(
            h.core
                .upsert_btc_grant(btc_grant(&site, BtcNetwork::Mainnet)?)
        );
    }
    // A new origin is refused (meta would not parse); a known one is replaced.
    assert!(!h.core.upsert_sol_grant(sol_grant(SITE)?));
    assert!(
        !h.core
            .upsert_btc_grant(btc_grant(SITE, BtcNetwork::Mainnet)?)
    );
    assert!(h.core.upsert_sol_grant(sol_grant("https://s0.example")?));
    assert_eq!(h.core.sol_grants().len(), yw_core::policy::MAX_CHAIN_GRANTS);
    assert!(
        !h.core
            .chain_grant_room(&origin(SITE)?, yw_core::policy::Family::Solana)
    );
    assert!(h.core.chain_grant_room(
        &origin("https://s1.example")?,
        yw_core::policy::Family::Bitcoin
    ));
    let connect = h.send(SITE, 1, "sol_connect", json("[]"));
    assert_eq!(single(&h, &connect)?, Err(ProviderError::TooManySites));
    let btc = h.send(
        SITE,
        1,
        "btc_requestAccounts",
        json(r#"[{"purposes":["payment"]}]"#),
    );
    assert_eq!(single(&h, &btc)?, Err(ProviderError::TooManySites));
    Ok(())
}

/// A request frame whose context carries `compatMode`.
fn with_mode(spec: &RequestSpec<'_>, mode: &str) -> TestResult<Vec<u8>> {
    let value = yw_json::parse(&request_frame(spec), &Limits::REQUEST)?;
    let mut pairs = Vec::new();
    for (key, item) in value.as_object().ok_or("object")?.iter() {
        if key == "context" {
            let mut context: Vec<(String, Value)> = item
                .as_object()
                .ok_or("context")?
                .iter()
                .map(|(name, entry)| (name.to_owned(), entry.clone()))
                .collect();
            context.push(("compatMode".to_owned(), Value::String(mode.to_owned())));
            pairs.push((
                key.to_owned(),
                Value::Object(Object::from_pairs(context).ok_or("dup")?),
            ));
        } else {
            pairs.push((key.to_owned(), item.clone()));
        }
    }
    Ok(yw_json::to_vec(&Value::Object(
        Object::from_pairs(pairs).ok_or("dup")?,
    )))
}

#[test]
fn compat_mode_must_match_the_family() -> TestResult {
    let mut h = Harness::new();
    let mut frame = |method: &str, mode: &str, request: u8| -> TestResult<Vec<u8>> {
        let sequence = h.next_sequence();
        with_mode(
            &RequestSpec {
                sequence,
                request,
                document: 1,
                origin: SITE,
                method,
                params: json("[]"),
                route: "permission",
                deadline: NOW_UNIX + 600_000,
            },
            mode,
        )
    };
    let cases = [
        ("sol_accounts", "phantom", true),
        ("sol_accounts", "metamask", false),
        ("btc_getNetwork", "unisat", true),
        ("btc_getNetwork", "xverse", true),
        ("btc_getNetwork", "phantom", false),
        ("eth_chainId", "xverse", false),
    ];
    let frames = cases
        .iter()
        .enumerate()
        .map(|(index, (method, mode, _))| frame(method, mode, u8::try_from(index + 1).unwrap_or(1)))
        .collect::<TestResult<Vec<_>>>()?;
    for bytes in &frames {
        h.raw(bytes);
    }
    let answers = h.responses();
    assert_eq!(answers.len(), cases.len());
    for ((_, body), (method, mode, ok)) in answers.iter().zip(cases) {
        assert_eq!(body.is_ok(), ok, "{method} {mode}");
        if !ok {
            assert_eq!(body, &Err(ProviderError::InvalidRequest));
        }
    }
    let _ = activation(1);
    Ok(())
}
