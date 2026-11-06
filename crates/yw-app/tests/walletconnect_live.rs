//! Live `WalletConnect` relay smoke test (spec/13 §10), ignored by default — it needs the network.
//!
//! `cargo test -p yw-app --test walletconnect_live -- --ignored --nocapture`
//!
//! With `YW_WC_PROJECT_ID` (a Reown Cloud project id): two relay clients (different did:key
//! identities) connect through the `WinHTTP` WebSocket, one subscribes a random topic, the other
//! publishes an envelope there, and the first receives it as `irn_subscription` and opens it.
//! Without the variable: one connection with a made-up project id must reach the relay's HTTP
//! answer (an upgrade or a 401/403 refusal) — TLS, the URL and the JWT are exercised either way.
//! Nothing is signed and no wallet is involved.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout, clippy::panic)]

use std::sync::Arc;

use yw_app::walletconnect::worker::{ConnectError, RelayConnector, RelayLink, WsConnector};
use yw_json::Value;

fn url(seed: &[u8; 32], project: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut sub = [0_u8; 32];
    yw_core::entropy::fill_random(&mut sub).unwrap();
    let jwt = yw_core::walletconnect::relay_auth_jwt(
        seed,
        &yw_core::hex::encode(&sub),
        yw_core::walletconnect::RELAY_URL,
        now,
        86_400,
    );
    format!("https://relay.walletconnect.org/?auth={jwt}&projectId={project}&ua=wc-2%2Frust-yourwallet-test%2Fwindows")
}

fn rpc(link: &dyn RelayLink, id: u64, method: &str, params: &str) {
    assert!(link.send(&format!(
        r#"{{"id":{id},"jsonrpc":"2.0","method":"{method}","params":{params}}}"#
    )));
}

fn wait_for(link: &dyn RelayLink, want: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..20 {
        let text = link.receive().expect("relay closed");
        let value = yw_json::parse(text.as_bytes(), &yw_json::Limits::RESPONSE).unwrap();
        if want(&value) {
            return value;
        }
    }
    panic!("no matching frame");
}

#[test]
#[ignore = "network: wss://relay.walletconnect.org"]
fn live_relay_round_trip() {
    let mut connector = WsConnector;
    let Ok(project) = std::env::var("YW_WC_PROJECT_ID") else {
        match connector.connect(&url(&[7; 32], "00000000000000000000000000000000")) {
            Ok(link) => {
                println!("relay accepted the made-up project id (upgrade completed)");
                link.abort();
            }
            Err(ConnectError::Unauthorized(code)) => {
                // 401 = the JWT was refused ("JWT is missing" / "JWT validation error: …", checked
                // 2026-11-06); 403 = the JWT passed and only the project id was refused.
                println!("relay refused the made-up project id: HTTP {code}");
                assert_eq!(code, 403, "the relay refused our auth JWT");
            }
            Err(ConnectError::Network) => {
                let parsed = yw_win::http::HttpsUrl::parse(&url(&[7; 32], "00000000000000000000000000000000"));
                let detail = parsed.map(|u| yw_win::ws::WebSocket::connect(&u, 15_000).err());
                panic!("relay not reachable: {detail:?}");
            }
        }
        return;
    };
    let a: Arc<dyn RelayLink> = connector.connect(&url(&[1; 32], &project)).unwrap();
    let b: Arc<dyn RelayLink> = connector.connect(&url(&[2; 32], &project)).unwrap();
    let key = [0x33_u8; 32];
    let topic = yw_core::hex::encode(&yw_core::walletconnect::topic_of(&key));
    rpc(&*a, 1, "irn_subscribe", &format!(r#"{{"topic":"{topic}"}}"#));
    let subscribed = wait_for(&*a, |v| v.as_object().and_then(|o| o.get("id")).is_some());
    println!("subscribe answer: {}", String::from_utf8_lossy(&yw_json::to_vec(&subscribed)));
    let message =
        yw_core::walletconnect::seal_envelope(&key, &[1; 12], br#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#, None)
            .unwrap();
    rpc(
        &*b,
        2,
        "irn_publish",
        &format!(r#"{{"topic":"{topic}","message":"{message}","ttl":30,"tag":1114}}"#),
    );
    let delivered = wait_for(&*a, |v| {
        v.as_object().and_then(|o| o.get("method")).and_then(Value::as_str) == Some("irn_subscription")
    });
    let data = delivered.as_object().unwrap().get("params").unwrap().as_object().unwrap().get("data").unwrap();
    let got = data.as_object().unwrap().get("message").unwrap().as_str().unwrap();
    let envelope = yw_core::walletconnect::Envelope::decode(got).unwrap();
    let plain = yw_core::walletconnect::open_envelope(&key, &envelope).unwrap();
    assert!(String::from_utf8(plain).unwrap().contains("wc_sessionPing"));
    println!("round trip ok");
    a.abort();
    b.abort();
}
