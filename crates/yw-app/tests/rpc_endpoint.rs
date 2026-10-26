//! ST-4 (spec/04 §6.5) endpoint `테스트` with a fake transport: chain/genesis/chain-name checks,
//! HTTP classification, no call without an endpoint, and no URL in messages or log lines.

use std::sync::Mutex;

use yw_app::errors::ErrorCode;
use yw_app::logging::{Field, format_line};
use yw_app::network::{BtcNet, NetworkId, SolCluster};
use yw_app::rpc::{HttpReply, RpcClient, TestOutcome, Transport, endpoint_for_test, test_endpoint};
use yw_app::settings::LogLevel;
use yw_win::http::{HttpError, HttpsUrl};

struct Fake {
    status: u16,
    result: &'static str,
    calls: Mutex<u32>,
}

impl Transport for Fake {
    fn post_json(&self, _url: &HttpsUrl, body: &[u8], _max: usize) -> Result<HttpReply, HttpError> {
        if let Ok(mut calls) = self.calls.lock() {
            *calls += 1;
        }
        let request = yw_json::parse(body, &yw_json::Limits::REQUEST)
            .map_err(|_| HttpError::InvalidHeader)?;
        let id = request
            .as_object()
            .and_then(|object| object.get("id"))
            .and_then(yw_json::Value::as_number)
            .and_then(yw_json::Number::as_u64)
            .unwrap_or(0);
        Ok(HttpReply {
            status: self.status,
            body: format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{}}}"#, self.result).into_bytes(),
        })
    }
}

fn fake(status: u16, result: &'static str) -> Fake {
    Fake {
        status,
        result,
        calls: Mutex::new(0),
    }
}

fn url() -> HttpsUrl {
    HttpsUrl::parse("https://secret-name.example/tok_secret_value/")
        .unwrap_or_else(|_| unreachable!("valid"))
}

#[test]
fn evm_chain_id_match_and_mismatch() {
    let ok = fake(200, r#""0x1""#);
    let client = RpcClient::new(&ok);
    assert_eq!(
        test_endpoint(&client, NetworkId::Eip155(1), &url()),
        TestOutcome::Ok("chainId 1".to_owned())
    );
    let base = fake(200, r#""0x2105""#);
    let client = RpcClient::new(&base);
    let outcome = test_endpoint(&client, NetworkId::Eip155(1), &url());
    assert_eq!(
        outcome,
        TestOutcome::Mismatch {
            item: "chainId",
            rpc_chain_id: Some(8_453)
        }
    );
    assert_eq!(
        outcome.message("Ethereum 메인넷"),
        "엔드포인트 테스트 실패: chainId 불일치 — 다른 네트워크의 URL입니다. (RPC chainId 8453) (E-RPC-010)"
    );
    let sepolia_on_mainnet = fake(200, r#""0x1""#);
    let client = RpcClient::new(&sepolia_on_mainnet);
    assert_eq!(
        test_endpoint(&client, NetworkId::Eip155(11_155_111), &url()).message("Sepolia 테스트넷"),
        "엔드포인트 테스트 실패: chainId 불일치 — 다른 네트워크의 URL입니다. (RPC chainId 1) (E-RPC-010)"
    );
    let garbage = fake(200, r#""zz""#);
    let client = RpcClient::new(&garbage);
    assert_eq!(
        test_endpoint(&client, NetworkId::Eip155(1), &url()),
        TestOutcome::Failed(ErrorCode::Rpc005)
    );
}

#[test]
fn solana_and_bitcoin_mismatches() {
    let other_genesis = fake(200, r#""EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG""#);
    let client = RpcClient::new(&other_genesis);
    assert_eq!(
        test_endpoint(&client, NetworkId::Solana(SolCluster::Mainnet), &url()),
        TestOutcome::Mismatch {
            item: "genesis",
            rpc_chain_id: None
        }
    );
    assert_eq!(
        test_endpoint(&client, NetworkId::Solana(SolCluster::Devnet), &url()),
        TestOutcome::Ok("genesis 일치".to_owned())
    );
    let test_chain = fake(200, r#"{"chain":"test","blocks":1}"#);
    let client = RpcClient::new(&test_chain);
    assert_eq!(
        test_endpoint(&client, NetworkId::Bitcoin(BtcNet::Testnet4), &url()),
        TestOutcome::Mismatch {
            item: "chain",
            rpc_chain_id: None
        }
    );
    let main = fake(200, r#"{"chain":"main"}"#);
    let client = RpcClient::new(&main);
    assert_eq!(
        test_endpoint(&client, NetworkId::Bitcoin(BtcNet::Mainnet), &url()),
        TestOutcome::Ok("chain main".to_owned())
    );
}

#[test]
fn http_status_classification() {
    for (status, code) in [
        (401, ErrorCode::Rpc003),
        (403, ErrorCode::Rpc003),
        (429, ErrorCode::Rpc004),
        (500, ErrorCode::Rpc007),
    ] {
        let transport = fake(status, r#""0x1""#);
        let client = RpcClient::new(&transport);
        assert_eq!(
            test_endpoint(&client, NetworkId::Eip155(1), &url()),
            TestOutcome::Failed(code),
            "{status}"
        );
    }
}

#[test]
fn no_endpoint_means_no_call_and_e_key_005() {
    let transport = fake(200, r#""0x1""#);
    assert_eq!(
        endpoint_for_test("", None).map(|_| ()),
        Err(ErrorCode::Key005)
    );
    assert_eq!(
        endpoint_for_test("  ", None).map(|_| ()),
        Err(ErrorCode::Key005)
    );
    assert_eq!(
        endpoint_for_test("http://x", Some(url())).map(|_| ()),
        Err(ErrorCode::Key003)
    );
    assert!(endpoint_for_test("", Some(url())).is_ok());
    assert_eq!(
        *transport
            .calls
            .lock()
            .unwrap_or_else(|_| unreachable!("lock")),
        0
    );
}

#[test]
fn messages_and_log_lines_never_contain_the_url() {
    let base = fake(200, r#""0x2105""#);
    let client = RpcClient::new(&base);
    let outcome = test_endpoint(&client, NetworkId::Eip155(1), &url());
    let message = outcome.message("Ethereum 메인넷");
    let line = format_line(
        0,
        LogLevel::Info,
        "rpc",
        "rpc.test",
        &[
            ("net", Field::Net(NetworkId::Eip155(1))),
            ("result", Field::Word(outcome.log_word())),
        ],
    );
    for text in [message.as_str(), line.as_str()] {
        assert!(!text.contains("secret-name"));
        assert!(!text.contains("tok_secret_value"));
        assert!(!text.contains("https://"));
    }
    assert!(line.contains("net=eip155:1"));
    assert!(line.contains("result=E-RPC-010"));
}
