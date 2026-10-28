//! Test support for the Bitcoin network layer (spec/09 §1 rules 4–5: no network, fake transport,
//! manual clock): a recording fake transport for GET, JSON-RPC POST and text POST with a
//! scripted handler, a manual clock that records sleeps, a log recorder, the raw `curl -i`
//! fixture parser, the recorded Esplora and Core fixtures, and a healthy testnet4 "world".
#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use yw_app::btc::{BtcEndpoint, BtcEnv, LogSink, Pace};
use yw_app::flow::evm::Clock;
use yw_app::logging::{Field, format_line};
use yw_app::rpc::{HttpReply, Transport};
use yw_app::settings::{BtcIndexer, LogLevel};
use yw_core::bip32::AccountXpub;
use yw_core::btc::BtcNetwork;
use yw_core::btc::network::{SIGNET_GENESIS_HEX, TESTNET3_GENESIS_HEX};
use yw_json::{Limits, Number, Object, Value};
use yw_win::http::{HttpError, HttpsUrl, Response};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A server-provided string that must never reach an outcome, error or display text.
pub const SERVER_STRING: &str = "SERVER-PHISHING-TEXT visit evil.example";
/// Fake Core endpoint (token-like path; must never appear in logs).
pub const CORE_URL: &str = "https://core.example.test/secret-token-path/";
/// Fake Esplora base.
pub const ESPLORA_BASE: &str = "https://esplora.example.test/testnet4/api";

pub const TESTNET4_GENESIS: &str =
    "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";
pub const MAINNET_GENESIS: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
pub const TESTNET3_GENESIS: &str = TESTNET3_GENESIS_HEX;
pub const SIGNET_GENESIS: &str = SIGNET_GENESIS_HEX;

/// testnet4 tip and median time of the recorded `getblockchaininfo` (2026-10-27).
pub const TIP: u32 = 157_717;
pub const MEDIAN_TIME: u64 = 1_793_068_708;
/// Local time of the tests (the fixture's block `time`).
pub const NOW_UNIX_SECS: u64 = 1_793_074_713;

/// The recorded testnet4 transaction `005aa50e…77f1` (vout 0 pays program `7b458433…ac75`).
pub const REAL_TXID: &str = "005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1";
pub const REAL_PROGRAM: &str = "7b458433d0c04323426ef88365bd4cfef141ac75";
pub const REAL_VALUE: u64 = 5_840_453_620_191;

/// abandon…about testnet4 account m/84'/1'/0' (spec/08 §14.1, public data).
pub const ACCOUNT_PUBKEY: &str =
    "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4";
pub const ACCOUNT_CHAIN_CODE: &str =
    "3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62";
/// Its receive 0/0 address.
pub const ADDRESS_0_0: &str = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl";

pub mod esplora {
    //! Raw `curl -i` responses recorded from mempool.space (spec/08 §4.5 E1–E3).
    pub const MAINNET_BLOCK_HEIGHT_0: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/mainnet-block-height-0.http");
    pub const MAINNET_BLOCK_HEIGHT_0_SLASH: &[u8] = include_bytes!(
        "../../../yw-core/tests/vectors/btc/esplora/mainnet-block-height-0-trailing-slash.http"
    );
    pub const MAINNET_TIP_HEIGHT: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/mainnet-tip-height.http");
    pub const MAINNET_ADDRESS_USED: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/mainnet-address-used.http");
    pub const TESTNET4_ADDRESS_MAINNET_400: &[u8] = include_bytes!(
        "../../../yw-core/tests/vectors/btc/esplora/testnet4-address-mainnet-400.http"
    );
    pub const TESTNET4_ADDRESS_UNUSED: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/testnet4-address-unused.http");
    pub const TESTNET4_ADDRESS_USED: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/testnet4-address-used.http");
    pub const TESTNET4_BLOCK_HEIGHT_0: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/testnet4-block-height-0.http");
    pub const TESTNET4_TIP_HEIGHT: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/testnet4-tip-height.http");
    pub const TESTNET4_TX_HEX: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/testnet4-tx-hex.http");
    pub const TESTNET4_TX_HEX_MISSING: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/testnet4-tx-hex-missing.http");
    pub const TESTNET4_TX_STATUS_CONFIRMED: &[u8] = include_bytes!(
        "../../../yw-core/tests/vectors/btc/esplora/testnet4-tx-status-confirmed.http"
    );
    pub const TESTNET4_TX_STATUS_MISSING: &[u8] = include_bytes!(
        "../../../yw-core/tests/vectors/btc/esplora/testnet4-tx-status-missing.http"
    );
    pub const TESTNET4_UTXO: &[u8] =
        include_bytes!("../../../yw-core/tests/vectors/btc/esplora/testnet4-utxo.http");
}

pub mod core {
    //! Bitcoin Core JSON-RPC bodies recorded 2026-10-27 (request id 1).
    pub const MAINNET_ESTIMATESMARTFEE_6: &[u8] =
        include_bytes!("../fixtures/btc_core/mainnet-estimatesmartfee-6.json");
    pub const MAINNET_GETBLOCKCHAININFO: &[u8] =
        include_bytes!("../fixtures/btc_core/mainnet-getblockchaininfo.json");
    pub const TESTNET4_ESTIMATESMARTFEE_6: &[u8] =
        include_bytes!("../fixtures/btc_core/testnet4-estimatesmartfee-6.json");
    pub const TESTNET4_GETBLOCKCHAININFO: &[u8] =
        include_bytes!("../fixtures/btc_core/testnet4-getblockchaininfo.json");
    pub const TESTNET4_GETBLOCKHASH_0: &[u8] =
        include_bytes!("../fixtures/btc_core/testnet4-getblockhash-0.json");
    pub const TESTNET4_GETMEMPOOLINFO: &[u8] =
        include_bytes!("../fixtures/btc_core/testnet4-getmempoolinfo.json");
    pub const TESTNET4_GETRAWTRANSACTION: &[u8] =
        include_bytes!("../fixtures/btc_core/testnet4-getrawtransaction.json");
    pub const TESTNET4_GETRAWTRANSACTION_MISSING: &[u8] =
        include_bytes!("../fixtures/btc_core/testnet4-getrawtransaction-missing.json");
    pub const TESTNET4_TESTMEMPOOLACCEPT_MISSING_INPUTS: &[u8] =
        include_bytes!("../fixtures/btc_core/testnet4-testmempoolaccept-missing-inputs.json");
}

/// Parses a raw `curl -i` capture (CRLF or LF): status line, headers, blank line, body.
pub fn http_fixture(raw: &[u8]) -> Response {
    let (head, body) = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| (&raw[..at], &raw[at + 4..]))
        .or_else(|| {
            raw.windows(2)
                .position(|window| window == b"\n\n")
                .map(|at| (&raw[..at], &raw[at + 2..]))
        })
        .unwrap_or((raw, &[]));
    let head = String::from_utf8_lossy(head);
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let content_type = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-type")
            .then(|| value.trim().to_owned())
    });
    Response {
        status,
        content_type,
        body: body.to_vec(),
    }
}

/// The body of a fixture as text.
pub fn fixture_body(raw: &[u8]) -> String {
    String::from_utf8_lossy(&http_fixture(raw).body).into_owned()
}

/// Request kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    /// `http_get`.
    Get,
    /// JSON-RPC `post_json`.
    Rpc,
    /// `http_post_text`.
    PostText,
}

/// One recorded request.
#[derive(Clone, Debug)]
pub struct Call {
    /// Kind.
    pub verb: Verb,
    /// Full URL (tests only).
    pub url: String,
    /// JSON-RPC method (empty for GET/POST text).
    pub method: String,
    /// JSON-RPC params as JSON text.
    pub params: String,
    /// Request body.
    pub body: Vec<u8>,
    /// Response cap asked.
    pub cap: usize,
    /// Monotonic ms when the request started.
    pub at_ms: u64,
}

impl Call {
    /// URL tail after the Esplora base (or the whole URL).
    pub fn path(&self) -> &str {
        self.url.strip_prefix(ESPLORA_BASE).unwrap_or(&self.url)
    }
}

/// A scripted answer.
#[derive(Clone, Debug)]
pub enum Reply {
    /// HTTP status, content type, body.
    Http(u16, Option<String>, Vec<u8>),
    /// JSON-RPC `result` JSON text.
    Result(String),
    /// JSON-RPC error with the server string as `message`.
    RpcError(i64),
    /// A whole envelope (fixture); its `id` is replaced by the request id.
    Envelope(Vec<u8>),
    /// A body sent unchanged with HTTP 200.
    Raw(Vec<u8>),
    /// Transport failure.
    Transport(HttpError),
    /// Advances the clock by `ms` (a late reply), then answers.
    Late(u64, Box<Reply>),
}

impl Reply {
    /// A recorded `curl -i` capture.
    pub fn fixture(raw: &[u8]) -> Self {
        let response = http_fixture(raw);
        Self::Http(response.status, response.content_type, response.body)
    }

    /// 200 `application/json`.
    pub fn json(body: &str) -> Self {
        Self::Http(
            200,
            Some("application/json".to_owned()),
            body.as_bytes().to_vec(),
        )
    }

    /// 200 `text/plain`.
    pub fn text(body: &str) -> Self {
        Self::Http(200, Some("text/plain".to_owned()), body.as_bytes().to_vec())
    }

    /// An error status with the server string as `text/plain` body.
    pub fn status(code: u16) -> Self {
        Self::Http(
            code,
            Some("text/plain".to_owned()),
            SERVER_STRING.as_bytes().to_vec(),
        )
    }
}

/// A manual clock: sleeping advances time and is recorded.
#[derive(Debug)]
pub struct ManualClock {
    now_ms: AtomicU64,
    unix_ms: AtomicU64,
    sleeps: Mutex<Vec<u64>>,
}

impl ManualClock {
    /// At [`NOW_UNIX_SECS`].
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            now_ms: AtomicU64::new(1_000_000),
            unix_ms: AtomicU64::new(NOW_UNIX_SECS * 1_000),
            sleeps: Mutex::new(Vec::new()),
        })
    }

    /// Advances both clocks without recording a sleep.
    pub fn advance(&self, ms: u64) {
        self.now_ms.fetch_add(ms, Ordering::SeqCst);
        self.unix_ms.fetch_add(ms, Ordering::SeqCst);
    }

    /// Sleeps so far (pacing waits included).
    pub fn sleeps(&self) -> Vec<u64> {
        self.sleeps
            .lock()
            .map(|list| list.clone())
            .unwrap_or_default()
    }

    /// The 429 back-off sleeps (pacing waits are below 200 ms).
    pub fn backoffs(&self) -> Vec<u64> {
        self.sleeps()
            .into_iter()
            .filter(|ms| *ms >= 1_000)
            .collect()
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    fn now_unix_ms(&self) -> u64 {
        self.unix_ms.load(Ordering::SeqCst)
    }

    fn sleep_ms(&self, ms: u64) {
        if let Ok(mut list) = self.sleeps.lock() {
            list.push(ms);
        }
        self.advance(ms);
    }
}

type Handler = dyn Fn(&Call) -> Reply + Send + Sync;

/// The recording fake transport. Every request costs 10 ms of clock time.
pub struct FakeBtc {
    handler: Box<Handler>,
    clock: Arc<ManualClock>,
    calls: Mutex<Vec<Call>>,
}

impl FakeBtc {
    /// A fake answering with `handler`.
    pub fn new(
        clock: &Arc<ManualClock>,
        handler: impl Fn(&Call) -> Reply + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            handler: Box::new(handler),
            clock: Arc::clone(clock),
            calls: Mutex::new(Vec::new()),
        })
    }

    /// Every request so far.
    pub fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }

    /// Number of requests.
    pub fn count(&self) -> usize {
        self.calls().len()
    }

    /// JSON-RPC methods in order.
    pub fn methods(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|call| call.verb == Verb::Rpc)
            .map(|call| call.method)
            .collect()
    }

    /// GET paths (after the Esplora base) in order.
    pub fn get_paths(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|call| call.verb == Verb::Get)
            .map(|call| call.path().to_owned())
            .collect()
    }

    /// Requests of `verb`.
    pub fn count_verb(&self, verb: Verb) -> usize {
        self.calls().iter().filter(|call| call.verb == verb).count()
    }

    fn record(&self, call: Call) -> Reply {
        let reply = (self.handler)(&call);
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
        self.clock.advance(10);
        reply
    }

    fn http(&self, reply: Reply) -> Result<Response, HttpError> {
        match reply {
            Reply::Http(status, content_type, body) => Ok(Response {
                status,
                content_type,
                body,
            }),
            Reply::Raw(body) => Ok(Response {
                status: 200,
                content_type: None,
                body,
            }),
            Reply::Transport(error) => Err(error),
            Reply::Late(ms, inner) => {
                self.clock.advance(ms);
                self.http(*inner)
            }
            Reply::Result(_) | Reply::RpcError(_) | Reply::Envelope(_) => {
                Err(HttpError::InvalidUrl)
            }
        }
    }
}

fn envelope(id: u64, member: (&str, Value)) -> Vec<u8> {
    let pairs = vec![
        ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
        (member.0.to_owned(), member.1),
        ("id".to_owned(), Value::Number(Number::from_u64(id))),
    ];
    Object::from_pairs(pairs)
        .map_or_else(Vec::new, |object| yw_json::to_vec(&Value::Object(object)))
}

fn big() -> Limits {
    Limits {
        max_bytes: 8 * 1_048_576,
        ..Limits::RESPONSE
    }
}

fn rpc_reply(reply: Reply, id: u64, clock: &ManualClock) -> Result<HttpReply, HttpError> {
    match reply {
        Reply::Result(text) => {
            let value = yw_json::parse(text.as_bytes(), &big()).unwrap_or(Value::Null);
            Ok(HttpReply {
                status: 200,
                body: envelope(id, ("result", value)),
            })
        }
        Reply::RpcError(code) => {
            let pairs = vec![
                (
                    "code".to_owned(),
                    Value::Number(
                        Number::from_literal(&code.to_string())
                            .unwrap_or_else(|_| Number::from_u64(0)),
                    ),
                ),
                (
                    "message".to_owned(),
                    Value::String(SERVER_STRING.to_owned()),
                ),
            ];
            let error = Object::from_pairs(pairs).map_or(Value::Null, Value::Object);
            Ok(HttpReply {
                status: 200,
                body: envelope(id, ("error", error)),
            })
        }
        Reply::Envelope(bytes) => {
            let value = yw_json::parse(&bytes, &big()).unwrap_or(Value::Null);
            let pairs: Vec<(String, Value)> = value
                .as_object()
                .map(|object| {
                    object
                        .iter()
                        .map(|(key, item)| {
                            let item = if key == "id" {
                                Value::Number(Number::from_u64(id))
                            } else {
                                item.clone()
                            };
                            (key.to_owned(), item)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let body = Object::from_pairs(pairs)
                .map_or_else(Vec::new, |object| yw_json::to_vec(&Value::Object(object)));
            Ok(HttpReply { status: 200, body })
        }
        Reply::Raw(body) => Ok(HttpReply { status: 200, body }),
        Reply::Http(status, _, body) => Ok(HttpReply { status, body }),
        Reply::Transport(error) => Err(error),
        Reply::Late(ms, inner) => {
            clock.advance(ms);
            rpc_reply(*inner, id, clock)
        }
    }
}

impl Transport for FakeBtc {
    fn post_json(
        &self,
        url: &HttpsUrl,
        body: &[u8],
        max_response: usize,
    ) -> Result<HttpReply, HttpError> {
        let request = yw_json::parse(body, &big()).map_err(|_| HttpError::InvalidUrl)?;
        let object = request.as_object().ok_or(HttpError::InvalidUrl)?;
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let id = object
            .get("id")
            .and_then(Value::as_number)
            .and_then(Number::as_u64)
            .unwrap_or(0);
        let params = object
            .get("params")
            .map(|params| String::from_utf8(yw_json::to_vec(params)).unwrap_or_default())
            .unwrap_or_default();
        let reply = self.record(Call {
            verb: Verb::Rpc,
            url: url.expose().to_owned(),
            method,
            params,
            body: body.to_vec(),
            cap: max_response,
            at_ms: self.clock.now_ms(),
        });
        rpc_reply(reply, id, &self.clock)
    }

    fn http_get(&self, url: &HttpsUrl, max_response: usize) -> Result<Response, HttpError> {
        let reply = self.record(Call {
            verb: Verb::Get,
            url: url.expose().to_owned(),
            method: String::new(),
            params: String::new(),
            body: Vec::new(),
            cap: max_response,
            at_ms: self.clock.now_ms(),
        });
        self.http(reply)
    }

    fn http_post_text(
        &self,
        url: &HttpsUrl,
        body: &[u8],
        max_response: usize,
    ) -> Result<Response, HttpError> {
        let reply = self.record(Call {
            verb: Verb::PostText,
            url: url.expose().to_owned(),
            method: String::new(),
            params: String::new(),
            body: body.to_vec(),
            cap: max_response,
            at_ms: self.clock.now_ms(),
        });
        self.http(reply)
    }
}

/// Records formatted log lines.
#[derive(Debug, Default)]
pub struct LogRecorder {
    lines: Mutex<Vec<String>>,
}

impl LogRecorder {
    /// Lines so far.
    pub fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|lines| lines.clone())
            .unwrap_or_default()
    }

    /// Asserts that no line names a URL, host or token (spec/04 §8).
    pub fn assert_no_url(&self) {
        let lines = self.lines();
        assert!(!lines.is_empty());
        for line in &lines {
            for forbidden in [
                "https",
                "example",
                "secret-token",
                "esplora.example",
                "core.example",
                SERVER_STRING,
            ] {
                assert!(!line.contains(forbidden), "{forbidden} in {line}");
            }
            assert!(line.contains("net=bitcoin:"), "{line}");
        }
    }
}

impl LogSink for LogRecorder {
    fn log(&self, level: LogLevel, event: &'static str, fields: &[(&'static str, Field<'_>)]) {
        if let Ok(mut lines) = self.lines.lock() {
            lines.push(format_line(0, level, "btc", event, fields));
        }
    }
}

/// Everything a job needs, owned.
pub struct Rig {
    pub clock: Arc<ManualClock>,
    pub fake: Arc<FakeBtc>,
    pub pace: Pace,
    pub log: LogRecorder,
    pub endpoint: BtcEndpoint,
}

impl Rig {
    /// A testnet4 rig with `indexer` and the scripted `handler`.
    pub fn new(
        indexer: BtcIndexer,
        handler: impl Fn(&Call) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let clock = ManualClock::new();
        let fake = FakeBtc::new(&clock, handler);
        Self {
            clock,
            fake,
            pace: Pace::new(),
            log: LogRecorder::default(),
            endpoint: endpoint(BtcNetwork::Testnet4, indexer),
        }
    }

    /// The job environment.
    pub fn env(&self) -> BtcEnv<'_> {
        BtcEnv {
            transport: &*self.fake,
            clock: &*self.clock,
            pace: &self.pace,
            log: &self.log,
        }
    }
}

/// The fake endpoint of `net`.
pub fn endpoint(net: BtcNetwork, indexer: BtcIndexer) -> BtcEndpoint {
    BtcEndpoint {
        net,
        core_url: HttpsUrl::parse(CORE_URL).unwrap_or_else(|_| unreachable_url()),
        indexer,
        esplora_base: HttpsUrl::parse(ESPLORA_BASE).unwrap_or_else(|_| unreachable_url()),
    }
}

#[expect(clippy::panic, reason = "test helper: the literal URLs always parse")]
fn unreachable_url() -> HttpsUrl {
    panic!("test URL")
}

/// The abandon…about testnet4 account.
pub fn account() -> AccountXpub {
    AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(ACCOUNT_PUBKEY).unwrap_or([2; 33]),
        chain_code: yw_core::hex::decode_array::<32>(ACCOUNT_CHAIN_CODE).unwrap_or([0; 32]),
    }
}

/// An Esplora address summary body.
pub fn address_json(address: &str, chain: [u32; 3], mempool: [u32; 3]) -> String {
    format!(
        "{{\"address\":\"{address}\",\"chain_stats\":{{\"funded_txo_count\":{},\"funded_txo_sum\":0,\"spent_txo_count\":{},\"spent_txo_sum\":0,\"tx_count\":{}}},\"mempool_stats\":{{\"funded_txo_count\":{},\"funded_txo_sum\":0,\"spent_txo_count\":{},\"spent_txo_sum\":0,\"tx_count\":{}}}}}",
        chain[0], chain[1], chain[2], mempool[0], mempool[1], mempool[2]
    )
}

/// The address of an Esplora `/address/{a}` or `/address/{a}/utxo` path.
pub fn path_address(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/address/")?;
    Some(rest.strip_suffix("/utxo").unwrap_or(rest))
}

/// `getblockchaininfo` result text.
pub fn chain_info(chain: &str, blocks: u32, headers: u32, ibd: bool, median: u64) -> String {
    format!(
        "{{\"chain\":\"{chain}\",\"blocks\":{blocks},\"headers\":{headers},\"initialblockdownload\":{ibd},\"mediantime\":{median},\"verificationprogress\":1,\"warnings\":\"{SERVER_STRING}\"}}"
    )
}

/// A healthy testnet4 world: Core genesis/chain info/mempool info, Esplora genesis and tip,
/// unused addresses with no UTXO; anything else 404.
pub fn healthy(call: &Call) -> Reply {
    match call.verb {
        Verb::Rpc => match call.method.as_str() {
            "getblockhash" => Reply::Envelope(core::TESTNET4_GETBLOCKHASH_0.to_vec()),
            "getblockchaininfo" => {
                Reply::Result(chain_info("testnet4", TIP, TIP, false, MEDIAN_TIME))
            }
            "getmempoolinfo" => Reply::Envelope(core::TESTNET4_GETMEMPOOLINFO.to_vec()),
            "bb_getBlockHash" => Reply::Result(format!("{{\"blockHash\":\"{TESTNET4_GENESIS}\"}}")),
            _ => Reply::RpcError(-32_601),
        },
        Verb::Get => {
            let path = call.path();
            if path == "/block-height/0" {
                Reply::fixture(esplora::TESTNET4_BLOCK_HEIGHT_0)
            } else if path == "/blocks/tip/height" {
                Reply::fixture(esplora::TESTNET4_TIP_HEIGHT)
            } else if let Some(address) = path_address(path) {
                if path.ends_with("/utxo") {
                    Reply::json("[]")
                } else {
                    Reply::json(&address_json(address, [0; 3], [0; 3]))
                }
            } else {
                Reply::status(404)
            }
        }
        Verb::PostText => Reply::status(500),
    }
}

/// Chain-check input of the tests.
pub fn chain_input() -> yw_app::btc::chain::ChainInput {
    yw_app::btc::chain::ChainInput {
        max_tip_seen: 0,
        now_unix_secs: NOW_UNIX_SECS,
    }
}

/// The JSON-RPC `params` of a call as a value.
pub fn params(call: &Call) -> Value {
    yw_json::parse(call.params.as_bytes(), &big()).unwrap_or(Value::Null)
}

/// First param as text.
pub fn first_param(call: &Call) -> String {
    params(call)
        .as_array()
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}
