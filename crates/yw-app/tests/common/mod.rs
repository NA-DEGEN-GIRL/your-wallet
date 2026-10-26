//! Test support: a scripted JSON-RPC transport that records every call (spec/09 §2.1 "가짜 RPC
//! 전송(호출 기록)") and a manual clock.
#![allow(dead_code, reason = "each test binary uses a different subset")]

pub mod evm;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yw_app::flow::evm::{Clock, SharedTransport};
use yw_app::rpc::{HttpReply, Transport};
use yw_json::{Limits, Number, Object, Value};
use yw_win::http::{HttpError, HttpsUrl};

/// A scripted answer.
#[derive(Clone, Debug)]
pub enum Answer {
    /// `result` JSON text.
    Result(String),
    /// JSON-RPC error with optional hex data.
    Error(i64, Option<String>),
    /// A whole envelope (fixture); its `id` is replaced by the request id.
    Envelope(Vec<u8>),
    /// HTTP status without a JSON body.
    Status(u16),
    /// Transport failure.
    Transport(HttpError),
    /// Answer after a real delay.
    Delayed(Duration, Box<Answer>),
}

type Handler = dyn Fn(&str, &Value) -> Answer + Send + Sync;

/// A fake transport.
pub struct FakeRpc {
    handler: Box<Handler>,
    calls: Mutex<Vec<(String, String)>>,
}

impl FakeRpc {
    /// A fake answering with `handler(method, params)`.
    pub fn new(handler: impl Fn(&str, &Value) -> Answer + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            handler: Box::new(handler),
            calls: Mutex::new(Vec::new()),
        })
    }

    /// Methods called so far.
    pub fn methods(&self) -> Vec<String> {
        self.calls
            .lock()
            .map(|calls| calls.iter().map(|(method, _)| method.clone()).collect())
            .unwrap_or_default()
    }

    /// Number of calls of `method`.
    pub fn count(&self, method: &str) -> usize {
        self.methods()
            .iter()
            .filter(|known| *known == method)
            .count()
    }

    /// Raw params text of every call of `method`.
    pub fn params_of(&self, method: &str) -> Vec<String> {
        self.calls
            .lock()
            .map(|calls| {
                calls
                    .iter()
                    .filter(|(known, _)| known == method)
                    .map(|(_, params)| params.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The transport as the pipelines take it.
    pub fn shared(self: &Arc<Self>) -> SharedTransport {
        Arc::clone(self) as SharedTransport
    }
}

fn envelope(id: u64, member: (&str, Value)) -> Vec<u8> {
    let pairs = vec![
        ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
        ("id".to_owned(), Value::Number(Number::from_u64(id))),
        (member.0.to_owned(), member.1),
    ];
    Object::from_pairs(pairs)
        .map_or_else(Vec::new, |object| yw_json::to_vec(&Value::Object(object)))
}

fn answer_bytes(answer: Answer, id: u64) -> Result<HttpReply, HttpError> {
    let limits = Limits {
        max_bytes: 8 * 1_024 * 1_024,
        ..Limits::RESPONSE
    };
    match answer {
        Answer::Result(text) => {
            let value = yw_json::parse(text.as_bytes(), &limits).unwrap_or(Value::Null);
            Ok(HttpReply {
                status: 200,
                body: envelope(id, ("result", value)),
            })
        }
        Answer::Error(code, data) => {
            let mut pairs = vec![
                (
                    "code".to_owned(),
                    Value::Number(
                        Number::from_literal(&code.to_string())
                            .unwrap_or_else(|_| Number::from_u64(0)),
                    ),
                ),
                ("message".to_owned(), Value::String("scripted".to_owned())),
            ];
            if let Some(data) = data {
                pairs.push(("data".to_owned(), Value::String(data)));
            }
            let error = Object::from_pairs(pairs).map_or(Value::Null, Value::Object);
            Ok(HttpReply {
                status: 200,
                body: envelope(id, ("error", error)),
            })
        }
        Answer::Envelope(bytes) => {
            let value = yw_json::parse(&bytes, &limits).unwrap_or(Value::Null);
            let pairs: Vec<(String, Value)> = value
                .as_object()
                .map(|object| {
                    object
                        .iter()
                        .map(|(key, item)| {
                            if key == "id" {
                                (key.to_owned(), Value::Number(Number::from_u64(id)))
                            } else {
                                (key.to_owned(), item.clone())
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            let body = Object::from_pairs(pairs)
                .map_or_else(Vec::new, |object| yw_json::to_vec(&Value::Object(object)));
            Ok(HttpReply { status: 200, body })
        }
        Answer::Status(status) => Ok(HttpReply {
            status,
            body: Vec::new(),
        }),
        Answer::Transport(error) => Err(error),
        Answer::Delayed(delay, inner) => {
            std::thread::sleep(delay);
            answer_bytes(*inner, id)
        }
    }
}

impl Transport for FakeRpc {
    fn post_json(
        &self,
        _url: &HttpsUrl,
        body: &[u8],
        _max_response: usize,
    ) -> Result<HttpReply, HttpError> {
        let limits = Limits {
            max_bytes: 4 * 1_024 * 1_024,
            ..Limits::REQUEST
        };
        let request = yw_json::parse(body, &limits).map_err(|_| HttpError::InvalidUrl)?;
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
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((
                method.clone(),
                String::from_utf8(yw_json::to_vec(&params)).unwrap_or_default(),
            ));
        }
        let answer = (self.handler)(&method, &params);
        answer_bytes(answer, id)
    }
}

/// A manual clock: sleeping advances time without waiting.
#[derive(Debug)]
pub struct FakeClock {
    now_ms: AtomicU64,
    unix_ms: AtomicU64,
}

impl FakeClock {
    /// At `unix_ms` wall time.
    pub fn at(unix_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(1_000_000),
            unix_ms: AtomicU64::new(unix_ms),
        }
    }

    /// Advances both clocks.
    pub fn advance(&self, ms: u64) {
        self.now_ms.fetch_add(ms, Ordering::SeqCst);
        self.unix_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    fn now_unix_ms(&self) -> u64 {
        self.unix_ms.load(Ordering::SeqCst)
    }

    fn sleep_ms(&self, ms: u64) {
        self.advance(ms);
    }
}

/// A test endpoint (never contacted).
pub fn url() -> HttpsUrl {
    HttpsUrl::parse("https://rpc.example.test/v1").unwrap_or_else(|_| {
        HttpsUrl::parse("https://example.com/").unwrap_or_else(|_| unreachable_url())
    })
}

#[expect(clippy::panic, reason = "test helper: the literal URLs always parse")]
fn unreachable_url() -> HttpsUrl {
    panic!("test URL")
}

/// `0x` + lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    format!("0x{}", yw_core::hex::encode(bytes))
}

/// The first param as a string (`eth_getBlockByNumber` tag, `eth_getTransactionCount` account).
pub fn param_str(params: &Value, index: usize) -> String {
    params
        .as_array()
        .and_then(|items| items.get(index))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// A per-method answer table with a default.
pub struct Script {
    /// Method → answer.
    pub answers: HashMap<String, Answer>,
}

impl Script {
    /// Answer for `method` or a JSON-RPC -32601.
    pub fn get(&self, method: &str) -> Answer {
        self.answers
            .get(method)
            .cloned()
            .unwrap_or(Answer::Error(-32_601, None))
    }
}
