//! Browser-bridge test support: a recording outlet and sink, request frame builders from the
//! shared goldens and a dispatcher with the built-in chains registered.

use std::sync::{Arc, Mutex};

use yw_app::browser::envelope::{BrowserEvent, Correlation, Id16, Id32};
use yw_app::browser::{
    BrowserCore, ChainEntry, ConnId, DappEvent, DappSink, Outbound, Outlet, SiteRequest, VaultView,
    WalletView,
};
use yw_app::flow::evm::chain_info;
use yw_app::settings::Settings;
use yw_core::policy::ProviderError;
use yw_json::{Limits, Number, Object, Value};

use super::{FakeClock, url};

/// The golden request (spec/05 §10.3).
pub const REQUEST_GOLDEN: &str =
    include_str!("../../../../extension/native-host/v1-request.golden.json");
/// The golden extension id placeholder.
pub const GOLDEN_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
/// Wall clock of the tests (2023-11-14).
pub const NOW_UNIX: u64 = 1_700_000_000_000;

/// Records outbound frames of one connection.
#[derive(Clone, Default)]
pub struct Recorder(pub Arc<Mutex<Vec<Outbound>>>);

impl Outlet for Recorder {
    fn send(&self, outbound: Outbound) -> bool {
        self.0.lock().map(|mut list| list.push(outbound)).is_ok()
    }
}

impl Recorder {
    /// Takes everything recorded so far.
    pub fn take(&self) -> Vec<Outbound> {
        self.0
            .lock()
            .map(|mut list| std::mem::take(&mut *list))
            .unwrap_or_default()
    }
}

/// Records UI events.
#[derive(Default)]
pub struct Sink(pub Mutex<Vec<DappEvent>>);

impl DappSink for Sink {
    fn push(&self, event: DappEvent) -> bool {
        self.0.lock().map(|mut list| list.push(event)).is_ok()
    }
}

impl Sink {
    /// Takes everything recorded so far.
    pub fn take(&self) -> Vec<DappEvent> {
        self.0
            .lock()
            .map(|mut list| std::mem::take(&mut *list))
            .unwrap_or_default()
    }

    /// The approval requests recorded so far.
    pub fn requests(&self) -> Vec<SiteRequest> {
        self.take()
            .into_iter()
            .filter_map(|event| match event {
                DappEvent::Request(request) => Some(*request),
                _ => None,
            })
            .collect()
    }
}

/// A dispatcher with one connection.
pub struct Harness {
    /// Dispatcher.
    pub core: Arc<BrowserCore>,
    /// UI events.
    pub sink: Arc<Sink>,
    /// Clock.
    pub clock: Arc<FakeClock>,
    /// Connection outbound frames.
    pub out: Recorder,
    /// Connection id.
    pub conn: ConnId,
    sequence: u64,
    request: u8,
}

/// Registered chains: the built-ins (and `extra` user chains) with a test URL each.
pub fn wallet(vault: VaultView, settings: &Settings) -> WalletView {
    let mut ids = vec![1, 11_155_111, 999];
    ids.extend(settings.evm_chains.iter().map(|chain| chain.chain_id));
    WalletView {
        vault,
        chains: ids
            .into_iter()
            .filter_map(|id| {
                chain_info(settings, id).map(|info| ChainEntry {
                    info,
                    url: Some(url()),
                })
            })
            .collect(),
        blocked: Vec::new(),
        evm_chain_id: settings.evm_chain_id,
        allow_localhost: settings.allow_localhost_dapps,
        sol_cluster: yw_core::sol::SolCluster::Mainnet,
        btc_network: yw_core::btc::BtcNetwork::Mainnet,
    }
}

impl Harness {
    /// A dispatcher pinned to the golden id, unlocked, with the default settings.
    pub fn new() -> Self {
        Self::with(VaultView::Unlocked, &Settings::default())
    }

    /// A dispatcher with an explicit vault state and settings.
    pub fn with(vault: VaultView, settings: &Settings) -> Self {
        let sink = Arc::new(Sink::default());
        let clock = Arc::new(FakeClock::at(NOW_UNIX));
        let core = BrowserCore::new(
            GOLDEN_ID,
            Arc::clone(&sink) as Arc<dyn DappSink>,
            Arc::clone(&clock) as Arc<dyn yw_app::flow::evm::Clock>,
        );
        core.set_wallet(wallet(vault, settings));
        let out = Recorder::default();
        let conn = core.open_connection(Box::new(out.clone()));
        sink.take();
        Self {
            core,
            sink,
            clock,
            out,
            conn,
            sequence: 0,
            request: 0,
        }
    }

    /// Sends a request from `origin` / `document`; returns its correlation.
    pub fn send(&mut self, origin: &str, document: u8, method: &str, params: Value) -> Correlation {
        let route = yw_core::policy::Method::parse(method)
            .map_or("permission", |known| known.route().as_str());
        self.send_with(origin, document, method, params, route, None)
    }

    /// Full control over route and deadline.
    pub fn send_with(
        &mut self,
        origin: &str,
        document: u8,
        method: &str,
        params: Value,
        route: &str,
        deadline: Option<u64>,
    ) -> Correlation {
        self.sequence += 1;
        self.request = self.request.wrapping_add(1).max(1);
        let frame = request_frame(&RequestSpec {
            sequence: self.sequence,
            request: self.request,
            document,
            origin,
            method,
            params,
            route,
            deadline: deadline.unwrap_or(NOW_UNIX + 600_000),
        });
        self.core.handle_frame(self.conn, &frame);
        correlation(self.sequence, self.request, document)
    }

    /// Sends raw bytes.
    pub fn raw(&mut self, frame: &[u8]) {
        self.core.handle_frame(self.conn, frame);
    }

    /// Uses up a sequence number (for hand-built frames).
    pub fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// Removes and returns the responses to `correlation`; everything else stays recorded.
    pub fn take_response(&self, wanted: &Correlation) -> Vec<Result<Value, ProviderError>> {
        let all = self.out.take();
        let mut found = Vec::new();
        let mut rest = Vec::new();
        for outbound in all {
            match outbound {
                Outbound::Response { correlation, body } if correlation == *wanted => {
                    found.push(body);
                }
                other => rest.push(other),
            }
        }
        if let Ok(mut list) = self.out.0.lock() {
            rest.extend(list.drain(..));
            *list = rest;
        }
        found
    }

    /// Takes every recorded response (events are dropped).
    pub fn responses(&self) -> Vec<(Correlation, Result<Value, ProviderError>)> {
        self.out
            .take()
            .into_iter()
            .filter_map(|outbound| match outbound {
                Outbound::Response { correlation, body } => Some((correlation, body)),
                Outbound::Event { .. } => None,
            })
            .collect()
    }
}

/// Identifies a document by one byte.
pub fn activation(document: u8) -> Id32 {
    let mut bytes = [0_u8; 32];
    bytes[31] = document.max(1);
    Id32(bytes)
}

/// The correlation of the n-th request.
pub fn correlation(sequence: u64, request: u8, document: u8) -> Correlation {
    Correlation {
        session_id: Id32([0xbb; 32]),
        sequence,
        activation_nonce: activation(document),
        request_id: Id16([request.max(1); 16]),
    }
}

/// Fields of a test request.
pub struct RequestSpec<'a> {
    /// Sequence.
    pub sequence: u64,
    /// Request id byte.
    pub request: u8,
    /// Document byte.
    pub document: u8,
    /// Origin.
    pub origin: &'a str,
    /// Method.
    pub method: &'a str,
    /// Params.
    pub params: Value,
    /// Route.
    pub route: &'a str,
    /// Deadline (Unix ms).
    pub deadline: u64,
}

fn set(object: &Object, changes: &[(&str, Value)]) -> Value {
    let pairs = object
        .iter()
        .map(|(key, value)| {
            let replaced = changes
                .iter()
                .find(|(name, _)| *name == key)
                .map_or_else(|| value.clone(), |(_, value)| value.clone());
            (key.to_owned(), replaced)
        })
        .collect();
    Object::from_pairs(pairs).map_or(Value::Null, Value::Object)
}

/// The golden request as a value.
pub fn golden_request() -> Value {
    yw_json::parse(REQUEST_GOLDEN.as_bytes(), &Limits::REQUEST).unwrap_or(Value::Null)
}

/// A request frame derived from the golden.
pub fn request_frame(spec: &RequestSpec<'_>) -> Vec<u8> {
    let golden = golden_request();
    let Some(object) = golden.as_object() else {
        return Vec::new();
    };
    let context = object
        .get("context")
        .and_then(Value::as_object)
        .map_or(Value::Null, |context| {
            set(
                context,
                &[
                    ("topOrigin", Value::String(spec.origin.to_owned())),
                    ("frameOrigin", Value::String(spec.origin.to_owned())),
                ],
            )
        });
    let value = set(
        object,
        &[
            ("sequence", Value::Number(Number::from_u64(spec.sequence))),
            (
                "deadlineUnixMs",
                Value::Number(Number::from_u64(spec.deadline)),
            ),
            (
                "activationNonce",
                Value::String(activation(spec.document).hex()),
            ),
            (
                "requestId",
                Value::String(Id16([spec.request.max(1); 16]).hex()),
            ),
            ("method", Value::String(spec.method.to_owned())),
            ("params", spec.params.clone()),
            ("route", Value::String(spec.route.to_owned())),
            ("context", context),
        ],
    );
    yw_json::to_vec(&value)
}

/// Parses JSON text (test literals).
pub fn json(text: &str) -> Value {
    yw_json::parse(text.as_bytes(), &Limits::REQUEST).unwrap_or(Value::Null)
}

/// Events recorded for `document`.
pub fn events_of(outbound: &[Outbound], document: u8) -> Vec<BrowserEvent> {
    outbound
        .iter()
        .filter_map(|item| match item {
            Outbound::Event {
                activation_nonce,
                event,
                ..
            } if *activation_nonce == activation(document) => Some(event.clone()),
            _ => None,
        })
        .collect()
}
