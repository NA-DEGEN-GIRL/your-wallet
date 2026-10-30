//! Native messaging envelope v1 (spec/05 §6.1, §6.5) and the pipe hello (§8.2).
//!
//! Ported from `archive/spec-v2.4:crates/native-host/src/wire.rs:832-1038` (exact key sets,
//! fixed-width lowercase hex identifiers, JavaScript safe integers, route/literal checks, cancel
//! sequencing) with serde replaced by yw-json, per-request errors instead of stream errors (D23,
//! [`EnvelopeError`] carries the correlation so the dispatcher answers that request only), the
//! v3 context rules (pinned extension id, spec/05 §4.7 origins, the localhost toggle) and a new
//! event encoder. Integers of the envelope accept `<digits>.0` (spec/05 §6.1,
//! `as_u64_allow_dot_zero`).

use core::fmt;

use yw_core::policy::{BrowserOrigin, ProviderError, Route};
use yw_json::{Limits, Number, Object, Value};

use crate::text::{json_object, json_str, json_u64};

/// `namespace` of every envelope.
pub const NAMESPACE: &str = "your-wallet";
/// Envelope version.
pub const PROTOCOL_VERSION: u64 = 1;
/// Pipe protocol version (hello).
pub const PIPE_PROTOCOL: u64 = 1;
/// JavaScript `Number.MAX_SAFE_INTEGER`.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Frame bound in both directions (spec/05 §7.3).
pub const MAX_FRAME_BYTES: usize = 1_048_576;

/// A 32-byte identifier, `id64` on the wire (64 lowercase hex, not all zero).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id32(pub [u8; 32]);

/// A 16-byte identifier, `id32` on the wire (32 lowercase hex, not all zero).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id16(pub [u8; 16]);

fn parse_fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N.saturating_mul(2) {
        return None;
    }
    let bytes = yw_core::hex::decode_array::<N>(text).ok()?;
    bytes.iter().any(|byte| *byte != 0).then_some(bytes)
}

impl Id32 {
    /// Parses `id64`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        parse_fixed::<32>(text).map(Self)
    }

    /// The wire form.
    #[must_use]
    pub fn hex(&self) -> String {
        yw_core::hex::encode(&self.0)
    }
}

impl Id16 {
    /// Parses `id32`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        parse_fixed::<16>(text).map(Self)
    }

    /// The wire form.
    #[must_use]
    pub fn hex(&self) -> String {
        yw_core::hex::encode(&self.0)
    }
}

impl fmt::Debug for Id32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Id32(..)")
    }
}

impl fmt::Debug for Id16 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Id16(..)")
    }
}

/// The extension compatibility mode the page was served under (spec/05 §2.12, §6.1 optional
/// `context.compatMode`). Display only: it never changes origin, permission or approval rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompatMode {
    /// `"metamask"`: the page saw the provider under the `MetaMask` identity.
    MetaMask,
    /// `"rabby"`: the page saw the provider under the `Rabby Wallet` identity.
    Rabby,
    /// `"phantom"`: Solana requests of a page that saw the `Phantom` identity.
    Phantom,
    /// `"unisat"`: Bitcoin requests through the `window.unisat` shim.
    Unisat,
    /// `"xverse"`: Bitcoin requests through the sats-connect (`XverseProviders`) shim.
    Xverse,
}

impl CompatMode {
    /// Parses the wire value. The default mode is the absence of the key, so `"off"` (like any
    /// other value) is not accepted.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "metamask" => Some(Self::MetaMask),
            "rabby" => Some(Self::Rabby),
            "phantom" => Some(Self::Phantom),
            "unisat" => Some(Self::Unisat),
            "xverse" => Some(Self::Xverse),
            _ => None,
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetaMask => "metamask",
            Self::Rabby => "rabby",
            Self::Phantom => "phantom",
            Self::Unisat => "unisat",
            Self::Xverse => "xverse",
        }
    }

    /// The wallet name shown in the approval windows.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MetaMask => "MetaMask",
            Self::Rabby => "Rabby",
            Self::Phantom => "Phantom",
            Self::Unisat => "UniSat",
            Self::Xverse => "Xverse",
        }
    }

    /// The method family the mode may tag (spec/05 §2.12: an EVM mode on a `sol_*` request, or
    /// the reverse, is a malformed request).
    #[must_use]
    pub const fn family(self) -> yw_core::policy::Family {
        match self {
            Self::MetaMask | Self::Rabby => yw_core::policy::Family::Evm,
            Self::Phantom => yw_core::policy::Family::Solana,
            Self::Unisat | Self::Xverse => yw_core::policy::Family::Bitcoin,
        }
    }
}

/// The browser context of a request (spec/05 §6.1 `context`, after validation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserContext {
    /// Chrome tab id.
    pub tab_id: u64,
    /// Chrome document id.
    pub document_id: String,
    /// Top-level origin (= frame origin).
    pub origin: BrowserOrigin,
    /// Page channel nonce.
    pub channel_nonce: Id32,
    /// Optional compatibility mode (spec/05 §2.12); `None` = default mode (key absent).
    pub compat_mode: Option<CompatMode>,
}

/// The four correlation fields every response echoes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Correlation {
    /// Native session.
    pub session_id: Id32,
    /// The request's `sequence`.
    pub sequence: u64,
    /// Document activation.
    pub activation_nonce: Id32,
    /// Request id.
    pub request_id: Id16,
}

/// A validated request envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestEnvelope {
    /// Correlation.
    pub correlation: Correlation,
    /// Extension deadline (Unix ms).
    pub deadline_unix_ms: u64,
    /// Profile install id (format only).
    pub profile_install_id: Id32,
    /// Method name (not yet checked against the allowlist).
    pub method: String,
    /// Params (array or object).
    pub params: Value,
    /// Route the extension computed.
    pub route: Route,
    /// Context.
    pub context: BrowserContext,
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Params and origins are dApp data (D28): never formatted.
        formatter
            .debug_struct("RequestEnvelope")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

/// A validated cancel envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelEnvelope {
    /// Native session.
    pub session_id: Id32,
    /// The cancel's own sequence.
    pub sequence: u64,
    /// Document activation.
    pub activation_nonce: Id32,
    /// Cancelled request id.
    pub request_id: Id16,
    /// Cancelled request's sequence (`1 ≤ requestSequence < sequence`).
    pub request_sequence: u64,
    /// `^[A-Za-z0-9_-]{1,128}$`.
    pub reason: String,
}

/// An inbound envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A request.
    Request(Box<RequestEnvelope>),
    /// A cancel (never answered).
    Cancel(CancelEnvelope),
}

/// Why a frame was not accepted (spec/05 §6.2 steps 1–4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Not JSON, not a request with well-formed correlation fields, or a bad cancel: dropped.
    Uncorrelated,
    /// A request envelope violation: -32600 for that request only.
    Invalid(Correlation),
    /// An http origin while `allowLocalhostDapps` is off: 4100.
    LocalhostDisabled(Correlation),
}

/// A provider event (spec/05 §6.1 `event`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "named after the wire events (accountsChanged, chainChanged, …)"
)]
pub enum BrowserEvent {
    /// `accountsChanged` (0..=16 accounts).
    AccountsChanged(Vec<[u8; 20]>),
    /// `chainChanged`.
    ChainChanged(u64),
    /// `solAccountsChanged`: the connected Solana account (0..=1 public keys, spec/05 §4.9).
    SolAccountsChanged(Vec<[u8; 32]>),
    /// `btcAccountsChanged`: the connected Bitcoin addresses (0..=2, spec/05 §4.9).
    BtcAccountsChanged(Vec<String>),
}

fn int_field(value: Option<&Value>) -> Option<u64> {
    value
        .and_then(Value::as_number)
        .and_then(Number::as_u64_allow_dot_zero)
}

fn safe_field(value: Option<&Value>) -> Option<u64> {
    int_field(value).filter(|number| (1..=MAX_SAFE_INTEGER).contains(number))
}

fn str_field<'v>(object: &'v Object, key: &str) -> Option<&'v str> {
    object.get(key).and_then(Value::as_str)
}

fn exact_keys(object: &Object, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.get(key).is_some())
}

fn valid_document_id(text: &str) -> bool {
    (1..=256).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// `^[A-Za-z0-9_-]{1,128}$` (cancel reasons).
#[must_use]
pub fn valid_reason(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn correlation_of(object: &Object) -> Option<Correlation> {
    Some(Correlation {
        session_id: Id32::parse(str_field(object, "sessionId")?)?,
        sequence: safe_field(object.get("sequence"))?,
        activation_nonce: Id32::parse(str_field(object, "activationNonce")?)?,
        request_id: Id16::parse(str_field(object, "requestId")?)?,
    })
}

const REQUEST_KEYS: [&str; 14] = [
    "namespace",
    "version",
    "role",
    "kind",
    "sessionId",
    "sequence",
    "deadlineUnixMs",
    "profileInstallId",
    "activationNonce",
    "requestId",
    "method",
    "params",
    "route",
    "context",
];
const CONTEXT_KEYS: [&str; 9] = [
    "browserFamily",
    "extensionId",
    "tabId",
    "frameId",
    "documentId",
    "topOrigin",
    "frameOrigin",
    "documentLifecycle",
    "channelNonce",
];
const CANCEL_KEYS: [&str; 10] = [
    "namespace",
    "version",
    "role",
    "kind",
    "sessionId",
    "sequence",
    "activationNonce",
    "requestId",
    "requestSequence",
    "reason",
];

fn common_literals(object: &Object, kind: &str) -> bool {
    str_field(object, "namespace") == Some(NAMESPACE)
        && int_field(object.get("version")) == Some(PROTOCOL_VERSION)
        && str_field(object, "role") == Some("extension")
        && str_field(object, "kind") == Some(kind)
}

/// The optional context key (spec/05 §6.1); envelope version 1 is unchanged without it.
const CONTEXT_COMPAT_KEY: &str = "compatMode";

fn parse_context(value: &Value, pinned_extension_id: &str) -> Option<BrowserContext> {
    let object = value.as_object()?;
    // Present → must be exactly "metamask" or "rabby" (a string); absent → default mode.
    let compat_mode = match object.get(CONTEXT_COMPAT_KEY) {
        None => None,
        Some(mode) => Some(CompatMode::parse(mode.as_str()?)?),
    };
    let expected_len = CONTEXT_KEYS.len() + usize::from(compat_mode.is_some());
    if object.len() != expected_len
        || !CONTEXT_KEYS.iter().all(|key| object.get(key).is_some())
        || str_field(object, "browserFamily") != Some("chrome")
        || str_field(object, "extensionId") != Some(pinned_extension_id)
        || int_field(object.get("frameId")) != Some(0)
        || str_field(object, "documentLifecycle") != Some("active")
    {
        return None;
    }
    let tab_id = int_field(object.get("tabId")).filter(|id| *id <= MAX_SAFE_INTEGER)?;
    let document_id = str_field(object, "documentId").filter(|id| valid_document_id(id))?;
    let top = str_field(object, "topOrigin")?;
    if str_field(object, "frameOrigin") != Some(top) {
        return None;
    }
    Some(BrowserContext {
        tab_id,
        document_id: document_id.to_owned(),
        origin: BrowserOrigin::parse(top)?,
        channel_nonce: Id32::parse(str_field(object, "channelNonce")?)?,
        compat_mode,
    })
}

fn parse_request(
    object: &Object,
    correlation: Correlation,
    pinned_extension_id: &str,
) -> Option<RequestEnvelope> {
    if !exact_keys(object, &REQUEST_KEYS) || !common_literals(object, "request") {
        return None;
    }
    let method = str_field(object, "method")?;
    if !(1..=96).contains(&method.chars().count()) {
        return None;
    }
    let params = object.get("params")?;
    if params.as_array().is_none() && params.as_object().is_none() {
        return None;
    }
    Some(RequestEnvelope {
        correlation,
        deadline_unix_ms: safe_field(object.get("deadlineUnixMs"))?,
        profile_install_id: Id32::parse(str_field(object, "profileInstallId")?)?,
        method: method.to_owned(),
        params: params.clone(),
        route: Route::parse(str_field(object, "route")?)?,
        context: parse_context(object.get("context")?, pinned_extension_id)?,
    })
}

fn parse_cancel(object: &Object) -> Option<CancelEnvelope> {
    if !exact_keys(object, &CANCEL_KEYS) || !common_literals(object, "cancel") {
        return None;
    }
    let sequence = safe_field(object.get("sequence"))?;
    let request_sequence = safe_field(object.get("requestSequence"))?;
    let reason = str_field(object, "reason").filter(|reason| valid_reason(reason))?;
    (request_sequence < sequence).then_some(())?;
    Some(CancelEnvelope {
        session_id: Id32::parse(str_field(object, "sessionId")?)?,
        sequence,
        activation_nonce: Id32::parse(str_field(object, "activationNonce")?)?,
        request_id: Id16::parse(str_field(object, "requestId")?)?,
        request_sequence,
        reason: reason.to_owned(),
    })
}

/// Parses one inbound frame (spec/05 §6.2 steps 1, 2 and 4; the sequence rule of step 3 needs
/// the connection state and is the dispatcher's).
///
/// # Errors
///
/// [`EnvelopeError`]: `Uncorrelated` frames are dropped, the others are answered.
pub fn parse_inbound(
    frame: &[u8],
    pinned_extension_id: &str,
    allow_localhost: bool,
) -> Result<Inbound, EnvelopeError> {
    let value = yw_json::parse(frame, &Limits::REQUEST).map_err(|_| EnvelopeError::Uncorrelated)?;
    let object = value.as_object().ok_or(EnvelopeError::Uncorrelated)?;
    if str_field(object, "kind") == Some("cancel") {
        return parse_cancel(object)
            .map(Inbound::Cancel)
            .ok_or(EnvelopeError::Uncorrelated);
    }
    let correlation = correlation_of(object).ok_or(EnvelopeError::Uncorrelated)?;
    let request = parse_request(object, correlation, pinned_extension_id)
        .ok_or(EnvelopeError::Invalid(correlation))?;
    if request.context.origin.is_http() && !allow_localhost {
        return Err(EnvelopeError::LocalhostDisabled(correlation));
    }
    Ok(Inbound::Request(Box::new(request)))
}

fn number_i64(value: i64) -> Value {
    Number::from_literal(&value.to_string()).map_or(Value::Null, Value::Number)
}

/// The JSON `error` member of a provider error (`data` only for sanitized upstream errors).
#[must_use]
pub fn error_value(error: &ProviderError) -> Value {
    let mut pairs = vec![
        ("code", number_i64(error.code())),
        ("message", json_str(error.message())),
    ];
    if let Some(data) = error.data() {
        pairs.push(("data", json_str(data)));
    }
    json_object(pairs)
}

fn response_value(
    correlation: &Correlation,
    out_sequence: u64,
    body: Result<&Value, &ProviderError>,
) -> Value {
    let (key, member) = match body {
        Ok(result) => ("result", result.clone()),
        Err(error) => ("error", error_value(error)),
    };
    json_object(vec![
        ("namespace", json_str(NAMESPACE)),
        ("version", json_u64(PROTOCOL_VERSION)),
        ("role", json_str("native-host")),
        ("kind", json_str("response")),
        ("sessionId", json_str(&correlation.session_id.hex())),
        ("sequence", json_u64(out_sequence)),
        ("requestSequence", json_u64(correlation.sequence)),
        (
            "activationNonce",
            json_str(&correlation.activation_nonce.hex()),
        ),
        ("requestId", json_str(&correlation.request_id.hex())),
        (key, member),
    ])
}

/// Encodes a response in the golden key order. The frame is guaranteed ≤ 1 MiB and within the
/// extension's `RESPONSE_LIMITS`; a result that would break either is replaced by
/// -32603 `Response too large.` (spec/05 §6.5, §3.5).
#[must_use]
pub fn encode_response(
    correlation: &Correlation,
    out_sequence: u64,
    body: Result<&Value, &ProviderError>,
) -> Vec<u8> {
    let bytes = yw_json::to_vec(&response_value(correlation, out_sequence, body));
    let fits = bytes.len() <= MAX_FRAME_BYTES
        && (body.is_err() || yw_json::parse(&bytes, &Limits::RESPONSE).is_ok());
    if fits {
        bytes
    } else {
        yw_json::to_vec(&response_value(
            correlation,
            out_sequence,
            Err(&ProviderError::ResponseTooLarge),
        ))
    }
}

/// `0x` + lowercase hex without leading zeros (`eth_chainId`, `chainChanged`).
#[must_use]
pub fn chain_id_hex(chain_id: u64) -> String {
    format!("0x{chain_id:x}")
}

/// `accountsChanged` / `eth_accounts` payload: lowercase addresses.
#[must_use]
pub fn accounts_value(accounts: &[[u8; 20]]) -> Value {
    Value::Array(
        accounts
            .iter()
            .map(|account| json_str(&format!("0x{}", yw_core::hex::encode(account))))
            .collect(),
    )
}

/// Encodes an event (spec/05 §6.1, golden key order).
#[must_use]
pub fn encode_event(
    session_id: &Id32,
    out_sequence: u64,
    activation_nonce: &Id32,
    event: &BrowserEvent,
) -> Vec<u8> {
    let (name, payload) = match event {
        BrowserEvent::AccountsChanged(accounts) => ("accountsChanged", accounts_value(accounts)),
        BrowserEvent::ChainChanged(chain_id) => {
            ("chainChanged", json_str(&chain_id_hex(*chain_id)))
        }
        BrowserEvent::SolAccountsChanged(keys) => (
            "solAccountsChanged",
            Value::Array(
                keys.iter()
                    .map(|key| json_str(&yw_core::codec::base58::base58_encode(key)))
                    .collect(),
            ),
        ),
        BrowserEvent::BtcAccountsChanged(addresses) => (
            "btcAccountsChanged",
            Value::Array(addresses.iter().map(|address| json_str(address)).collect()),
        ),
    };
    yw_json::to_vec(&json_object(vec![
        ("namespace", json_str(NAMESPACE)),
        ("version", json_u64(PROTOCOL_VERSION)),
        ("role", json_str("native-host")),
        ("kind", json_str("event")),
        ("sessionId", json_str(&session_id.hex())),
        ("sequence", json_u64(out_sequence)),
        ("activationNonce", json_str(&activation_nonce.hex())),
        ("event", json_str(name)),
        ("payload", payload),
    ]))
}

/// A valid hello from yw-host (spec/05 §8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// yw-host version (log only).
    pub host_version: String,
    /// yw-host process id (log only).
    pub pid: u32,
}

/// Why a hello was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloReject {
    /// Wrong protocol or malformed hello.
    Protocol,
    /// `extensionOrigin` is not the pinned origin.
    Origin,
}

impl HelloReject {
    /// The `reason` value.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Origin => "origin",
        }
    }
}

/// Checks a hello frame against the pinned `chrome-extension://<id>/` origin.
///
/// # Errors
///
/// [`HelloReject`] (a malformed hello counts as `Protocol`).
pub fn parse_hello(frame: &[u8], pinned_origin: &str) -> Result<Hello, HelloReject> {
    let value = yw_json::parse(frame, &Limits::REQUEST).map_err(|_| HelloReject::Protocol)?;
    let object = value.as_object().ok_or(HelloReject::Protocol)?;
    if !exact_keys(
        object,
        &["kind", "protocol", "hostVersion", "extensionOrigin", "pid"],
    ) || str_field(object, "kind") != Some("hello")
        || int_field(object.get("protocol")) != Some(PIPE_PROTOCOL)
    {
        return Err(HelloReject::Protocol);
    }
    let host_version = str_field(object, "hostVersion")
        .filter(|text| (1..=32).contains(&text.len()))
        .ok_or(HelloReject::Protocol)?;
    let pid = int_field(object.get("pid"))
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or(HelloReject::Protocol)?;
    if str_field(object, "extensionOrigin") != Some(pinned_origin) {
        return Err(HelloReject::Origin);
    }
    Ok(Hello {
        host_version: host_version.to_owned(),
        pid,
    })
}

/// `{"kind":"hello-ack","protocol":1,"appVersion":…}`.
#[must_use]
pub fn encode_hello_ack(app_version: &str) -> Vec<u8> {
    yw_json::to_vec(&json_object(vec![
        ("kind", json_str("hello-ack")),
        ("protocol", json_u64(PIPE_PROTOCOL)),
        ("appVersion", json_str(app_version)),
    ]))
}

/// `{"kind":"hello-reject","reason":…}`.
#[must_use]
pub fn encode_hello_reject(reason: HelloReject) -> Vec<u8> {
    yw_json::to_vec(&json_object(vec![
        ("kind", json_str("hello-reject")),
        ("reason", json_str(reason.reason())),
    ]))
}
