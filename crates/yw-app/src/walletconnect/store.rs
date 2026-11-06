//! The persisted `WalletConnect` state (spec/13 §8): the optional meta key `walletconnect` —
//! `{"clientSeed": hex32, "sessions": [Session…]}` — inside the sealed `meta.ywm` (the vault's
//! meta key encrypts it at rest, so session keys and the relay client key never touch disk in the
//! clear). A malformed session is dropped on read; a malformed document resets to empty.

use yw_core::evm::address::{Address, parse_address};
use yw_json::Value;
use yw_core::secret::Zeroizing;

use super::engine::Session;
use super::{Metadata, VerifyStatus};
use crate::text::{json_object, json_str, json_u64};

/// The meta key.
pub const META_KEY: &str = "walletconnect";

/// The decoded state.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct WcStore {
    /// The relay client Ed25519 seed (`did:key` identity; the relay mailbox follows it).
    pub client_seed: Option<Zeroizing<[u8; 32]>>,
    /// Sessions.
    pub sessions: Vec<Session>,
}

impl core::fmt::Debug for WcStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "WcStore({} sessions)", self.sessions.len())
    }
}

fn hex32(value: Option<&Value>) -> Option<[u8; 32]> {
    yw_core::hex::decode_array::<32>(value?.as_str()?).ok()
}

fn u64_of(value: Option<&Value>) -> Option<u64> {
    value?.as_number()?.as_u64()
}

fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn session_from(value: &Value) -> Option<Session> {
    let object = value.as_object()?;
    let accounts: Vec<Address> = object
        .get("accounts")?
        .as_array()?
        .iter()
        .map(|item| parse_address(item.as_str()?).ok())
        .collect::<Option<_>>()?;
    let chains: Vec<u64> = object
        .get("chains")?
        .as_array()?
        .iter()
        .map(|item| item.as_number()?.as_u64())
        .collect::<Option<_>>()?;
    if accounts.is_empty() || chains.is_empty() {
        return None;
    }
    let sym_key = Zeroizing::new(hex32(object.get("symKey"))?);
    let topic = hex32(object.get("topic"))?;
    // The topic is the hash of the key: a stored pair that disagrees is not used.
    if yw_core::walletconnect::topic_of(&sym_key) != topic {
        return None;
    }
    Some(Session {
        topic,
        sym_key,
        peer_public: hex32(object.get("peerPublic"))?,
        peer: Metadata::from_value(object.get("peer")),
        accounts,
        chains,
        methods: strings(object.get("methods"))?,
        events: strings(object.get("events"))?,
        expiry: u64_of(object.get("expiry"))?,
        acknowledged: object.get("acknowledged")?.as_bool()?,
        verify: VerifyStatus::parse(object.get("verify")?.as_str()?)?,
        created: u64_of(object.get("created"))?,
    })
}

fn session_to(session: &Session) -> Value {
    json_object(vec![
        ("topic", json_str(&yw_core::hex::encode(&session.topic))),
        ("symKey", json_str(&yw_core::hex::encode(session.sym_key.as_ref()))),
        (
            "peerPublic",
            json_str(&yw_core::hex::encode(&session.peer_public)),
        ),
        ("peer", session.peer.to_value()),
        (
            "accounts",
            Value::Array(
                session
                    .accounts
                    .iter()
                    .map(|a| json_str(&format!("0x{}", yw_core::hex::encode(a.as_bytes()))))
                    .collect(),
            ),
        ),
        (
            "chains",
            Value::Array(session.chains.iter().map(|c| json_u64(*c)).collect()),
        ),
        (
            "methods",
            Value::Array(session.methods.iter().map(|m| json_str(m)).collect()),
        ),
        (
            "events",
            Value::Array(session.events.iter().map(|e| json_str(e)).collect()),
        ),
        ("expiry", json_u64(session.expiry)),
        ("acknowledged", Value::Bool(session.acknowledged)),
        ("verify", json_str(session.verify.as_str())),
        ("created", json_u64(session.created)),
    ])
}

impl WcStore {
    /// Reads the meta value (absent or malformed: empty).
    #[must_use]
    pub fn from_value(value: Option<&Value>) -> Self {
        let Some(object) = value.and_then(Value::as_object) else {
            return Self::default();
        };
        Self {
            client_seed: hex32(object.get("clientSeed")).map(Zeroizing::new),
            sessions: object
                .get("sessions")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(session_from).collect())
                .unwrap_or_default(),
        }
    }

    /// The meta value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut members = Vec::new();
        if let Some(seed) = &self.client_seed {
            members.push(("clientSeed", json_str(&yw_core::hex::encode(seed.as_ref()))));
        }
        members.push((
            "sessions",
            Value::Array(self.sessions.iter().map(session_to).collect()),
        ));
        json_object(members)
    }

    /// Whether there is nothing to store.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.client_seed.is_none() && self.sessions.is_empty()
    }
}
