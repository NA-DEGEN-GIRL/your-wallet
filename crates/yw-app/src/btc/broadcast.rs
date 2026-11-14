//! `btc::broadcast` (spec/08 §11.3): the broadcast primitives. [`test_mempool_accept`] and
//! [`send_raw_transaction`] run `check_chain` steps 1–2 right before their Core call (spec/08
//! §2) and return yw-core's `policy` input types; the decisions (`check_mempool_accept`,
//! `broadcast_outcome`) are yw-core's. The manual Esplora `POST <base>/tx`
//! ([`esplora_broadcast_confirmed`]) is a separate, user-confirmed action: no automatic path
//! (broadcast, tracking, refresh) calls it, the indexer request generator cannot produce it, and
//! it refuses unless [`manual_broadcast_offered`].

use yw_core::btc::Txid;
use yw_core::btc::policy::{MempoolAccept, SendRawResult};
use yw_win::http::HttpsUrl;

use super::chain::{ChainInput, ChainSession, check_core};
use super::client::{BtcClient, Tag};
use super::indexer::{IndexerError, media_type, transport_error};
use super::rpc;
use super::{BtcEndpoint, BtcError};
use crate::logging::Field;
use crate::settings::{BtcIndexer, LogLevel};

/// Manual `POST /tx` response cap (4 KiB).
pub const CAP_TX_POST: usize = 4 * 1_024;

/// `testmempoolaccept` after `check_chain` steps 1–2. `maxfeerate` is yw-core's literal
/// (`VerifiedSignedTx::maxfeerate`).
///
/// # Errors
///
/// [`BtcError`] (a communication error leaves the record `Signed` with [다시 시도]).
pub fn test_mempool_accept(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    raw: &[u8],
    maxfeerate: &str,
    input: ChainInput,
) -> Result<MempoolAccept, BtcError> {
    check_core(client, session, input)?;
    let accept = rpc::test_mempool_accept(client, raw, maxfeerate)?;
    // The `reject-reason` is kept and logged only as its known token (or `unknown`).
    let reject = accept
        .reject_reason
        .as_deref()
        .and_then(yw_core::btc::policy::known_reject_token)
        .unwrap_or(if accept.allowed { "none" } else { "unknown" });
    client.log(
        LogLevel::Info,
        "testmempoolaccept",
        Tag::core("testmempoolaccept", Some(accept.txid)),
        &[
            (
                "allowed",
                Field::Word(if accept.allowed { "true" } else { "false" }),
            ),
            ("reject", Field::Word(reject)),
        ],
    );
    Ok(accept)
}

/// The log word of a `sendrawtransaction` result.
#[must_use]
pub const fn send_word(result: SendRawResult) -> &'static str {
    match result {
        SendRawResult::Txid(_) => "txid",
        SendRawResult::NotTxid => "not_txid",
        SendRawResult::RpcError { .. } => "rpc_error",
        SendRawResult::Timeout => "timeout",
        SendRawResult::Transport => "transport",
        SendRawResult::Refused => "refused",
    }
}

/// `sendrawtransaction` after `check_chain` steps 1–2. `Err` means nothing was sent.
///
/// # Errors
///
/// [`BtcError`] from the chain check.
pub fn send_raw_transaction(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    raw: &[u8],
    maxfeerate: &str,
    local_txid: &Txid,
    input: ChainInput,
) -> Result<SendRawResult, BtcError> {
    check_core(client, session, input)?;
    let result = rpc::send_raw_transaction(client, raw, maxfeerate, local_txid);
    let matches = matches!(result, SendRawResult::Txid(txid) if txid == *local_txid);
    client.log(
        LogLevel::Info,
        "broadcast",
        Tag::core("sendrawtransaction", Some(*local_txid)),
        &[
            ("outcome", Field::Word(send_word(result))),
            ("same_txid", Field::Word(if matches { "yes" } else { "no" })),
        ],
    );
    Ok(result)
}

/// The facts of the journal entry that decide whether [Esplora로 전송] is offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManualBroadcastGate {
    /// The journal state is `BroadcastUnknown`.
    pub broadcast_unknown: bool,
    /// The last Core `sendrawtransaction` of this entry was a communication failure
    /// (yw-core `BroadcastOutcome::BroadcastUnknown { comm_failure: true, .. }`).
    pub comm_failure: bool,
}

/// spec/08 §11.3: `indexer == esplora`, `BroadcastUnknown`, the last Core send was a
/// communication failure (not an RPC rejection), step 3 passed in this session and the Esplora
/// base did not change since (a change resets the session).
#[must_use]
pub fn manual_broadcast_offered(
    endpoint: &BtcEndpoint,
    session: &ChainSession,
    gate: ManualBroadcastGate,
) -> bool {
    endpoint.indexer == BtcIndexer::Esplora
        && session.network() == endpoint.net
        && session.indexer_verified()
        && gate.broadcast_unknown
        && gate.comm_failure
}

/// Manual Esplora broadcast result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EsploraPostOutcome {
    /// 200 `text/plain` with exactly the local txid (spec/08 §11.3 "Submitted": the journal state
    /// stays `BroadcastUnknown` per the §12.1 table and tracking moves it on).
    Submitted,
    /// Another txid or a malformed body: stay `BroadcastUnknown` + "응답 txid 불일치".
    TxidMismatch,
    /// HTTP 400: stay `BroadcastUnknown` + E-BTC-008 (the node's reason is not shown).
    Rejected,
    /// Anything else (E-BTC-001; E-BTC-002 after the 429 retries).
    Failed(IndexerError),
}

impl EsploraPostOutcome {
    /// The fixed text in `lang`.
    #[must_use]
    pub fn text(self, lang: yw_core::lang::Lang) -> String {
        match self {
            Self::Submitted => String::new(),
            Self::TxidMismatch => super::text::TXID_MISMATCH.get(lang).to_owned(),
            Self::Rejected => crate::errors::ErrorCode::Btc008.text_in(lang),
            Self::Failed(error) => error.text(lang, BtcIndexer::Esplora),
        }
    }
}

/// The user-confirmed `POST <esploraBaseUrl>/tx` (T-BTC-ESPLORA-BROADCAST accepted): body =
/// lowercase hex of the journal's raw bytes, `Content-Type: text/plain`, 4 KiB response cap,
/// paced and 429-retried like every BTC request.
///
/// # Errors
///
/// `Indexer(Refused)` without any request when [`manual_broadcast_offered`] is false.
pub fn esplora_broadcast_confirmed(
    client: &BtcClient<'_>,
    session: &ChainSession,
    gate: ManualBroadcastGate,
    raw: &[u8],
    local_txid: &Txid,
) -> Result<EsploraPostOutcome, BtcError> {
    let endpoint = client.endpoint();
    if !manual_broadcast_offered(endpoint, session, gate) {
        return Err(BtcError::Indexer(IndexerError::Refused));
    }
    let base = endpoint.esplora_base.expose();
    let url = HttpsUrl::parse(&format!("{}/tx", base.strip_suffix('/').unwrap_or(base)))
        .map_err(|_| BtcError::Indexer(IndexerError::Refused))?;
    let tag = Tag {
        idx: Some(BtcIndexer::Esplora),
        what: "tx-post",
        is_method: false,
        txid: Some(*local_txid),
    };
    let body = yw_core::hex::encode(raw);
    let outcome = match client.post_text(&url, body.as_bytes(), CAP_TX_POST, tag) {
        Err(error) => EsploraPostOutcome::Failed(match transport_error(error) {
            IndexerError::Unreachable(cause) => IndexerError::Unreachable(cause),
            _ => IndexerError::Unreachable(None),
        }),
        Ok(response) => match response.status {
            200 => {
                let text_plain =
                    media_type(response.content_type.as_deref()).as_deref() == Some("text/plain");
                let returned = core::str::from_utf8(&response.body)
                    .ok()
                    .and_then(|text| Txid::from_display_hex(text).ok());
                if text_plain && returned == Some(*local_txid) {
                    EsploraPostOutcome::Submitted
                } else {
                    EsploraPostOutcome::TxidMismatch
                }
            }
            400 => EsploraPostOutcome::Rejected,
            429 => EsploraPostOutcome::Failed(IndexerError::RateLimited),
            _ => EsploraPostOutcome::Failed(IndexerError::Unreachable(None)),
        },
    };
    let word = match outcome {
        EsploraPostOutcome::Submitted => "submitted",
        EsploraPostOutcome::TxidMismatch => "txid_mismatch",
        EsploraPostOutcome::Rejected => "E-BTC-008",
        EsploraPostOutcome::Failed(error) => error.code().code(),
    };
    client.log(
        LogLevel::Warn,
        "esplora_broadcast",
        tag,
        &[("outcome", Field::Word(word))],
    );
    Ok(outcome)
}
