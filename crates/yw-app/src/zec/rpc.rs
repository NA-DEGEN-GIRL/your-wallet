//! Zcash node and Blockbook calls (spec/12 §4): the chain check (genesis pin, `chain`, tip,
//! `consensus.nextblock`, `upgrades`), the address UTXOs (`getaddressutxos` or Blockbook
//! `utxo/<address>`; when that answer is over its limits, `gettxout` of the outputs already
//! known), transaction status (`getrawtransaction <txid> 1`) and `sendrawtransaction`. Every
//! answer is an untrusted observation: amounts and scripts are bound by the ZIP 244 signature (a
//! lie makes the transaction invalid), the tip and branch id are cross-checked against the
//! upgrade table (`yw_core::zec::upgrade`). URLs are never logged.

use yw_core::zec::upgrade::ConsensusObservation;
use yw_core::zec::{ZecNetwork, ZecOutPoint, ZecUtxo};
use yw_json::{Number, Value};
use yw_win::http::{HttpError, HttpsUrl};

use crate::errors::ErrorCode;
use crate::rpc::{RpcClient, RpcFailure, Transport, classify};

/// Largest JSON answer of one call.
const MAX_RESPONSE: usize = 4 * 1_024 * 1_024;
/// Largest node tip accepted (the expiry field limit is 499,999,999).
const MAX_TIP: u64 = 400_000_000;

/// Why a Zcash call failed (fixed texts only, never a remote string).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecRpcError {
    /// Transport / HTTP / JSON-RPC failure.
    Rpc(ErrorCode),
    /// The endpoint is another chain (genesis or `chain` differs).
    WrongChain,
    /// The node is not synced (`headers` far above `blocks`) or its tip is implausible.
    NotSynced,
    /// A malformed answer.
    Malformed,
    /// The node has no address index (`getaddressutxos` missing, `-32601`).
    NoAddressIndex,
    /// The address UTXO answer went past the 4 MiB / JSON node limits (usually many dust
    /// outputs, spec/12 §4.3): only outputs already known are shown.
    TooMany,
}

/// Fixed texts of the Zcash calls (spec/12 §4, spec/14).
pub mod text {
    yw_core::texts! {
        WRONG_CHAIN = "RPC가 다른 네트워크를 가리킵니다 (Zcash genesis 또는 chain 불일치)."
            / "The RPC points to another network (Zcash genesis or chain mismatch).";
        NOT_SYNCED = "Zcash 노드가 동기화 중이거나 블록 높이가 올바르지 않습니다."
            / "The Zcash node is syncing or its block height is invalid.";
        MALFORMED = "Zcash 노드 응답 형식이 올바르지 않습니다."
            / "The Zcash node's answer is malformed.";
        NO_ADDRESS_INDEX = "이 Zcash 엔드포인트는 주소 조회(getaddressutxos)를 지원하지 않습니다. 설정에서 UTXO 원천을 Blockbook으로 바꾸세요."
            / "This Zcash endpoint does not support address lookups (getaddressutxos). Switch the UTXO source to Blockbook in Settings.";
        TOO_MANY = "UTXO가 너무 많아 일부만 표시합니다 (아주 작은 출력이 많아 응답 한도 4 MiB를 넘었습니다). 이미 알고 있던 출력만 표시하고 보낼 수 있습니다."
            / "Too many UTXOs, so only some are shown (many tiny outputs pushed the answer over the 4 MiB limit). Only outputs already known are shown and can be sent.";
    }
}

impl ZecRpcError {
    /// The fixed text in `lang`.
    #[must_use]
    pub fn text_in(self, lang: yw_core::lang::Lang) -> String {
        let text = match self {
            Self::Rpc(code) => return code.text_in(lang),
            Self::WrongChain => text::WRONG_CHAIN,
            Self::NotSynced => text::NOT_SYNCED,
            Self::Malformed => text::MALFORMED,
            Self::NoAddressIndex => text::NO_ADDRESS_INDEX,
            Self::TooMany => text::TOO_MANY,
        };
        text.get(lang).to_owned()
    }
}

impl From<RpcFailure> for ZecRpcError {
    fn from(failure: RpcFailure) -> Self {
        match failure {
            RpcFailure::Rpc(-32_601) => Self::NoAddressIndex,
            other => Self::Rpc(classify(other)),
        }
    }
}

/// The checked chain view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainView {
    /// Tip height.
    pub tip: u32,
    /// Consensus observation for `upgrade::tx_consensus`.
    pub consensus: ConsensusObservation,
}

fn u64_of(value: Option<&Value>) -> Option<u64> {
    value?.as_number().and_then(Number::as_u64)
}

fn branch_of(text: &str) -> Option<u32> {
    (text.len() == 8)
        .then(|| u32::from_str_radix(text, 16).ok())
        .flatten()
}

/// `getblockhash 0` must be the pinned genesis and `getblockchaininfo.chain` the network's;
/// returns the tip, next branch and upgrade heights.
///
/// # Errors
///
/// [`ZecRpcError`].
pub fn chain_check(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    network: ZecNetwork,
) -> Result<ChainView, ZecRpcError> {
    let genesis = client.call(
        url,
        "getblockhash",
        Value::Array(vec![Value::Number(Number::from_u64(0))]),
    )?;
    if genesis.as_str() != Some(network.genesis_hex()) {
        return Err(ZecRpcError::WrongChain);
    }
    let info = client.call_limited(
        url,
        "getblockchaininfo",
        Value::Array(Vec::new()),
        MAX_RESPONSE,
    )?;
    parse_chain_info(&info, network)
}

/// Parses `getblockchaininfo` (spec/12 §4.2).
///
/// # Errors
///
/// [`ZecRpcError`].
pub fn parse_chain_info(info: &Value, network: ZecNetwork) -> Result<ChainView, ZecRpcError> {
    let object = info.as_object().ok_or(ZecRpcError::Malformed)?;
    if object.get("chain").and_then(Value::as_str) != Some(network.chain_name()) {
        return Err(ZecRpcError::WrongChain);
    }
    let blocks = u64_of(object.get("blocks")).ok_or(ZecRpcError::Malformed)?;
    if blocks > MAX_TIP {
        return Err(ZecRpcError::NotSynced);
    }
    if let Some(headers) = u64_of(object.get("headers"))
        && headers > blocks.saturating_add(2)
    {
        return Err(ZecRpcError::NotSynced);
    }
    let next = object
        .get("consensus")
        .and_then(Value::as_object)
        .and_then(|consensus| consensus.get("nextblock"))
        .and_then(Value::as_str)
        .and_then(branch_of)
        .ok_or(ZecRpcError::Malformed)?;
    let mut upgrades = Vec::new();
    if let Some(list) = object.get("upgrades").and_then(Value::as_object) {
        for (key, entry) in list.iter() {
            let (Some(branch), Some(height)) = (
                branch_of(key),
                u64_of(
                    entry
                        .as_object()
                        .and_then(|entry| entry.get("activationheight")),
                ),
            ) else {
                return Err(ZecRpcError::Malformed);
            };
            upgrades.push((
                branch,
                u32::try_from(height).map_err(|_| ZecRpcError::Malformed)?,
            ));
        }
    }
    let tip = u32::try_from(blocks).map_err(|_| ZecRpcError::NotSynced)?;
    Ok(ChainView {
        tip,
        consensus: ConsensusObservation {
            tip,
            next_branch: next,
            upgrades,
        },
    })
}

fn outpoint(txid: &str, index: u64) -> Option<ZecOutPoint> {
    Some(ZecOutPoint {
        txid: yw_core::zec::tx::txid_from_display(txid).ok()?,
        index: u32::try_from(index).ok()?,
    })
}

/// `getaddressutxos {"addresses": [address]}` (Zebra / zcashd `-insightexplorer`): confirmed
/// outputs of our address with our script only.
///
/// # Errors
///
/// [`ZecRpcError`].
pub fn utxos_node(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    address: &str,
    script_hex: &str,
) -> Result<Vec<ZecUtxo>, ZecRpcError> {
    let params = Value::Array(vec![Value::Object(
        yw_json::Object::from_pairs(vec![(
            "addresses".to_owned(),
            Value::Array(vec![Value::String(address.to_owned())]),
        )])
        .unwrap_or_default(),
    )]);
    let result = client
        .call_detailed(url, "getaddressutxos", params, MAX_RESPONSE)
        .map_err(|error| {
            if error.over_limit {
                ZecRpcError::TooMany
            } else {
                error.failure.into()
            }
        })?;
    parse_node_utxos(&result, address, script_hex)
}

/// Which of `points` the node still has unspent (`gettxout <txid> <n> true`: an object is
/// unspent, `null` spent or unknown). Used when the address list is over its limits.
///
/// # Errors
///
/// [`ZecRpcError`] of the first failed call (`NoAddressIndex` for `-32601`: no `gettxout`).
pub fn unspent_of(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    points: &[ZecOutPoint],
) -> Result<Vec<ZecOutPoint>, ZecRpcError> {
    let mut out = Vec::new();
    for point in points {
        let params = Value::Array(vec![
            Value::String(yw_core::zec::tx::txid_display(&point.txid)),
            Value::Number(Number::from_u64(u64::from(point.index))),
            Value::Bool(true),
        ]);
        match client.call(url, "gettxout", params)? {
            Value::Null => {}
            Value::Object(_) => out.push(*point),
            _ => return Err(ZecRpcError::Malformed),
        }
    }
    Ok(out)
}

/// What a UTXO answer leaves after [`keep_useful`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsefulUtxos {
    /// The kept outputs, largest first (at most [`yw_core::zec::ZEC_MAX_UTXOS`]).
    pub utxos: Vec<ZecUtxo>,
    /// Outputs left out: dust (≤ [`yw_core::zec::ZEC_MIN_UTXO`]) and the smallest beyond the
    /// limit.
    pub ignored: usize,
}

/// Drops dust (outputs not worth their own marginal input fee) and keeps the largest
/// [`yw_core::zec::ZEC_MAX_UTXOS`] (ties by outpoint): many tiny outputs sent to the address
/// never fail the refresh (dust griefing, spec/12 §4.3).
#[must_use]
pub fn keep_useful(all: Vec<ZecUtxo>) -> UsefulUtxos {
    let total = all.len();
    let mut utxos: Vec<ZecUtxo> = all
        .into_iter()
        .filter(|utxo| utxo.value > yw_core::zec::ZEC_MIN_UTXO)
        .collect();
    utxos.sort_by(|a, b| b.value.cmp(&a.value).then(a.outpoint.cmp(&b.outpoint)));
    utxos.truncate(yw_core::zec::ZEC_MAX_UTXOS);
    UsefulUtxos {
        ignored: total.saturating_sub(utxos.len()),
        utxos,
    }
}

/// Parses a `getaddressutxos` answer (spec/12 §4.3): every row of our script (no count limit
/// here, see [`keep_useful`]). A `coinbase: true` row (when the node says so) is marked.
///
/// # Errors
///
/// [`ZecRpcError::Malformed`].
pub fn parse_node_utxos(
    result: &Value,
    address: &str,
    script_hex: &str,
) -> Result<Vec<ZecUtxo>, ZecRpcError> {
    let rows = result.as_array().ok_or(ZecRpcError::Malformed)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row.as_object().ok_or(ZecRpcError::Malformed)?;
        if row.get("address").and_then(Value::as_str) != Some(address) {
            return Err(ZecRpcError::Malformed);
        }
        // Another script (not our P2PKH) is not spendable by us: skipped, never signed.
        if row
            .get("script")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .as_deref()
            != Some(script_hex)
        {
            continue;
        }
        let point = row
            .get("txid")
            .and_then(Value::as_str)
            .zip(u64_of(row.get("outputIndex")))
            .and_then(|(txid, index)| outpoint(txid, index))
            .ok_or(ZecRpcError::Malformed)?;
        let value = u64_of(row.get("satoshis")).ok_or(ZecRpcError::Malformed)?;
        let height = u64_of(row.get("height"))
            .filter(|height| *height > 0)
            .and_then(|height| u32::try_from(height).ok());
        out.push(ZecUtxo {
            outpoint: point,
            value,
            height,
            coinbase: row.get("coinbase").and_then(Value::as_bool) == Some(true),
        });
    }
    Ok(out)
}

/// Blockbook `GET <url>/api/v2/utxo/<address>`.
///
/// # Errors
///
/// [`ZecRpcError`].
pub fn utxos_blockbook(
    transport: &dyn Transport,
    url: &HttpsUrl,
    address: &str,
) -> Result<Vec<ZecUtxo>, ZecRpcError> {
    let base = url.expose();
    let target = HttpsUrl::parse(&format!(
        "{}/api/v2/utxo/{address}",
        base.strip_suffix('/').unwrap_or(base)
    ))
    .map_err(|_| ZecRpcError::Rpc(ErrorCode::Key003))?;
    let response = transport
        .http_get(&target, MAX_RESPONSE)
        .map_err(|error| match error {
            HttpError::TooLarge => ZecRpcError::TooMany,
            other => ZecRpcError::Rpc(classify(RpcFailure::Http(other))),
        })?;
    if !(200..300).contains(&response.status) {
        return Err(ZecRpcError::Rpc(classify(RpcFailure::Status(
            response.status,
        ))));
    }
    let limits = yw_json::Limits {
        max_bytes: MAX_RESPONSE,
        ..yw_json::Limits::RESPONSE
    };
    let value = yw_json::parse(&response.body, &limits).map_err(|error| match error {
        yw_json::ParseError::TooLarge
        | yw_json::ParseError::TooManyNodes
        | yw_json::ParseError::TooManyItems => ZecRpcError::TooMany,
        _ => ZecRpcError::Malformed,
    })?;
    parse_blockbook_utxos(&value)
}

/// Parses a Blockbook `utxo` answer: `[{txid, vout, value: "<zats>", height?, coinbase?}]`.
///
/// # Errors
///
/// [`ZecRpcError::Malformed`].
pub fn parse_blockbook_utxos(value: &Value) -> Result<Vec<ZecUtxo>, ZecRpcError> {
    let rows = value.as_array().ok_or(ZecRpcError::Malformed)?;
    rows.iter()
        .map(|row| {
            let row = row.as_object().ok_or(ZecRpcError::Malformed)?;
            let point = row
                .get("txid")
                .and_then(Value::as_str)
                .zip(u64_of(row.get("vout")))
                .and_then(|(txid, index)| outpoint(txid, index))
                .ok_or(ZecRpcError::Malformed)?;
            let value = row
                .get("value")
                .and_then(Value::as_str)
                .and_then(crate::network::parse_decimal_u64)
                .ok_or(ZecRpcError::Malformed)?;
            let height = u64_of(row.get("height"))
                .filter(|height| *height > 0)
                .and_then(|height| u32::try_from(height).ok());
            Ok(ZecUtxo {
                outpoint: point,
                value,
                height,
                coinbase: row.get("coinbase").and_then(Value::as_bool) == Some(true),
            })
        })
        .collect()
}

/// A transaction's status at the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// In a block at this height.
    Mined(u32),
    /// Known but not in the best chain (mempool, or a side chain).
    Known,
    /// `-5`: not in the mempool or best chain.
    NotFound,
}

/// `getrawtransaction <txid> 1`.
///
/// # Errors
///
/// [`ZecRpcError`].
pub fn tx_status(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    txid_hex: &str,
) -> Result<TxStatus, ZecRpcError> {
    let params = Value::Array(vec![
        Value::String(txid_hex.to_owned()),
        Value::Number(Number::from_u64(1)),
    ]);
    match client.call_limited(url, "getrawtransaction", params, MAX_RESPONSE) {
        Ok(value) => Ok(parse_tx_status(&value)),
        Err(RpcFailure::Rpc(-5)) => Ok(TxStatus::NotFound),
        Err(failure) => Err(failure.into()),
    }
}

/// Mined when `height` is a positive integer (Zebra omits it in the mempool and gives `-1` on a
/// side chain).
#[must_use]
pub fn parse_tx_status(value: &Value) -> TxStatus {
    match value
        .as_object()
        .and_then(|object| u64_of(object.get("height")))
        .filter(|height| *height > 0)
        .and_then(|height| u32::try_from(height).ok())
    {
        Some(height) => TxStatus::Mined(height),
        None => TxStatus::Known,
    }
}

/// The node's answer to `sendrawtransaction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// Accepted (or already known / already in the chain, `-27`).
    Accepted,
    /// Refused by policy or consensus (`-25`, `-26`).
    Rejected(i64),
    /// No usable answer (transport, other error): the bytes may have reached the node.
    Unknown(ErrorCode),
}

/// `sendrawtransaction <hex>`; an accepted answer must be our txid.
#[must_use]
pub fn send_raw(client: &RpcClient<'_>, url: &HttpsUrl, raw: &[u8], txid_hex: &str) -> SendOutcome {
    let params = Value::Array(vec![Value::String(yw_core::hex::encode(raw))]);
    match client.call(url, "sendrawtransaction", params) {
        Ok(Value::String(answer)) if answer.eq_ignore_ascii_case(txid_hex) => SendOutcome::Accepted,
        Ok(_) => SendOutcome::Unknown(ErrorCode::Rpc005),
        Err(RpcFailure::Rpc(-27)) => SendOutcome::Accepted,
        Err(RpcFailure::Rpc(code @ (-25 | -26))) => SendOutcome::Rejected(code),
        Err(failure) => SendOutcome::Unknown(classify(failure)),
    }
}
