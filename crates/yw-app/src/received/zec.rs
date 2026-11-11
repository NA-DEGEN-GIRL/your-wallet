//! Zcash received history (spec/04 §2.6, spec/12, 2026-11-11), transparent address only: one
//! insight-style `getaddressdeltas {"addresses":[a],"start":h,"end":tip}` per read on the
//! configured node (zcashd `-insightexplorer`), from the tip of the last chain-checked refresh.
//! The first read looks back [`FIRST_WINDOW`] blocks, later ones continue after the last height
//! scanned. A transaction is incoming when all of its deltas for the address are positive (no
//! spend of ours); the node names no sender. A node without the call (`-32601`, e.g. Zebra) and
//! the Blockbook source are not used: the card says so instead.

use std::collections::BTreeMap;

use yw_core::zec::format_zec;
use yw_json::{Number, Object, Value};
use yw_win::http::HttpsUrl;

use super::{Cursor, DUST_ZEC_ZATS, Fetched, Found, Incoming};
use crate::rpc::{RpcClient, RpcFailure, Transport, classify};
use crate::settings::ZecIndexer;

/// Blocks the first read looks back (≈ 17 days at 75 s).
pub const FIRST_WINDOW: u32 = 20_000;
/// `getaddressdeltas` response bound.
pub const MAX_RESPONSE: usize = 4 * 1_048_576;
/// The card's line when the node or source has no address deltas.
pub const T_NO_DELTAS: &str = "이 Zcash 엔드포인트는 주소 내역 조회(getaddressdeltas)를 지원하지 않아 받은 내역을 표시하지 않습니다 — 탐색기에서 확인하세요.";
/// The sender line of every row (the deltas carry only our own address).
pub const T_NO_SENDER: &str = "보낸 주소: 노드 응답에 없어 표시하지 않습니다";
/// The error when the answer is over its bound (a dust flood): that range is skipped.
pub const T_TOO_MANY: &str = "이 범위의 주소 내역이 너무 많아(먼지 입금 등) 건너뛰었습니다";

/// One `getaddressdeltas` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    /// Txid (display hex).
    pub txid: String,
    /// Zats (negative: a spend of ours).
    pub zats: i64,
    /// Height.
    pub height: u64,
}

fn delta_of(object: &Object) -> Option<Delta> {
    let txid = object.get("txid")?.as_str()?;
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(Delta {
        txid: txid.to_ascii_lowercase(),
        zats: object
            .get("satoshis")?
            .as_number()
            .and_then(Number::as_i64)?,
        height: object.get("height")?.as_number().and_then(Number::as_u64)?,
    })
}

/// Parses a `getaddressdeltas` result (an array, or `{"deltas": […]}` with `chainInfo`).
///
/// # Errors
///
/// `Malformed` when there is no list.
pub fn parse_deltas(result: &Value) -> Result<Vec<Delta>, RpcFailure> {
    let list = match result {
        Value::Array(list) => list,
        Value::Object(object) => object
            .get("deltas")
            .and_then(Value::as_array)
            .ok_or(RpcFailure::Malformed)?,
        _ => return Err(RpcFailure::Malformed),
    };
    Ok(list
        .iter()
        .filter_map(Value::as_object)
        .filter_map(delta_of)
        .collect())
}

/// The incoming transactions of `deltas`: every delta of the txid positive (a zero sum is dust).
#[must_use]
pub fn derive(deltas: &[Delta]) -> Found {
    let mut by_tx: BTreeMap<&str, (i128, bool, u64)> = BTreeMap::new();
    for delta in deltas {
        let slot = by_tx.entry(&delta.txid).or_insert((0, false, delta.height));
        slot.0 = slot.0.saturating_add(i128::from(delta.zats));
        slot.1 |= delta.zats < 0;
        slot.2 = slot.2.max(delta.height);
    }
    let mut found = Found::default();
    for (txid, (sum, spent, height)) in by_tx {
        if spent {
            continue;
        }
        let zats = u64::try_from(sum).unwrap_or(0);
        if zats < DUST_ZEC_ZATS {
            found.dust.push(txid.to_owned());
            continue;
        }
        found.entries.push(Incoming {
            key: txid.to_owned(),
            hash: txid.to_owned(),
            time_ms: None,
            block: Some(height),
            amount: format_zec(zats),
            symbol: "ZEC".to_owned(),
            from: None,
            from_note: Some(T_NO_SENDER),
            pending: false,
        });
    }
    found
}

/// One read.
///
/// # Errors
///
/// A fixed error text.
pub fn fetch(
    transport: &dyn Transport,
    url: &HttpsUrl,
    indexer: ZecIndexer,
    address: &str,
    tip: u32,
    cursor: &Cursor,
) -> Result<Fetched, String> {
    if indexer != ZecIndexer::Node {
        return Ok(Fetched {
            unsupported: Some(T_NO_DELTAS),
            ..Fetched::default()
        });
    }
    let floor = tip.saturating_sub(FIRST_WINDOW.saturating_sub(1)).max(1);
    let start = match cursor {
        Cursor::Height(next) => (*next).max(floor),
        _ => floor,
    };
    if start > tip {
        return Ok(Fetched {
            cursor: cursor.clone(),
            ..Fetched::default()
        });
    }
    let params = Value::Array(vec![Value::Object(
        Object::from_pairs(vec![
            (
                "addresses".to_owned(),
                Value::Array(vec![Value::String(address.to_owned())]),
            ),
            (
                "start".to_owned(),
                Value::Number(Number::from_u64(u64::from(start))),
            ),
            (
                "end".to_owned(),
                Value::Number(Number::from_u64(u64::from(tip))),
            ),
        ])
        .unwrap_or_default(),
    )]);
    let next = Cursor::Height(tip.saturating_add(1));
    let client = RpcClient::new(transport);
    match client.call_detailed(url, "getaddressdeltas", params, MAX_RESPONSE) {
        Ok(result) => Ok(Fetched {
            found: derive(&parse_deltas(&result).map_err(|f| classify(f).text())?),
            cursor: next,
            ..Fetched::default()
        }),
        Err(error) if error.failure == RpcFailure::Rpc(-32_601) => Ok(Fetched {
            unsupported: Some(T_NO_DELTAS),
            ..Fetched::default()
        }),
        // A dust flood: that range is skipped (never asked again) and the card says so.
        Err(error) if error.over_limit => Ok(Fetched {
            cursor: next,
            note: Some(T_TOO_MANY),
            ..Fetched::default()
        }),
        Err(error) => Err(classify(error.failure).text()),
    }
}

#[cfg(test)]
mod tests {
    use yw_json::Limits;

    use super::{T_NO_SENDER, derive, parse_deltas};

    /// A `getaddressdeltas` fixture (zcashd insight shape): a deposit in two outputs, our send
    /// (a spend and its change), a dust deposit.
    #[test]
    fn address_deltas_become_rows_and_dust() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let text = format!(
            r#"[
            {{"satoshis":150000,"txid":"{a}","index":0,"blockindex":3,"height":2800000,"address":"t1x"}},
            {{"satoshis":50000,"txid":"{a}","index":1,"blockindex":3,"height":2800000,"address":"t1x"}},
            {{"satoshis":-200000,"txid":"{b}","index":0,"blockindex":1,"height":2800100,"address":"t1x"}},
            {{"satoshis":90000,"txid":"{b}","index":2,"blockindex":1,"height":2800100,"address":"t1x"}},
            {{"satoshis":5000,"txid":"{c}","index":0,"blockindex":9,"height":2800200,"address":"t1x"}}
        ]"#
        );
        let value = yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap();
        let deltas = parse_deltas(&value).unwrap();
        assert_eq!(deltas.len(), 5);
        let found = derive(&deltas);
        assert_eq!(found.entries.len(), 1);
        assert_eq!(found.entries[0].amount, "0.00200000");
        assert_eq!(found.entries[0].block, Some(2_800_000));
        assert_eq!(found.entries[0].from_note, Some(T_NO_SENDER));
        assert_eq!(found.dust, [c]);
        let wrapped = yw_json::parse(
            format!(r#"{{"deltas":{text}}}"#).as_bytes(),
            &Limits::RESPONSE,
        )
        .unwrap();
        assert_eq!(parse_deltas(&wrapped).unwrap().len(), 5);
        assert!(parse_deltas(&yw_json::Value::Null).is_err());
    }
}
