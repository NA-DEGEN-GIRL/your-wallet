//! `HyperCore` received history (spec/04 §2.6, spec/11, 2026-11-11): one `POST {api}/info`
//! `{"type":"userNonFundingLedgerUpdates","user":…,"startTime":…}` per read (the first looks back
//! [`FIRST_WINDOW_MS`], later ones start after the newest update seen; Hyperliquid answers a
//! time range oldest first, at most a few hundred items, so a full answer simply continues on the
//! next read). Listed: `deposit` (USDC from the Arbitrum bridge) and the transfers whose
//! `destination` is the account and whose `user` is not — `internalTransfer` (`usdSend`),
//! `spotTransfer` (`spotSend`) and `send` (`sendAsset`) — of the allowlisted tokens
//! ([`super::DUST_HC`]). Everything else (funding, vaults, own class transfers, other tokens) is
//! skipped.

use yw_core::evm::address::{Address, parse_address};
use yw_core::hypercore::{HYPE_SYSTEM_ADDRESS, system_address_index};
use yw_json::{Number, Object, Value};

use super::{Cursor, DUST_HC, Fetched, Found, Incoming, decimal_text};
use crate::hypercore::{HcEndpoint, MAX_INFO_RESPONSE, post};
use crate::rpc::Transport;
use crate::text::{json_object, json_str, json_u64};

/// How far back the first read looks (30 days).
pub const FIRST_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
/// The sender line of a bridge deposit.
pub const T_DEPOSIT: &str = "보낸 곳: Arbitrum 브리지 입금 (보낸 주소 없음)";
/// The sender line of a transfer from a `HyperEVM` system address (a move from `HyperEVM`).
pub const T_FROM_EVM: &str = "보낸 곳: HyperEVM에서 이동 (시스템 주소)";

/// The `/info` body.
#[must_use]
pub fn body(user: &Address, start_ms: u64) -> Vec<u8> {
    yw_json::to_vec(&json_object(vec![
        ("type", json_str("userNonFundingLedgerUpdates")),
        ("user", json_str(&user.to_lower_hex())),
        ("startTime", json_u64(start_ms)),
    ]))
}

fn text<'v>(object: &'v Object, key: &str) -> Option<&'v str> {
    object.get(key).and_then(Value::as_str)
}

/// `Some(amount)` when `amount` of `token` is on the allowlist and at or above its threshold,
/// `None` for dust (zero included); `Err` for a token off the allowlist or a malformed amount.
fn listed(token: &str, amount: &str) -> Result<Option<String>, ()> {
    let (_, threshold) = DUST_HC
        .iter()
        .find(|(symbol, _)| *symbol == token)
        .ok_or(())?;
    let amount = decimal_text(amount).ok_or(())?;
    let value = crate::app_hypercore::api_units(amount, 18).ok_or(())?;
    let floor = crate::app_hypercore::api_units(threshold, 18).ok_or(())?;
    Ok((value >= floor).then(|| amount.to_owned()))
}

/// The listed rows and dust keys of a `userNonFundingLedgerUpdates` answer for `account`, and
/// the newest `time` in it; `None` when the answer is not an array (entries of another shape are
/// skipped).
#[must_use]
pub fn parse_ledger(value: &Value, account: &Address) -> Option<(Found, Option<u64>)> {
    let list = value.as_array()?;
    let mut found = Found::default();
    let mut newest: Option<u64> = None;
    for item in list.iter().filter_map(Value::as_object) {
        let Some(time) = item
            .get("time")
            .and_then(Value::as_number)
            .and_then(Number::as_u64)
        else {
            continue;
        };
        newest = Some(newest.map_or(time, |seen| seen.max(time)));
        let Some(delta) = item.get("delta").and_then(Value::as_object) else {
            continue;
        };
        let hash = text(item, "hash")
            .filter(|hash| {
                hash.len() == 66
                    && hash.starts_with("0x")
                    && hash.bytes().skip(2).all(|byte| byte.is_ascii_hexdigit())
            })
            .unwrap_or("")
            .to_ascii_lowercase();
        let Some(kind) = text(delta, "type") else {
            continue;
        };
        let (token, amount, from) = match kind {
            "deposit" => ("USDC", text(delta, "usdc"), None),
            "internalTransfer" | "spotTransfer" | "send" => {
                let to = text(delta, "destination").and_then(|to| parse_address(to).ok());
                let from = text(delta, "user").and_then(|from| parse_address(from).ok());
                let (Some(to), Some(from)) = (to, from) else {
                    continue;
                };
                if to != *account || from == *account {
                    continue;
                }
                let (token, amount) = if kind == "internalTransfer" {
                    ("USDC", text(delta, "usdc"))
                } else {
                    (text(delta, "token").unwrap_or(""), text(delta, "amount"))
                };
                (token, amount, Some(from))
            }
            _ => continue,
        };
        let key = format!("{hash}:{time}:{kind}");
        match listed(token, amount.unwrap_or("")) {
            Err(()) => {}
            Ok(None) => found.dust.push(key),
            Ok(Some(amount)) => {
                let system = from.is_some_and(|from| {
                    from == HYPE_SYSTEM_ADDRESS || system_address_index(&from).is_some()
                });
                found.entries.push(Incoming {
                    key,
                    hash,
                    time_ms: Some(time),
                    block: None,
                    amount,
                    symbol: token.to_owned(),
                    from: from.filter(|_| !system).map(Address::to_lower_hex),
                    from_note: match (from, system) {
                        (None, _) => Some(T_DEPOSIT),
                        (Some(_), true) => Some(T_FROM_EVM),
                        (Some(_), false) => None,
                    },
                    pending: false,
                });
            }
        }
    }
    Some((found, newest))
}

/// One read.
///
/// # Errors
///
/// A fixed error text.
pub fn fetch(
    transport: &dyn Transport,
    endpoint: &HcEndpoint,
    account: &Address,
    cursor: &Cursor,
    start_ms: u64,
) -> Result<Fetched, String> {
    let (start, previous) = match cursor {
        Cursor::Time(newest) => (newest.saturating_add(1), Some(*newest)),
        _ => (start_ms, None),
    };
    let value = post(
        transport,
        endpoint,
        "/info",
        &body(account, start),
        MAX_INFO_RESPONSE,
    )?;
    let (found, newest) = parse_ledger(&value, account)
        .ok_or_else(|| "Hyperliquid API 응답 형식이 올바르지 않습니다".to_owned())?;
    let cursor = match newest.max(previous) {
        Some(time) => Cursor::Time(time),
        None => Cursor::Time(start.saturating_sub(1)),
    };
    Ok(Fetched {
        found,
        cursor,
        ..Fetched::default()
    })
}

#[cfg(test)]
mod tests {
    use yw_core::evm::address::Address;
    use yw_json::Limits;

    use super::{T_DEPOSIT, T_FROM_EVM, body, parse_ledger};

    const ME: &str = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
    const THEM: &str = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

    fn me() -> Address {
        yw_core::evm::address::parse_address(ME).unwrap()
    }

    /// A ledger fixture in the documented shape (`time`, `hash`, `delta`).
    #[test]
    fn ledger_updates_to_the_account_become_rows_and_dust() {
        let hash = format!("0x{}", "c".repeat(64));
        let text = format!(
            r#"[
            {{"time":1700000000001,"hash":"{hash}","delta":{{"type":"deposit","usdc":"250.0"}}}},
            {{"time":1700000000002,"hash":"{hash}","delta":{{"type":"internalTransfer","usdc":"10.5","user":"{THEM}","destination":"{ME}","fee":"0.0"}}}},
            {{"time":1700000000003,"hash":"{hash}","delta":{{"type":"spotTransfer","token":"HYPE","amount":"1.25","usdcValue":"30.0","user":"{THEM}","destination":"{ME}","fee":"0.0","nativeTokenFee":"0.0","nonce":1,"feeToken":"USDC"}}}},
            {{"time":1700000000004,"hash":"{hash}","delta":{{"type":"spotTransfer","token":"PURR","amount":"500","usdcValue":"1.0","user":"{THEM}","destination":"{ME}","fee":"0.0","nativeTokenFee":"0.0","nonce":2,"feeToken":"USDC"}}}},
            {{"time":1700000000005,"hash":"{hash}","delta":{{"type":"internalTransfer","usdc":"0.001","user":"{THEM}","destination":"{ME}","fee":"0.0"}}}},
            {{"time":1700000000006,"hash":"{hash}","delta":{{"type":"send","user":"{THEM}","destination":"{ME}","sourceDex":"","destinationDex":"spot","token":"USDC","amount":"0.0","usdcValue":"0.0","fee":"0.0","nativeTokenFee":"0.0","nonce":3,"feeToken":"USDC"}}}},
            {{"time":1700000000007,"hash":"{hash}","delta":{{"type":"internalTransfer","usdc":"7.0","user":"{ME}","destination":"{THEM}","fee":"1.0"}}}},
            {{"time":1700000000008,"hash":"{hash}","delta":{{"type":"spotTransfer","token":"HYPE","amount":"2.0","usdcValue":"50.0","user":"0x2222222222222222222222222222222222222222","destination":"{ME}","fee":"0.0","nativeTokenFee":"0.0","nonce":null,"feeToken":"HYPE"}}}},
            {{"time":1700000000009,"hash":"{hash}","delta":{{"type":"funding","coin":"ETH","usdc":"-3.6","szi":"1","fundingRate":"0.0001"}}}},
            {{"time":1700000000010,"hash":"{hash}","delta":{{"type":"accountClassTransfer","usdc":"5.0","toPerp":true}}}}
        ]"#
        );
        let value = yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap();
        let (found, newest) = parse_ledger(&value, &me()).unwrap();
        assert_eq!(newest, Some(1_700_000_000_010));
        let rows: Vec<(&str, &str)> = found
            .entries
            .iter()
            .map(|row| (row.amount.as_str(), row.symbol.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("250.0", "USDC"),
                ("10.5", "USDC"),
                ("1.25", "HYPE"),
                ("2.0", "HYPE")
            ]
        );
        assert_eq!(found.entries[0].from, None);
        assert_eq!(found.entries[0].from_note, Some(T_DEPOSIT));
        assert_eq!(found.entries[1].from.as_deref(), Some(THEM));
        assert_eq!(found.entries[1].hash, hash);
        assert_eq!(found.entries[3].from, None);
        assert_eq!(found.entries[3].from_note, Some(T_FROM_EVM));
        // 0.001 USDC (below 0.01) and a 0 USDC `send`: dust. PURR (not allowlisted), our own
        // outgoing transfer, funding and class transfers: not listed, not counted.
        assert_eq!(found.dust.len(), 2);
        assert!(parse_ledger(&yw_json::Value::Null, &me()).is_none());
        let sent = String::from_utf8(body(&me(), 5)).unwrap();
        assert_eq!(
            sent,
            format!(r#"{{"type":"userNonFundingLedgerUpdates","user":"{ME}","startTime":5}}"#)
        );
    }
}
