//! Solana received history (spec/04 §2.6, spec/07 §12.3, 2026-11-11): after the genesis check,
//! `getSignaturesForAddress` (limit [`SIG_LIMIT`]) of the selected account and of its derived
//! token accounts of the allowlisted mints (a transfer to an existing token account does not name
//! the wallet), then `getTransaction` (`jsonParsed`, `maxSupportedTransactionVersion` 0) only for
//! signatures not looked at before (at most [`MAX_TX_LOOKUPS`] per read). A transaction is an
//! incoming transfer when the account did not sign it and its SOL balance or an allowlisted
//! token balance it owns went up; everything else is skipped. Other mints are never read.

use yw_core::sol::pda::associated_token_address;
use yw_core::sol::rent::format_amount;
use yw_core::sol::template::spl_entries;
use yw_core::sol::{SolAddress, SolCluster};
use yw_json::{Number, Object, Value};

use super::{Cursor, DUST_SOL_LAMPORTS, Fetched, Found, Incoming};
use crate::errors::ErrorCode;
use crate::rpc::{RpcClient, Transport, classify};
use crate::sol::flow::{SolEndpoint, check_genesis};
use crate::text::{json_object, json_str, json_u64};
use yw_core::lang::Lang;

/// Signatures asked per address.
pub const SIG_LIMIT: u64 = 20;
/// Most `getTransaction` calls of one read (the rest on the next read).
pub const MAX_TX_LOOKUPS: usize = 20;
/// Most signatures remembered as looked at.
pub const MAX_SEEN: usize = 200;

/// One `getSignaturesForAddress` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigInfo {
    /// Base58 signature.
    pub signature: String,
    /// Slot.
    pub slot: u64,
    /// The transaction failed (moved nothing).
    pub failed: bool,
    /// `blockTime` (seconds).
    pub block_time: Option<u64>,
    /// `confirmationStatus` was `processed`.
    pub processed: bool,
}

fn u64_of(value: Option<&Value>) -> Option<u64> {
    value?.as_number().and_then(Number::as_u64)
}

/// Parses a `getSignaturesForAddress` result (entries of another shape are skipped).
///
/// # Errors
///
/// [`ErrorCode::Rpc005`] when the result is not an array.
pub fn parse_signatures(result: &Value) -> Result<Vec<SigInfo>, ErrorCode> {
    let list = result.as_array().ok_or(ErrorCode::Rpc005)?;
    Ok(list
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|object| {
            let signature = object.get("signature")?.as_str()?;
            // A base58 64-byte signature is 64–88 characters.
            if !(64..=88).contains(&signature.len())
                || yw_core::codec::base58::base58_decode_64(signature).is_err()
            {
                return None;
            }
            Some(SigInfo {
                signature: signature.to_owned(),
                slot: u64_of(object.get("slot"))?,
                failed: object.get("err").is_some_and(|error| !error.is_null()),
                block_time: u64_of(object.get("blockTime")),
                processed: object.get("confirmationStatus").and_then(Value::as_str)
                    == Some("processed"),
            })
        })
        .collect())
}

fn keys_of(transaction: &Object) -> Option<Vec<(SolAddress, bool, bool)>> {
    let keys = transaction
        .get("message")?
        .as_object()?
        .get("accountKeys")?
        .as_array()?;
    keys.iter()
        .map(|key| {
            let key = key.as_object()?;
            Some((
                SolAddress::parse(key.get("pubkey")?.as_str()?).ok()?,
                key.get("signer")?.as_bool()?,
                key.get("writable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ))
        })
        .collect()
}

fn balances(meta: &Object, key: &str) -> Option<Vec<u64>> {
    meta.get(key)?
        .as_array()?
        .iter()
        .map(|value| value.as_number().and_then(Number::as_u64))
        .collect()
}

/// `(account index, mint, owner, raw amount)` of a token balance list.
fn token_balances(meta: &Object, key: &str) -> Vec<(u64, String, String, u64)> {
    meta.get(key)
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|entry| {
                    let entry = entry.as_object()?;
                    let amount = entry
                        .get("uiTokenAmount")?
                        .as_object()?
                        .get("amount")?
                        .as_str()?
                        .parse::<u64>()
                        .ok()?;
                    Some((
                        u64_of(entry.get("accountIndex"))?,
                        entry.get("mint")?.as_str()?.to_owned(),
                        entry.get("owner")?.as_str()?.to_owned(),
                        amount,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

type Keys = [(SolAddress, bool, bool)];
type TokenBalance = (u64, String, String, u64);

/// The owner's SOL change: `(gained lamports, sender)` — the sender is the account that lost the
/// most (the fee payer otherwise); `Some((0, None))` for a zero-lamport transfer to a writable
/// owner account in a transaction without token balances; `None` otherwise.
fn sol_change(meta: &Object, keys: &Keys, owner: &SolAddress) -> Option<(u64, Option<String>)> {
    let pre = balances(meta, "preBalances")?;
    let post = balances(meta, "postBalances")?;
    if pre.len() != keys.len() || post.len() != keys.len() {
        return None;
    }
    let delta = |index: usize| {
        i128::from(post.get(index).copied().unwrap_or(0))
            - i128::from(pre.get(index).copied().unwrap_or(0))
    };
    let index = keys.iter().position(|(key, ..)| key == owner)?;
    let gained = delta(index);
    if gained > 0 {
        let from = (0..keys.len())
            .filter(|other| *other != index)
            .min_by_key(|other| delta(*other))
            .filter(|other| delta(*other) < 0)
            .or(Some(0))
            .and_then(|other| keys.get(other))
            .map(|(key, ..)| key.to_base58());
        return Some((u64::try_from(gained).unwrap_or(u64::MAX), from));
    }
    (gained == 0
        && keys.get(index).is_some_and(|(_, _, writable)| *writable)
        && token_balances(meta, "postTokenBalances").is_empty())
    .then_some((0, None))
}

/// The owner's change of `mint`: `(gained raw units, sender)` when it owns a token account of
/// it in the transaction and the sum did not go down (0 = a zero-token transfer).
fn token_change(
    pre: &[TokenBalance],
    post: &[TokenBalance],
    owner: &str,
    mint: &str,
) -> Option<(u64, Option<String>)> {
    let amount_at = |list: &[TokenBalance], index: u64| {
        list.iter()
            .find(|(at, token, ..)| *at == index && token == mint)
            .map_or(0, |(.., amount)| *amount)
    };
    let accounts: Vec<u64> = post
        .iter()
        .filter(|(_, token, holder, _)| token == mint && holder == owner)
        .map(|(index, ..)| *index)
        .collect();
    if accounts.is_empty() {
        return None;
    }
    let gained: i128 = accounts
        .iter()
        .map(|index| i128::from(amount_at(post, *index)) - i128::from(amount_at(pre, *index)))
        .sum();
    let gained = u64::try_from(gained).ok()?;
    let from = pre
        .iter()
        .filter(|(index, token, holder, _)| {
            token == mint && holder != owner && !accounts.contains(index)
        })
        .find(|(index, _, _, before)| amount_at(post, *index) < *before)
        .map(|(_, _, holder, _)| holder.clone());
    Some((gained, from))
}

/// The incoming transfers of one `getTransaction` (jsonParsed) result for `owner`: SOL when its
/// balance went up, each allowlisted mint of `cluster` when the balance of a token account it
/// owns went up. Nothing when it failed or when `owner` signed it (its own send or action).
/// Zero changes of a writable owner account (a 0-lamport or 0-token transfer) are dust.
#[must_use]
pub fn incoming_of(
    result: &Value,
    owner: &SolAddress,
    cluster: SolCluster,
    info: &SigInfo,
) -> Found {
    let mut found = Found::default();
    let Some(object) = result.as_object() else {
        return found;
    };
    let Some(meta) = object.get("meta").and_then(Value::as_object) else {
        return found;
    };
    let keys = object
        .get("transaction")
        .and_then(Value::as_object)
        .and_then(keys_of);
    let Some(keys) = keys.filter(|_| meta.get("err").is_some_and(Value::is_null)) else {
        return found;
    };
    if keys.iter().any(|(key, signer, _)| key == owner && *signer) {
        return found;
    }
    let time_ms = u64_of(object.get("blockTime"))
        .or(info.block_time)
        .map(|seconds| seconds.saturating_mul(1_000));
    let fee_payer = keys.first().map(|(key, ..)| key.to_base58());
    let mut add = |key: String, raw: u64, threshold: u64, amount: String, symbol: &str, from| {
        if raw < threshold {
            found.dust.push(key);
        } else {
            found.entries.push(Incoming {
                key,
                hash: info.signature.clone(),
                time_ms,
                block: Some(info.slot),
                amount,
                symbol: symbol.to_owned(),
                from,
                from_note: None,
                pending: info.processed,
                ..Incoming::default()
            });
        }
    };
    if let Some((lamports, from)) = sol_change(meta, &keys, owner) {
        add(
            format!("{}:SOL", info.signature),
            lamports,
            DUST_SOL_LAMPORTS,
            format_amount(lamports, 9),
            "SOL",
            from.or_else(|| fee_payer.clone()),
        );
    }
    let owner_text = owner.to_base58();
    let pre = token_balances(meta, "preTokenBalances");
    let post = token_balances(meta, "postTokenBalances");
    for entry in spl_entries(cluster) {
        let mint = entry.mint.to_base58();
        let Some((raw, from)) = token_change(&pre, &post, &owner_text, &mint) else {
            continue;
        };
        let threshold = 10_u64
            .checked_pow(u32::from(
                entry.decimals.saturating_sub(super::DUST_TOKEN_DIGITS),
            ))
            .unwrap_or(1);
        add(
            format!("{}:{mint}", info.signature),
            raw,
            threshold.max(1),
            format_amount(raw, entry.decimals),
            entry.symbol,
            from.or_else(|| fee_payer.clone()),
        );
    }
    found
}

fn signatures(
    client: &RpcClient<'_>,
    endpoint: &SolEndpoint,
    address: &SolAddress,
) -> Result<Vec<SigInfo>, ErrorCode> {
    let config = json_object(vec![
        ("limit", json_u64(SIG_LIMIT)),
        ("commitment", json_str("confirmed")),
    ]);
    let result = client
        .call(
            &endpoint.url,
            "getSignaturesForAddress",
            Value::Array(vec![json_str(&address.to_base58()), config]),
        )
        .map_err(classify)?;
    parse_signatures(&result)
}

fn transaction(
    client: &RpcClient<'_>,
    endpoint: &SolEndpoint,
    signature: &str,
) -> Result<Value, ErrorCode> {
    let config = json_object(vec![
        ("encoding", json_str("jsonParsed")),
        ("maxSupportedTransactionVersion", json_u64(0)),
        ("commitment", json_str("confirmed")),
    ]);
    client
        .call(
            &endpoint.url,
            "getTransaction",
            Value::Array(vec![json_str(signature), config]),
        )
        .map_err(classify)
}

/// The account and its allowlisted token accounts (derived locally).
#[must_use]
pub fn addresses(owner: &SolAddress, cluster: SolCluster) -> Vec<SolAddress> {
    let mut out = vec![*owner];
    for entry in spl_entries(cluster) {
        if let Ok((ata, _)) = associated_token_address(owner, &entry.token_program, &entry.mint) {
            out.push(ata);
        }
    }
    out
}

/// One read.
///
/// # Errors
///
/// A fixed error text.
pub fn fetch(
    transport: &dyn Transport,
    endpoint: &SolEndpoint,
    owner: &SolAddress,
    cursor: &Cursor,
    lang: Lang,
) -> Result<Fetched, String> {
    let client = RpcClient::new(transport);
    if !check_genesis(&client, endpoint).map_err(|code| code.text_in(lang))? {
        return Err(ErrorCode::Rpc006.text_in(lang));
    }
    let mut seen: Vec<String> = match cursor {
        Cursor::Seen(list) => list.clone(),
        _ => Vec::new(),
    };
    let mut infos: Vec<SigInfo> = Vec::new();
    for address in addresses(owner, endpoint.cluster) {
        for info in signatures(&client, endpoint, &address).map_err(|code| code.text_in(lang))? {
            if !infos.iter().any(|known| known.signature == info.signature) {
                infos.push(info);
            }
        }
    }
    infos.sort_by_key(|info| core::cmp::Reverse(info.slot));
    let mut found = Found::default();
    let mut looked = Vec::new();
    let mut lookups = 0_usize;
    let mut failure = None;
    for info in infos {
        if seen.contains(&info.signature) {
            continue;
        }
        if info.failed {
            looked.push(info.signature);
            continue;
        }
        if lookups >= MAX_TX_LOOKUPS {
            break;
        }
        lookups = lookups.saturating_add(1);
        match transaction(&client, endpoint, &info.signature) {
            // Not served yet: asked again on the next read.
            Ok(Value::Null) => {}
            Ok(result) => {
                let more = incoming_of(&result, owner, endpoint.cluster, &info);
                // A processed (unconfirmed) one is looked at again later.
                if !info.processed {
                    looked.push(info.signature.clone());
                }
                found.entries.extend(more.entries);
                found.dust.extend(more.dust);
            }
            Err(code) => {
                failure = Some(code);
                break;
            }
        }
    }
    if let Some(code) = failure
        && looked.is_empty()
        && found.entries.is_empty()
    {
        return Err(code.text_in(lang));
    }
    looked.append(&mut seen);
    looked.truncate(MAX_SEEN);
    Ok(Fetched {
        found,
        cursor: Cursor::Seen(looked),
        ..Fetched::default()
    })
}

#[cfg(test)]
mod tests {
    use yw_core::sol::{SolAddress, SolCluster};
    use yw_json::Limits;

    use super::{SigInfo, incoming_of, parse_signatures};

    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn sig() -> String {
        yw_core::codec::base58::base58_encode(&[5; 64])
    }

    fn json(text: &str) -> yw_json::Value {
        yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap()
    }

    fn owner() -> SolAddress {
        SolAddress::from_bytes([7; 32])
    }

    fn sender() -> SolAddress {
        SolAddress::from_bytes([9; 32])
    }

    fn info() -> SigInfo {
        SigInfo {
            signature: sig(),
            slot: 300,
            failed: false,
            block_time: Some(1_700_000_000),
            processed: false,
        }
    }

    fn tx(owner_signs: bool, pre: [u64; 3], post: [u64; 3], tokens: (&str, &str)) -> String {
        format!(
            r#"{{"slot":300,"blockTime":1700000001,"meta":{{"err":null,"fee":5000,"preBalances":[{},{},{}],"postBalances":[{},{},{}],"preTokenBalances":[{}],"postTokenBalances":[{}]}},"transaction":{{"signatures":["{}"],"message":{{"accountKeys":[{{"pubkey":"{}","signer":true,"writable":true,"source":"transaction"}},{{"pubkey":"{}","signer":{owner_signs},"writable":true,"source":"transaction"}},{{"pubkey":"11111111111111111111111111111111","signer":false,"writable":false,"source":"transaction"}}]}}}}}}"#,
            pre[0],
            pre[1],
            pre[2],
            post[0],
            post[1],
            post[2],
            tokens.0,
            tokens.1,
            sig(),
            sender().to_base58(),
            owner().to_base58(),
        )
    }

    fn token(index: u64, owner: &SolAddress, amount: u64) -> String {
        format!(
            r#"{{"accountIndex":{index},"mint":"{USDC}","owner":"{}","programId":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","uiTokenAmount":{{"amount":"{amount}","decimals":6}}}}"#,
            owner.to_base58()
        )
    }

    #[test]
    fn signature_list_parsing() {
        let sig = sig();
        let list = parse_signatures(&json(&format!(
            r#"[{{"signature":"{sig}","slot":5,"err":null,"blockTime":7,"confirmationStatus":"finalized"}},{{"signature":"{sig}","slot":6,"err":{{"InstructionError":[0,"x"]}},"blockTime":null,"confirmationStatus":"processed"}},{{"signature":"short","slot":1}}]"#
        )))
        .unwrap();
        assert_eq!(list.len(), 2);
        assert!(!list[0].failed && list[0].block_time == Some(7) && !list[0].processed);
        assert!(list[1].failed && list[1].processed);
        assert!(parse_signatures(&json("{}")).is_err());
    }

    /// Small `getTransaction` fixtures: SOL in, our own send, dust, zero, a failed transaction.
    #[test]
    fn incoming_sol_from_others_only() {
        // 0.25 SOL from the fee payer.
        let found = incoming_of(
            &json(&tx(
                false,
                [2_000_000_000, 0, 1],
                [1_749_995_000, 250_000_000, 1],
                ("", ""),
            )),
            &owner(),
            SolCluster::Mainnet,
            &info(),
        );
        assert_eq!(found.entries.len(), 1);
        let row = &found.entries[0];
        assert_eq!(
            (row.amount.as_str(), row.symbol.as_str()),
            ("0.250000000", "SOL")
        );
        assert_eq!(row.from, Some(sender().to_base58()));
        assert_eq!(row.time_ms, Some(1_700_000_001_000));
        assert_eq!(row.hash, sig());
        // Our own send (the account signed): nothing.
        let own = incoming_of(
            &json(&tx(
                true,
                [0, 2_000_000_000, 1],
                [250_000_000, 1_749_995_000, 1],
                ("", ""),
            )),
            &owner(),
            SolCluster::Mainnet,
            &info(),
        );
        assert_eq!(own, super::Found::default());
        // Dust SOL (poisoning) and a zero-lamport transfer: counted only.
        let dust = incoming_of(
            &json(&tx(false, [1_000_000, 5, 1], [994_000, 1_005, 1], ("", ""))),
            &owner(),
            SolCluster::Mainnet,
            &info(),
        );
        assert!(dust.entries.is_empty());
        assert_eq!(dust.dust.len(), 1);
        let zero = incoming_of(
            &json(&tx(false, [1_000_000, 5, 1], [995_000, 5, 1], ("", ""))),
            &owner(),
            SolCluster::Mainnet,
            &info(),
        );
        assert_eq!(zero.dust.len(), 1);
        // A failed transaction moves nothing.
        let failed = tx(
            false,
            [2_000_000_000, 0, 1],
            [1_749_995_000, 250_000_000, 1],
            ("", ""),
        )
        .replace(r#""err":null"#, r#""err":{"InstructionError":[0,"x"]}"#);
        assert_eq!(
            incoming_of(&json(&failed), &owner(), SolCluster::Mainnet, &info()),
            super::Found::default()
        );
    }

    #[test]
    fn incoming_allowlisted_tokens_only() {
        // 12.5 USDC from the sender's token account (index 2 here stands for it).
        let pre = format!(
            "{},{}",
            token(1, &owner(), 0),
            token(2, &sender(), 20_000_000)
        );
        let post = format!(
            "{},{}",
            token(1, &owner(), 12_500_000),
            token(2, &sender(), 7_500_000)
        );
        let usdc = incoming_of(
            &json(&tx(false, [9, 9, 1], [9, 9, 1], (&pre, &post))),
            &owner(),
            SolCluster::Mainnet,
            &info(),
        );
        assert_eq!(usdc.entries.len(), 1);
        assert_eq!(usdc.entries[0].amount, "12.500000");
        assert_eq!(usdc.entries[0].symbol, "USDC");
        assert_eq!(usdc.entries[0].from, Some(sender().to_base58()));
        // A dust USDC amount (0.00005) and another mint: never listed.
        let other = format!(
            r#"{{"accountIndex":1,"mint":"{}","owner":"{}","uiTokenAmount":{{"amount":"999","decimals":0}}}}"#,
            SolAddress::from_bytes([3; 32]).to_base58(),
            owner().to_base58()
        );
        let small = incoming_of(
            &json(&tx(
                false,
                [9, 9, 1],
                [9, 9, 1],
                ("", &format!("{},{other}", token(1, &owner(), 50))),
            )),
            &owner(),
            SolCluster::Mainnet,
            &info(),
        );
        assert!(small.entries.is_empty());
        assert_eq!(small.dust.len(), 1);
        // Devnet has its own allowlist: the mainnet USDC mint is not on it.
        let devnet = incoming_of(
            &json(&tx(false, [9, 9, 1], [9, 9, 1], (&pre, &post))),
            &owner(),
            SolCluster::Devnet,
            &info(),
        );
        assert!(devnet.entries.is_empty());
    }
}
