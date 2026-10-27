//! Live read-only Solana checks (spec/07 §10 CU measurement, §15.2 methods, §16 provider rows,
//! spec/09 §2.5 "SOL") through the yw-app `sol::rpc` / `sol::flow` path.
//!
//! `cargo test -p yw-app --test sol_live_probe -- --ignored --test-threads=1 --nocapture`
//!
//! - Endpoints come only from the development file (spec/01 §4.6): `YW_RPC_JSON` names the file,
//!   otherwise `%USERPROFILE%\.yw-dev\rpc.json`; keys `solana:mainnet`, `solana:devnet`
//!   (missing → skip). The real path must be outside the repository.
//! - Output names networks by `NetworkId` only: no URL, host, token or server message.
//! - Nothing is signed or sent: messages are unsigned (`simulateTransaction` with
//!   `sigVerify:false`, `getFeeForMessage`), addresses are validator identities read from
//!   `getVoteAccounts` and random addresses; no key is used.
#![expect(
    clippy::print_stdout,
    reason = "the probe report is console output (NetworkId only, no secrets)"
)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use yw_app::rpc::{RpcClient, RpcFailure, classify};
use yw_app::sol::flow::{PreviewJob, PreviewOutcome, SolEndpoint, pre_sign, preview};
use yw_app::sol::rpc as sol;
use yw_core::bip32::path::AccountIndex;
use yw_core::codec::base58::base58_encode;
use yw_core::slip10::SolKeySource;
use yw_core::sol::display::SimSummary;
use yw_core::sol::fee::{SOL_TRANSFER_CU_LIMIT, max_fee};
use yw_core::sol::message::{assemble_transaction, encode_message};
use yw_core::sol::recipient::check_recipient;
use yw_core::sol::template::SPL_ALLOWLIST;
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore};
use yw_json::{Limits as JsonLimits, Number, Object, Value};
use yw_win::http::{Client, HttpError, HttpsUrl};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAX_CONFIG_BYTES: usize = 64 * 1_024;
const BIG_RESPONSE: usize = 8 * 1_024 * 1_024;
const SIM_RUNS: usize = 10;

fn config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("YW_RPC_JSON") {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("USERPROFILE").map(|home| Path::new(&home).join(".yw-dev").join("rpc.json"))
}

fn config() -> Result<Vec<(SolCluster, HttpsUrl)>, String> {
    let cannot = || "설정 파일을 읽을 수 없습니다: rpc.json".to_owned();
    let path = config_path().ok_or_else(cannot)?;
    let real = std::fs::canonicalize(&path).map_err(|_| cannot())?;
    let repo = std::fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .map_err(|_| cannot())?;
    if real.starts_with(&repo) {
        return Err("설정 파일이 저장소 안에 있습니다. 저장소 밖에 두세요.".to_owned());
    }
    let bytes = std::fs::read(&real).map_err(|_| cannot())?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(cannot());
    }
    let body = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    let value = yw_json::parse(body, &JsonLimits::REQUEST).map_err(|_| cannot())?;
    let object = value.as_object().ok_or_else(cannot)?;
    let mut out = Vec::new();
    for (key, cluster) in [
        ("solana:devnet", SolCluster::Devnet),
        ("solana:mainnet", SolCluster::Mainnet),
    ] {
        let Some(item) = object.get(key) else {
            continue;
        };
        let url = item
            .as_str()
            .and_then(|text| HttpsUrl::parse(text).ok())
            .ok_or_else(|| format!("rpc.json: {key} 값이 올바르지 않습니다"))?;
        out.push((cluster, url));
    }
    Ok(out)
}

#[derive(Default)]
struct Report {
    failures: Vec<String>,
}

impl Report {
    fn line(&mut self, net: &str, check: &str, ok: bool, kv: &str) {
        println!(
            "{net:<16} {check:<34} {} {kv}",
            if ok { "ok " } else { "err" }
        );
        if !ok {
            self.failures.push(format!("{net} {check}"));
        }
    }

    fn finish(self) -> TestResult {
        if self.failures.is_empty() {
            Ok(())
        } else {
            Err(format!("not ok: {}", self.failures.join(", ")).into())
        }
    }
}

fn failure_kv(failure: RpcFailure) -> String {
    let detail = match failure {
        RpcFailure::Http(HttpError::Timeout) => "transport=timeout".to_owned(),
        RpcFailure::Http(HttpError::TooLarge) => "transport=too_large".to_owned(),
        RpcFailure::Http(HttpError::Tls) => "transport=tls".to_owned(),
        RpcFailure::Http(_) => "transport=other".to_owned(),
        RpcFailure::Status(status) => format!("http={status}"),
        RpcFailure::Rpc(code) => format!("code={code}"),
        RpcFailure::Malformed => "malformed".to_owned(),
        RpcFailure::Late => "late".to_owned(),
    };
    format!("{detail} class={}", classify(failure).code())
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn object(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(
        Object::from_pairs(
            pairs
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
        .unwrap_or_default(),
    )
}

fn number(value: u64) -> Value {
    Value::Number(Number::from_u64(value))
}

fn u64_at(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_number).and_then(Number::as_u64)
}

fn context_value(result: &Value) -> Option<&Value> {
    result.as_object().and_then(|object| object.get("value"))
}

/// Standard base64 decoding (account data of the mint check).
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| -> Option<u32> {
        Some(u32::from(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let bytes = text.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0_u32;
        for (index, byte) in chunk.iter().enumerate() {
            acc |= value(*byte)? << (18 - 6 * u32::try_from(index).ok()?);
        }
        let produced = chunk.len().saturating_sub(1);
        for index in 0..produced {
            out.push(u8::try_from((acc >> (16 - 8 * u32::try_from(index).ok()?)) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Validator identities (system-owned keypairs that pay vote fees: funded-looking addresses).
fn identities(client: &RpcClient<'_>, url: &HttpsUrl) -> Vec<SolAddress> {
    let params = Value::Array(vec![object(vec![
        ("commitment", text("finalized")),
        ("keepUnstakedDelinquents", Value::Bool(false)),
    ])]);
    let Ok(result) = client.call_limited(url, "getVoteAccounts", params, BIG_RESPONSE) else {
        return Vec::new();
    };
    result
        .as_object()
        .and_then(|object| object.get("current"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|entry| {
                    entry
                        .as_object()
                        .and_then(|object| object.get("nodePubkey"))
                        .and_then(Value::as_str)
                        .and_then(|text| SolAddress::parse(text).ok())
                })
                .take(40)
                .collect()
        })
        .unwrap_or_default()
}

fn random_address(salt: u8) -> SolAddress {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let digest = yw_core::codec::sha256(&[&nanos.to_le_bytes()[..], &[salt]].concat());
    SolAddress::from_bytes(digest)
}

/// A funded system-owned identity with at least `min` lamports.
fn funded(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    candidates: &[SolAddress],
    min: u64,
    skip: Option<SolAddress>,
) -> Option<(SolAddress, u64)> {
    for candidate in candidates {
        if Some(*candidate) == skip {
            continue;
        }
        let Ok(balance) = sol::balance(client, url, candidate) else {
            continue;
        };
        if balance < min {
            continue;
        }
        if let Ok(Some(info)) = sol::account_info(client, url, candidate)
            && info.owner == SolAddress::from_bytes([0; 32])
            && !info.executable
        {
            return Some((*candidate, balance));
        }
    }
    None
}

fn sim_units(summary: SimSummary) -> String {
    match summary {
        SimSummary::Ok { units } => format!("units={units}"),
        SimSummary::Failed { err, units } => {
            format!("failed err={err} units={}", units.unwrap_or(0))
        }
        SimSummary::NoResult => "no-result".to_owned(),
    }
}

#[expect(clippy::too_many_lines, reason = "one probe sequence per cluster")]
fn probe_cluster(report: &mut Report, cluster: SolCluster, url: &HttpsUrl) -> TestResult {
    let net = cluster.network_id();
    let transport = Client::new(yw_app::rpc::RPC_TIMEOUTS).map_err(|_| "WinHTTP")?;
    let client = RpcClient::new(&transport);
    // getGenesisHash (spec/07 §15.1).
    match sol::genesis_hash(&client, url) {
        Ok(genesis) => report.line(
            net,
            "getGenesisHash",
            genesis == cluster.genesis(),
            &format!("genesis={}", base58_encode(&genesis)),
        ),
        Err(failure) => report.line(net, "getGenesisHash", false, &failure_kv(failure)),
    }
    // getLatestBlockhash + getBlockHeight + isBlockhashValid.
    let started = Instant::now();
    let latest = sol::latest_blockhash(&client, url);
    let latency = started.elapsed().as_millis();
    let height = sol::block_height(&client, url);
    let mut blockhash = [0_u8; 32];
    match (latest, height) {
        (Ok((hash, last_valid)), Ok(height)) => {
            blockhash = hash;
            report.line(
                net,
                "getLatestBlockhash+getBlockHeight",
                last_valid >= height && last_valid <= height + 300,
                &format!(
                    "lvbh-height={} latency_ms={latency}",
                    last_valid.saturating_sub(height)
                ),
            );
            let valid = client.call(
                url,
                "isBlockhashValid",
                Value::Array(vec![
                    text(&base58_encode(&hash)),
                    object(vec![("commitment", text("finalized"))]),
                ]),
            );
            match valid {
                Ok(result) => {
                    let value = context_value(&result).and_then(Value::as_bool);
                    report.line(
                        net,
                        "isBlockhashValid",
                        value == Some(true),
                        &format!("value={value:?}"),
                    );
                }
                Err(failure) => report.line(net, "isBlockhashValid", false, &failure_kv(failure)),
            }
        }
        (Err(failure), _) | (_, Err(failure)) => {
            report.line(
                net,
                "getLatestBlockhash+getBlockHeight",
                false,
                &failure_kv(failure),
            );
        }
    }
    // Rent (spec/07 §11: read every preview, never a constant).
    for size in [0_u64, 165] {
        match sol::minimum_rent(&client, url, size) {
            Ok(rent) => report.line(
                net,
                &format!("getMinimumBalanceForRent({size})"),
                rent > 0 && rent <= if size == 0 { 2_000_000 } else { 5_000_000 },
                &format!("lamports={rent}"),
            ),
            Err(failure) => report.line(
                net,
                &format!("getMinimumBalanceForRent({size})"),
                false,
                &failure_kv(failure),
            ),
        }
    }
    let ids = identities(&client, url);
    report.line(
        net,
        "getVoteAccounts identities",
        !ids.is_empty(),
        &format!("count={}", ids.len()),
    );
    let rent0 = sol::minimum_rent(&client, url, 0).unwrap_or(890_880);
    let Some((from, balance)) = funded(&client, url, &ids, rent0 * 4 + 1_000_000, None) else {
        report.line(net, "funded system identity", false, "none");
        return Ok(());
    };
    report.line(
        net,
        "funded system identity",
        true,
        &format!("address={from} balance={balance}"),
    );
    let existing = funded(&client, url, &ids, 1, Some(from)).map(|(address, _)| address);
    // Prioritization fees (p75 input).
    match sol::prioritization_fees(&client, url, &[from]) {
        Ok(fees) => {
            let p75 = yw_core::sol::fee::p75(&fees);
            let nonzero = fees.iter().filter(|fee| **fee > 0).count();
            report.line(
                net,
                "getRecentPrioritizationFees",
                true,
                &format!("count={} nonzero={nonzero} p75={p75}", fees.len()),
            );
        }
        Err(failure) => report.line(
            net,
            "getRecentPrioritizationFees",
            false,
            &failure_kv(failure),
        ),
    }
    // getFeeForMessage: base fee and whether the priority fee is included (spec/07 §16).
    let fresh = random_address(1);
    for price in [0_u64, 1_000, 1_000_000] {
        let core = SolTransferCore {
            from,
            to: fresh,
            asset: SolAsset::Sol,
            amount: rent0 + 1_000,
            cu_limit: SOL_TRANSFER_CU_LIMIT,
            cu_price_micro: price,
        };
        let expected = max_fee(SOL_TRANSFER_CU_LIMIT, price).unwrap_or(0);
        match sol::fee_for_message(&client, url, &encode_message(&core, &blockhash)) {
            Ok(Some(fee)) => report.line(
                net,
                &format!("getFeeForMessage price={price}"),
                fee == expected,
                &format!("rpc={fee} local_max={expected}"),
            ),
            Ok(None) => report.line(
                net,
                &format!("getFeeForMessage price={price}"),
                false,
                "value=null",
            ),
            Err(failure) => report.line(
                net,
                &format!("getFeeForMessage price={price}"),
                false,
                &failure_kv(failure),
            ),
        }
    }
    // CU measurement (spec/07 §10): the real template ×10 to a new and to an existing account.
    let mut targets = vec![("new", fresh)];
    if let Some(existing) = existing {
        targets.push(("existing", existing));
    }
    let mut overall = 0_u64;
    for (kind, to) in targets {
        let mut max_units = 0_u64;
        let mut ok_runs = 0_usize;
        let mut last = String::new();
        for run in 0..SIM_RUNS {
            let core = SolTransferCore {
                from,
                to: if kind == "new" {
                    random_address(u8::try_from(run + 10).unwrap_or(0))
                } else {
                    to
                },
                asset: SolAsset::Sol,
                amount: rent0 + 1_000,
                cu_limit: SOL_TRANSFER_CU_LIMIT,
                cu_price_micro: 0,
            };
            let tx = assemble_transaction(&[0; 64], &encode_message(&core, &[0; 32]));
            let summary = sol::simulate(&client, url, &tx);
            if let SimSummary::Ok { units } = summary {
                max_units = max_units.max(units);
                ok_runs += 1;
            }
            last = sim_units(summary);
        }
        overall = overall.max(max_units);
        report.line(
            net,
            &format!("simulate T_SOL x{SIM_RUNS} ({kind})"),
            ok_runs == SIM_RUNS && max_units + 150 <= u64::from(SOL_TRANSFER_CU_LIMIT),
            &format!("ok_runs={ok_runs} max_units={max_units} last={last}"),
        );
    }
    println!(
        "{net:<16} {:<34} -- measured_max={overall} limit=m+150={} constant={SOL_TRANSFER_CU_LIMIT}",
        "CU limit",
        overall + 150
    );
    // getSignatureStatuses: recent and old signatures with and without history search.
    let signatures = client.call(
        url,
        "getSignaturesForAddress",
        Value::Array(vec![
            text(&from.to_base58()),
            object(vec![
                ("limit", number(1_000)),
                ("commitment", text("finalized")),
            ]),
        ]),
    );
    match signatures {
        Ok(Value::Array(list)) if !list.is_empty() => {
            let pick = |entry: Option<&Value>| {
                entry
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("signature"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            };
            let age = |entry: Option<&Value>| {
                entry
                    .and_then(Value::as_object)
                    .and_then(|object| u64_at(object.get("blockTime")))
                    .map_or(0, |time| {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |elapsed| elapsed.as_secs());
                        now.saturating_sub(time)
                    })
            };
            let newest = (pick(list.first()), age(list.first()));
            let oldest = (pick(list.last()), age(list.last()));
            for (label, (signature, age)) in [("newest", newest), ("oldest", oldest)] {
                let Some(signature) = signature else { continue };
                let off = sol::signature_status(&client, url, &signature, false);
                let on = sol::signature_status(&client, url, &signature, true);
                report.line(
                    net,
                    &format!("getSignatureStatuses {label}"),
                    on.is_ok_and(|status| status != yw_core::sol::broadcast::SigStatus::NotFound),
                    &format!("history_off={off:?} history_on={on:?} age_s={age}"),
                );
            }
        }
        Ok(_) => report.line(net, "getSignaturesForAddress", false, "empty"),
        Err(failure) => report.line(net, "getSignaturesForAddress", false, &failure_kv(failure)),
    }
    let unknown = base58_encode(&[0x11; 64]);
    let status = sol::signature_status(&client, url, &unknown, true);
    report.line(
        net,
        "getSignatureStatuses unknown",
        status == Ok(yw_core::sol::broadcast::SigStatus::NotFound),
        &format!("{status:?}"),
    );
    // dataSlice and the SPL allowlist mint (owner Token, 82 bytes, decimals 6, initialized).
    for entry in SPL_ALLOWLIST
        .iter()
        .filter(|entry| entry.cluster == cluster)
    {
        let Ok(mint) = SolAddress::parse(entry.mint) else {
            continue;
        };
        let sliced = sol::account_info(&client, url, &mint);
        let full = client.call(
            url,
            "getAccountInfo",
            Value::Array(vec![
                text(entry.mint),
                object(vec![
                    ("encoding", text("base64")),
                    ("commitment", text("finalized")),
                ]),
            ]),
        );
        let data = full.ok().and_then(|result| {
            context_value(&result)
                .and_then(Value::as_object)
                .and_then(|object| object.get("data"))
                .and_then(Value::as_array)
                .and_then(|pair| pair.first())
                .and_then(Value::as_str)
                .and_then(base64_decode)
        });
        let owner_ok = sliced.as_ref().is_ok_and(|info| {
            info.is_some_and(|info| {
                info.owner.to_base58() == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            })
        });
        let shape = data
            .as_ref()
            .map(|data| (data.len(), data.get(44).copied(), data.get(45).copied()));
        report.line(
            net,
            &format!("mint {}", entry.symbol),
            owner_ok && shape == Some((82, Some(entry.decimals), Some(1))),
            &format!(
                "mint={} dataSlice_owner_token={owner_ok} shape={shape:?}",
                entry.mint
            ),
        );
    }
    // The app path, read-only: preview (no key) and the pre-sign lookup.
    let endpoint = SolEndpoint {
        cluster,
        url: url.clone(),
    };
    let to = random_address(99);
    let recipient =
        check_recipient(&to.to_base58(), &from, &[]).map_err(|error| format!("{error:?}"))?;
    let job = PreviewJob {
        job: 1,
        endpoint: endpoint.clone(),
        source: SolKeySource::Standard(AccountIndex::ZERO),
        from,
        account_label: "probe".to_owned(),
        recipient,
        amount: Some(rent0 + 1_000),
        fee_cap: 100_000,
        max_cu_price: 1_000_000,
        pending_exists: false,
        journal_room: true,
    };
    let started = Instant::now();
    match preview(&transport, &job).outcome {
        PreviewOutcome::Ready(prepared) => report.line(
            net,
            "app preview (read-only)",
            prepared.facts.blocks.is_empty(),
            &format!(
                "blocks={:?} flags={:#04x} price={} max_fee={} rpc_fee={:?} sim={} ms={}",
                prepared.facts.blocks,
                prepared.flags,
                prepared.core.cu_price_micro,
                prepared.max_fee,
                prepared.facts.rpc_fee,
                sim_units(prepared.facts.simulation),
                started.elapsed().as_millis()
            ),
        ),
        PreviewOutcome::Failed { code, .. } => {
            report.line(
                net,
                "app preview (read-only)",
                false,
                &format!("code={}", code.code()),
            );
        }
    }
    match pre_sign(&transport, &endpoint) {
        Ok((_, last_valid)) => report.line(
            net,
            "app pre-sign lookup",
            true,
            &format!("lvbh={last_valid}"),
        ),
        Err(error) => report.line(net, "app pre-sign lookup", false, &format!("{error:?}")),
    }
    Ok(())
}

#[test]
#[ignore = "live network: reads %USERPROFILE%\\.yw-dev\\rpc.json (spec/09 §2.5)"]
fn live_solana_probe() -> TestResult {
    let entries = config()?;
    let mut report = Report::default();
    if entries.is_empty() {
        println!("solana:*          (no endpoints configured)        skip");
    }
    for (cluster, url) in &entries {
        probe_cluster(&mut report, *cluster, url)?;
    }
    report.finish()
}
