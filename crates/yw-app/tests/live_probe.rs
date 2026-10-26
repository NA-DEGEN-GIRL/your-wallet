//! Live read-only checks against the configured endpoints (spec/09 §2.5, spec/03 §1.5 A6–A8,
//! A9 (c)–(e), L-LIMITS, the §1.2 "구현 시 확인" registry rows) through the yw-app `rpc::evm` path.
//!
//! `cargo test -p yw-app --test live_probe -- --ignored --test-threads=1 --nocapture`
//!
//! - Endpoints come only from the development file (spec/01 §4.6): `YW_RPC_JSON` names the file,
//!   otherwise `%USERPROFILE%\.yw-dev\rpc.json`; strict JSON object ≤ 64 KiB whose real path is
//!   outside the repository; keys `eip155:1`, `eip155:11155111`, `eip155:999` (missing → skip).
//! - Output names networks by `NetworkId` only: no URL, host, token or server message is printed
//!   (errors show the JSON-RPC code, HTTP status or transport kind).
//! - Nothing is signed or broadcast: `eth_simulateV1`, `eth_estimateGas` and the read-only
//!   preparation use random or observed addresses and never a key.
#![expect(
    clippy::print_stdout,
    reason = "the probe report is console output (NetworkId only, no secrets)"
)]

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use yw_app::flow::evm::prepare::{PrepareJob, PrepareOutcome, SendIntent, prepare};
use yw_app::flow::evm::{
    ChainCache, ChainCheck, ChainJob, Limits, SharedTransport, SystemClock, check_chain,
};
use yw_app::rpc::evm as rpc;
use yw_app::rpc::{RPC_TIMEOUTS, RpcClient, RpcFailure, classify};
use yw_core::approval::{ApprovalId, ApprovalOrigin, SimulationBinding};
use yw_core::codec::keccak256;
use yw_core::evm::abi::{SEL_DECIMALS, SEL_SYMBOL, decode_decimals, decode_symbol};
use yw_core::evm::address::Address;
use yw_core::evm::amount::{U256, format_gwei};
use yw_core::evm::chain::{
    ChainInfo, ContractRole, GenesisRule, OPENSEA_CONDUIT_KEY, ethereum_mainnet, hyperevm_mainnet,
    sepolia,
};
use yw_core::evm::fee::suggest_fees;
use yw_core::evm::simulate::{SimOutcome, SimStatus};
use yw_core::vault::EvmKeySource;
use yw_json::{Limits as JsonLimits, Number, Object, Value};
use yw_win::http::{Client, HttpError, HttpsUrl};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAX_CONFIG_BYTES: usize = 64 * 1_024;
const LOGS_MAX_RESPONSE: usize = 4 * 1_024 * 1_024;
const HYPEREVM_FIRST_GENESIS: &str =
    "0xd8fcc13b6a195b88b7b2da3722ff6cad767b13a8c1e9ffb1c73aa9d216d895f0";
const TRANSFER_TOPIC: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const WETH9_DEPOSIT_TOPIC: &str =
    "e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c";
const WETH9_WITHDRAWAL_TOPIC: &str =
    "7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65";

// ----- configuration (spec/01 §4.6) ----------------------------------------------------------

fn config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("YW_RPC_JSON") {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("USERPROFILE").map(|home| Path::new(&home).join(".yw-dev").join("rpc.json"))
}

/// Reads the endpoint file; errors are fixed texts (never the path's content or parser text).
fn config() -> Result<Vec<(String, HttpsUrl)>, String> {
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
    let mut entries = Vec::new();
    for key in ["eip155:1", "eip155:11155111", "eip155:999"] {
        let Some(item) = object.get(key) else {
            continue;
        };
        let url = item
            .as_str()
            .and_then(|text| HttpsUrl::parse(text).ok())
            .ok_or_else(|| format!("rpc.json: {key} 값이 올바르지 않습니다"))?;
        entries.push((key.to_owned(), url));
    }
    Ok(entries)
}

fn endpoint(entries: &[(String, HttpsUrl)], key: &str) -> Option<HttpsUrl> {
    entries
        .iter()
        .find(|(known, _)| known == key)
        .map(|(_, url)| url.clone())
}

// ----- report --------------------------------------------------------------------------------

#[derive(Default)]
struct Report {
    failures: Vec<String>,
}

impl Report {
    fn line(&mut self, net: &str, check: &str, ok: bool, kv: &str) {
        println!(
            "{net:<16} {check:<28} {} {kv}",
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

/// An error as key=value without server text.
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

fn hex(bytes: &[u8]) -> String {
    format!("0x{}", yw_core::hex::encode(bytes))
}

fn quantity(value: u64) -> Value {
    Value::String(format!("0x{value:x}"))
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn object(pairs: Vec<(&str, Value)>) -> Value {
    Object::from_pairs(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .map_or(Value::Null, Value::Object)
}

fn random_address(salt: u8) -> Address {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut seed = nanos.to_be_bytes().to_vec();
    seed.push(salt);
    let digest = keccak256(&seed);
    let mut bytes = [0_u8; 20];
    bytes.copy_from_slice(digest.get(12..32).unwrap_or(&[0; 20]));
    Address::from_bytes(bytes)
}

fn quantity_of(value: Option<&Value>) -> Option<u64> {
    U256::parse_quantity_lenient(value?.as_str()?)
        .ok()?
        .to_u64()
}

fn chain_job(info: &ChainInfo, url: &HttpsUrl) -> ChainJob {
    ChainJob {
        caps: info.default_caps,
        info: info.clone(),
        url: url.clone(),
    }
}

fn chains() -> [(&'static str, ChainInfo); 3] {
    [
        ("eip155:1", ethereum_mainnet()),
        ("eip155:11155111", sepolia()),
        ("eip155:999", hyperevm_mainnet()),
    ]
}

fn client() -> Result<Client, String> {
    Client::new(RPC_TIMEOUTS).map_err(|_| "HTTPS 클라이언트를 만들 수 없습니다".to_owned())
}

// ----- chain checks and a read-only preparation ----------------------------------------------

/// Senders of the 20 most recent blocks, newest first (system senders `0x2222…` skipped,
/// `HyperEVM` blocks are small and often carry only system transactions), at most `max`.
fn recent_senders(client: &RpcClient<'_>, url: &HttpsUrl, max: usize) -> Vec<Address> {
    let Ok(latest) = rpc::block_number(client, url) else {
        return Vec::new();
    };
    let mut out: Vec<Address> = Vec::new();
    for number in (latest.saturating_sub(19)..=latest).rev() {
        let Ok(block) = client.call_limited(
            url,
            "eth_getBlockByNumber",
            Value::Array(vec![quantity(number), Value::Bool(true)]),
            LOGS_MAX_RESPONSE,
        ) else {
            continue;
        };
        let transactions = block
            .as_object()
            .and_then(|object| object.get("transactions"))
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        for tx in &transactions {
            let Some(from) = tx
                .as_object()
                .and_then(|tx| tx.get("from"))
                .and_then(Value::as_str)
                .and_then(|from| yw_core::evm::address::parse_address(from).ok())
            else {
                continue;
            };
            if !from.to_lower_hex().starts_with("0x2222222222") && !out.contains(&from) {
                out.push(from);
            }
            if out.len() >= max {
                return out;
            }
        }
    }
    out
}

/// A recent sender that is an EOA without code, has no pending transaction (`pending ==
/// latest`, otherwise the app rightly answers E06) and holds ≥ 0.01 native.
fn funded_sender(client: &RpcClient<'_>, url: &HttpsUrl) -> Option<Address> {
    let threshold = U256::from_u64(10_000_000_000_000_000);
    recent_senders(client, url, 12).into_iter().find(|from| {
        let idle = matches!(
            (
                rpc::transaction_count(client, url, from, "latest"),
                rpc::transaction_count(client, url, from, "pending"),
            ),
            (Ok(latest), Ok(pending)) if latest == pending
        );
        idle && rpc::code(client, url, from).is_ok_and(|code| code.is_empty())
            && rpc::balance(client, url, from, "latest").is_ok_and(|value| value >= threshold)
    })
}

fn binding_kv(binding: &SimulationBinding) -> String {
    match binding {
        SimulationBinding::Simulated { verdict, .. } => format!("sim={verdict:?}"),
        SimulationBinding::None { reason } => format!("sim=None({reason:?})"),
        SimulationBinding::NotApplicable => "sim=n/a".to_owned(),
    }
}

fn read_only_prepare(
    report: &mut Report,
    net: &str,
    info: &ChainInfo,
    url: &HttpsUrl,
    http: &Client,
) {
    let client = RpcClient::new(http);
    let Some(sender) = funded_sender(&client, url) else {
        report.line(
            net,
            "prepare (read-only)",
            false,
            "no funded EOA sender in latest block",
        );
        return;
    };
    let job = PrepareJob {
        job: 1,
        chain: chain_job(info, url),
        id: ApprovalId([1; 16]),
        origin: ApprovalOrigin::App,
        account: sender,
        signer: EvmKeySource::Derived(yw_core::bip32::path::AccountIndex::ZERO),
        intent: SendIntent {
            to: random_address(7),
            value: U256::from_u64(1),
            data: Vec::new(),
            access_list: Vec::new(),
            dapp_gas: None,
        },
        replace: None,
        records: Vec::new(),
        journal_room: true,
        address_book: Vec::new(),
        extra_warnings: Vec::new(),
        limits: Limits::PRODUCTION,
    };
    let started = Instant::now();
    let Ok(owned) = Client::new(RPC_TIMEOUTS) else {
        report.line(net, "prepare (read-only)", false, "no HTTPS client");
        return;
    };
    let shared: SharedTransport = std::sync::Arc::new(owned);
    let result = prepare(
        &shared,
        &mut ChainCache::default(),
        &job,
        &SystemClock,
        &|_| {},
    );
    let elapsed = started.elapsed().as_millis();
    match result.outcome {
        PrepareOutcome::Ready(prepared) => {
            let rules: Vec<String> = prepared
                .draft
                .display
                .warnings
                .iter()
                .map(|warning| warning.rule.label())
                .collect();
            let simulated_ok = matches!(
                prepared.draft.simulation,
                SimulationBinding::Simulated { .. }
            );
            report.line(
                net,
                "prepare (read-only)",
                simulated_ok,
                &format!(
                    "{} gasLimit={} maxFee={} tip={} risk={:?} rules=[{}] ms={elapsed}",
                    binding_kv(&prepared.draft.simulation),
                    prepared.context.tx.gas_limit,
                    format_gwei(&prepared.context.tx.max_fee_per_gas),
                    format_gwei(&prepared.context.tx.max_priority_fee_per_gas),
                    prepared.draft.display.risk,
                    rules.join(","),
                ),
            );
        }
        PrepareOutcome::Failed(failure) => report.line(
            net,
            "prepare (read-only)",
            false,
            &format!(
                "failed code={} rule={} ms={elapsed}",
                failure.code.code(),
                failure.rule().label()
            ),
        ),
    }
}

#[test]
#[ignore = "live network: reads %USERPROFILE%\\.yw-dev\\rpc.json (spec/09 §2.5)"]
fn live_chain_checks_and_read_only_prepare() -> TestResult {
    let entries = config()?;
    let http = client()?;
    let mut report = Report::default();
    for (net, info) in chains() {
        let Some(url) = endpoint(&entries, net) else {
            println!("{net:<16} skip");
            continue;
        };
        let client = RpcClient::new(&http);
        let check = check_chain(&client, &url, &info, &SystemClock, 150);
        match check {
            ChainCheck::Verified {
                genesis,
                pinned_now,
            } => {
                let expected = match info.genesis {
                    GenesisRule::Fixed(fixed) => fixed == genesis,
                    GenesisRule::PinOnFirstUse(_) => hex(&genesis) == HYPEREVM_FIRST_GENESIS,
                };
                report.line(
                    net,
                    "chain check (app)",
                    expected,
                    &format!("genesis={} pinned_now={pinned_now}", hex(&genesis)),
                );
            }
            other => report.line(net, "chain check (app)", false, &format!("{other:?}")),
        }
        read_only_prepare(&mut report, net, &info, &url, &http);
    }
    report.finish()
}

// ----- L-LIMITS, A6–A8, A9 (c)(d) -------------------------------------------------------------

fn fee_history_shape(
    report: &mut Report,
    net: &str,
    info: &ChainInfo,
    client: &RpcClient<'_>,
    url: &HttpsUrl,
) {
    let raw = client.call(
        url,
        "eth_feeHistory",
        Value::Array(vec![
            text("0xa"),
            text("latest"),
            Value::Array(vec![Value::Number(Number::from_u64(50))]),
        ]),
    );
    let Ok(raw) = raw else {
        report.line(
            net,
            "A7 eth_feeHistory",
            false,
            &raw.err().map(failure_kv).unwrap_or_default(),
        );
        return;
    };
    let count = |key: &str| {
        raw.as_object()
            .and_then(|object| object.get(key))
            .and_then(Value::as_array)
            .map_or(0, <[Value]>::len)
    };
    let rewards_single = raw
        .as_object()
        .and_then(|object| object.get("reward"))
        .and_then(Value::as_array)
        .is_some_and(|rows| {
            rows.iter()
                .all(|row| row.as_array().is_some_and(|row| row.len() == 1))
        });
    let shape_ok = count("baseFeePerGas") == 11
        && count("gasUsedRatio") == 10
        && count("reward") == 10
        && rewards_single;
    let fees = rpc::fee_history(client, url, 10)
        .ok()
        .and_then(|history| suggest_fees(&history, info).ok());
    report.line(
        net,
        "A7 eth_feeHistory",
        shape_ok && fees.is_some(),
        &format!(
            "baseFeePerGas={} gasUsedRatio={} reward={}x{} app_fees={}",
            count("baseFeePerGas"),
            count("gasUsedRatio"),
            count("reward"),
            u8::from(rewards_single),
            fees.map_or_else(
                || "-".to_owned(),
                |fees| format!(
                    "tip {} / maxFee {}",
                    format_gwei(&fees.max_priority_fee_per_gas),
                    format_gwei(&fees.max_fee_per_gas)
                )
            ),
        ),
    );
}

fn logs_query(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    from: u64,
    to: u64,
    address: &Address,
    topic: Option<&str>,
) -> (Result<usize, RpcFailure>, u128) {
    let mut filter = vec![
        ("fromBlock", quantity(from)),
        ("toBlock", quantity(to)),
        ("address", text(&address.to_lower_hex())),
    ];
    if let Some(topic) = topic {
        filter.push(("topics", Value::Array(vec![text(&format!("0x{topic}"))])));
    }
    let started = Instant::now();
    let result = client
        .call_limited(
            url,
            "eth_getLogs",
            Value::Array(vec![object(filter)]),
            LOGS_MAX_RESPONSE,
        )
        .and_then(|value| {
            value
                .as_array()
                .map(<[Value]>::len)
                .ok_or(RpcFailure::Malformed)
        });
    (result, started.elapsed().as_millis())
}

fn logs_limits(
    report: &mut Report,
    net: &str,
    info: &ChainInfo,
    client: &RpcClient<'_>,
    url: &HttpsUrl,
) {
    let Ok(latest) = rpc::block_number(client, url) else {
        report.line(net, "A8 eth_getLogs", false, "eth_blockNumber failed");
        return;
    };
    let from = latest.saturating_sub(9_999);
    // A quiet registry contract over 10,000 blocks: the range must be accepted.
    let quiet = info
        .contracts
        .iter()
        .find(|contract| contract.role == ContractRole::Seaport15)
        .map(|contract| contract.address);
    if let Some(quiet) = quiet {
        let (result, ms) = logs_query(client, url, from, latest, &quiet, None);
        match result {
            Ok(count) => report.line(
                net,
                "A8 getLogs 10000 blocks",
                true,
                &format!("logs={count} ms={ms}"),
            ),
            Err(failure) => report.line(
                net,
                "A8 getLogs 10000 blocks",
                false,
                &format!("{} ms={ms}", failure_kv(failure)),
            ),
        }
    }
    // A busy token's Transfer logs over the same range: observe the provider's result limit.
    if let Some(token) = info.tokens.first() {
        let (result, ms) = logs_query(
            client,
            url,
            from,
            latest,
            &token.address,
            Some(TRANSFER_TOPIC),
        );
        let kv = match result {
            Ok(count) => format!("logs={count} ms={ms}"),
            Err(failure) => format!("{} ms={ms}", failure_kv(failure)),
        };
        report.line(net, "A8 getLogs busy (observe)", true, &kv);
        let (result, ms) = logs_query(
            client,
            url,
            latest.saturating_sub(99),
            latest,
            &token.address,
            Some(TRANSFER_TOPIC),
        );
        let kv = match result {
            Ok(count) => format!("logs={count} ms={ms}"),
            Err(failure) => format!("{} ms={ms}", failure_kv(failure)),
        };
        report.line(net, "A8 getLogs busy 100 blocks", true, &kv);
    }
}

/// `eth_simulateV1` with `stateOverrides` (a fresh funded sender), timed and parsed by the app.
/// One 1-wei `eth_simulateV1` call to `to` (a fresh address when `None`) from a funded random
/// sender; `check` names the line and `expect` the call status.
struct SimCase<'a> {
    check: &'a str,
    to: Option<Address>,
    expect: SimStatus,
}

fn simulate_with_overrides(
    report: &mut Report,
    net: &str,
    info: &ChainInfo,
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    case: &SimCase<'_>,
) {
    let check = case.check;
    let Ok(Some(history)) = rpc::fee_history(client, url, 10).map(Some) else {
        report.line(net, check, false, "no fee history");
        return;
    };
    let base = history
        .base_fee_per_gas
        .last()
        .copied()
        .unwrap_or(U256::ZERO);
    let tip = U256::from_u64(1_000_000_000);
    let max_fee = base
        .checked_mul_u64(2)
        .and_then(|value| value.checked_add(tip))
        .unwrap_or(tip);
    let from = random_address(1);
    let call = object(vec![
        ("from", text(&from.to_lower_hex())),
        (
            "to",
            text(&case.to.unwrap_or_else(|| random_address(2)).to_lower_hex()),
        ),
        ("value", text("0x1")),
        ("gas", quantity(1_000_000)),
        ("maxFeePerGas", text(&max_fee.to_quantity())),
        ("maxPriorityFeePerGas", text(&tip.to_quantity())),
        ("chainId", quantity(info.chain_id)),
        ("type", text("0x2")),
    ]);
    let overrides = object(vec![(
        from.to_lower_hex().as_str(),
        object(vec![("balance", text("0xde0b6b3a7640000"))]),
    )]);
    let payload = object(vec![
        (
            "blockStateCalls",
            Value::Array(vec![object(vec![
                ("stateOverrides", overrides),
                ("calls", Value::Array(vec![call])),
            ])]),
        ),
        ("traceTransfers", Value::Bool(true)),
        ("validation", Value::Bool(true)),
    ]);
    let id = client.next_id();
    let request = object(vec![
        ("jsonrpc", text("2.0")),
        ("id", Value::Number(Number::from_u64(id))),
        ("method", text("eth_simulateV1")),
        ("params", Value::Array(vec![payload, text("latest")])),
    ]);
    let body = yw_json::to_vec(&request);
    let started = Instant::now();
    let reply = client.post_raw(url, &body, rpc::SIMULATE_MAX_RESPONSE);
    let ms = started.elapsed().as_millis();
    let outcome = match reply {
        Ok(reply) => rpc::simulate_http_outcome(reply.status, &reply.body, id),
        Err(_) => SimOutcome::Malformed,
    };
    match outcome {
        SimOutcome::Block(block) => {
            let emitters: Vec<String> = block
                .call
                .logs
                .iter()
                .map(|log| log.address.to_lower_hex())
                .collect();
            report.line(
                net,
                check,
                block.call.status == case.expect && ms < 10_000,
                &format!(
                    "status={:?} gasUsed={} maxUsedGas={} logs={} emitters=[{}] ms={ms}",
                    block.call.status,
                    block.call.gas_used,
                    block
                        .call
                        .max_used_gas
                        .map_or_else(|| "-".to_owned(), |gas| gas.to_string()),
                    block.call.logs.len(),
                    emitters.join(","),
                ),
            );
        }
        other => report.line(net, check, false, &format!("{other:?} ms={ms}")),
    }
}

/// A6: the `pending` tag is accepted for recent senders; senders with
/// `pending > latest` show the mempool reflected (counted, not required).
fn pending_nonce(report: &mut Report, net: &str, client: &RpcClient<'_>, url: &HttpsUrl) {
    let senders = recent_senders(client, url, 12);
    let mut observed = Vec::new();
    for sender in &senders {
        let latest = rpc::transaction_count(client, url, sender, "latest");
        let pending = rpc::transaction_count(client, url, sender, "pending");
        match (latest, pending) {
            (Ok(latest), Ok(pending)) => observed.push((latest, pending)),
            (latest, pending) => {
                report.line(
                    net,
                    "A6 pending nonce",
                    false,
                    &format!(
                        "latest={} pending={}",
                        latest.err().map_or_else(|| "ok".to_owned(), failure_kv),
                        pending.err().map_or_else(|| "ok".to_owned(), failure_kv)
                    ),
                );
                return;
            }
        }
    }
    // A block between the two reads (or a lagging pool view) can leave `pending < latest`.
    let behind = observed
        .iter()
        .filter(|(latest, pending)| pending < latest)
        .count();
    let ahead = observed
        .iter()
        .filter(|(latest, pending)| pending > latest)
        .count();
    report.line(
        net,
        "A6 pending nonce",
        !observed.is_empty(),
        &format!(
            "senders={} pending_ahead={ahead} pending_behind={behind} (own-send reflection: M4-2 manual)",
            observed.len()
        ),
    );
}

/// A9 (c)(d): `HyperEVM` recent blocks — gas limits (small/big), base fees, type-2 acceptance.
fn hyperevm_blocks(
    report: &mut Report,
    net: &str,
    info: &ChainInfo,
    client: &RpcClient<'_>,
    url: &HttpsUrl,
) {
    let Ok(latest) = rpc::block_number(client, url) else {
        report.line(net, "A9(c)(d) blocks", false, "eth_blockNumber failed");
        return;
    };
    let mut limits = Vec::new();
    let mut blocks: Vec<(u64, String)> = Vec::new();
    for number in latest.saturating_sub(69)..=latest {
        let Ok(block) = client.call(
            url,
            "eth_getBlockByNumber",
            Value::Array(vec![quantity(number), Value::Bool(false)]),
        ) else {
            continue;
        };
        let object = block.as_object();
        let limit = quantity_of(object.and_then(|object| object.get("gasLimit")));
        let fee = object
            .and_then(|object| object.get("baseFeePerGas"))
            .and_then(Value::as_str)
            .and_then(|value| U256::parse_quantity_lenient(value).ok());
        if let (Some(limit), Some(fee)) = (limit, fee) {
            limits.push(limit);
            blocks.push((limit, format_gwei(&fee)));
        }
    }
    let mut distinct = limits.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let small = info.small_block_gas_limit;
    report.line(
        net,
        "A9(d) recent gasLimit",
        small.is_some_and(|small| limits.contains(&small)),
        &format!("distinct={distinct:?} constant={small:?}"),
    );
    let fees_of = |big: bool| {
        let mut fees: Vec<String> = blocks
            .iter()
            .filter(|(limit, _)| (Some(*limit) != small) == big)
            .map(|(_, fee)| fee.clone())
            .collect();
        fees.sort_unstable();
        fees.dedup();
        fees.join(", ")
    };
    let big = limits.iter().filter(|limit| Some(**limit) != small).count();
    report.line(
        net,
        "A9(c) 70 blocks",
        blocks.len() == 70,
        &format!(
            "blocks={} big_blocks={big} small_baseFee=[{}] big_baseFee=[{}]",
            blocks.len(),
            fees_of(false),
            fees_of(true)
        ),
    );
    // Type 2 accepted (estimate with EIP-1559 fields, no value).
    let call = object(vec![
        ("from", text(&random_address(3).to_lower_hex())),
        ("to", text(&random_address(4).to_lower_hex())),
        ("value", text("0x0")),
        ("type", text("0x2")),
        ("maxFeePerGas", text("0x0")),
        ("maxPriorityFeePerGas", text("0x0")),
    ]);
    let estimate = client.call(
        url,
        "eth_estimateGas",
        Value::Array(vec![call, text("latest")]),
    );
    match estimate {
        Ok(value) => report.line(
            net,
            "A9(c) type 2 estimate",
            quantity_of(Some(&value)) == Some(21_000),
            &format!("gas={:?}", quantity_of(Some(&value))),
        ),
        Err(failure) => report.line(net, "A9(c) type 2 estimate", false, &failure_kv(failure)),
    }
}

#[test]
#[ignore = "live network: reads %USERPROFILE%\\.yw-dev\\rpc.json (spec/09 §2.5)"]
fn live_limits_fee_history_logs_and_simulation() -> TestResult {
    let entries = config()?;
    let http = client()?;
    let mut report = Report::default();
    for (net, info) in chains() {
        let Some(url) = endpoint(&entries, net) else {
            println!("{net:<16} skip");
            continue;
        };
        let client = RpcClient::new(&http);
        fee_history_shape(&mut report, net, &info, &client, &url);
        if info.chain_id == 999 {
            hyperevm_blocks(&mut report, net, &info, &client, &url);
        } else {
            logs_limits(&mut report, net, &info, &client, &url);
        }
        simulate_with_overrides(
            &mut report,
            net,
            &info,
            &client,
            &url,
            &SimCase {
                check: "A8 eth_simulateV1 (overrides)",
                to: None,
                expect: SimStatus::Success,
            },
        );
        // The M4-5 (a) manual case: ETH to the Sepolia USDC contract must revert.
        if let Some(usdc) = info.tokens.iter().find(|token| token.symbol == "USDC")
            && info.chain_id == 11_155_111
        {
            simulate_with_overrides(
                &mut report,
                net,
                &info,
                &client,
                &url,
                &SimCase {
                    check: "M4-5(a) ETH to USDC reverts",
                    to: Some(usdc.address),
                    expect: SimStatus::Failure,
                },
            );
        }
        pending_nonce(&mut report, net, &client, &url);
    }
    report.finish()
}

// ----- registry (spec/03 §1.2, A9 (e)) ---------------------------------------------------------

fn selector(signature: &str) -> [u8; 4] {
    let digest = keccak256(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The ABI string at head word `index` of `output`.
fn abi_string(output: &[u8], index: usize) -> Option<String> {
    let word = |at: usize| -> Option<usize> {
        let bytes = output.get(at..at.checked_add(32)?)?;
        let value = U256::from_be_bytes(bytes.try_into().ok()?).to_u64()?;
        usize::try_from(value).ok()
    };
    let offset = word(index.checked_mul(32)?)?;
    let length = word(offset)?;
    let start = offset.checked_add(32)?;
    let bytes = output.get(start..start.checked_add(length)?)?;
    String::from_utf8(bytes.to_vec()).ok()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn check_tokens(
    report: &mut Report,
    net: &str,
    info: &ChainInfo,
    client: &RpcClient<'_>,
    url: &HttpsUrl,
) {
    for token in info.tokens {
        let code = rpc::code(client, url, &token.address).unwrap_or_default();
        let decimals = rpc::eth_call(client, url, &token.address, &SEL_DECIMALS, "latest")
            .ok()
            .and_then(|output| decode_decimals(&output));
        let symbol = rpc::eth_call(client, url, &token.address, &SEL_SYMBOL, "latest")
            .ok()
            .and_then(|output| decode_symbol(&output));
        let mut extra = String::new();
        let mut ok = !code.is_empty()
            && decimals == Some(token.decimals)
            && symbol.as_deref() == Some(token.symbol);
        if token.symbol == "WHYPE" {
            let deposit = yw_core::hex::decode(WETH9_DEPOSIT_TOPIC).unwrap_or_default();
            let withdrawal = yw_core::hex::decode(WETH9_WITHDRAWAL_TOPIC).unwrap_or_default();
            let topics = contains(&code, &deposit) && contains(&code, &withdrawal);
            ok &= topics;
            extra = format!(" weth9_topics={topics}");
        }
        report.line(
            net,
            &format!("registry {}", token.symbol),
            ok,
            &format!(
                "address={} code={}B decimals={decimals:?} symbol={symbol:?}{extra}",
                token.address.to_checksum(),
                code.len()
            ),
        );
    }
}

fn chain_word(chain_id: u64) -> [u8; 32] {
    U256::from_u64(chain_id).to_be_bytes()
}

/// EIP-712 domain separator of Permit2 (`name = "Permit2"`, no version).
fn permit2_separator(chain_id: u64, address: &Address) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(&keccak256(
        b"EIP712Domain(string name,uint256 chainId,address verifyingContract)",
    ));
    encoded.extend_from_slice(&keccak256(b"Permit2"));
    encoded.extend_from_slice(&chain_word(chain_id));
    encoded.extend_from_slice(&[0; 12]);
    encoded.extend_from_slice(address.as_bytes());
    keccak256(&encoded)
}

fn domain_separator(client: &RpcClient<'_>, url: &HttpsUrl, address: &Address) -> Option<[u8; 32]> {
    let output = rpc::eth_call(
        client,
        url,
        address,
        &selector("DOMAIN_SEPARATOR()"),
        "latest",
    )
    .ok()?;
    output.as_slice().try_into().ok()
}

/// `code` with every occurrence of each 32-byte word zeroed.
fn mask(code: &[u8], words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = code.to_vec();
    for word in words {
        let mut index = 0;
        while index + 32 <= out.len() {
            if out.get(index..index + 32) == Some(word.as_slice()) {
                if let Some(slot) = out.get_mut(index..index + 32) {
                    slot.fill(0);
                }
                index += 32;
            } else {
                index += 1;
            }
        }
    }
    out
}

fn check_contracts(
    report: &mut Report,
    net: &str,
    info: &ChainInfo,
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    mainnet_permit2: Option<&(Vec<u8>, [u8; 32])>,
) {
    for contract in info.contracts {
        let code = rpc::code(client, url, &contract.address).unwrap_or_default();
        let mut ok = !code.is_empty();
        let mut extra = String::new();
        match contract.role {
            ContractRole::Seaport15 | ContractRole::Seaport16 => {
                let expected = if contract.role == ContractRole::Seaport16 {
                    "1.6"
                } else {
                    "1.5"
                };
                let version = rpc::eth_call(
                    client,
                    url,
                    &contract.address,
                    &selector("information()"),
                    "latest",
                )
                .ok()
                .and_then(|output| abi_string(&output, 0));
                ok &= version.as_deref() == Some(expected);
                extra = format!(" version={version:?}");
            }
            ContractRole::Permit2 if info.chain_id == 999 => {
                // Permit2 keeps chainId and DOMAIN_SEPARATOR as immutables in its runtime code,
                // so the code equals mainnet's once those two words are masked on both sides.
                let raw_same = mainnet_permit2
                    .is_some_and(|(reference, _)| keccak256(reference) == keccak256(&code));
                let separator = domain_separator(client, url, &contract.address);
                let expected = permit2_separator(info.chain_id, &contract.address);
                let masked_same =
                    mainnet_permit2.is_some_and(|(reference, reference_separator)| {
                        let mainnet = mask(reference, &[chain_word(1), *reference_separator]);
                        let here = mask(&code, &[chain_word(info.chain_id), expected]);
                        keccak256(&mainnet) == keccak256(&here)
                    });
                ok &= masked_same && separator == Some(expected);
                extra = format!(
                    " raw_hash_equals_mainnet={raw_same} masked_equals_mainnet={masked_same} domain_separator_ok={}",
                    separator == Some(expected)
                );
            }
            _ if contract.label == "Seaport ConduitController" => {
                let mut data = selector("getConduit(bytes32)").to_vec();
                data.extend_from_slice(&OPENSEA_CONDUIT_KEY);
                let output = rpc::eth_call(client, url, &contract.address, &data, "latest")
                    .unwrap_or_default();
                let conduit = output.get(12..32).map(hex);
                let exists = output.get(63) == Some(&1);
                let expected = info
                    .contracts
                    .iter()
                    .find(|known| known.label == "OpenSea Conduit")
                    .map(|known| known.address.to_lower_hex());
                let matches = conduit.is_some() && conduit == expected && exists;
                ok &= matches;
                extra = format!(
                    " getConduit(OPENSEA_CONDUIT_KEY)=({}, {exists})",
                    conduit.unwrap_or_default()
                );
            }
            _ => {}
        }
        report.line(
            net,
            &format!("registry {}", contract.label),
            ok,
            &format!(
                "address={} code={}B{extra}",
                contract.address.to_checksum(),
                code.len()
            ),
        );
    }
}

#[test]
#[ignore = "live network: reads %USERPROFILE%\\.yw-dev\\rpc.json (spec/09 §2.5)"]
fn live_registry_entries() -> TestResult {
    let entries = config()?;
    let http = client()?;
    let mut report = Report::default();
    let mut mainnet_permit2 = None;
    for (net, info) in chains() {
        let Some(url) = endpoint(&entries, net) else {
            println!("{net:<16} skip");
            continue;
        };
        let client = RpcClient::new(&http);
        if info.chain_id == 1 {
            mainnet_permit2 = info
                .contracts
                .iter()
                .find(|contract| contract.role == ContractRole::Permit2)
                .and_then(|contract| {
                    let code = rpc::code(&client, &url, &contract.address).ok()?;
                    let separator = domain_separator(&client, &url, &contract.address)?;
                    Some((code, separator))
                });
        }
        check_tokens(&mut report, net, &info, &client, &url);
        check_contracts(
            &mut report,
            net,
            &info,
            &client,
            &url,
            mainnet_permit2.as_ref(),
        );
    }
    report.finish()
}
