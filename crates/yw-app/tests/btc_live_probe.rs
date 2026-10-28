//! Live read-only Bitcoin checks (spec/08 §4.5 E1–E3, C1–C2; spec/09 §2.5 "BTC") through the
//! yw-app `btc::*` path: `check_chain` on both networks with the default Esplora bases,
//! `estimatesmartfee` 2/6/24, `getmempoolinfo`, `getmempoolentry` availability, the recorded
//! testnet4 transaction through `getrawtransaction` + `verify_prev_output`, the abandon…about
//! testnet4 account discovery through the indexer, the Esplora `/utxo` list of a public address,
//! one tracking observation, and `testmempoolaccept` of a transaction spending a random prevout
//! (expect `missing-inputs`).
//!
//! `cargo test -p yw-app --test btc_live_probe -- --ignored --test-threads=1 --nocapture`
//!
//! - Core endpoints come only from the development file (spec/01 §4.6): `YW_RPC_JSON` names the
//!   file, otherwise `%USERPROFILE%\.yw-dev\rpc.json`; keys `bitcoin:mainnet`,
//!   `bitcoin:testnet4` (missing → skip). The real path must be outside the repository.
//! - Output names networks by `NetworkId` only: no URL, host, token or server message. The
//!   Esplora bases are the public defaults (not secret) and are not printed either; another public
//!   Esplora server can be chosen with `YW_BTC_ESPLORA_MAINNET` / `YW_BTC_ESPLORA_TESTNET4`.
//! - Read-only: never `sendrawtransaction`, never `POST /tx`; nothing is signed.
#![expect(
    clippy::print_stdout,
    reason = "the probe report is console output (NetworkId only, no secrets)"
)]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use yw_app::btc::chain::{ChainInput, check_full};
use yw_app::btc::flow::{DiscoveryJob, TrackJob, discover, observe_tx, prev_transaction};
use yw_app::btc::indexer::{BtcIndexerReq, BtcIndexerResp, fetch};
use yw_app::btc::rpc::{
    MempoolEntry, estimate_smart_fee, get_mempool_entry, get_mempool_info, test_mempool_accept,
};
use yw_app::btc::{
    BtcClient, BtcEndpoint, BtcEnv, BtcError, ChainSession, LogSink, Pace, Trigger, network_id,
};
use yw_app::flow::evm::{Clock, SystemClock};
use yw_app::logging::Field;
use yw_app::rpc::{RPC_TIMEOUTS, RpcFailure, classify};
use yw_app::settings::{BtcIndexer, LogLevel};
use yw_core::bip32::AccountXpub;
use yw_core::btc::address::BtcAddress;
use yw_core::btc::prevtx::verify_prev_output;
use yw_core::btc::script::p2wpkh_script_pubkey;
use yw_core::btc::tx::{Transaction, TxIn, TxOut, serialize, sha256d};
use yw_core::btc::{BTC_CONF_TARGETS, BtcNetwork, OutPoint, Sats, Txid};
use yw_json::Limits as JsonLimits;
use yw_win::http::{Client, HttpsUrl};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAX_CONFIG_BYTES: usize = 64 * 1_024;
const REAL_TXID: &str = "005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1";
const REAL_PROGRAM: &str = "7b458433d0c04323426ef88365bd4cfef141ac75";
const ACCOUNT_PUBKEY: &str = "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4";
const ACCOUNT_CHAIN_CODE: &str = "3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62";

fn config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("YW_RPC_JSON") {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("USERPROFILE").map(|home| Path::new(&home).join(".yw-dev").join("rpc.json"))
}

fn config() -> Result<Vec<(BtcNetwork, HttpsUrl)>, String> {
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
    for net in [BtcNetwork::Testnet4, BtcNetwork::Mainnet] {
        let key = net.network_id();
        let Some(item) = object.get(key) else {
            continue;
        };
        let url = item
            .as_str()
            .and_then(|text| HttpsUrl::parse(text).ok())
            .ok_or_else(|| format!("rpc.json: {key} 값이 올바르지 않습니다"))?;
        out.push((net, url));
    }
    Ok(out)
}

#[derive(Default)]
struct Report {
    failures: Vec<String>,
}

impl Report {
    fn line(&mut self, net: BtcNetwork, check: &str, ok: bool, kv: &str) {
        println!(
            "{:<16} {check:<26} {} {kv}",
            network_id(net).to_string(),
            if ok { "ok " } else { "err" }
        );
        if !ok {
            self.failures.push(format!("{} {check}", network_id(net)));
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

/// Request lines are not printed (they carry no URL anyway); only the report is.
struct QuietLog;

impl LogSink for QuietLog {
    fn log(&self, _level: LogLevel, _event: &'static str, _fields: &[(&'static str, Field<'_>)]) {}
}

fn rpc_kv(failure: RpcFailure) -> String {
    let detail = match failure {
        RpcFailure::Http(error) => format!("transport={}", yw_app::btc::client::http_word(error)),
        RpcFailure::Status(status) => format!("http={status}"),
        RpcFailure::Rpc(code) => format!("code={code}"),
        RpcFailure::Malformed => "malformed".to_owned(),
        RpcFailure::Late => "late".to_owned(),
    };
    format!("{detail} class={}", classify(failure).code())
}

fn btc_kv(error: BtcError) -> String {
    match error {
        BtcError::Core(failure) => rpc_kv(failure),
        BtcError::Indexer(error) => format!("indexer={:?} class={}", error, error.code().code()),
        other => format!("error={}", other.log_word()),
    }
}

fn account() -> Option<AccountXpub> {
    Some(AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(ACCOUNT_PUBKEY).ok()?,
        chain_code: yw_core::hex::decode_array::<32>(ACCOUNT_CHAIN_CODE).ok()?,
    })
}

/// A structurally valid transaction spending a prevout nobody has (expect `missing-inputs`).
fn invalid_spend(clock: &dyn Clock) -> Option<Vec<u8>> {
    let seed = sha256d(&clock.now_unix_ms().to_le_bytes());
    let program = yw_core::hex::decode_array::<20>(REAL_PROGRAM).ok()?;
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: Txid::from_bytes(seed),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_fffd,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: Sats::new(10_000)?,
            script_pubkey: p2wpkh_script_pubkey(&program).to_vec(),
        }],
        lock_time: 0,
    };
    Some(serialize(&tx, false))
}

/// The Esplora base: the public default, or `YW_BTC_ESPLORA_MAINNET` / `YW_BTC_ESPLORA_TESTNET4`
/// (another public Esplora server, checked like the settings value, spec/04 §6.1; not secret).
fn esplora_base(net: BtcNetwork) -> Result<HttpsUrl, &'static str> {
    let name = match net {
        BtcNetwork::Mainnet => "YW_BTC_ESPLORA_MAINNET",
        BtcNetwork::Testnet4 => "YW_BTC_ESPLORA_TESTNET4",
    };
    let text = match std::env::var(name) {
        Ok(value) => {
            yw_app::settings::validate_esplora_url(&value).ok_or("esplora override rejected")?
        }
        Err(_) => net.esplora_default().to_owned(),
    };
    HttpsUrl::parse(&text).map_err(|_| "esplora base")
}

#[expect(clippy::too_many_lines, reason = "one linear probe per network")]
fn probe_network(report: &mut Report, net: BtcNetwork, core_url: &HttpsUrl) -> TestResult {
    let transport = Client::new(RPC_TIMEOUTS).map_err(|_| "WinHTTP")?;
    let clock = SystemClock;
    let pace = Pace::new();
    let log = QuietLog;
    let env = BtcEnv {
        transport: &transport,
        clock: &clock,
        pace: &pace,
        log: &log,
    };
    let endpoint = BtcEndpoint {
        net,
        core_url: core_url.clone(),
        indexer: BtcIndexer::Esplora,
        esplora_base: esplora_base(net)?,
    };
    let client = BtcClient::new(env, &endpoint);
    let mut session = ChainSession::new(net, net);
    let input = ChainInput {
        max_tip_seen: 0,
        now_unix_secs: clock.now_unix_ms() / 1_000,
    };
    let started = Instant::now();
    match check_full(&client, &mut session, input) {
        Ok(status) => report.line(
            net,
            "check_chain (1-4)",
            true,
            &format!(
                "tip={} lag={:?} ms={}",
                status.tip_height,
                status.lag_warning,
                started.elapsed().as_millis()
            ),
        ),
        Err(error) => {
            report.line(net, "check_chain (1-4)", false, &btc_kv(error));
            return Ok(());
        }
    }
    for target in BTC_CONF_TARGETS {
        let check = format!("estimatesmartfee {target}");
        match estimate_smart_fee(&client, target) {
            Ok(rate) => report.line(net, &check, true, &format!("sat_per_kvb={rate:?}")),
            Err(failure) => report.line(net, &check, false, &rpc_kv(failure)),
        }
    }
    match get_mempool_info(&client) {
        Ok(info) => report.line(
            net,
            "getmempoolinfo",
            true,
            &format!(
                "mempoolminfee={} minrelaytxfee={} incrementalrelayfee={} (sat/kvB)",
                info.mempool_min, info.min_relay, info.incremental
            ),
        ),
        Err(failure) => report.line(net, "getmempoolinfo", false, &rpc_kv(failure)),
    }
    if net != BtcNetwork::Testnet4 {
        return Ok(());
    }
    let real = Txid::from_display_hex(REAL_TXID).map_err(|_| "txid")?;
    match get_mempool_entry(&client, &real) {
        Ok(entry) => report.line(
            net,
            "getmempoolentry (confirmed)",
            entry != MempoolEntry::InMempool,
            &format!("entry={entry:?}"),
        ),
        Err(failure) => report.line(net, "getmempoolentry (confirmed)", false, &rpc_kv(failure)),
    }
    let program = yw_core::hex::decode_array::<20>(REAL_PROGRAM)?;
    match prev_transaction(&client, &session, &real) {
        Ok(Some((raw, source))) => {
            match verify_prev_output(&raw, &real, 0, &p2wpkh_script_pubkey(&program)) {
                Ok(prev) => report.line(
                    net,
                    "getrawtransaction+verify",
                    true,
                    &format!(
                        "source={source:?} bytes={} value={}",
                        raw.len(),
                        prev.value.get()
                    ),
                ),
                Err(error) => report.line(
                    net,
                    "getrawtransaction+verify",
                    false,
                    &format!("source={source:?} verify={error:?}"),
                ),
            }
        }
        Ok(None) => report.line(net, "getrawtransaction+verify", false, "unavailable"),
        Err(error) => report.line(net, "getrawtransaction+verify", false, &btc_kv(error)),
    }
    let track = TrackJob {
        txid: real,
        mempool_entry: true,
        indexer_only: false,
        replacements: Vec::new(),
        trigger: Trigger::User,
        chain: input,
    };
    match observe_tx(&client, &mut session, &track) {
        Ok(result) => report.line(
            net,
            "tracking observation",
            matches!(
                result.observation,
                yw_core::journal::btc::TrackObservation::Confirmed { .. }
            ),
            &format!(
                "observation={:?} getmempoolentry_unsupported={}",
                result.observation, result.mempool_entry_unsupported
            ),
        ),
        Err(error) => report.line(net, "tracking observation", false, &btc_kv(error)),
    }
    let payee = BtcAddress::p2wpkh(net, &program);
    match fetch(&client, &BtcIndexerReq::Utxo(payee)) {
        Ok(BtcIndexerResp::Utxo(list)) => report.line(
            net,
            "esplora utxo (public addr)",
            !list.is_empty(),
            &format!(
                "count={} confirmed={}",
                list.len(),
                list.iter().filter(|utxo| utxo.height.is_some()).count()
            ),
        ),
        Ok(other) => report.line(
            net,
            "esplora utxo (public addr)",
            false,
            &format!("{other:?}"),
        ),
        Err(error) => report.line(
            net,
            "esplora utxo (public addr)",
            false,
            &format!("indexer={error:?} class={}", error.code().code()),
        ),
    }
    let account = account().ok_or("account")?;
    let job = DiscoveryJob {
        account,
        discovery: yw_core::btc::Discovery::full(),
        chain: input,
    };
    let started = Instant::now();
    match discover(
        &client,
        &mut session,
        &job,
        &AtomicBool::new(false),
        &mut |_| {},
    ) {
        Ok(result) => {
            let mut meta = yw_core::btc::BtcMeta::new(net, account);
            let applied = result.discovery.apply(&mut meta).is_ok();
            report.line(
                net,
                "discovery (abandon account)",
                applied && meta.last_used_receive().is_some(),
                &format!(
                    "receive_next={} receive_last={:?} change_next={} change_last={:?} checked={} ms={}",
                    meta.receive_next(),
                    meta.last_used_receive(),
                    meta.change_next(),
                    meta.last_used_change(),
                    result.addresses.len(),
                    started.elapsed().as_millis()
                ),
            );
        }
        Err(error) => report.line(net, "discovery (abandon account)", false, &btc_kv(error)),
    }
    let raw = invalid_spend(&clock).ok_or("invalid spend")?;
    match test_mempool_accept(&client, &raw, "0.00002000") {
        Ok(accept) => report.line(
            net,
            "testmempoolaccept (bogus)",
            !accept.allowed && accept.reject_reason.as_deref() == Some("missing-inputs"),
            &format!(
                "allowed={} reject={}",
                accept.allowed,
                accept.reject_reason.as_deref().unwrap_or("none")
            ),
        ),
        Err(failure) => report.line(net, "testmempoolaccept (bogus)", false, &rpc_kv(failure)),
    }
    Ok(())
}

#[test]
#[ignore = "live network: reads %USERPROFILE%\\.yw-dev\\rpc.json (spec/09 §2.5)"]
fn live_bitcoin_probe() -> TestResult {
    let entries = config()?;
    let mut report = Report::default();
    if entries.is_empty() {
        println!("bitcoin:*        (no endpoints configured)  skip");
    }
    for (net, url) in &entries {
        probe_network(&mut report, *net, url)?;
    }
    report.finish()
}
