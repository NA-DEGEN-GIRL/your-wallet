//! The Bitcoin flow at the app level (spec/08 §2–§12, spec/04 §2.6–§3): the `BtcUi` controller
//! driven like the App glue does, with the real key worker on a throwaway vault in a temp folder
//! (BIP-39 test vector `abandon … about`, testnet4, never a real seed) and the real RPC worker
//! over the recording fake transport and the manual clock (no network). Covered: enable
//! testnet4 → account node of spec/08 §14.1 → discovery → refresh with a verified UTXO →
//! plan → draft → issue/consume → `SignBtc` → pre-check → `Broadcasting` (`change_next`) → send
//! → `Submitted` (sent script) → tracking → `Confirmed` (own change) → activity row; D20
//! (`inflight_blocks_new_send`, `rbf_allowed_while_inflight`), `network_mismatch_blocks` (no
//! BTC request), and no BTC request while locked except the Esplora settings `테스트`.

mod btc_support;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use btc_support::{
    ACCOUNT_CHAIN_CODE, ACCOUNT_PUBKEY, CORE_URL, Call, ESPLORA_BASE, FakeBtc, ManualClock, Reply,
    TIP, TestResult, Verb, account, address_json, healthy, params, path_address, xpub,
};
use yw_app::apikeys::ApiKeys;
use yw_app::app_btc::{
    BtcAction, BtcAmountUnit, BtcApprovalItem, BtcCtx, BtcFeeChoice, BtcGate, BtcScreen, BtcUi,
};
use yw_app::btc::Trigger;
use yw_app::btc::chain::ChainInput;
use yw_app::btc::flow::RefreshJob;
use yw_app::btc::work::{BtcRpcEvent, BtcRpcJob, BtcTarget};
use yw_app::events::{
    EventQueue, ImportedAccount, JournalView, KeyJob, KeyOutcome, RpcEvent, UiEvent,
};
use yw_app::flow::evm::{Clock, Limits};
use yw_app::meta::Meta;
use yw_app::network::{BtcNet, NetworkId};
use yw_app::settings::{BitcoinSettings, BtcIndexer};
use yw_app::ui::approval_view::Block;
use yw_app::workers::journal::btc::BtcMetaOp;
use yw_app::workers::key::KeyWorker;
use yw_app::workers::rpc::{RpcJob, RpcWorker};
use yw_core::approval::{ApprovalId, ApprovalStore};
use yw_core::bip32::path::BtcChain;
use yw_core::btc::address::script_pubkey;
use yw_core::btc::amount::format_btc;
use yw_core::btc::script::p2wpkh_script_pubkey;
use yw_core::btc::tx::{
    Transaction, TxIn, TxOut, parse_transaction, serialize, txid, vsize, wtxid,
};
use yw_core::btc::{
    BtcAccountId, BtcAccountKey, BtcNetwork, OutPoint, Sats, ScriptType, Txid, parse_address,
};
use yw_core::journal::btc::BtcTxState;
use yw_core::keyimport::{ImportPreview, ImportSpec};
use yw_core::secret::Zeroizing;
use yw_win::http::HttpsUrl;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD: &[u8] = b"m8-btc-flow-test!";
/// BIP173 testnet P2WPKH example (not ours).
const RECIPIENT: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const FUNDING_VALUE: u64 = 100_000;
const FUNDING_HEIGHT: u32 = TIP - 10;
/// One confirmation at `TIP` (final, spec/08 §12.2-4).
const CONFIRM_HEIGHT: u32 = TIP;
const BLOCK_HASH: &str = "00000000000000000000000000000000000000000000000000000000000000aa";

/// The fake chain shared with the transport handler: transactions with their height (`None` =
/// in the mempool), answered by Core and by a minimal Esplora indexer computed from them.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent fault switches of the fake chain"
)]
struct World {
    txs: Vec<(Transaction, Vec<u8>, Option<u32>)>,
    reject: Option<&'static str>,
    /// `sendrawtransaction` answers this RPC error code (nothing reaches the mempool).
    send_error: Option<i64>,
    /// `sendrawtransaction` fails in transport (a communication failure).
    send_transport: bool,
    /// Core's mempool does not see the world's mempool (`getmempoolentry` always `-5`), while
    /// the indexer does (review M1).
    core_mempool_blind: bool,
    /// After an accepted `testmempoolaccept`, `getblockhash` fails once (the chain check right
    /// before `sendrawtransaction` fails, nothing is sent).
    fail_chain_after_precheck: bool,
    prechecked: bool,
    /// `testmempoolaccept` fails in transport after receiving the bytes (a communication
    /// failure of the pre-check: the record stays `Signed`).
    precheck_transport: bool,
    /// Core `getblockchaininfo.blocks` instead of `TIP`.
    core_tip: Option<u32>,
}

impl World {
    fn find(&self, id: &str) -> Option<&(Transaction, Vec<u8>, Option<u32>)> {
        self.txs
            .iter()
            .find(|(tx, ..)| txid(tx).to_display_hex() == id)
    }

    fn confirm(&mut self, id: &Txid, height: u32) {
        for entry in &mut self.txs {
            if txid(&entry.0) == *id {
                entry.2 = Some(height);
            }
        }
    }

    fn spent_by(&self, outpoint: &OutPoint, confirmed: Option<bool>) -> bool {
        self.txs.iter().any(|(tx, _, height)| {
            confirmed.is_none_or(|want| height.is_some() == want)
                && tx.inputs.iter().any(|input| input.prevout == *outpoint)
        })
    }

    fn value_of(&self, outpoint: &OutPoint) -> Option<u64> {
        self.txs.iter().find_map(|(tx, ..)| {
            if txid(tx) != outpoint.txid {
                return None;
            }
            tx.outputs
                .get(usize::try_from(outpoint.vout).ok()?)
                .map(|output| output.value.get())
        })
    }

    /// `(outpoint, value, height)` of the outputs paying `script`.
    fn outputs_to(&self, script: &[u8]) -> Vec<(OutPoint, u64, Option<u32>)> {
        let mut out = Vec::new();
        for (tx, _, height) in &self.txs {
            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.script_pubkey == script {
                    out.push((
                        OutPoint {
                            txid: txid(tx),
                            vout: u32::try_from(vout).unwrap_or(0),
                        },
                        output.value.get(),
                        *height,
                    ));
                }
            }
        }
        out
    }

    fn address(&self, address: &str) -> String {
        let Ok(kind) = parse_address(address, BtcNetwork::Testnet4) else {
            return address_json(address, [0; 3], [0; 3]);
        };
        let script = script_pubkey(&kind);
        let outputs = self.outputs_to(&script);
        let mut chain = [0_u32; 3];
        let mut mempool = [0_u32; 3];
        for (outpoint, _, height) in &outputs {
            if height.is_some() {
                chain[0] += 1;
                if self.spent_by(outpoint, Some(true)) {
                    chain[1] += 1;
                }
            } else {
                mempool[0] += 1;
            }
            if self.spent_by(outpoint, Some(false)) {
                mempool[1] += 1;
            }
        }
        let touching = |confirmed: bool| {
            self.txs
                .iter()
                .filter(|(tx, _, height)| {
                    height.is_some() == confirmed
                        && (tx
                            .outputs
                            .iter()
                            .any(|output| output.script_pubkey == script)
                            || tx.inputs.iter().any(|input| {
                                outputs
                                    .iter()
                                    .any(|(outpoint, ..)| *outpoint == input.prevout)
                            }))
                })
                .count()
        };
        chain[2] = u32::try_from(touching(true)).unwrap_or(0);
        mempool[2] = u32::try_from(touching(false)).unwrap_or(0);
        address_json(address, chain, mempool)
    }

    fn utxo(&self, address: &str) -> String {
        let Ok(kind) = parse_address(address, BtcNetwork::Testnet4) else {
            return "[]".to_owned();
        };
        let items: Vec<String> = self
            .outputs_to(&script_pubkey(&kind))
            .into_iter()
            .filter(|(outpoint, ..)| !self.spent_by(outpoint, None))
            .filter_map(|(outpoint, value, height)| {
                let height = height?;
                Some(format!(
                    "{{\"txid\":\"{}\",\"vout\":{},\"status\":{{\"confirmed\":true,\"block_height\":{height},\"block_hash\":\"{BLOCK_HASH}\",\"block_time\":1793000000}},\"value\":{value}}}",
                    outpoint.txid.to_display_hex(),
                    outpoint.vout
                ))
            })
            .collect();
        format!("[{}]", items.join(","))
    }
}

fn funding_tx() -> TestResult<(Transaction, Vec<u8>)> {
    let program = yw_core::btc::address::p2wpkh_program(&xpub(), BtcChain::Receive, 0)
        .map_err(|error| format!("{error:?}"))?;
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: Txid::from_bytes([0x33; 32]),
                vout: 1,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_fffd,
            witness: vec![vec![0x30; 71], vec![0x02; 33]],
        }],
        outputs: vec![TxOut {
            value: Sats::new(FUNDING_VALUE).ok_or("sats")?,
            script_pubkey: p2wpkh_script_pubkey(&program).to_vec(),
        }],
        lock_time: 0,
    };
    let raw = serialize(&tx, true);
    Ok((tx, raw))
}

fn first_hex(call: &Call) -> Option<Vec<u8>> {
    let value = params(call);
    let first = value.as_array()?.first()?;
    let text = match first.as_array() {
        Some(inner) => inner.first()?.as_str()?.to_owned(),
        None => first.as_str()?.to_owned(),
    };
    yw_core::hex::decode(&text).ok()
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per faked Core and Esplora call"
)]
fn answer(world: &Mutex<World>, call: &Call) -> Reply {
    let Ok(mut world) = world.lock() else {
        return Reply::status(500);
    };
    match (call.verb, call.method.as_str()) {
        (Verb::Rpc, "estimatesmartfee") => {
            Reply::Envelope(btc_support::core::TESTNET4_ESTIMATESMARTFEE_6.to_vec())
        }
        (Verb::Rpc, "getrawtransaction") => match world.find(&btc_support::first_param(call)) {
            Some((_, raw, _)) => Reply::Result(format!("\"{}\"", yw_core::hex::encode(raw))),
            None => Reply::RpcError(-5),
        },
        (Verb::Rpc, "testmempoolaccept") => {
            let Some(tx) = first_hex(call).and_then(|raw| parse_transaction(&raw).ok()) else {
                return Reply::RpcError(-22);
            };
            let id = txid(&tx).to_display_hex();
            let witness_id = Txid::from_bytes(wtxid(&tx)).to_display_hex();
            if world.precheck_transport {
                return Reply::Transport(yw_win::http::HttpError::Timeout);
            }
            if let Some(reason) = world.reject {
                return Reply::Result(format!(
                    "[{{\"txid\":\"{id}\",\"wtxid\":\"{witness_id}\",\"allowed\":false,\"reject-reason\":\"{reason}\"}}]"
                ));
            }
            let inputs: u64 = tx
                .inputs
                .iter()
                .filter_map(|input| world.value_of(&input.prevout))
                .sum();
            let outputs: u64 = tx.outputs.iter().map(|output| output.value.get()).sum();
            let fee = Sats::new(inputs.saturating_sub(outputs)).unwrap_or(Sats::ZERO);
            world.prechecked = true;
            Reply::Result(format!(
                "[{{\"txid\":\"{id}\",\"wtxid\":\"{witness_id}\",\"allowed\":true,\"vsize\":{},\"fees\":{{\"base\":{}}}}}]",
                vsize(&tx),
                format_btc(fee)
            ))
        }
        (Verb::Rpc, "sendrawtransaction") => {
            let Some(raw) = first_hex(call) else {
                return Reply::RpcError(-22);
            };
            let Ok(tx) = parse_transaction(&raw) else {
                return Reply::RpcError(-22);
            };
            if let Some(code) = world.send_error {
                return Reply::RpcError(code);
            }
            if world.send_transport {
                return Reply::Transport(yw_win::http::HttpError::Timeout);
            }
            let id = txid(&tx);
            if world.find(&id.to_display_hex()).is_none() {
                world.txs.push((tx, raw, None));
            }
            Reply::Result(format!("\"{}\"", id.to_display_hex()))
        }
        (Verb::Rpc, "getmempoolentry") => match world.find(&btc_support::first_param(call)) {
            Some((_, _, None)) if !world.core_mempool_blind => {
                Reply::Result("{\"vsize\":141}".to_owned())
            }
            _ => Reply::RpcError(-5),
        },
        (Verb::Rpc, "getblockhash") if world.fail_chain_after_precheck && world.prechecked => {
            world.fail_chain_after_precheck = false;
            Reply::Transport(yw_win::http::HttpError::Timeout)
        }
        (Verb::Rpc, "getblockchaininfo") if world.core_tip.is_some() => {
            let tip = world.core_tip.unwrap_or(TIP);
            Reply::Result(btc_support::chain_info(
                "testnet4",
                tip,
                tip,
                false,
                btc_support::MEDIAN_TIME,
            ))
        }
        (Verb::Rpc, "gettxout") => {
            let value = params(call);
            let items = value.as_array().map(<[_]>::to_vec).unwrap_or_default();
            let id = items
                .first()
                .and_then(yw_json::Value::as_str)
                .unwrap_or("")
                .to_owned();
            let vout = items
                .get(1)
                .and_then(yw_json::Value::as_number)
                .and_then(yw_json::Number::as_u64)
                .and_then(|vout| u32::try_from(vout).ok())
                .unwrap_or(u32::MAX);
            let Some((tx, _, height)) = world.find(&id) else {
                return Reply::Result("null".to_owned());
            };
            let outpoint = OutPoint {
                txid: txid(tx),
                vout,
            };
            let Some(output) = usize::try_from(vout).ok().and_then(|at| tx.outputs.get(at)) else {
                return Reply::Result("null".to_owned());
            };
            if world.spent_by(&outpoint, None) {
                return Reply::Result("null".to_owned());
            }
            let confirmations = height.map_or(0, |height| TIP.saturating_sub(height) + 1);
            Reply::Result(format!(
                "{{\"bestblock\":\"{BLOCK_HASH}\",\"confirmations\":{confirmations},\"value\":{},\"scriptPubKey\":{{\"hex\":\"{}\"}},\"coinbase\":false}}",
                format_btc(output.value),
                yw_core::hex::encode(&output.script_pubkey)
            ))
        }
        (Verb::Get, _) => {
            let path = call.path();
            if let Some(address) = path_address(path) {
                return Reply::json(&if path.ends_with("/utxo") {
                    world.utxo(address)
                } else {
                    world.address(address)
                });
            }
            if let Some(rest) = path.strip_prefix("/tx/")
                && let Some(id) = rest.strip_suffix("/hex")
            {
                return match world.find(id) {
                    Some((_, raw, _)) => Reply::text(&yw_core::hex::encode(raw)),
                    None => Reply::status(404),
                };
            }
            if let Some(rest) = path.strip_prefix("/tx/")
                && let Some(id) = rest.strip_suffix("/status")
            {
                return Reply::json(&match world.find(id) {
                    Some((_, _, Some(height))) => format!(
                        "{{\"confirmed\":true,\"block_height\":{height},\"block_hash\":\"{BLOCK_HASH}\",\"block_time\":1793070000}}"
                    ),
                    _ => "{\"confirmed\":false}".to_owned(),
                });
            }
            healthy(call)
        }
        _ => healthy(call),
    }
}

struct ClockRef(Arc<ManualClock>);

impl Clock for ClockRef {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }

    fn now_unix_ms(&self) -> u64 {
        self.0.now_unix_ms()
    }

    fn sleep_ms(&self, ms: u64) {
        self.0.sleep_ms(ms);
    }
}

/// Distinct temp folder per call (pid + counter: two tests in the same millisecond never share one).
static NEXT_DIR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn temp_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "yw-app-btc-flow-{tag}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    // A folder left by an earlier run whose pid was the same starts empty again.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// The App glue of the controller: the same action handling, the worker results delivered in
/// FIFO order.
struct Harness {
    dir: PathBuf,
    key: KeyWorker,
    rpc: RpcWorker,
    events: EventQueue,
    fake: Arc<FakeBtc>,
    clock: Arc<ManualClock>,
    world: Arc<Mutex<World>>,
    ui: BtcUi,
    settings: BitcoinSettings,
    apikeys: ApiKeys,
    meta: Option<Meta>,
    journal: Option<JournalView>,
    unlocked: bool,
    /// `false` for a wallet started from a private key (`MetaLoaded.has_mnemonic`).
    has_mnemonic: bool,
    queued: Vec<BtcApprovalItem>,
    confirms: usize,
    screens: Vec<BtcScreen>,
    banners: Vec<String>,
    work: VecDeque<BtcAction>,
}

impl Harness {
    /// A wallet imported from `abandon … about`.
    fn new(tag: &str) -> TestResult<Self> {
        let mut harness = Self::bare(tag)?;
        harness.import();
        Ok(harness)
    }

    /// A key-only wallet started from the Bitcoin WIF `wif` used as `script_type`.
    fn key_only(tag: &str, wif: &str, script_type: ScriptType) -> TestResult<Self> {
        let mut harness = Self::bare(tag)?;
        harness.start_with_key(wif, script_type)?;
        Ok(harness)
    }

    fn bare(tag: &str) -> TestResult<Self> {
        let dir = temp_dir(tag)?;
        let clock = ManualClock::new();
        let world = Arc::new(Mutex::new(World::default()));
        let (funding, raw) = funding_tx()?;
        if let Ok(mut state) = world.lock() {
            state.txs.push((funding, raw, Some(FUNDING_HEIGHT)));
        }
        let shared = Arc::clone(&world);
        let fake = FakeBtc::new(&clock, move |call| answer(&shared, call));
        let rpc = RpcWorker::new(
            Some(Arc::clone(&fake) as Arc<dyn yw_app::rpc::Transport>),
            Box::new(ClockRef(Arc::clone(&clock))),
            Limits::PRODUCTION,
        );
        let mut apikeys = ApiKeys::default();
        apikeys.set_rpc(
            NetworkId::Bitcoin(BtcNet::Testnet4),
            &HttpsUrl::parse(CORE_URL)?,
        );
        let settings = BitcoinSettings {
            esplora_testnet4: ESPLORA_BASE.to_owned(),
            ..BitcoinSettings::default()
        };
        let harness = Self {
            key: KeyWorker::new(&dir),
            dir,
            rpc,
            events: EventQueue::new(Box::new(|| {})),
            fake,
            clock,
            world,
            ui: BtcUi::default(),
            settings,
            apikeys,
            meta: None,
            journal: None,
            unlocked: false,
            has_mnemonic: true,
            queued: Vec::new(),
            confirms: 0,
            screens: Vec::new(),
            banners: Vec::new(),
            work: VecDeque::new(),
        };
        Ok(harness)
    }

    /// "개인키로 시작하기" with a Bitcoin key through the key worker (S18 → S19 → commit), then
    /// what the App does on `KeyStartCommitted`: Bitcoin on with the key's network, meta and
    /// journal loaded like the unlock path.
    fn start_with_key(&mut self, wif: &str, script_type: ScriptType) -> TestResult {
        let _ = self.key.handle(KeyJob::Load);
        let preview = self.key.handle(KeyJob::PreviewKeyStart {
            password: Some(Zeroizing::new(PASSWORD.to_vec())),
            spec: ImportSpec::Btc(script_type),
            key: Zeroizing::new(wif.as_bytes().to_vec()),
        });
        let Some(KeyOutcome::KeyStartPreview(Ok(ImportPreview::Btc(info)))) = preview.first()
        else {
            return Err("no Bitcoin preview".into());
        };
        let network = info.network;
        let committed = self.key.handle(KeyJob::CommitKeyStart);
        if !matches!(
            committed.first(),
            Some(KeyOutcome::KeyStartCommitted(Ok(())))
        ) {
            return Err("key start not committed".into());
        }
        self.settings.enabled = true;
        self.settings.network = yw_app::btc::app_network(network);
        self.unlocked = true;
        self.key_job(KeyJob::LoadMeta);
        self.key_job(KeyJob::LoadJournal);
        self.drain();
        if self.meta.is_none() || self.journal.is_none() || self.has_mnemonic {
            return Err("key-only meta not loaded".into());
        }
        Ok(())
    }

    /// `개인키 가져오기` on the Bitcoin tab like the App (`on_key_imported`): the vault stores the
    /// tag-4 record, then `AddImported` stores and selects its account (a refresh follows).
    fn import_key(&mut self, wif: &str, script_type: ScriptType) -> TestResult<BtcAccountKey> {
        let outcomes = self.key.handle(KeyJob::ImportKey {
            spec: ImportSpec::Btc(script_type),
            key: Zeroizing::new(wif.as_bytes().to_vec()),
        });
        let Some(KeyOutcome::KeyImported(Ok(ImportedAccount::Btc(id, info)))) =
            outcomes.into_iter().next()
        else {
            return Err("Bitcoin key not imported".into());
        };
        let key = info
            .account_key(*id.as_bytes())
            .map_err(|error| format!("{error:?}"))?;
        self.key_job(KeyJob::BtcMeta {
            op: BtcMetaOp::AddImported {
                network: info.network,
                key,
            },
        });
        self.drain();
        Ok(key)
    }

    /// Imports `abandon … about` and loads meta and the journal like the unlock path.
    fn import(&mut self) {
        let _ = self.key.handle(KeyJob::Load);
        let preview = self.key.handle(KeyJob::PreviewImport {
            password: Some(Zeroizing::new(PASSWORD.to_vec())),
            phrase: Zeroizing::new(ABANDON.as_bytes().to_vec()),
            passphrase: None,
        });
        assert!(matches!(preview.first(), Some(KeyOutcome::Preview(Ok(_)))));
        let imported = self.key.handle(KeyJob::CommitImport);
        assert!(matches!(
            imported.first(),
            Some(KeyOutcome::Imported(Ok(())))
        ));
        self.unlocked = true;
        self.key_job(KeyJob::LoadMeta);
        self.key_job(KeyJob::LoadJournal);
        self.drain();
        assert!(self.meta.is_some() && self.journal.is_some());
    }

    fn call(&mut self, call: impl FnOnce(&mut BtcUi, &BtcCtx<'_>) -> Vec<BtcAction>) {
        let actions = {
            let ctx = BtcCtx {
                settings: &self.settings,
                apikeys: &self.apikeys,
                meta: self.meta.as_ref(),
                journal: self.journal.as_ref(),
                unlocked: self.unlocked,
                has_mnemonic: self.has_mnemonic,
                now_ms: self.clock.now_ms(),
                now_unix_ms: self.clock.now_unix_ms(),
            };
            call(&mut self.ui, &ctx)
        };
        self.work.extend(actions);
    }

    fn ctx(&self) -> BtcCtx<'_> {
        BtcCtx {
            settings: &self.settings,
            apikeys: &self.apikeys,
            meta: self.meta.as_ref(),
            journal: self.journal.as_ref(),
            unlocked: self.unlocked,
            has_mnemonic: self.has_mnemonic,
            now_ms: self.clock.now_ms(),
            now_unix_ms: self.clock.now_unix_ms(),
        }
    }

    fn key_job(&mut self, job: KeyJob) {
        self.work.push_back(BtcAction::Key(Box::new(job)));
    }

    /// Runs every queued action and the worker results they cause.
    fn drain(&mut self) {
        while let Some(action) = self.work.pop_front() {
            match action {
                BtcAction::Key(job) => {
                    for outcome in self.key.handle(*job) {
                        self.key_outcome(outcome);
                    }
                }
                BtcAction::Rpc(job) => {
                    self.rpc.handle(*job, &self.events);
                    for event in self.events.drain() {
                        if let UiEvent::Rpc(RpcEvent::Btc(event)) = event {
                            self.call(|ui, ctx| ui.on_rpc_event(ctx, *event));
                        }
                    }
                }
                BtcAction::SetMeta(btc, accounts) => {
                    if let Some(meta) = self.meta.as_mut() {
                        meta.btc = btc;
                        meta.btc_accounts = *accounts;
                    }
                }
                BtcAction::Enqueue(item) => self.queued.push(*item),
                BtcAction::SaveSettings(settings, _) => self.settings = *settings,
                BtcAction::Confirm => self.confirms += 1,
                BtcAction::Screen(screen) => self.screens.push(screen),
                BtcAction::Banner(_, text) => self.banners.push(text),
            }
        }
    }

    fn key_outcome(&mut self, outcome: KeyOutcome) {
        match outcome {
            KeyOutcome::Meta(Ok(loaded)) => {
                self.has_mnemonic = loaded.has_mnemonic;
                self.meta = Some(*loaded.meta);
            }
            KeyOutcome::Journal(Ok(view)) => {
                self.journal = Some(view);
                self.call(BtcUi::journal_changed);
            }
            KeyOutcome::ActivityMoved(rows) => {
                if let Some(meta) = self.meta.as_mut() {
                    for (network, entry) in &rows {
                        meta.upsert_activity(&network.to_string(), entry);
                    }
                }
            }
            outcome @ (KeyOutcome::BtcMeta(_)
            | KeyOutcome::SignedBtc(_)
            | KeyOutcome::BtcJournal(_)) => {
                self.call(|ui, ctx| ui.on_key_outcome(ctx, outcome));
            }
            _ => {}
        }
    }

    fn run(&mut self, call: impl FnOnce(&mut BtcUi, &BtcCtx<'_>) -> Vec<BtcAction>) {
        self.call(call);
        self.drain();
    }

    fn btc_meta(&self) -> Option<&yw_core::btc::BtcMeta> {
        self.meta.as_ref().and_then(|meta| meta.btc.as_deref())
    }

    fn records(&self) -> Vec<yw_core::journal::btc::BtcRecord> {
        self.journal
            .as_ref()
            .map(|journal| journal.btc_records.clone())
            .unwrap_or_default()
    }

    /// Approves the oldest queued item like A01 would (issue at display, consume).
    fn approve(&mut self) -> TestResult {
        let item = self.queued.remove(0);
        let draft =
            BtcUi::draft(&item, ApprovalId::random()?).map_err(yw_app::errors::ErrorCode::code)?;
        let mut store = ApprovalStore::new();
        let now = self.clock.now_ms();
        let request = store.issue(draft, now, self.clock.now_unix_ms())?;
        assert!(
            yw_app::ui::approval::validate_for_display(&request.display).is_ok(),
            "every BTC field has a label"
        );
        let approved = store.consume(request.id, request.digest, now.saturating_add(1))?;
        self.run(|ui, ctx| ui.consumed(ctx, approved, &item));
        Ok(())
    }

    /// Enables testnet4 and runs creation, discovery and the first refresh.
    fn enable(&mut self) {
        self.run(|ui, ctx| ui.enable(ctx, BtcNetwork::Testnet4));
    }

    /// [`Harness::enable`], then BIP84 account 0 switched to HD mode (a new receive address each
    /// time, change on the change chain; spec/08 §3.5) for the tests of the HD index rules.
    fn enable_hd(&mut self) {
        self.enable();
        self.run(|ui, ctx| ui.set_address_mode(ctx, false));
        assert!(self.btc_meta().is_some_and(|meta| !meta.fixed_address()));
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn send_form(harness: &mut Harness, amount_sats: &str, rate: &str) {
    harness.run(|ui, ctx| {
        ui.set_recipient(ctx, RECIPIENT);
        ui.set_unit(ctx, BtcAmountUnit::Sats);
        ui.set_amount(ctx, amount_sats);
        ui.set_fee_choice(ctx, BtcFeeChoice::Manual, false);
        ui.set_manual_rate(rate, false);
        Vec::new()
    });
}

#[test]
#[expect(clippy::too_many_lines, reason = "one end-to-end send in order")]
fn testnet4_send_end_to_end() -> TestResult {
    let mut harness = Harness::new("e2e")?;
    harness.enable_hd();
    // Settings written, BtcMeta of the spec/08 §14.1 testnet4 account node, discovery done.
    assert!(harness.settings.enabled);
    assert_eq!(harness.settings.network, BtcNet::Testnet4);
    let meta = harness.btc_meta().ok_or("btc meta")?;
    assert_eq!(meta.network(), BtcNetwork::Testnet4);
    assert_eq!(
        yw_core::hex::encode(&meta.account().identity()),
        ACCOUNT_PUBKEY
    );
    assert_eq!(
        yw_core::hex::encode(&meta.account().xpub().ok_or("xpub")?.chain_code),
        ACCOUNT_CHAIN_CODE
    );
    assert!(meta.discovery_done());
    assert_eq!(meta.receive_next(), 1);
    assert_eq!(meta.last_used_receive(), Some(0));
    assert_eq!(meta.change_next(), 0);
    // The refresh verified the funding output through Core and the spec/08 §5 hash check.
    assert_eq!(meta.verified().len(), 1);
    assert_eq!(meta.verified()[0].value.get(), FUNDING_VALUE);
    let balance = harness.ui.balance(&harness.ctx()).ok_or("balance")?;
    assert_eq!(balance.available.get(), FUNDING_VALUE);
    assert_eq!(harness.ui.tip, Some(TIP));
    assert!(harness.ui.indexer_verified);
    assert_eq!(harness.ui.discovery.checked, 21 + 20);
    // Never an xpub, descriptor or fee API request.
    assert!(harness.fake.calls().iter().all(|call| {
        !call.url.contains("xpub") && !call.url.contains("fee") && call.verb != Verb::PostText
    }));

    // Send form: no estimate on testnet4 → manual input with the floor.
    harness.run(|ui, ctx| {
        ui.set_recipient(ctx, RECIPIENT);
        ui.set_unit(ctx, BtcAmountUnit::Sats);
        ui.set_amount(ctx, "30000");
        Vec::new()
    });
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    assert!(harness.queued.is_empty());
    assert_eq!(harness.ui.send.fee.choice, BtcFeeChoice::Manual);
    assert_eq!(harness.ui.send.fee.manual_text, "1");
    assert_eq!(harness.ui.send.fee.error, None);
    assert_eq!(
        harness.ui.send.info.as_deref(),
        Some("노드가 수수료 추정을 주지 않았습니다. 직접 입력하세요(하한 1 sat/vB)")
    );
    assert!(harness.ui.can_review(&harness.ctx()));
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    assert_eq!(harness.queued.len(), 1);
    let item = harness.queued[0].clone();
    assert_eq!(item.plan.amount().get(), 30_000);
    assert_eq!(item.plan.change().map(|change| change.index), Some(0));
    assert!(item.facts.first_time_recipient);
    assert!(harness.ui.slot);

    harness.approve()?;
    // Signed → pre-check accepted → Broadcasting (change_next) → sent → Submitted.
    let records = harness.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.state, BtcTxState::Submitted);
    let sent_txid = record.txid;
    assert_eq!(harness.ui.result, Some(sent_txid));
    assert!(harness.screens.contains(&BtcScreen::SendResult));
    let meta = harness.btc_meta().ok_or("btc meta")?;
    assert_eq!(meta.change_next(), 1);
    assert!(!meta.is_first_time(&record.recipient_script().ok_or("script")?));
    let methods = harness.fake.methods();
    let precheck = methods
        .iter()
        .position(|method| method == "testmempoolaccept")
        .ok_or("no precheck")?;
    let send = methods
        .iter()
        .position(|method| method == "sendrawtransaction")
        .ok_or("no send")?;
    // check_chain steps 1–2 right before each.
    assert_eq!(
        methods[precheck - 2..precheck],
        ["getblockhash", "getblockchaininfo"]
    );
    assert_eq!(
        methods[send - 2..send],
        ["getblockhash", "getblockchaininfo"]
    );
    assert!(precheck < send);
    let flow = harness.ui.flow(&sent_txid).ok_or("flow")?;
    assert_eq!(flow.note.as_deref(), Some("전송했습니다"));

    // D20: no second send while in flight; the fee bump is allowed.
    assert_eq!(
        harness.ui.send_block(&harness.ctx()).as_deref(),
        Some(yw_core::btc::policy::texts::IN_FLIGHT)
    );
    send_form(&mut harness, "10000", "2");
    let before = harness.fake.count();
    harness.run(|ui, ctx| ui.review(ctx, [8; 32]));
    assert!(harness.queued.is_empty());
    assert_eq!(harness.fake.count(), before, "inflight_blocks_new_send");
    harness.run(BtcUi::open_bump);
    assert_eq!(harness.ui.bump.target, Some(sent_txid));
    harness.run(|ui, ctx| {
        ui.set_fee_choice(ctx, BtcFeeChoice::Manual, true);
        ui.set_manual_rate("5", true);
        Vec::new()
    });
    harness.run(|ui, ctx| ui.review_bump(ctx, [9; 32]));
    assert_eq!(harness.queued.len(), 1, "rbf_allowed_while_inflight");
    let bump = harness.queued.remove(0);
    assert_eq!(bump.plan.replaces(), Some(sent_txid));
    assert!(bump.plan.fee().get() > record.fee.get());
    harness.run(|ui, _| {
        ui.approval_finished(&bump, yw_app::ui::approval::QueueOutcome::Rejected);
        Vec::new()
    });
    assert!(!harness.ui.slot);

    // Tracking: in the mempool, then confirmed with one confirmation (final).
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    assert_eq!(harness.records()[0].state, BtcTxState::InMempool);
    if let Ok(mut world) = harness.world.lock() {
        world.confirm(&sent_txid, CONFIRM_HEIGHT);
    }
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    let records = harness.records();
    let record = records
        .iter()
        .find(|record| record.txid == sent_txid)
        .ok_or("record")?;
    assert_eq!(record.state, BtcTxState::Confirmed);
    assert_eq!(record.confirmed_height, Some(CONFIRM_HEIGHT));
    // Own change inserted from the local bytes.
    let change = record.change_outpoint().ok_or("change")?;
    let meta = harness.btc_meta().ok_or("btc meta")?;
    let own = meta
        .verified()
        .iter()
        .find(|utxo| utxo.outpoint == change)
        .ok_or("own change")?;
    assert!(own.own);
    assert_eq!(own.chain, BtcChain::Change);
    assert_eq!(own.index, 0);
    // Finished at one confirmation → meta activity `bitcoin:testnet4`.
    let activity = harness
        .meta
        .as_ref()
        .ok_or("meta")?
        .activity_of("bitcoin:testnet4");
    let row = activity
        .iter()
        .find(|row| row.tx_id == sent_txid.to_display_hex())
        .ok_or("activity row")?;
    assert_eq!(row.status, "succeeded");
    assert_eq!(row.amount, "30000");
    assert_eq!(row.counterparty, RECIPIENT);
    assert_eq!(row.account, "");
    assert_eq!(row.title, "[Bitcoin testnet4] 보내기: 0.00030000 BTC");
    let rows = harness.ui.activity_rows(&harness.ctx());
    let view = rows
        .iter()
        .find(|view| view.txid == sent_txid.to_display_hex())
        .ok_or("tab row")?;
    assert_eq!(view.status, "확정 (서버 기준)");
    assert!(!view.can_bump);
    // New sends are allowed again.
    assert_eq!(harness.ui.send_block(&harness.ctx()), None);
    assert!(harness.banners.is_empty(), "{:?}", harness.banners);
    Ok(())
}

#[test]
fn precheck_rejection_keeps_change_index() -> TestResult {
    let mut harness = Harness::new("reject")?;
    harness.enable_hd();
    if let Ok(mut world) = harness.world.lock() {
        world.reject = Some("min relay fee not met");
    }
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    harness.approve()?;
    let records = harness.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, BtcTxState::Rejected);
    assert_eq!(
        harness
            .ui
            .flow(&records[0].txid)
            .and_then(|flow| flow.note.clone())
            .as_deref(),
        Some("수수료율이 노드 최소값보다 낮습니다")
    );
    // Not sent, change index reusable.
    assert!(
        !harness
            .fake
            .methods()
            .contains(&"sendrawtransaction".to_owned())
    );
    assert_eq!(harness.btc_meta().ok_or("meta")?.change_next(), 0);
    if let Ok(mut world) = harness.world.lock() {
        world.reject = None;
    }
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    let item = harness.queued.first().ok_or("plan")?;
    assert_eq!(item.plan.change().map(|change| change.index), Some(0));
    // Review H1: the same plan signs to the same txid. The finished `Rejected` record goes to
    // activity and the new one is sent (it used to stay `Signed` and block every send).
    let rejected = records[0].txid;
    assert_eq!(item.plan.txid(), rejected, "byte-identical transaction");
    harness.approve()?;
    let records = harness.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].txid, rejected);
    assert_eq!(records[0].state, BtcTxState::Submitted);
    let activity = harness
        .meta
        .as_ref()
        .ok_or("meta")?
        .activity_of("bitcoin:testnet4");
    assert!(
        activity
            .iter()
            .any(|row| row.tx_id == rejected.to_display_hex() && row.status == "rejected")
    );
    assert_eq!(harness.btc_meta().ok_or("meta")?.change_next(), 1);
    Ok(())
}

/// Review fix: `sendrawtransaction` `-26` gives the change index back (nothing was relayed).
#[test]
fn rejected_send_gives_change_index_back() -> TestResult {
    let mut harness = Harness::new("send-rejected")?;
    harness.enable();
    if let Ok(mut world) = harness.world.lock() {
        world.send_error = Some(-26);
    }
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    harness.approve()?;
    let records = harness.records();
    assert_eq!(records[0].state, BtcTxState::Rejected);
    assert_eq!(harness.btc_meta().ok_or("meta")?.change_next(), 0);
    Ok(())
}

/// Review fix: the chain check right before `sendrawtransaction` failed — nothing was sent, so
/// the record is not `BroadcastUnknown`: it stays `Broadcasting` and the same bytes can be sent
/// again.
#[test]
fn send_stopped_by_chain_check_stays_broadcasting() -> TestResult {
    let mut harness = Harness::new("send-chain")?;
    harness.enable();
    if let Ok(mut world) = harness.world.lock() {
        world.fail_chain_after_precheck = true;
    }
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    harness.approve()?;
    let record = harness.records()[0].clone();
    assert_eq!(record.state, BtcTxState::Broadcasting);
    assert!(
        !harness
            .fake
            .methods()
            .contains(&"sendrawtransaction".to_owned())
    );
    let flow = harness.ui.flow(&record.txid).ok_or("flow")?;
    assert!(flow.retry_send);
    assert!(
        flow.note
            .as_deref()
            .is_some_and(|note| note.starts_with(yw_app::app_btc::NOT_SENT))
    );
    let view = view_of(&harness, &record.txid)?;
    assert!(view.can_rebroadcast && !view.can_abandon);
    harness.run(|ui, ctx| ui.rebroadcast(ctx, record.txid));
    assert_eq!(harness.records()[0].state, BtcTxState::Submitted);
    Ok(())
}

/// Review fix: "the last Core send was a communication failure" is kept in the journal, so
/// [Esplora로 전송] is still offered after a restart (no session flow any more).
#[test]
fn comm_failure_survives_restart() -> TestResult {
    let mut harness = Harness::new("comm-restart")?;
    harness.enable();
    if let Ok(mut world) = harness.world.lock() {
        world.send_transport = true;
    }
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    harness.approve()?;
    let record = harness.records()[0].clone();
    assert_eq!(record.state, BtcTxState::BroadcastUnknown);
    assert!(record.last_send_comm_failure);
    assert!(view_of(&harness, &record.txid)?.can_esplora);
    // "Restart": the session flows are gone; a refresh verifies the indexer again.
    harness.ui = BtcUi::default();
    harness.run(|ui, ctx| ui.refresh(ctx, yw_app::btc::Trigger::User));
    assert!(harness.ui.indexer_verified);
    assert!(harness.ui.flow(&record.txid).is_none());
    assert!(view_of(&harness, &record.txid)?.can_esplora);
    Ok(())
}

/// Review M1: while Core's mempool lacks the transaction but the indexer still has it, the
/// tracking rounds count it as "in a mempool", so [포기] is never offered.
#[test]
fn indexer_unconfirmed_is_never_abandonable() -> TestResult {
    let mut harness = Harness::new("blind-core")?;
    harness.enable();
    if let Ok(mut world) = harness.world.lock() {
        world.core_mempool_blind = true;
    }
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    harness.approve()?;
    let txid = harness.records()[0].txid;
    for _ in 0..12 {
        harness.clock.advance(60_000);
        harness.run(BtcUi::tick);
    }
    let record = harness.records()[0].clone();
    assert_eq!(record.state, BtcTxState::InMempool);
    assert_eq!(record.not_found_count, 0);
    assert!(!view_of(&harness, &txid)?.can_abandon);
    Ok(())
}

/// Review M2: planning is refused while the Core tip is far above the indexer tip.
#[test]
fn plan_refused_when_core_far_ahead_of_indexer() -> TestResult {
    let mut harness = Harness::new("tip-ahead")?;
    harness.enable();
    if let Ok(mut world) = harness.world.lock() {
        world.core_tip = Some(TIP + 50);
    }
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    assert!(harness.queued.is_empty());
    assert!(
        harness
            .ui
            .send
            .info
            .as_deref()
            .is_some_and(|info| info.contains("인덱서")),
        "{:?}",
        harness.ui.send.info
    );
    // The stored `max_tip_seen` did not follow the runaway Core tip.
    assert!(harness.btc_meta().ok_or("meta")?.max_tip_seen() <= TIP + 3);
    Ok(())
}

/// Review fix: a stored `max_tip_seen` above what the node reports blocks every check; after
/// [블록 높이 기록 초기화] (confirmed) the next refresh works again.
#[test]
fn reset_tip_after_regression() -> TestResult {
    let mut harness = Harness::new("tip-reset")?;
    harness.enable();
    // A wrong, too high tip remembered earlier (e.g. by another endpoint without an indexer
    // tip to cap it); the honest node now looks "regressed".
    let mut raised = harness.btc_meta().ok_or("meta")?.clone();
    raised.observe_tip(TIP + 20)?;
    if let Some(stored) = harness.meta.as_mut() {
        stored.btc = Some(Box::new(raised));
    }
    harness.run(|ui, ctx| ui.refresh(ctx, yw_app::btc::Trigger::User));
    assert!(harness.ui.tip_regressed, "{:?}", harness.ui.blocked);
    let confirms = harness.confirms;
    harness.run(BtcUi::reset_tip);
    assert_eq!(harness.confirms, confirms + 1);
    harness.run(BtcUi::confirm_yes);
    assert!(!harness.ui.tip_regressed);
    assert!(harness.ui.blocked.is_none(), "{:?}", harness.ui.blocked);
    assert_eq!(harness.ui.tip, Some(TIP));
    Ok(())
}

/// W-ADDR-3 for Bitcoin: a recipient that matches a known address (an earlier recipient) in the
/// first 4 and last 4 characters after `tb1q` needs `주소 전체를 직접 확인했습니다`.
#[test]
fn look_alike_recipient_needs_ack() -> TestResult {
    let mut harness = Harness::new("look-alike")?;
    harness.enable();
    // An earlier recipient in the activity that differs from `RECIPIENT` only in the middle.
    let earlier = "tb1qw508zzqejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    assert!(yw_core::btc::address::is_look_alike(earlier, RECIPIENT));
    if let Some(meta) = harness.meta.as_mut() {
        meta.upsert_activity(
            "bitcoin:testnet4",
            &yw_app::meta::ActivityEntry {
                account: String::new(),
                tx_id: "11".repeat(32),
                title: "[Bitcoin testnet4] 보내기: 0.00010000 BTC".to_owned(),
                asset: "native".to_owned(),
                amount: "10000".to_owned(),
                counterparty: earlier.to_owned(),
                status: "succeeded".to_owned(),
                time_unix_ms: 1,
            },
        );
    }
    send_form(&mut harness, "30000", "2");
    assert!(harness.ui.send.recipient.is_some());
    let note = harness.ui.send.look_alike.clone().ok_or("W-ADDR-3")?;
    assert!(note.contains("주소 오염"), "{note}");
    assert!(!harness.ui.can_review(&harness.ctx()));
    harness.ui.toggle_address_ack();
    assert!(harness.ui.can_review(&harness.ctx()));
    // Another recipient: no note, the check is cleared.
    harness.run(|ui, ctx| {
        ui.set_recipient(
            ctx,
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        );
        Vec::new()
    });
    assert!(harness.ui.send.recipient.is_some());
    assert!(harness.ui.send.look_alike.is_none());
    assert!(!harness.ui.send.ack);
    Ok(())
}

#[test]
fn network_mismatch_blocks() -> TestResult {
    let mut harness = Harness::new("mismatch")?;
    harness.enable();
    let before = harness.fake.count();
    // settings.json changed by hand to mainnet (with its endpoint): every BTC call is blocked.
    harness.apikeys.set_rpc(
        NetworkId::Bitcoin(BtcNet::Mainnet),
        &HttpsUrl::parse(CORE_URL)?,
    );
    harness.settings.network = BtcNet::Mainnet;
    assert_eq!(
        harness.ctx().gate(),
        Err(BtcGate::Mismatch {
            meta: BtcNetwork::Testnet4,
            settings: BtcNetwork::Mainnet
        })
    );
    harness.run(BtcUi::after_meta);
    assert_eq!(
        harness.ui.blocked.as_deref(),
        Some("BTC 네트워크 설정이 지갑 데이터와 다릅니다")
    );
    harness.run(BtcUi::open_tab);
    harness.run(|ui, ctx| ui.refresh(ctx, Trigger::User));
    harness.run(|ui, ctx| ui.discover(ctx, false));
    harness.run(BtcUi::open_receive);
    harness.clock.advance(120_000);
    harness.run(BtcUi::tick);
    send_form(&mut harness, "1000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [1; 32]));
    assert!(harness.queued.is_empty());
    assert_eq!(harness.fake.count(), before, "no BTC request");
    // The worker refuses a mismatched job without any request as well.
    let job = RpcJob::Btc(Box::new(BtcRpcJob::Refresh {
        job: 99,
        target: BtcTarget {
            endpoint: btc_support::endpoint(BtcNetwork::Mainnet, BtcIndexer::Esplora),
            meta_net: BtcNetwork::Testnet4,
        },
        work: RefreshJob {
            account: account(),
            receive_count: 1,
            change_count: 0,
            known: Vec::new(),
            inflight_change: Vec::new(),
            chain: ChainInput {
                max_tip_seen: 0,
                now_unix_secs: harness.clock.now_unix_ms() / 1_000,
            },
            trigger: Trigger::User,
        },
    }));
    harness.rpc.handle(job, &harness.events);
    let events = harness.events.drain();
    assert!(matches!(
        events.first(),
        Some(UiEvent::Rpc(RpcEvent::Btc(event))) if matches!(
            **event,
            BtcRpcEvent::Refreshed { result: Err(yw_app::btc::BtcError::Blocked(
                yw_app::btc::BtcBlock::NetworkMismatch
            )), .. }
        )
    ));
    assert_eq!(harness.fake.count(), before);
    // [설정을 testnet4로 되돌리기] writes the meta network back to settings.
    harness.run(BtcUi::mismatch_keep_meta);
    assert_eq!(harness.settings.network, BtcNet::Testnet4);
    assert!(harness.ctx().gate().is_ok());
    Ok(())
}

#[test]
fn locked_no_btc_calls_except_esplora_test() -> TestResult {
    let mut harness = Harness::new("locked")?;
    harness.enable();
    let records_before = harness.fake.count();
    harness.run(|ui, _| ui.lock());
    harness.unlocked = false;
    assert_eq!(harness.ctx().gate(), Err(BtcGate::Locked));
    harness.run(BtcUi::open_tab);
    harness.run(|ui, ctx| ui.refresh(ctx, Trigger::User));
    harness.run(|ui, ctx| ui.discover(ctx, true));
    harness.run(BtcUi::open_receive);
    harness.clock.advance(600_000);
    harness.run(BtcUi::tick);
    send_form(&mut harness, "1000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [1; 32]));
    harness.run(BtcUi::open_bump);
    harness.run(|ui, ctx| ui.review_bump(ctx, [1; 32]));
    assert_eq!(
        harness.fake.count(),
        records_before,
        "no BTC call while locked"
    );
    assert!(harness.ui.receive.is_none());
    // The settings `테스트` runs: exactly `GET <base>/block-height/0`, no address.
    harness.run(|ui, ctx| ui.test_esplora_url(ctx, BtcNetwork::Testnet4, ""));
    let calls = harness.fake.calls();
    assert_eq!(calls.len(), records_before + 1);
    let last = calls.last().ok_or("call")?;
    assert_eq!(last.verb, Verb::Get);
    assert_eq!(last.path(), "/block-height/0");
    let (net, message, ok) = harness.ui.esplora_tests.first().cloned().ok_or("message")?;
    assert_eq!(net, BtcNetwork::Testnet4);
    assert!(ok);
    assert_eq!(
        message,
        "Esplora 서버가 작동합니다. (Bitcoin testnet4, genesis 일치)"
    );
    // A bad URL is refused locally (E-BTC-006) without a request.
    harness.run(|ui, ctx| {
        ui.test_esplora_url(ctx, BtcNetwork::Testnet4, "https://x.btc.quiknode.pro/tok")
    });
    assert_eq!(harness.fake.count(), records_before + 1);
    Ok(())
}

#[test]
fn receive_address_shown_after_persisted_issue() -> TestResult {
    let mut harness = Harness::new("receive")?;
    harness.enable_hd();
    // Discovery: 0/0 used → receive_next 1, the range [1, 1) is empty → issue index 1.
    harness.call(BtcUi::open_receive);
    // Queued, not shown yet.
    assert!(harness.ui.receive.is_none());
    harness.drain();
    let view = harness.ui.receive.clone().ok_or("receive view")?;
    assert_eq!(view.index, 1);
    assert_eq!(view.path, "m/84'/1'/0'/0/1");
    assert_eq!(view.qr, format!("bitcoin:{}", view.address));
    assert!(view.address.starts_with("tb1q"));
    assert_eq!(view.banner, "BITCOIN TESTNET4 — 가치 없음");
    assert_eq!(harness.btc_meta().ok_or("meta")?.receive_next(), 2);
    // Re-opening shows the same unused address (no new issue).
    harness.run(BtcUi::open_receive);
    assert_eq!(harness.ui.receive.as_ref().map(|view| view.index), Some(1));
    assert_eq!(harness.btc_meta().ok_or("meta")?.receive_next(), 2);
    // "새 주소" up to the gap: the 20th unused asks first ([이전 주소 사용] / [그래도 발급]).
    for _ in 0..19 {
        harness.run(BtcUi::new_receive_address);
    }
    assert_eq!(harness.btc_meta().ok_or("meta")?.receive_next(), 21);
    harness.run(BtcUi::new_receive_address);
    assert_eq!(harness.confirms, 1);
    assert_eq!(harness.btc_meta().ok_or("meta")?.receive_next(), 21);
    harness.run(BtcUi::confirm_yes);
    assert_eq!(harness.btc_meta().ok_or("meta")?.receive_next(), 22);
    Ok(())
}

#[test]
fn corrupt_btc_journal_stops_btc_sending_only() -> TestResult {
    let mut harness = Harness::new("corrupt")?;
    harness.enable();
    if let Some(journal) = harness.journal.as_mut() {
        journal.btc_corrupt = 1;
    }
    assert_eq!(
        harness.ui.send_block(&harness.ctx()).as_deref(),
        Some("거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)")
    );
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    assert!(harness.queued.is_empty());
    // Reading still works.
    let before = harness.fake.count();
    harness.run(|ui, ctx| ui.refresh(ctx, Trigger::User));
    assert!(harness.fake.count() > before);
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "plan, draft and the whole view checked"
)]
fn approval_view_shows_btc_money_rows() -> TestResult {
    // Planning needs no key: the public account node and one verified output.
    let mut meta = yw_core::btc::BtcMeta::new(BtcNetwork::Testnet4, xpub());
    let outpoint = OutPoint {
        txid: Txid::from_bytes([0x44; 32]),
        vout: 0,
    };
    meta.apply_refresh(
        &[yw_core::btc::meta::ListedUtxo {
            outpoint,
            chain: BtcChain::Receive,
            index: 0,
            height: TIP - 10,
        }],
        &[yw_core::btc::meta::VerifiedUtxo {
            outpoint,
            value: Sats::new(FUNDING_VALUE).ok_or("sats")?,
            chain: BtcChain::Receive,
            index: 0,
            height: TIP - 10,
            is_coinbase: false,
            own: false,
        }],
        &[],
        &[],
    );
    let candidates = meta.spendable(TIP, &[]);
    let plan = yw_core::btc::plan_send(&yw_core::btc::SendRequest {
        network: BtcNetwork::Testnet4,
        account: meta.account(),
        recipient: parse_address(RECIPIENT, BtcNetwork::Testnet4)
            .map_err(|error| format!("{error:?}"))?,
        amount: yw_core::btc::SendAmount::Exact(Sats::new(30_000).ok_or("sats")?),
        fee: yw_core::btc::FeeChoice {
            rate: yw_core::btc::FeeRate::from_sat_per_kvb(2_000),
            source: yw_core::btc::FeeSource::Manual,
        },
        candidates: &candidates,
        tip_height: TIP,
        change_next: 0,
        layout_seed: [1; 32],
        typed_fee_override: None,
        conflicts: &[],
    })
    .map_err(|error| format!("{error:?}"))?;
    let item = BtcApprovalItem {
        network: BtcNetwork::Testnet4,
        facts: meta
            .send_facts(&plan, TIP, &[])
            .map_err(|error| format!("{error:?}"))?,
        account: account(),
        tip_height: TIP,
        plan,
    };
    let draft =
        BtcUi::draft(&item, ApprovalId::random()?).map_err(yw_app::errors::ErrorCode::code)?;
    let request = ApprovalStore::new().issue(draft, 1, 1_793_074_713_000)?;
    // Folded (`자세히` closed): the summary, the money rows and the critical fields only.
    let folded = yw_app::ui::approval_view::signing_view(&request, false, true, Vec::new(), false)
        .map_err(yw_app::errors::ErrorCode::code)?;
    let folded_labels: Vec<String> = folded
        .blocks
        .iter()
        .filter_map(|block| match block {
            Block::Field { label, .. } => Some(label.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        folded_labels,
        [
            "금액",
            "잔돈",
            "입력",
            "수수료",
            "총 차감",
            "받는 주소",
            "주소 종류"
        ]
    );
    assert!(folded.has_raw);
    assert!(matches!(
        folded.blocks.first(),
        Some(Block::Summary { sentence, address: Some(_), .. }) if sentence.contains("아래 주소로 보냅니다")
    ));
    let view = yw_app::ui::approval_view::signing_view(&request, true, true, Vec::new(), false)
        .map_err(yw_app::errors::ErrorCode::code)?;
    let sections: Vec<&str> = view
        .blocks
        .iter()
        .filter_map(|block| match block {
            Block::Section(title) => Some(*title),
            _ => None,
        })
        .collect();
    // Money first, then this request's warnings (first-time recipient), then the critical fields.
    assert_eq!(sections, ["금액·수수료", "확인할 경고", "핵심 정보"]);
    assert!(view.band.is_none());
    let fields: Vec<(String, bool)> = view
        .blocks
        .iter()
        .filter_map(|block| match block {
            Block::Field { label, mono, .. } => Some((label.clone(), *mono)),
            _ => None,
        })
        .collect();
    let labels: Vec<&str> = fields.iter().map(|(label, _)| label.as_str()).collect();
    // The money rows (0x0603–0x0607) first, then the rest of the details in field order.
    assert_eq!(
        labels,
        [
            "금액",
            "잔돈",
            "입력",
            "수수료",
            "총 차감",
            "받는 주소",
            "주소 종류",
            "승인 후 잔액",
            "고급"
        ]
    );
    assert!(
        fields
            .iter()
            .any(|(label, mono)| label == "받는 주소" && *mono)
    );
    assert_eq!(
        view.header
            .iter()
            .map(|(label, _)| label.as_str())
            .collect::<Vec<_>>(),
        ["요청 출처", "네트워크", "서명 계정"]
    );
    assert!(
        view.header
            .iter()
            .any(|(_, value)| value.contains("BITCOIN TESTNET4"))
    );
    assert_eq!(
        yw_app::ui::approval_view::BtcBanner::of(BtcNetwork::Mainnet).text(),
        "BITCOIN MAINNET"
    );
    Ok(())
}

fn view_of(harness: &Harness, txid: &Txid) -> TestResult<yw_app::app_btc::BtcActivityView> {
    harness
        .ui
        .activity_rows(&harness.ctx())
        .into_iter()
        .find(|view| view.txid == txid.to_display_hex())
        .ok_or_else(|| "activity row".into())
}

/// Review fix (spec/08 §12.1, §12.2-3): after a failed send (`BroadcastUnknown` right away)
/// [포기] is neither shown nor accepted; after 10 tracking rounds that found the transaction
/// neither in the mempool nor confirmed it is offered and goes through.
#[test]
fn abandon_offered_only_after_not_found_limit() -> TestResult {
    let mut harness = Harness::new("abandon")?;
    harness.enable();
    if let Ok(mut world) = harness.world.lock() {
        world.send_error = Some(-1);
    }
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    harness.approve()?;
    let txid = harness.records()[0].txid;
    assert_eq!(harness.records()[0].state, BtcTxState::BroadcastUnknown);
    let view = view_of(&harness, &txid)?;
    assert!(view.can_rebroadcast);
    assert!(!view.can_abandon, "no [포기] right after the send failed");
    let confirms = harness.confirms;
    harness.run(|ui, ctx| ui.abandon(ctx, txid));
    assert_eq!(harness.confirms, confirms);
    assert!(harness.ui.confirm.is_none());
    for round in 0..10 {
        assert!(!view_of(&harness, &txid)?.can_abandon, "round {round}");
        harness.clock.advance(60_000);
        harness.run(BtcUi::tick);
    }
    let record = harness.records()[0].clone();
    assert_eq!(record.state, BtcTxState::BroadcastUnknown);
    assert_eq!(record.not_found_count, 10);
    assert!(view_of(&harness, &txid)?.can_abandon);
    harness.run(|ui, ctx| ui.abandon(ctx, txid));
    assert_eq!(harness.confirms, confirms + 1);
    harness.run(BtcUi::confirm_yes);
    assert_eq!(harness.records()[0].state, BtcTxState::Abandoned);
    // Review M1: the next send must spend an input of the abandoned transaction, so at most one
    // of the two can confirm; when the new one confirms the abandoned one is `Conflicted`.
    let abandoned_inputs: Vec<OutPoint> =
        record.inputs.iter().map(|input| input.outpoint).collect();
    if let Ok(mut world) = harness.world.lock() {
        world.send_error = None;
    }
    send_form(&mut harness, "20000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [8; 32]));
    let item = harness.queued.first().ok_or("plan")?;
    assert!(
        item.plan
            .inputs()
            .iter()
            .any(|input| abandoned_inputs.contains(&input.outpoint))
    );
    let new_txid = item.plan.txid();
    assert_ne!(new_txid, txid);
    harness.approve()?;
    let records = harness.records();
    let new = records
        .iter()
        .find(|record| record.txid == new_txid)
        .ok_or("new record")?;
    assert_eq!(new.state, BtcTxState::Submitted);
    if let Ok(mut world) = harness.world.lock() {
        world.confirm(&new_txid, CONFIRM_HEIGHT);
    }
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    let states: Vec<(Txid, BtcTxState)> = harness
        .records()
        .iter()
        .map(|record| (record.txid, record.state))
        .collect();
    assert!(
        states.contains(&(new_txid, BtcTxState::Confirmed)),
        "{states:?}"
    );
    assert!(
        states.contains(&(txid, BtcTxState::Conflicted)),
        "{states:?}"
    );
    Ok(())
}

/// Review fix (spec/08 §11.3): `testmempoolaccept` answering `txn-already-in-mempool` does not
/// reject the send: nothing is sent, the record is `BroadcastUnknown` (change index used, form
/// not restored), and tracking moves it to `InMempool`.
#[test]
fn precheck_already_in_mempool_keeps_tracking() -> TestResult {
    let mut harness = Harness::new("known")?;
    harness.enable_hd();
    if let Ok(mut world) = harness.world.lock() {
        world.reject = Some("txn-already-in-mempool");
    }
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    harness.approve()?;
    let record = harness.records()[0].clone();
    assert_eq!(record.state, BtcTxState::BroadcastUnknown);
    assert_eq!(
        harness
            .ui
            .flow(&record.txid)
            .and_then(|flow| flow.note.clone())
            .as_deref(),
        Some("이미 전송된 거래입니다")
    );
    assert!(
        !harness
            .fake
            .methods()
            .contains(&"sendrawtransaction".to_owned())
    );
    assert_eq!(harness.btc_meta().ok_or("meta")?.change_next(), 1);
    assert!(harness.ui.send.to_text.is_empty(), "form not restored");
    assert!(!view_of(&harness, &record.txid)?.can_abandon);
    // The node does have it: the next tracking round (scheduled now) sees it in the mempool.
    if let Ok(mut world) = harness.world.lock() {
        world.reject = None;
        let tx = parse_transaction(&record.raw).map_err(|error| format!("{error:?}"))?;
        world.txs.push((tx, record.raw.clone(), None));
    }
    harness.run(BtcUi::tick);
    assert_eq!(harness.records()[0].state, BtcTxState::InMempool);
    Ok(())
}

/// A confirmed transaction paying `value` to `script` (a funding of another account).
fn funding_to(script: Vec<u8>, value: u64, salt: u8) -> TestResult<(Transaction, Vec<u8>)> {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: Txid::from_bytes([salt; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_fffd,
            witness: vec![vec![0x30; 71], vec![0x02; 33]],
        }],
        outputs: vec![TxOut {
            value: Sats::new(value).ok_or("sats")?,
            script_pubkey: script,
        }],
        lock_time: 0,
    };
    let raw = serialize(&tx, true);
    Ok((tx, raw))
}

/// spec/08 §3 every address type at the app level: `계정 추가` of each type (the key worker derives
/// `m/{44|49|84|86}'/1'/n'`, stores and selects it), discovery and a refresh that verifies a
/// funding of its receive address 0, the account rows, the receive screen, a send through the
/// real RPC worker (prepare → approval → sign → post-sign verification → pre-check → send), the
/// version 2 journal record of that account, tracking to one confirmation with the own change
/// inserted into that account (not BIP84 account 0), the activity row's account tag, and the
/// switch back. Each type runs in both address modes (spec/08 §3.5): fixed address (the default
/// of a new account: no `새 주소`, change back to the receive address `…/0/0`, `change_next`
/// unchanged) and HD (change on the change chain, `change_next` 1).
#[test]
#[expect(clippy::too_many_lines, reason = "one account of each type end to end")]
fn every_address_type_end_to_end() -> TestResult {
    let rounds = ScriptType::CHOICES
        .into_iter()
        .flat_map(|script_type| [(script_type, true), (script_type, false)]);
    for (round, (script_type, fixed)) in rounds.enumerate() {
        let salt = u8::try_from(round).unwrap_or(0).saturating_add(0x60);
        let number = u32::from(script_type == ScriptType::P2wpkh);
        let mut harness = Harness::new(&format!(
            "types-{}-{}",
            script_type.json_name(),
            if fixed { "fixed" } else { "hd" }
        ))?;
        harness.enable();
        let primary_before = harness.btc_meta().ok_or("primary")?.clone();
        assert!(
            primary_before.fixed_address(),
            "BIP84 account 0 defaults to fixed"
        );
        harness.run(|ui, ctx| {
            ui.open_add_account(ctx);
            Vec::new()
        });
        assert!(harness.ui.add_account_open);
        assert_eq!(
            harness.ui.add_source,
            yw_app::app_btc::BtcAddSource::Standard
        );
        harness.run(|ui, ctx| ui.add_account(ctx, script_type));
        assert!(!harness.ui.add_account_open);
        assert!(
            harness
                .ctx()
                .btc_meta()
                .ok_or("new account")?
                .fixed_address(),
            "a new account starts in fixed-address mode"
        );
        if !fixed {
            harness.run(|ui, ctx| ui.set_address_mode(ctx, false));
            assert!(!harness.ctx().btc_meta().ok_or("hd")?.fixed_address());
        }
        // BIP84 account 0 is meta `btc`: the first added native segwit account is 1.
        let expected_id = BtcAccountId::Hd {
            script_type,
            account: number,
        };
        let meta = harness.meta.as_ref().ok_or("meta")?;
        assert_eq!(meta.btc_accounts.selected, Some(expected_id));
        let account = harness.ctx().btc_meta().ok_or("active account")?.clone();
        assert_eq!(account.id(), expected_id);
        assert!(
            account.discovery_done(),
            "discovery ran for the new account"
        );
        // BIP84 account 0 is unchanged.
        assert_eq!(harness.btc_meta(), Some(&primary_before));
        // The receive screen issues receive 0 (stored first) and shows the type and the path;
        // fund it and refresh.
        let address = account.address(BtcChain::Receive, 0)?;
        harness.run(BtcUi::open_receive);
        let view = harness.ui.receive.clone().ok_or("receive view")?;
        assert_eq!(view.address, address.as_str());
        assert!(view.kind.starts_with(script_type.name()));
        assert_eq!(
            view.path,
            format!("m/{}'/1'/{number}'/0/0", script_type.purpose().number())
        );
        assert_eq!(view.fixed, fixed);
        if fixed {
            // One address: no `새 주소` (refused by the key worker too), the explanation shown.
            assert!(
                view.note
                    .contains("받은 돈과 보내고 남은 잔돈이 모두 이 주소로"),
                "{}",
                view.note
            );
            harness.run(BtcUi::new_receive_address);
            assert!(harness.ui.receive_message.is_some());
            harness.run(BtcUi::open_receive);
            assert_eq!(harness.ui.receive.as_ref().map(|view| view.index), Some(0));
        }
        let first = address.as_str().chars().next().ok_or("address")?;
        assert!(match script_type {
            ScriptType::P2pkh => matches!(first, 'm' | 'n'),
            ScriptType::P2shP2wpkh => first == '2',
            ScriptType::P2wpkh => address.as_str().starts_with("tb1q"),
            ScriptType::P2tr => address.as_str().starts_with("tb1p"),
        });
        let (funding, raw) = funding_to(address.script_pubkey(), FUNDING_VALUE, salt)?;
        if let Ok(mut world) = harness.world.lock() {
            world.txs.push((funding, raw, Some(FUNDING_HEIGHT)));
        }
        harness.run(|ui, ctx| ui.refresh(ctx, Trigger::User));
        let account = harness.ctx().btc_meta().ok_or("active")?.clone();
        assert_eq!(account.verified().len(), 1, "{script_type:?}");
        assert_eq!(
            harness
                .ui
                .balance(&harness.ctx())
                .ok_or("balance")?
                .available
                .get(),
            FUNDING_VALUE
        );
        let rows = harness.ui.account_rows(&harness.ctx());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, BtcAccountId::PRIMARY);
        assert!(rows[1].selected && rows[1].id == expected_id);
        assert_eq!(rows[1].available.get(), FUNDING_VALUE);
        assert!(rows[1].kind.starts_with(script_type.name()));
        // Send through the RPC worker and the key worker.
        send_form(&mut harness, "30000", "2");
        harness.run(|ui, ctx| ui.review(ctx, [salt; 32]));
        assert_eq!(harness.queued.len(), 1, "{:?}", harness.ui.send.info);
        let item = harness.queued[0].clone();
        assert_eq!(item.plan.account(), account.account());
        harness.approve()?;
        let records = harness.records();
        let record = records
            .iter()
            .find(|record| record.account == expected_id)
            .ok_or("record of the account")?;
        assert_eq!(record.state, BtcTxState::Submitted);
        assert_eq!(record.script_type, script_type);
        let sent = parse_transaction(&record.raw)?;
        assert_eq!(sent.has_witness(), script_type.is_segwit());
        let sent_txid = record.txid;
        let record_change = record.change.ok_or("record change")?;
        let change_output = sent
            .outputs
            .get(usize::try_from(record_change.vout)?)
            .ok_or("change output")?;
        let account = harness.ctx().btc_meta().ok_or("active")?.clone();
        if fixed {
            // Change back to the receive address `…/0/0`; no change-chain index is used.
            assert_eq!(record_change.index, 0);
            assert_eq!(change_output.script_pubkey, address.script_pubkey());
            assert_eq!(account.change_next(), 0);
        } else {
            // The change index moved in this account, not in BIP84 account 0.
            assert_eq!(
                change_output.script_pubkey,
                account.expected_script(BtcChain::Change, 0)?
            );
            assert_eq!(account.change_next(), 1);
        }
        assert_eq!(harness.btc_meta().ok_or("primary")?.change_next(), 0);
        // Tracking to one confirmation (final): own change into this account.
        harness.clock.advance(60_000);
        harness.run(BtcUi::tick);
        if let Ok(mut world) = harness.world.lock() {
            world.confirm(&sent_txid, CONFIRM_HEIGHT);
        }
        harness.clock.advance(60_000);
        harness.run(BtcUi::tick);
        let record = harness
            .records()
            .into_iter()
            .find(|record| record.txid == sent_txid)
            .ok_or("record")?;
        assert_eq!(record.state, BtcTxState::Confirmed);
        let change = record.change_outpoint().ok_or("change")?;
        let account = harness.ctx().btc_meta().ok_or("active")?.clone();
        let own_path = if fixed {
            (BtcChain::Receive, 0)
        } else {
            (BtcChain::Change, 0)
        };
        assert!(account.verified().iter().any(|utxo| utxo.outpoint == change
            && utxo.own
            && (utxo.chain, utxo.index) == own_path));
        assert!(
            !harness
                .btc_meta()
                .ok_or("primary")?
                .verified()
                .iter()
                .any(|utxo| utxo.outpoint == change)
        );
        let activity = harness
            .meta
            .as_ref()
            .ok_or("meta")?
            .activity_of("bitcoin:testnet4");
        let row = activity
            .iter()
            .find(|row| row.tx_id == sent_txid.to_display_hex())
            .ok_or("activity row")?;
        assert_eq!(row.account, expected_id.activity_tag());
        assert!(
            harness
                .ui
                .activity_rows(&harness.ctx())
                .iter()
                .any(|view| view.txid == sent_txid.to_display_hex())
        );
        // Back to BIP84 account 0: its activity list does not show the other account's row.
        harness.run(|ui, ctx| ui.select_account(ctx, BtcAccountId::PRIMARY));
        assert_eq!(harness.ctx().active_id(), BtcAccountId::PRIMARY);
        assert_eq!(
            harness.meta.as_ref().ok_or("meta")?.btc_accounts.selected,
            None
        );
        assert!(
            !harness
                .ui
                .activity_rows(&harness.ctx())
                .iter()
                .any(|view| view.txid == sent_txid.to_display_hex())
        );
        assert_eq!(
            harness
                .ui
                .balance(&harness.ctx())
                .ok_or("balance")?
                .available
                .get(),
            FUNDING_VALUE
        );
        assert!(harness.banners.is_empty(), "{:?}", harness.banners);
    }
    Ok(())
}

// ----- imported keys (spec/08 §3.5, spec/04 §2.18) -----------------------------------------------

/// BIP49 test vector key (abandon `m/49'/1'/0'/0/0`), compressed, testnet WIF (public).
const BIP49_TEST_WIF: &str = "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ";
/// Secret 1 (public key = G), uncompressed, testnet WIF (public).
const ONE_TEST_UNCOMPRESSED_WIF: &str = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx";

/// One imported key of each address type: compressed for the three segwit/Taproot types,
/// uncompressed for P2PKH (the only type an uncompressed key may have).
const IMPORTED: [(&str, ScriptType); 4] = [
    (BIP49_TEST_WIF, ScriptType::P2wpkh),
    (BIP49_TEST_WIF, ScriptType::P2tr),
    (BIP49_TEST_WIF, ScriptType::P2shP2wpkh),
    (ONE_TEST_UNCOMPRESSED_WIF, ScriptType::P2pkh),
];

/// The public facts of `wif` used as `script_type` (what S19 shows).
fn imported_info(wif: &str, script_type: ScriptType) -> TestResult<yw_core::keyimport::BtcKeyInfo> {
    match yw_core::keyimport::ImportKey::parse(ImportSpec::Btc(script_type), wif)?.preview()? {
        ImportPreview::Btc(info) => Ok(info),
        ImportPreview::Evm(_) | ImportPreview::Sol(_) | ImportPreview::Zec(_) => {
            Err("not a Bitcoin key".into())
        }
    }
}

/// One imported key end to end: funded on the fake chain, listed (badge, balance, selected),
/// received to, sent from (prepare → approve → sign with the vault's tag-4 record → post-sign
/// verification → pre-check → send), tracked to one confirmation with the change back to the same
/// address inserted into the imported account, and its activity tag.
#[expect(clippy::too_many_lines, reason = "one imported account end to end")]
fn imported_round(key_only: bool, salt: u8, wif: &str, script_type: ScriptType) -> TestResult {
    let info = imported_info(wif, script_type)?;
    assert_eq!(info.network, BtcNetwork::Testnet4);
    let ours = script_pubkey(&info.kind);
    let tag = format!(
        "imported-{}-{}",
        if key_only { "keyonly" } else { "mnemonic" },
        script_type.json_name()
    );
    let (funding, raw) = funding_to(ours.clone(), FUNDING_VALUE, salt)?;
    let mut harness = if key_only {
        Harness::key_only(&tag, wif, script_type)?
    } else {
        let mut harness = Harness::new(&tag)?;
        harness.enable();
        harness
    };
    if let Ok(mut world) = harness.world.lock() {
        world.txs.push((funding, raw, Some(FUNDING_HEIGHT)));
    }
    let primary_before = harness.btc_meta().cloned();
    let account = if key_only {
        // The key start wrote its account; the tab opens with a refresh (no discovery).
        let account = *harness
            .ctx()
            .btc_meta()
            .ok_or("imported account")?
            .account();
        assert!(harness.ctx().primary_meta().is_none());
        assert_eq!(harness.ctx().gate(), Ok(()));
        harness.run(BtcUi::open_tab);
        account
    } else {
        // `AddImported` stores and selects it; the refresh of the new account follows.
        harness.import_key(wif, script_type)?
    };
    assert!(account.is_single());
    let BtcAccountId::Imported { id } = account.id() else {
        return Err("not an imported account".into());
    };
    let meta = harness.meta.as_ref().ok_or("meta")?;
    assert_eq!(meta.btc_accounts.selected, Some(account.id()));
    let active = harness.ctx().btc_meta().ok_or("active")?.clone();
    assert_eq!(active.account(), &account);
    assert!(active.discovery_done(), "a single key needs no discovery");
    assert_eq!(active.verified().len(), 1, "{script_type:?}");
    assert_eq!(
        harness
            .ui
            .balance(&harness.ctx())
            .ok_or("balance")?
            .available
            .get(),
        FUNDING_VALUE
    );
    // The account list: the imported row with its badge, short address, type and balance.
    let rows = harness.ui.account_rows(&harness.ctx());
    let row = rows.iter().find(|row| row.imported).ok_or("imported row")?;
    assert!(row.selected && row.id == account.id());
    assert_eq!(row.name, yw_app::app_btc::short_address(&info.address));
    assert!(row.kind.starts_with(script_type.name()));
    assert_eq!(row.available.get(), FUNDING_VALUE);
    if key_only {
        // No BIP84 account 0: the imported key is the only account and holds the tip.
        assert_eq!(rows.len(), 1);
        let ctx = harness.ctx();
        let holder = ctx.tip_meta().ok_or("tip holder")?;
        assert_eq!(holder.id(), account.id());
        assert_eq!(holder.max_tip_seen(), TIP);
    } else {
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, BtcAccountId::PRIMARY);
        assert!(!rows[0].imported);
    }
    // Receive: its one address (stored as receive 0), the path "가져온 키".
    harness.run(BtcUi::open_receive);
    let view = harness.ui.receive.clone().ok_or("receive view")?;
    assert_eq!(view.address, info.address);
    assert_eq!(view.path, "가져온 키");
    assert!(view.kind.starts_with(script_type.name()));
    // Send through the RPC worker and the key worker.
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [salt; 32]));
    assert_eq!(harness.queued.len(), 1, "{:?}", harness.ui.send.info);
    let item = harness.queued[0].clone();
    assert_eq!(item.plan.account(), &account);
    let change = item.plan.change().ok_or("change")?;
    assert_eq!(account.change_path(change.index), (BtcChain::Receive, 0));
    harness.approve()?;
    let record = harness
        .records()
        .into_iter()
        .find(|record| record.account == account.id())
        .ok_or("record of the imported account")?;
    assert_eq!(record.state, BtcTxState::Submitted);
    assert_eq!(record.script_type, script_type);
    let sent = parse_transaction(&record.raw)?;
    assert_eq!(sent.has_witness(), script_type.is_segwit());
    let input = sent.inputs.first().ok_or("input")?;
    let pubkey = info.public_key.as_bytes();
    match script_type {
        ScriptType::P2pkh => {
            // `<sig> <K>` with the 65-byte uncompressed key, no witness.
            assert!(input.witness.is_empty());
            assert!(input.script_sig.ends_with(pubkey) && pubkey.len() == 65);
        }
        ScriptType::P2shP2wpkh => {
            assert_eq!(input.script_sig.len(), 23);
            assert_eq!(input.witness.get(1).map(Vec::as_slice), Some(pubkey));
        }
        ScriptType::P2wpkh => {
            assert!(input.script_sig.is_empty());
            assert_eq!(input.witness.get(1).map(Vec::as_slice), Some(pubkey));
        }
        ScriptType::P2tr => {
            assert!(input.script_sig.is_empty());
            assert_eq!(input.witness.len(), 1);
            assert_eq!(input.witness.first().map(Vec::len), Some(64));
        }
    }
    // The change goes back to the same address.
    let vout = usize::try_from(change.vout)?;
    assert_eq!(
        sent.outputs.get(vout).map(|out| &out.script_pubkey),
        Some(&ours)
    );
    let sent_txid = record.txid;
    // D20 per account: no second send while in flight.
    assert_eq!(
        harness.ui.send_block(&harness.ctx()).as_deref(),
        Some(yw_core::btc::policy::texts::IN_FLIGHT)
    );
    // Tracking to one confirmation (final): the change is inserted into the imported account.
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    if let Ok(mut world) = harness.world.lock() {
        world.confirm(&sent_txid, CONFIRM_HEIGHT);
    }
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    let record = harness
        .records()
        .into_iter()
        .find(|record| record.txid == sent_txid)
        .ok_or("record")?;
    assert_eq!(record.state, BtcTxState::Confirmed);
    let change = record.change_outpoint().ok_or("change outpoint")?;
    let active = harness.ctx().btc_meta().ok_or("active")?.clone();
    let own = active
        .verified()
        .iter()
        .find(|utxo| utxo.outpoint == change)
        .ok_or("own change in the imported account")?;
    assert!(own.own && own.chain == BtcChain::Receive && own.index == 0);
    if !key_only {
        // BIP84 account 0 did not move.
        assert_eq!(harness.btc_meta().cloned(), primary_before);
    }
    let activity = harness
        .meta
        .as_ref()
        .ok_or("meta")?
        .activity_of("bitcoin:testnet4");
    let row = activity
        .iter()
        .find(|row| row.tx_id == sent_txid.to_display_hex())
        .ok_or("activity row")?;
    assert_eq!(
        row.account,
        format!("imported/{}", yw_core::hex::encode(&id))
    );
    assert_eq!(row.status, "succeeded");
    assert_eq!(harness.ui.send_block(&harness.ctx()), None);
    assert!(harness.banners.is_empty(), "{:?}", harness.banners);
    Ok(())
}

/// spec/08 §3.5 at the app level, mnemonic wallet: every address type of an imported WIF key
/// (`개인키 가져오기` → `AddImported`) next to BIP84 account 0.
#[test]
fn imported_keys_in_a_mnemonic_wallet_end_to_end() -> TestResult {
    for (round, (wif, script_type)) in IMPORTED.into_iter().enumerate() {
        let salt = u8::try_from(round).unwrap_or(0).saturating_add(0x70);
        imported_round(false, salt, wif, script_type)?;
    }
    Ok(())
}

/// spec/08 §3.5 at the app level, key-only wallet ("개인키로 시작하기" with a Bitcoin key): no
/// BIP84 account 0, no discovery; the imported key's account holds the wallet-level tip.
#[test]
fn imported_keys_in_a_key_only_wallet_end_to_end() -> TestResult {
    for (round, (wif, script_type)) in IMPORTED.into_iter().enumerate() {
        let salt = u8::try_from(round).unwrap_or(0).saturating_add(0x80);
        imported_round(true, salt, wif, script_type)?;
    }
    Ok(())
}

/// A key-only wallet with only a Bitcoin key: lock and unlock keep its account (and the tip it
/// holds); `계정 추가` is refused (no recovery words); its last key cannot be removed.
#[test]
fn key_only_bitcoin_wallet_locks_and_keeps_its_account() -> TestResult {
    let mut harness = Harness::key_only("keyonly-lock", BIP49_TEST_WIF, ScriptType::P2tr)?;
    harness.run(BtcUi::open_tab);
    let account = *harness.ctx().btc_meta().ok_or("account")?.account();
    let BtcAccountId::Imported { id } = account.id() else {
        return Err("not imported".into());
    };
    assert_eq!(
        harness
            .ctx()
            .tip_meta()
            .map(yw_core::btc::BtcMeta::max_tip_seen),
        Some(TIP)
    );
    // No HD accounts in a key-only wallet.
    harness.run(|ui, ctx| {
        ui.open_add_account(ctx);
        Vec::new()
    });
    assert!(!harness.ui.add_account_open);
    harness.run(|ui, ctx| ui.add_account(ctx, ScriptType::P2wpkh));
    assert_eq!(
        harness
            .meta
            .as_ref()
            .ok_or("meta")?
            .btc_accounts
            .accounts
            .len(),
        1
    );
    // Lock, reload, unlock: straight to `Unlocked`; the account (and its tip) come back.
    harness.unlocked = false;
    harness.run(|ui, _| ui.lock());
    let _ = harness.key.handle(KeyJob::Lock);
    harness.meta = None;
    harness.journal = None;
    let loaded = harness.key.handle(KeyJob::Load);
    assert!(matches!(
        loaded.first(),
        Some(KeyOutcome::Loaded {
            status: yw_core::vault::VaultStatus::Locked,
            ..
        })
    ));
    let unlocked = harness.key.handle(KeyJob::Unlock {
        password: Zeroizing::new(PASSWORD.to_vec()),
    });
    assert!(matches!(
        unlocked.first(),
        Some(KeyOutcome::Status(Ok(
            yw_core::vault::VaultStatus::Unlocked {
                alt_passphrase: false
            }
        )))
    ));
    harness.unlocked = true;
    harness.key_job(KeyJob::LoadMeta);
    harness.key_job(KeyJob::LoadJournal);
    harness.drain();
    assert!(!harness.has_mnemonic);
    let ctx = harness.ctx();
    assert_eq!(ctx.gate(), Ok(()));
    assert_eq!(ctx.btc_meta().map(|meta| *meta.account()), Some(account));
    assert_eq!(
        ctx.tip_meta().map(yw_core::btc::BtcMeta::max_tip_seen),
        Some(TIP)
    );
    // The only key of a key-only wallet stays (`LastKey`), with its account.
    let outcomes = harness.key.handle(KeyJob::RemoveImportedKey {
        password: Zeroizing::new(PASSWORD.to_vec()),
        id: yw_core::vault::RecordId::from_bytes(id),
    });
    assert!(matches!(
        outcomes.as_slice(),
        [KeyOutcome::ImportedKeyRemoved(Err(
            yw_core::error::VaultError::LastKey
        ))]
    ));
    Ok(())
}

/// Removing an imported Bitcoin key (spec/04 §2.18): refused while its account has an in-flight
/// transaction (the UI says why before the password; the key worker refuses too); once the
/// transaction is confirmed the vault record and the account go, the selection falls back to
/// BIP84 account 0, and the next meta load agrees.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "refusal, removal and reload in order"
)]
fn imported_key_removal() -> TestResult {
    let info = imported_info(BIP49_TEST_WIF, ScriptType::P2wpkh)?;
    let (funding, raw) = funding_to(script_pubkey(&info.kind), FUNDING_VALUE, 0x90)?;
    let mut harness = Harness::new("imported-remove")?;
    harness.enable();
    if let Ok(mut world) = harness.world.lock() {
        world.txs.push((funding, raw, Some(FUNDING_HEIGHT)));
    }
    let account = harness.import_key(BIP49_TEST_WIF, ScriptType::P2wpkh)?;
    let BtcAccountId::Imported { id } = account.id() else {
        return Err("not imported".into());
    };
    let record_id = yw_core::vault::RecordId::from_bytes(id);
    // An open approval of this account: the UI refuses before the password.
    send_form(&mut harness, "30000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [0x91; 32]));
    assert!(harness.ui.slot);
    assert_eq!(
        harness.ctx().remove_block(id, harness.ui.slot),
        Some(yw_app::app_btc::REMOVE_BUSY_APPROVAL)
    );
    harness.approve()?;
    // In flight: the UI and the key worker both refuse; nothing is removed.
    assert_eq!(
        harness.ctx().remove_block(id, harness.ui.slot),
        Some(yw_app::app_btc::REMOVE_BUSY_IN_FLIGHT)
    );
    let outcomes = harness.key.handle(KeyJob::RemoveImportedKey {
        password: Zeroizing::new(PASSWORD.to_vec()),
        id: record_id,
    });
    assert!(matches!(
        outcomes.as_slice(),
        [KeyOutcome::ImportedKeyBusy(busy)] if *busy == record_id
    ));
    assert!(
        harness
            .meta
            .as_ref()
            .ok_or("meta")?
            .btc_accounts
            .get(BtcNetwork::Testnet4, account.id())
            .is_some()
    );
    // Confirmed (one confirmation is final): removal goes through.
    let sent_txid = harness
        .records()
        .first()
        .map(|record| record.txid)
        .ok_or("record")?;
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    if let Ok(mut world) = harness.world.lock() {
        world.confirm(&sent_txid, CONFIRM_HEIGHT);
    }
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    assert_eq!(harness.ctx().remove_block(id, harness.ui.slot), None);
    // A wrong password removes nothing.
    let outcomes = harness.key.handle(KeyJob::RemoveImportedKey {
        password: Zeroizing::new(b"not the password 1".to_vec()),
        id: record_id,
    });
    assert!(matches!(
        outcomes.as_slice(),
        [KeyOutcome::ImportedKeyRemoved(Err(
            yw_core::error::VaultError::UnlockFailed
        ))]
    ));
    let outcomes = harness.key.handle(KeyJob::RemoveImportedKey {
        password: Zeroizing::new(PASSWORD.to_vec()),
        id: record_id,
    });
    let mut outcomes = outcomes.into_iter();
    assert!(matches!(
        outcomes.next(),
        Some(KeyOutcome::ImportedKeyRemoved(Ok((
            removed,
            yw_core::keyimport::ImportChain::Btc
        )))) if removed == record_id
    ));
    for outcome in outcomes {
        harness.key_outcome(outcome);
    }
    harness.drain();
    let meta = harness.meta.as_ref().ok_or("meta")?;
    assert!(
        meta.btc_accounts
            .get(BtcNetwork::Testnet4, account.id())
            .is_none()
    );
    assert_eq!(meta.btc_accounts.selected, None);
    assert_eq!(harness.ctx().active_id(), BtcAccountId::PRIMARY);
    assert!(
        harness
            .ui
            .account_rows(&harness.ctx())
            .iter()
            .all(|row| !row.imported)
    );
    // Its finished activity row stays; the next meta load agrees (no stale account, no mismatch).
    assert!(
        meta.activity_of("bitcoin:testnet4")
            .iter()
            .any(|row| row.tx_id == sent_txid.to_display_hex())
    );
    let loaded = harness.key.handle(KeyJob::LoadMeta);
    let Some(KeyOutcome::Meta(Ok(loaded))) = loaded.first() else {
        return Err("meta".into());
    };
    assert!(!loaded.mismatch);
    assert!(loaded.meta.btc_accounts.accounts.is_empty());
    Ok(())
}

/// A second confirmed funding of receive address 0 (`value` sats), so the planner has a choice.
fn add_second_funding(harness: &Harness, value: u64) -> TestResult<OutPoint> {
    let script = funding_tx()?.0.outputs[0].script_pubkey.clone();
    let (tx, raw) = funding_to(script, value, 0x44)?;
    let outpoint = OutPoint {
        txid: txid(&tx),
        vout: 0,
    };
    if let Ok(mut world) = harness.world.lock() {
        world.txs.push((tx, raw, Some(FUNDING_HEIGHT)));
    }
    Ok(outpoint)
}

fn funding_outpoint() -> TestResult<OutPoint> {
    Ok(OutPoint {
        txid: txid(&funding_tx()?.0),
        vout: 0,
    })
}

/// The inputs of the first queued plan.
fn queued_inputs(harness: &Harness) -> TestResult<Vec<OutPoint>> {
    let item = harness.queued.first().ok_or("plan")?;
    Ok(item
        .plan
        .inputs()
        .iter()
        .map(|input| input.outpoint)
        .collect())
}

/// Signs the reviewed plan while the controller sees the wallet locked: the record stays
/// `Signed` and nothing reaches the RPC (the key worker itself is unlocked).
fn sign_without_precheck(harness: &mut Harness) -> TestResult<Txid> {
    harness.unlocked = false;
    let signed = harness.approve();
    harness.unlocked = true;
    signed?;
    let record = harness.records().last().cloned().ok_or("record")?;
    assert_eq!(record.state, BtcTxState::Signed);
    assert!(!record.disclosed);
    Ok(record.txid)
}

/// Security review (hostile RPC double payment): the RPC receives the signed bytes through
/// `testmempoolaccept` and answers "rejected". The record was marked disclosed in the journal
/// before the call, so the next send (another amount and fee rate) must spend one of its
/// inputs: at most one of the two can confirm.
#[test]
fn hostile_rpc_rejection_after_receiving_constrains_next_send() -> TestResult {
    let mut harness = Harness::new("hostile-reject")?;
    let small = add_second_funding(&harness, 60_000)?;
    let big = funding_outpoint()?;
    harness.enable();
    assert_eq!(harness.btc_meta().ok_or("meta")?.verified().len(), 2);
    if let Ok(mut world) = harness.world.lock() {
        world.reject = Some("min relay fee not met");
    }
    // 70,000 sats need the 100,000 output.
    send_form(&mut harness, "70000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    assert_eq!(queued_inputs(&harness)?, vec![big]);
    harness.approve()?;
    let rejected = harness.records()[0].clone();
    assert_eq!(rejected.state, BtcTxState::Rejected);
    assert!(rejected.disclosed, "marked before testmempoolaccept");
    assert!(
        harness
            .fake
            .methods()
            .contains(&"testmempoolaccept".to_owned())
    );
    // The next send: another amount and fee rate. Unconstrained, the smallest sufficient input
    // (60,000) would be chosen; the disclosed record forces its input.
    if let Ok(mut world) = harness.world.lock() {
        world.reject = None;
    }
    send_form(&mut harness, "20000", "3");
    harness.run(|ui, ctx| ui.review(ctx, [8; 32]));
    let inputs = queued_inputs(&harness)?;
    assert!(inputs.contains(&big), "{inputs:?}");
    assert!(!inputs.contains(&small), "{inputs:?}");
    let item = harness.queued.first().ok_or("plan")?;
    assert_ne!(item.plan.txid(), rejected.txid);
    harness.approve()?;
    let records = harness.records();
    let new = records
        .iter()
        .find(|record| record.state == BtcTxState::Submitted)
        .ok_or("new send")?;
    assert!(new.disclosed);
    Ok(())
}

/// Security review: the pre-check fails in transport after the RPC received the bytes; the
/// record stays `Signed` but is disclosed. [취소] says so, and the next send must spend one of
/// its inputs. The journal step comes first: [전송 계속] queues only the `Disclose` journal
/// job, no RPC call.
#[test]
fn cancel_after_precheck_failure_constrains_next_send() -> TestResult {
    use yw_app::workers::journal::btc::BtcJournalOp;
    let mut harness = Harness::new("cancel-disclosed")?;
    let small = add_second_funding(&harness, 60_000)?;
    let big = funding_outpoint()?;
    harness.enable();
    send_form(&mut harness, "70000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    let txid = sign_without_precheck(&mut harness)?;
    let before = harness.fake.count();
    // [전송 계속]: the journal write is queued alone; nothing went to the RPC yet.
    harness.call(|ui, ctx| ui.continue_signed(ctx, txid));
    assert_eq!(harness.fake.count(), before);
    assert_eq!(harness.work.len(), 1);
    let disclose_first = matches!(
        harness.work.front(),
        Some(BtcAction::Key(job)) if matches!(
            job.as_ref(),
            KeyJob::BtcJournal { op: BtcJournalOp::Disclose { txid: queued, .. }, .. }
                if *queued == txid
        )
    );
    assert!(disclose_first);
    if let Ok(mut world) = harness.world.lock() {
        world.precheck_transport = true;
    }
    harness.drain();
    assert!(
        harness
            .fake
            .methods()
            .contains(&"testmempoolaccept".to_owned())
    );
    let record = harness.records()[0].clone();
    assert_eq!(record.state, BtcTxState::Signed);
    assert!(record.disclosed);
    assert!(harness.ui.flow(&txid).ok_or("flow")?.retry_precheck);
    // [취소]: the text says the RPC may have it and the next send reuses an input.
    harness.run(|ui, ctx| ui.cancel_signed(ctx, txid));
    let (_, text, _) = harness.ui.confirm.ok_or("confirm")?.texts();
    assert_eq!(text, yw_core::btc::policy::texts::CANCEL_DISCLOSED_CONFIRM);
    harness.run(BtcUi::confirm_yes);
    let cancelled = harness.records()[0].clone();
    assert_eq!(cancelled.state, BtcTxState::Abandoned);
    assert_eq!(cancelled.not_found_count, 0);
    assert!(cancelled.disclosed);
    if let Ok(mut world) = harness.world.lock() {
        world.precheck_transport = false;
    }
    send_form(&mut harness, "20000", "3");
    harness.run(|ui, ctx| ui.review(ctx, [8; 32]));
    let inputs = queued_inputs(&harness)?;
    assert!(inputs.contains(&big), "{inputs:?}");
    assert!(!inputs.contains(&small), "{inputs:?}");
    Ok(())
}

/// Security review: [취소] of a `Signed` record whose bytes never left the app keeps the
/// existing behaviour: the old text and no constraint on the next send.
#[test]
fn undisclosed_signed_cancel_has_no_constraint() -> TestResult {
    let mut harness = Harness::new("cancel-undisclosed")?;
    let small = add_second_funding(&harness, 60_000)?;
    harness.enable();
    send_form(&mut harness, "70000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    let txid = sign_without_precheck(&mut harness)?;
    assert!(
        !harness
            .fake
            .methods()
            .contains(&"testmempoolaccept".to_owned())
    );
    harness.run(|ui, ctx| ui.cancel_signed(ctx, txid));
    let (_, text, _) = harness.ui.confirm.ok_or("confirm")?.texts();
    assert_eq!(
        text,
        "서명했지만 보내지 않은 거래를 취소합니다. 이 거래는 전송하지 않습니다."
    );
    harness.run(BtcUi::confirm_yes);
    let cancelled = harness.records()[0].clone();
    assert_eq!(cancelled.state, BtcTxState::Abandoned);
    assert!(!cancelled.disclosed);
    send_form(&mut harness, "20000", "3");
    harness.run(|ui, ctx| ui.review(ctx, [8; 32]));
    assert_eq!(queued_inputs(&harness)?, vec![small]);
    Ok(())
}

// ----- account identities (spec/08 §3.5, §12.1 "같은 주소의 다른 계정") ----------------------------

/// A confirmed funding of `script` (`value` sats, distinguished by `salt`) on the fake chain.
fn fund_script(harness: &Harness, script: Vec<u8>, value: u64, salt: u8) -> TestResult<OutPoint> {
    let (tx, raw) = funding_to(script, value, salt)?;
    let outpoint = OutPoint {
        txid: txid(&tx),
        vout: 0,
    };
    if let Ok(mut world) = harness.world.lock() {
        world.txs.push((tx, raw, Some(FUNDING_HEIGHT)));
    }
    Ok(outpoint)
}

/// Removes imported key `id` the way an older build without the removal block could: the
/// worker is locked, another vault instance on the same folder removes the record, and the
/// wallet is unlocked again (meta load drops the account).
fn remove_bypassing_block(harness: &mut Harness, id: [u8; 16]) -> TestResult {
    use yw_app::store::{FileStorage, LockedSlotBox};
    harness.unlocked = false;
    harness.run(|ui, _| ui.lock());
    let _ = harness.key.handle(KeyJob::Lock);
    harness.meta = None;
    harness.journal = None;
    {
        let mut vault = yw_core::vault::Vault::load(Box::new(
            FileStorage::open(&harness.dir).map_err(|error| format!("{error:?}"))?,
        ))?;
        let password = yw_core::password::VaultPassword::new(PASSWORD)
            .map_err(|error| format!("{error:?}"))?;
        let slot = Box::new(LockedSlotBox::new().map_err(|error| format!("{error:?}"))?);
        vault.unlock(&password, slot)?;
        vault.remove_imported_key(&password, yw_core::vault::RecordId::from_bytes(id))?;
        vault.lock();
    }
    let _ = harness.key.handle(KeyJob::Load);
    let unlocked = harness.key.handle(KeyJob::Unlock {
        password: Zeroizing::new(PASSWORD.to_vec()),
    });
    if !matches!(
        unlocked.first(),
        Some(KeyOutcome::Status(Ok(
            yw_core::vault::VaultStatus::Unlocked { .. }
        )))
    ) {
        return Err("unlock after the removal".into());
    }
    harness.unlocked = true;
    harness.key_job(KeyJob::LoadMeta);
    harness.key_job(KeyJob::LoadJournal);
    harness.drain();
    Ok(())
}

/// Security review (double payment across account identities): an imported key's send is
/// cancelled after the RPC received its bytes (`Abandoned`, disclosed). While it may still
/// confirm the key cannot be removed (UI and key worker). Removed anyway (an older build) and
/// imported again, the key gets a new vault record id, i.e. a new account identity: the next send
/// must still spend an input of the abandoned transaction (matched by script, not account id),
/// so at most one of the two can confirm.
#[test]
fn reimported_key_must_conflict_with_its_abandoned_send() -> TestResult {
    use yw_app::workers::journal::btc::BtcJournalOp;
    let info = imported_info(BIP49_TEST_WIF, ScriptType::P2wpkh)?;
    let ours = script_pubkey(&info.kind);
    let mut harness = Harness::new("reimport-abandoned")?;
    let big = fund_script(&harness, ours.clone(), FUNDING_VALUE, 0xa0)?;
    let small = fund_script(&harness, ours, 60_000, 0xa1)?;
    harness.enable();
    let first = harness.import_key(BIP49_TEST_WIF, ScriptType::P2wpkh)?;
    let BtcAccountId::Imported { id } = first.id() else {
        return Err("not imported".into());
    };
    assert_eq!(
        harness.ctx().btc_meta().ok_or("account")?.verified().len(),
        2
    );
    // 70,000 sats need the 100,000 output; signed while the controller sees the wallet locked.
    send_form(&mut harness, "70000", "2");
    harness.run(|ui, ctx| ui.review(ctx, [7; 32]));
    assert_eq!(queued_inputs(&harness)?, vec![big]);
    let txid = sign_without_precheck(&mut harness)?;
    // [전송 계속]: the pre-check fails in transport after the RPC received the bytes; [취소].
    harness.call(|ui, ctx| ui.continue_signed(ctx, txid));
    assert!(matches!(
        harness.work.front(),
        Some(BtcAction::Key(job)) if matches!(
            job.as_ref(),
            KeyJob::BtcJournal { op: BtcJournalOp::Disclose { .. }, .. }
        )
    ));
    if let Ok(mut world) = harness.world.lock() {
        world.precheck_transport = true;
    }
    harness.drain();
    harness.run(|ui, ctx| ui.cancel_signed(ctx, txid));
    harness.run(BtcUi::confirm_yes);
    let abandoned = harness.records()[0].clone();
    assert_eq!(abandoned.state, BtcTxState::Abandoned);
    assert!(abandoned.disclosed);
    assert_eq!(abandoned.account, first.id());
    if let Ok(mut world) = harness.world.lock() {
        world.precheck_transport = false;
    }
    // It may still confirm: the key stays (UI before the password, and the key worker).
    assert_eq!(
        harness.ctx().remove_block(id, harness.ui.slot),
        Some(yw_app::app_btc::REMOVE_BUSY_IN_FLIGHT)
    );
    let record_id = yw_core::vault::RecordId::from_bytes(id);
    let outcomes = harness.key.handle(KeyJob::RemoveImportedKey {
        password: Zeroizing::new(PASSWORD.to_vec()),
        id: record_id,
    });
    assert!(matches!(
        outcomes.as_slice(),
        [KeyOutcome::ImportedKeyBusy(busy)] if *busy == record_id
    ));
    // Removed anyway, then imported again: a new identity of the same address.
    remove_bypassing_block(&mut harness, id)?;
    assert!(
        harness
            .meta
            .as_ref()
            .ok_or("meta")?
            .btc_accounts
            .get(BtcNetwork::Testnet4, first.id())
            .is_none()
    );
    let second = harness.import_key(BIP49_TEST_WIF, ScriptType::P2wpkh)?;
    assert_ne!(second.id(), first.id());
    assert_eq!(harness.ctx().active_id(), second.id());
    assert_eq!(
        harness.ctx().btc_meta().ok_or("account")?.verified().len(),
        2
    );
    // By account id the new identity has no records; the abandoned send still binds it.
    assert!(harness.ctx().records().is_empty());
    assert_eq!(harness.ctx().related_records(), vec![abandoned.clone()]);
    assert_eq!(
        harness.ctx().remove_block(
            match second.id() {
                BtcAccountId::Imported { id } => id,
                BtcAccountId::Hd { .. }
                | BtcAccountId::EvmShared { .. }
                | BtcAccountId::Hardware { .. } => {
                    return Err("not imported".into());
                }
            },
            harness.ui.slot
        ),
        Some(yw_app::app_btc::REMOVE_BUSY_IN_FLIGHT)
    );
    // Unconstrained, the smallest sufficient input (60,000) would be chosen.
    send_form(&mut harness, "20000", "3");
    harness.run(|ui, ctx| ui.review(ctx, [8; 32]));
    let inputs = queued_inputs(&harness)?;
    assert!(inputs.contains(&big), "{inputs:?}");
    assert!(!inputs.contains(&small), "{inputs:?}");
    harness.approve()?;
    let records = harness.records();
    let new = records
        .iter()
        .find(|record| record.account == second.id())
        .ok_or("new send")?;
    assert_eq!(new.state, BtcTxState::Submitted);
    assert!(new.inputs.iter().any(|input| input.outpoint == big));
    Ok(())
}

/// spec/08 §3.5: a WIF whose address (on its network, as the chosen type) is already an address
/// of an account — here receive 0 of the HD P2SH-P2WPKH account 0 (`m/49'/1'/0'/0/0`) — is
/// refused (E-VLT-011): one address never gets two account identities. The same key as another
/// address type is a different address and is imported.
#[test]
fn wif_of_an_hd_address_is_refused() -> TestResult {
    use yw_app::events::ImportedAccount;
    let mut harness = Harness::new("wif-alias")?;
    harness.enable();
    harness.run(|ui, ctx| ui.add_account(ctx, ScriptType::P2shP2wpkh));
    let nested = BtcAccountId::Hd {
        script_type: ScriptType::P2shP2wpkh,
        account: 0,
    };
    let account = harness
        .meta
        .as_ref()
        .ok_or("meta")?
        .btc_accounts
        .get(BtcNetwork::Testnet4, nested)
        .ok_or("nested account")?
        .clone();
    let info = imported_info(BIP49_TEST_WIF, ScriptType::P2shP2wpkh)?;
    assert_eq!(
        account
            .address(BtcChain::Receive, 0)
            .map_err(|error| format!("{error:?}"))?
            .as_str(),
        info.address
    );
    let outcomes = harness.key.handle(KeyJob::ImportKey {
        spec: ImportSpec::Btc(ScriptType::P2shP2wpkh),
        key: Zeroizing::new(BIP49_TEST_WIF.as_bytes().to_vec()),
    });
    assert!(matches!(
        outcomes.as_slice(),
        [KeyOutcome::KeyImported(Err(
            yw_core::error::VaultError::DuplicateKey
        ))]
    ));
    // Nothing stored: the vault has no record, meta no new account.
    let accounts_before = harness
        .meta
        .as_ref()
        .ok_or("meta")?
        .btc_accounts
        .accounts
        .len();
    harness.key_job(KeyJob::LoadMeta);
    harness.drain();
    let meta = harness.meta.as_ref().ok_or("meta")?;
    assert_eq!(meta.btc_accounts.accounts.len(), accounts_before);
    assert!(
        meta.btc_accounts
            .accounts
            .iter()
            .all(|account| !account.is_single())
    );
    // As native segwit the key has another address: imported.
    let outcomes = harness.key.handle(KeyJob::ImportKey {
        spec: ImportSpec::Btc(ScriptType::P2wpkh),
        key: Zeroizing::new(BIP49_TEST_WIF.as_bytes().to_vec()),
    });
    assert!(matches!(
        outcomes.as_slice(),
        [KeyOutcome::KeyImported(Ok(ImportedAccount::Btc(..)))]
    ));
    Ok(())
}

// ----- fixed-address mode and EVM-shared keys (spec/08 §3.5) -------------------------------------

/// The settled send of the queued item: approve, then tracking to one confirmation.
fn send_and_confirm(harness: &mut Harness, amount: &str, seed: u8) -> TestResult<Txid> {
    send_form(harness, amount, "2");
    harness.run(|ui, ctx| ui.review(ctx, [seed; 32]));
    if harness.queued.len() != 1 {
        return Err(format!("not queued: {:?}", harness.ui.send.info).into());
    }
    harness.approve()?;
    let sent = harness
        .records()
        .into_iter()
        .find(|record| record.state == BtcTxState::Submitted)
        .ok_or("submitted record")?
        .txid;
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    if let Ok(mut world) = harness.world.lock() {
        world.confirm(&sent, CONFIRM_HEIGHT);
    }
    harness.clock.advance(60_000);
    harness.run(BtcUi::tick);
    Ok(sent)
}

/// spec/08 §3.5: BIP84 account 0 of a wallet is in fixed-address mode (old metas and new
/// wallets alike). Discovery still scans with the gap limit, so a deposit made earlier to `/0/1`
/// is found and spent; the receive screen always shows `m/84'/1'/0'/0/0` with the explanation
/// and no `새 주소`; the change of a send returns to `/0/0` (`change_next` stays 0, the own change
/// lands on `/0/0`). The mode switch HD ↔ fixed is persisted and refused while a BTC approval is
/// open.
#[test]
fn fixed_address_mode_end_to_end() -> TestResult {
    let mut harness = Harness::new("fixed")?;
    // A deposit to receive 1 made before (another wallet in HD mode, or this one before the
    // switch): discovery must still see it.
    let second = account().address(BtcNetwork::Testnet4, BtcChain::Receive, 1)?;
    let (deposit, raw) = funding_to(second.script_pubkey(), 60_000, 0x71)?;
    let deposit_outpoint = OutPoint {
        txid: txid(&deposit),
        vout: 0,
    };
    if let Ok(mut world) = harness.world.lock() {
        world.txs.push((deposit, raw, Some(FUNDING_HEIGHT)));
    }
    harness.enable();
    let meta = harness.btc_meta().ok_or("meta")?.clone();
    assert!(meta.fixed_address());
    assert_eq!(meta.receive_next(), 2, "discovery found /0/0 and /0/1");
    assert_eq!(meta.verified().len(), 2);
    assert_eq!(
        harness
            .ui
            .balance(&harness.ctx())
            .ok_or("balance")?
            .available
            .get(),
        FUNDING_VALUE + 60_000
    );
    // The receive screen: always /0/0, no new address.
    harness.run(BtcUi::open_receive);
    let view = harness.ui.receive.clone().ok_or("receive view")?;
    assert_eq!((view.index, view.path.as_str()), (0, "m/84'/1'/0'/0/0"));
    assert!(view.fixed && !view.single_key);
    assert_eq!(view.address, meta.address(BtcChain::Receive, 0)?.as_str());
    harness.run(BtcUi::new_receive_address);
    assert_eq!(
        harness.ui.receive_message.as_deref(),
        Some("이 계정은 주소 하나만 써서 새 주소를 만들 수 없습니다")
    );
    assert_eq!(harness.btc_meta().ok_or("meta")?.receive_next(), 2);
    // A send that needs both inputs: change back to /0/0.
    let sent = send_and_confirm(&mut harness, "130000", 0x72)?;
    let record = harness
        .records()
        .into_iter()
        .find(|record| record.txid == sent)
        .ok_or("record")?;
    assert_eq!(record.state, BtcTxState::Confirmed);
    assert!(
        record
            .inputs
            .iter()
            .any(|input| input.outpoint == deposit_outpoint
                && (input.chain, input.index) == (BtcChain::Receive, 1))
    );
    let change = record.change.ok_or("change")?;
    assert_eq!(change.index, 0);
    let tx = parse_transaction(&record.raw)?;
    assert_eq!(
        tx.outputs
            .get(usize::try_from(change.vout)?)
            .ok_or("change output")?
            .script_pubkey,
        meta.expected_script(BtcChain::Receive, 0)?
    );
    let meta = harness.btc_meta().ok_or("meta")?.clone();
    assert_eq!(meta.change_next(), 0, "no change-chain index used");
    let own = meta
        .verified()
        .iter()
        .find(|utxo| utxo.own)
        .ok_or("own change")?;
    assert_eq!((own.chain, own.index), (BtcChain::Receive, 0));
    // Switch to HD: persisted (a fresh LoadMeta reads it back), the next unused address.
    harness.run(|ui, ctx| ui.set_address_mode(ctx, false));
    harness.key_job(KeyJob::LoadMeta);
    harness.drain();
    assert!(!harness.btc_meta().ok_or("meta")?.fixed_address());
    harness.run(BtcUi::open_receive);
    let view = harness.ui.receive.clone().ok_or("hd view")?;
    assert_eq!((view.index, view.fixed), (2, false));
    harness.run(BtcUi::new_receive_address);
    assert_eq!(harness.ui.receive.as_ref().map(|view| view.index), Some(3));
    // Refused while a BTC approval is open.
    harness.ui.slot = true;
    harness.run(|ui, ctx| ui.set_address_mode(ctx, true));
    assert_eq!(
        harness.ui.account_message.as_deref(),
        Some(yw_app::app_btc::ADDRESS_MODE_BUSY)
    );
    assert!(!harness.btc_meta().ok_or("meta")?.fixed_address());
    harness.ui.slot = false;
    // Back to fixed: /0/0 again, indices kept.
    harness.run(|ui, ctx| ui.set_address_mode(ctx, true));
    let meta = harness.btc_meta().ok_or("meta")?;
    assert!(meta.fixed_address());
    assert_eq!(meta.receive_next(), 4);
    harness.run(BtcUi::open_receive);
    assert_eq!(harness.ui.receive.as_ref().map(|view| view.index), Some(0));
    assert!(harness.banners.is_empty(), "{:?}", harness.banners);
    Ok(())
}

/// Testnet WIF of the EVM key `m/44'/60'/0'/0/0` of `abandon … about` (public test key).
const EVM0_TEST_WIF: &str = "cNUcMV1Uwy9xWKgNzrjKaJ5A7bPTk4Gs8KPujpMqzwkfUuBoD4Kv";

/// spec/08 §3.5 "EVM 계정과 같은 키" at the app level: the chooser starts at the standard path;
/// the EVM key needs the explicit source, an EVM account and the confirmation; the key worker
/// derives the EVM public key, stores and selects the account (no discovery); its one address is
/// the vector address of every type; a send through the real workers returns the change to the
/// same address and confirms with the own change; the same EVM index and type twice, and the
/// same address as an imported key (either order), are refused.
#[test]
#[expect(clippy::too_many_lines, reason = "one scenario per address type")]
fn evm_shared_account_end_to_end() -> TestResult {
    let vectors = [
        (
            ScriptType::P2wpkh,
            "tb1qgsvdpdxec8hsu57lhxg5xem7refr233zqds492",
        ),
        (
            ScriptType::P2tr,
            "tb1p08q6wdgnqe0gwpp4ygs0y8lwgxlpv2l4uc0zq5qjnagwtg92fussh9p5y9",
        ),
        (
            ScriptType::P2shP2wpkh,
            "2MvXGPvpYDuY3DamixGw9SFyM6t5iFE1NbY",
        ),
        (ScriptType::P2pkh, "mmj1yHwjveGUmtpfxSrcVhbRq8c4RtLA7N"),
    ];
    for (round, (script_type, expected)) in vectors.into_iter().enumerate() {
        let salt = u8::try_from(round).unwrap_or(0).saturating_add(0x80);
        let mut harness = Harness::new(&format!("evm-{}", script_type.json_name()))?;
        harness.enable();
        let id = BtcAccountId::EvmShared {
            evm_index: 0,
            script_type,
        };
        // Default (a): the standard path; a type button adds an HD account directly.
        harness.run(|ui, ctx| {
            ui.open_add_account(ctx);
            Vec::new()
        });
        assert_eq!(
            harness.ui.add_source,
            yw_app::app_btc::BtcAddSource::Standard
        );
        // (b) needs the explicit choice and the confirmation.
        harness.run(|ui, ctx| {
            ui.set_add_source(yw_app::app_btc::BtcAddSource::EvmShared);
            ui.set_add_evm_index(ctx, 0);
            Vec::new()
        });
        harness.run(|ui, ctx| ui.add_account(ctx, script_type));
        assert_eq!(harness.confirms, 1);
        assert!(
            harness.ctx().accounts().iter().all(|meta| meta.id() != id),
            "nothing before the confirmation"
        );
        let (_, text, _) = harness.ui.confirm.ok_or("confirm")?.texts();
        assert!(text.contains("m/44'/60'/0'/0/0") && text.contains("공개키가 같아져"));
        harness.run(BtcUi::confirm_yes);
        let account = harness.ctx().btc_meta().ok_or("active")?.clone();
        assert_eq!(account.id(), id);
        assert!(account.discovery_done() && account.fixed_address() && !account.is_imported());
        assert_eq!(account.address(BtcChain::Receive, 0)?.as_str(), expected);
        let rows = harness.ui.account_rows(&harness.ctx());
        let row = rows.iter().find(|row| row.id == id).ok_or("row")?;
        assert!(row.selected && row.evm_shared == Some(0) && !row.imported && row.fixed);
        // The receive screen: the one address, the EVM path and the warning.
        harness.run(BtcUi::open_receive);
        let view = harness.ui.receive.clone().ok_or("receive")?;
        assert_eq!(view.address, expected);
        assert_eq!(view.path, "m/44'/60'/0'/0/0");
        assert!(view.fixed && view.single_key);
        assert!(
            view.note
                .contains("복구 단어만 넣으면 이 주소가 보이지 않습니다")
        );
        // Fund, refresh, send: change back to the same address.
        let script = account.expected_script(BtcChain::Receive, 0)?;
        let (funding, raw) = funding_to(script.clone(), FUNDING_VALUE, salt)?;
        if let Ok(mut world) = harness.world.lock() {
            world.txs.push((funding, raw, Some(FUNDING_HEIGHT)));
        }
        harness.run(|ui, ctx| ui.refresh(ctx, Trigger::User));
        assert_eq!(
            harness.ctx().btc_meta().ok_or("active")?.verified().len(),
            1
        );
        let sent = send_and_confirm(&mut harness, "30000", salt)?;
        let record = harness
            .records()
            .into_iter()
            .find(|record| record.txid == sent)
            .ok_or("record")?;
        assert_eq!((record.account, record.state), (id, BtcTxState::Confirmed));
        let change = record.change.ok_or("change")?;
        let tx = parse_transaction(&record.raw)?;
        assert_eq!(
            tx.outputs
                .get(usize::try_from(change.vout)?)
                .ok_or("change output")?
                .script_pubkey,
            script
        );
        let account = harness.ctx().btc_meta().ok_or("active")?.clone();
        assert_eq!((account.receive_next(), account.change_next()), (1, 0));
        assert!(
            account
                .verified()
                .iter()
                .any(|utxo| utxo.own && (utxo.chain, utxo.index) == (BtcChain::Receive, 0))
        );
        let activity = harness
            .meta
            .as_ref()
            .ok_or("meta")?
            .activity_of("bitcoin:testnet4");
        assert!(activity.iter().any(|row| row.tx_id == sent.to_display_hex()
            && row.account == format!("evm/{}/0", script_type.json_name())));
        // The same EVM index and type again: refused, nothing added.
        let before = harness.meta.as_ref().ok_or("meta")?.btc_accounts.clone();
        harness.run(|ui, ctx| {
            ui.open_add_account(ctx);
            ui.set_add_source(yw_app::app_btc::BtcAddSource::EvmShared);
            Vec::new()
        });
        harness.run(|ui, ctx| ui.add_account(ctx, script_type));
        harness.run(BtcUi::confirm_yes);
        assert_eq!(harness.meta.as_ref().ok_or("meta")?.btc_accounts, before);
        assert!(harness.ui.account_message.is_some());
        // The same key imported as a WIF with the same type: the address is taken (E-VLT-011).
        let outcomes = harness.key.handle(KeyJob::ImportKey {
            spec: ImportSpec::Btc(script_type),
            key: Zeroizing::new(EVM0_TEST_WIF.as_bytes().to_vec()),
        });
        assert!(
            matches!(
                outcomes.first(),
                Some(KeyOutcome::KeyImported(Err(
                    yw_core::error::VaultError::DuplicateKey
                )))
            ),
            "{script_type:?}"
        );
        assert!(harness.banners.is_empty(), "{:?}", harness.banners);
    }
    // The other order: the key imported first, then the EVM-shared account of that address.
    let mut harness = Harness::new("evm-after-import")?;
    harness.enable();
    harness.import_key(EVM0_TEST_WIF, ScriptType::P2wpkh)?;
    let before = harness.meta.as_ref().ok_or("meta")?.btc_accounts.clone();
    harness.run(|ui, ctx| {
        ui.open_add_account(ctx);
        ui.set_add_source(yw_app::app_btc::BtcAddSource::EvmShared);
        Vec::new()
    });
    harness.run(|ui, ctx| ui.add_account(ctx, ScriptType::P2wpkh));
    harness.run(BtcUi::confirm_yes);
    assert_eq!(harness.meta.as_ref().ok_or("meta")?.btc_accounts, before);
    assert!(harness.ui.account_message.is_some());
    // Another type of the same key is another address: allowed.
    harness.run(|ui, ctx| {
        ui.open_add_account(ctx);
        ui.set_add_source(yw_app::app_btc::BtcAddSource::EvmShared);
        Vec::new()
    });
    harness.run(|ui, ctx| ui.add_account(ctx, ScriptType::P2tr));
    harness.run(BtcUi::confirm_yes);
    assert_eq!(
        harness.ctx().active_id(),
        BtcAccountId::EvmShared {
            evm_index: 0,
            script_type: ScriptType::P2tr
        }
    );
    Ok(())
}
