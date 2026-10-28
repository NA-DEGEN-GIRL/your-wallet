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
use yw_app::events::{EventQueue, JournalView, KeyJob, KeyOutcome, RpcEvent, UiEvent};
use yw_app::flow::evm::{Clock, Limits};
use yw_app::meta::Meta;
use yw_app::network::{BtcNet, NetworkId};
use yw_app::settings::{BitcoinSettings, BtcIndexer};
use yw_app::ui::approval_view::Block;
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
use yw_core::btc::{BtcNetwork, OutPoint, Sats, Txid, parse_address};
use yw_core::journal::btc::BtcTxState;
use yw_core::secret::Zeroizing;
use yw_win::http::HttpsUrl;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP173 testnet P2WPKH example (not ours).
const RECIPIENT: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const FUNDING_VALUE: u64 = 100_000;
const FUNDING_HEIGHT: u32 = TIP - 10;
/// Six confirmations at `TIP`.
const CONFIRM_HEIGHT: u32 = TIP - 5;
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
    queued: Vec<BtcApprovalItem>,
    confirms: usize,
    screens: Vec<BtcScreen>,
    banners: Vec<String>,
    work: VecDeque<BtcAction>,
}

impl Harness {
    fn new(tag: &str) -> TestResult<Self> {
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
        let mut harness = Self {
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
            queued: Vec::new(),
            confirms: 0,
            screens: Vec::new(),
            banners: Vec::new(),
            work: VecDeque::new(),
        };
        harness.import();
        Ok(harness)
    }

    /// Imports `abandon … about` and loads meta and the journal like the unlock path.
    fn import(&mut self) {
        let _ = self.key.handle(KeyJob::Load);
        let preview = self.key.handle(KeyJob::PreviewImport {
            password: Some(Zeroizing::new(b"m8-btc-flow-test!".to_vec())),
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
            KeyOutcome::Meta(Ok(loaded)) => self.meta = Some(loaded.meta),
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
    harness.enable();
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

    // Tracking: in the mempool, then confirmed with 6 confirmations.
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
    // Finished (6 confirmations) → meta activity `bitcoin:testnet4`.
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
    assert_eq!(view.status, "확정(6+) (서버 기준)");
    assert!(!view.can_bump);
    // New sends are allowed again.
    assert_eq!(harness.ui.send_block(&harness.ctx()), None);
    assert!(harness.banners.is_empty(), "{:?}", harness.banners);
    Ok(())
}

#[test]
fn precheck_rejection_keeps_change_index() -> TestResult {
    let mut harness = Harness::new("reject")?;
    harness.enable();
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
    harness.enable();
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
    harness.enable();
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
/// version 2 journal record of that account, tracking to 6 confirmations with the own change
/// inserted into that account (not BIP84 account 0), the activity row's account tag, and the
/// switch back.
#[test]
#[expect(clippy::too_many_lines, reason = "one account of each type end to end")]
fn every_address_type_end_to_end() -> TestResult {
    use yw_core::btc::{BtcAccountId, ScriptType};
    for (round, script_type) in ScriptType::CHOICES.into_iter().enumerate() {
        let salt = u8::try_from(round).unwrap_or(0).saturating_add(0x60);
        let number = u32::from(script_type == ScriptType::P2wpkh);
        let mut harness = Harness::new(&format!("types-{}", script_type.json_name()))?;
        harness.enable();
        let primary_before = harness.btc_meta().ok_or("primary")?.clone();
        harness.run(|ui, ctx| {
            ui.open_add_account(ctx);
            Vec::new()
        });
        assert!(harness.ui.add_account_open);
        harness.run(|ui, ctx| ui.add_account(ctx, script_type));
        assert!(!harness.ui.add_account_open);
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
        // The change index moved in this account, not in BIP84 account 0.
        let account = harness.ctx().btc_meta().ok_or("active")?.clone();
        assert_eq!(account.change_next(), 1);
        assert_eq!(harness.btc_meta().ok_or("primary")?.change_next(), 0);
        // Tracking to 6 confirmations: own change into this account.
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
        assert!(
            account
                .verified()
                .iter()
                .any(|utxo| utxo.outpoint == change && utxo.own)
        );
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
