//! Live `HyperCore` checks against the public **testnet** API only (spec/11 §9.3). Never mainnet.
//!
//! `cargo test -p yw-app --test hypercore_live -- --ignored --test-threads=1 --nocapture`
//!
//! 1. Read-only: `spotMeta` and the two balance queries of a fresh address parse with the core
//!    parsers (the live shape matches the docs).
//! 2. Signer recovery: a throwaway random key (never a user key) is put in an in-memory key-only
//!    vault, one action of every kind is built, issued and consumed through the approval store
//!    and signed by the vault exactly like the app does, then posted to the testnet `/exchange`.
//!    The account has no funds and does not exist there, so Hyperliquid answers `status: err`
//!    naming the address it recovered from the signature: it must be ours, which proves the
//!    EIP-712 encoding byte for byte without moving anything. Five requests in total.
#![expect(
    clippy::print_stdout,
    reason = "the probe report is console output (no secrets)"
)]

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use yw_core::approval::{ApprovalId, ApprovalStore};
use yw_core::error::StorageError;
use yw_core::evm::address::Address;
use yw_core::hypercore::display::{HcApprovalInput, HcRecipient, build_hypercore_request};
use yw_core::hypercore::{
    HcAction, HcExchangeReply, HcNetwork, HcPayload, TESTNET_API, info_perp_state_body,
    info_spot_meta_body, info_spot_state_body, parse_exchange_reply, parse_perp_state,
    parse_spot_meta, parse_spot_state,
};
use yw_core::keyimport::{ImportKey, ImportSpec};
use yw_core::password::VaultPassword;
use yw_core::vault::{EvmKeySource, FileKind, LockedSlot, SLOT_LEN, Vault, VaultStorage};
use yw_json::{Limits, Value};
use yw_win::http::{Client, HttpsUrl};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAX_RESPONSE: usize = 8 * 1_024 * 1_024;
const META_LIMITS: Limits = Limits {
    max_bytes: 8 * 1_024 * 1_024,
    max_depth: 32,
    max_nodes: 2_000_000,
    max_items: 2_000_000,
};

type Files = Vec<(FileKind, Vec<u8>)>;

#[derive(Clone, Default)]
struct MemStorage(Arc<Mutex<Files>>);

impl VaultStorage for MemStorage {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| StorageError::Io(0))?
            .iter()
            .find(|(file, _)| *file == kind)
            .map(|(_, bytes)| bytes.clone()))
    }

    fn load_prev(&self, _kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    fn commit(
        &mut self,
        kind: FileKind,
        _expected: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let mut files = self.0.lock().map_err(|_| StorageError::Io(0))?;
        files.retain(|(file, _)| *file != kind);
        files.push((kind, bytes.to_vec()));
        Ok(())
    }

    fn quarantine(&mut self, _kind: FileKind, _now_unix: u64) -> Result<(), StorageError> {
        Ok(())
    }
}

struct HeapSlot(Box<[u8; SLOT_LEN]>);

impl LockedSlot for HeapSlot {
    fn bytes(&self) -> &[u8; SLOT_LEN] {
        &self.0
    }

    fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
        &mut self.0
    }
}

fn now_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn post(client: &Client, path: &str, body: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let url = HttpsUrl::parse(&format!("{TESTNET_API}{path}"))?;
    let response = client.post_json(&url, None, body, MAX_RESPONSE)?;
    if response.status != 200 {
        return Err(format!("HTTP {}", response.status).into());
    }
    Ok(yw_json::parse(&response.body, &META_LIMITS)?)
}

#[test]
#[ignore = "live network: Hyperliquid testnet API (spec/11 §9.3)"]
#[expect(clippy::too_many_lines, reason = "one live scenario")]
fn testnet_info_shapes_and_signer_recovery() -> TestResult {
    let client = Client::new(yw_app::rpc::RPC_TIMEOUTS)?;

    // A throwaway key from the OS CSPRNG, only in memory.
    let mut secret = [0_u8; 32];
    yw_core::entropy::fill_random(&mut secret)?;
    let hex = yw_core::hex::encode(&secret);
    secret.fill(0);
    let key = ImportKey::parse(ImportSpec::Evm, &hex)?;
    drop(hex);
    let mut vault = Vault::load(Box::new(MemStorage::default()))?;
    let record = vault.create_with_key(
        &VaultPassword::new(b"throwaway password 1")?,
        key,
        Box::new(HeapSlot(Box::new([0; SLOT_LEN]))),
        now_ms()? / 1_000,
    )?;
    let source = EvmKeySource::Raw(record);
    let account = vault.evm_address(source)?;
    println!("account {}", account.to_checksum());

    // 1. Read-only shapes.
    let tokens = parse_spot_meta(&post(&client, "/info", &info_spot_meta_body())?)?;
    let purr = tokens
        .iter()
        .find(|token| token.name == "PURR" && token.index == 1)
        .ok_or("PURR missing from spotMeta")?;
    let hype = tokens
        .iter()
        .find(|token| token.is_hype())
        .ok_or("HYPE missing from spotMeta")?;
    println!(
        "spotMeta tokens={} PURR wei={} HYPE index={} system={}",
        tokens.len(),
        purr.wei_decimals,
        hype.index,
        hype.system_address().to_lower_hex()
    );
    let spot = parse_spot_state(&post(&client, "/info", &info_spot_state_body(&account))?)?;
    let perp = parse_perp_state(&post(&client, "/info", &info_perp_state_body(&account))?)?;
    println!(
        "fresh account: spot balances={} accountValue={} withdrawable={}",
        spot.len(),
        perp.account_value,
        perp.withdrawable
    );

    // 2. Signer recovery for every kind (one request each).
    let destination = Address::from_bytes([0x11; 20]);
    let payloads = [
        HcPayload::UsdSend {
            destination,
            amount: "1".to_owned(),
        },
        HcPayload::SpotSend {
            destination,
            token: purr.wire(),
            amount: "1".to_owned(),
        },
        HcPayload::Withdraw {
            destination: account,
            amount: "2".to_owned(),
        },
        HcPayload::UsdClassTransfer {
            amount: "1".to_owned(),
            to_perp: true,
        },
        HcPayload::SendAsset {
            destination: hype.system_address(),
            source_dex: "spot".to_owned(),
            destination_dex: "spot".to_owned(),
            token: hype.wire(),
            amount: "0.01".to_owned(),
        },
    ];
    let mut store = ApprovalStore::new();
    let ours = account.to_lower_hex();
    let mut failures = Vec::new();
    for payload in payloads {
        let action = HcAction::new(HcNetwork::Testnet, now_ms()?, payload);
        let input = HcApprovalInput {
            action: &action,
            account,
            signer: source,
            token: None,
            recipient: HcRecipient::default(),
        };
        let draft =
            build_hypercore_request(yw_core::lang::Lang::Ko, ApprovalId::random()?, &input)?;
        let request = store.issue(draft, 0, now_ms()?)?;
        let approved = store.consume(request.id, request.digest, 1)?;
        let signature = yw_core::evm::sign::sign_typed_data(&vault, approved)?;
        let reply = parse_exchange_reply(&post(
            &client,
            "/exchange",
            &action.exchange_body(&signature),
        )?)?;
        let (ok, text) = match &reply {
            HcExchangeReply::Ok => (
                false,
                "status ok (unexpected for an empty account)".to_owned(),
            ),
            HcExchangeReply::Err(message) => (
                message.to_ascii_lowercase().contains(&ours),
                message.clone(),
            ),
        };
        println!(
            "{:<17} recovered-signer-is-ours={ok} reply: {text}",
            action.kind().wire_type()
        );
        if !ok {
            failures.push(action.kind().wire_type());
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("signer not recovered for {failures:?}").into())
    }
}
