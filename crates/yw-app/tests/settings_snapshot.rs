//! Review M1 / L15: the security settings snapshot kept in the vault-encrypted meta and its
//! comparison with the plaintext `settings.json` after an unlock (`settings::reconcile`).

use yw_app::meta::{Meta, parse as parse_meta};
use yw_app::settings::{
    BtcIndexer, Differing, EvmChainDef, LlmSettings, SecuritySnapshot, Settings, load, reconcile,
};
use yw_core::evm::chain::{HYPEREVM_MAINNET, SimulationSupport};

const CONSENTED: &str = "https://api.example.org/v1/chat/completions";
const ATTACKER: &str = "https://attacker.example/v1/chat/completions";
const PIN: [u8; 32] = [0x99; 32];
const LIMITS: yw_json::Limits = yw_json::Limits {
    max_bytes: 65_536,
    max_depth: 8,
    max_nodes: 4_096,
    max_items: 4_096,
};

fn llm_on(endpoint: &str) -> LlmSettings {
    LlmSettings {
        enabled: true,
        endpoint: endpoint.to_owned(),
        model: "m".to_owned(),
        privacy_notice_version: 1,
        ..LlmSettings::default()
    }
}

fn user_chain(id: u64, genesis: [u8; 32]) -> EvmChainDef {
    EvmChainDef {
        chain_id: id,
        name: format!("Chain {id}"),
        symbol: "ETH".to_owned(),
        decimals: 18,
        quicknode_subdomain: None,
        alchemy_label: None,
        explorer: None,
        simulation: SimulationSupport::Auto,
        genesis_hash: genesis,
    }
}

/// What the app last wrote: AI on for api.example.org, `HyperEVM` and a user chain pinned.
fn written() -> Settings {
    Settings {
        llm_explain: llm_on(CONSENTED),
        evm_genesis_pins: vec![(HYPEREVM_MAINNET, PIN)],
        evm_chains: vec![user_chain(4_242, [0x42; 32])],
        ..Settings::default()
    }
}

/// The file bytes after `settings.json` was edited by hand: `edit` changes the loaded settings.
fn tampered(edit: impl FnOnce(&mut Settings)) -> Settings {
    let mut settings = load(Some(&written().to_json())).settings;
    edit(&mut settings);
    // Through the real loader, as the app reads it at the next start.
    load(Some(&settings.to_json())).settings
}

#[test]
fn untouched_file_matches_its_snapshot() {
    let snapshot = SecuritySnapshot::of(&written());
    let file = load(Some(&written().to_json())).settings;
    let outcome = reconcile(&file, &snapshot, &[]);
    assert!(!outcome.write_file && !outcome.llm_forced_off);
    assert!(outcome.pins_restored.is_empty() && outcome.differing.is_empty());
    assert_eq!(outcome.effective, file);
    assert_eq!(outcome.snapshot, snapshot);
}

/// M1: the endpoint swapped for another host in the plain file switches the AI off (file and
/// memory); the proof of concept's `privacy_notice_version = 1` forgery does not count as consent.
#[test]
fn llm_endpoint_changed_outside_the_app_is_switched_off() {
    let snapshot = SecuritySnapshot::of(&written());
    let file = tampered(|settings| settings.llm_explain.endpoint = ATTACKER.to_owned());
    assert!(yw_app::explain::config::effectively_enabled(
        &file.llm_explain
    ));
    let outcome = reconcile(&file, &snapshot, &[]);
    assert!(outcome.llm_forced_off && outcome.write_file);
    assert!(!outcome.effective.llm_explain.enabled);
    assert!(!outcome.file.llm_explain.enabled);
    // The consent stays with the host the user agreed to.
    assert_eq!(outcome.snapshot.llm.host, "api.example.org");
    assert!(outcome.snapshot.llm_consented_to("api.example.org"));
    assert!(!outcome.snapshot.llm_consented_to("attacker.example"));

    // AI switched off by the user, then switched on again (and the notice forged) in the file.
    let mut off = written();
    off.llm_explain.enabled = false;
    off.llm_explain.privacy_notice_version = 0;
    let snapshot = SecuritySnapshot::of(&off);
    let file = tampered(|settings| {
        settings.llm_explain.enabled = true;
        settings.llm_explain.privacy_notice_version = 1;
    });
    let outcome = reconcile(&file, &snapshot, &[]);
    assert!(outcome.llm_forced_off);
    assert!(!outcome.effective.llm_explain.enabled);

    // Switched on in this run before the check (`saved_early`): taken over, consent recorded.
    let outcome = reconcile(&file, &snapshot, &["llm_explain"]);
    assert!(!outcome.llm_forced_off);
    assert!(outcome.snapshot.llm_consented_to("api.example.org"));

    // Off in the file: nothing to do even with another endpoint.
    let file = tampered(|settings| {
        settings.llm_explain.enabled = false;
        settings.llm_explain.endpoint = ATTACKER.to_owned();
    });
    let outcome = reconcile(&file, &SecuritySnapshot::of(&written()), &[]);
    assert!(!outcome.llm_forced_off && !outcome.write_file);
}

/// L15: a deleted or changed genesis pin is restored from the snapshot (never re-TOFU), even
/// for a key saved before the check; a pin the snapshot lacks (first use) is taken over.
#[test]
fn genesis_pins_are_restored_never_re_pinned() {
    let snapshot = SecuritySnapshot::of(&written());
    for file in [
        tampered(|settings| settings.evm_genesis_pins.clear()),
        tampered(|settings| settings.evm_genesis_pins = vec![(HYPEREVM_MAINNET, [0x66; 32])]),
    ] {
        for early in [&[][..], &["evmGenesisPins"][..]] {
            let outcome = reconcile(&file, &snapshot, early);
            assert_eq!(outcome.pins_restored, vec![HYPEREVM_MAINNET]);
            assert!(outcome.write_file);
            assert_eq!(
                outcome.effective.evm_genesis_pins,
                vec![(HYPEREVM_MAINNET, PIN)]
            );
            assert_eq!(outcome.file.evm_genesis_pins, vec![(HYPEREVM_MAINNET, PIN)]);
            // Through the loader again: the restored pin is what the next start reads.
            assert_eq!(
                load(Some(&outcome.file.to_json()))
                    .settings
                    .evm_genesis_pins,
                vec![(HYPEREVM_MAINNET, PIN)]
            );
        }
    }
    // A user chain's genesis changed in the file.
    let file = tampered(|settings| settings.evm_chains[0].genesis_hash = [0x13; 32]);
    let outcome = reconcile(&file, &snapshot, &[]);
    assert_eq!(outcome.pins_restored, vec![4_242]);
    assert_eq!(outcome.effective.evm_chains[0].genesis_hash, [0x42; 32]);

    // First use while locked: the snapshot had no HyperEVM pin yet.
    let mut before = written();
    before.evm_genesis_pins.clear();
    let outcome = reconcile(
        &load(Some(&written().to_json())).settings,
        &SecuritySnapshot::of(&before),
        &[],
    );
    assert!(outcome.pins_restored.is_empty());
    assert_eq!(outcome.snapshot.pin(HYPEREVM_MAINNET), Some(PIN));
}

/// L15: fee caps, auto-lock and the Bitcoin indexer changed outside the app: the snapshot
/// values are used, the file values are kept for `파일 값 사용`, nothing is written.
#[test]
fn other_differences_use_the_snapshot_until_the_user_decides() {
    let snapshot = SecuritySnapshot::of(&written());
    let file = tampered(|settings| {
        settings.auto_lock_minutes = 60;
        settings.fee_caps[0].1.max_fee_per_gas_gwei = "10000".to_owned();
        settings.bitcoin.indexer = BtcIndexer::BbRest;
        settings.bitcoin.esplora_mainnet = "https://indexer.attacker.example/api".to_owned();
    });
    let outcome = reconcile(&file, &snapshot, &[]);
    assert!(!outcome.write_file);
    assert_eq!(
        outcome.differing,
        vec![Differing::FeeCaps, Differing::AutoLock, Differing::Indexer]
    );
    let written = written();
    assert_eq!(outcome.effective.auto_lock_minutes, 10);
    assert_eq!(outcome.effective.fee_caps, written.fee_caps);
    assert_eq!(outcome.effective.bitcoin, written.bitcoin);
    assert_eq!(outcome.file, file);
    assert_eq!(outcome.snapshot, snapshot);
    // `파일 값 사용` = the snapshot of the file values.
    let accepted = SecuritySnapshot::of(&outcome.file);
    assert_eq!(accepted.auto_lock_minutes, 60);
    assert!(reconcile(&file, &accepted, &[]).differing.is_empty());

    // Saved by the app itself before the check: taken over without a banner.
    let outcome = reconcile(
        &file,
        &snapshot,
        &["autoLockMinutes", "feeCaps", "bitcoin.indexer"],
    );
    assert!(outcome.differing.is_empty());
    assert_eq!(outcome.effective.auto_lock_minutes, 60);
    assert_eq!(outcome.snapshot.auto_lock_minutes, 60);
    assert_eq!(outcome.snapshot.btc_indexer, BtcIndexer::BbRest);

    // `파일 값 사용` pressed while locked: every component is taken over except the LLM consent.
    let file = tampered(|settings| {
        settings.auto_lock_minutes = 60;
        settings.llm_explain.endpoint = ATTACKER.to_owned();
    });
    let outcome = reconcile(&file, &snapshot, &[yw_app::settings::ACCEPT_FILE_KEY]);
    assert!(outcome.differing.is_empty());
    assert_eq!(outcome.snapshot.auto_lock_minutes, 60);
    assert!(outcome.llm_forced_off);
    assert_eq!(outcome.snapshot.llm.host, "api.example.org");
}

/// A user chain added in the file (its genesis never pinned by the app) is not used until
/// accepted; an active chain id that pointed to it falls back to the default.
#[test]
fn chains_added_outside_the_app_wait_for_the_user() {
    let snapshot = SecuritySnapshot::of(&written());
    let file = tampered(|settings| {
        settings.evm_chains.push(user_chain(7_777, [0x77; 32]));
        settings.evm_chain_id = 7_777;
    });
    let outcome = reconcile(&file, &snapshot, &[]);
    assert_eq!(outcome.differing, vec![Differing::NewChains]);
    assert!(
        outcome
            .effective
            .evm_chains
            .iter()
            .all(|chain| chain.chain_id != 7_777)
    );
    assert_eq!(
        outcome.effective.evm_chain_id,
        Settings::default().evm_chain_id
    );
    assert_eq!(outcome.file.evm_chains.len(), 2);
    let outcome = reconcile(&file, &snapshot, &["evmChains"]);
    assert!(outcome.differing.is_empty());
    assert_eq!(outcome.snapshot.pin(7_777), Some([0x77; 32]));
}

#[test]
fn snapshot_json_round_trip_and_strict_parse() {
    let mut settings = written();
    settings.bitcoin.indexer = BtcIndexer::BbRpc;
    let snapshot = SecuritySnapshot::of(&settings);
    let value = snapshot.to_json();
    assert_eq!(SecuritySnapshot::from_json(&value), Some(snapshot.clone()));
    let text = String::from_utf8(yw_json::to_vec(&value)).unwrap();
    for bad in [
        text.replace(r#""version":1"#, r#""version":2"#),
        text.replace(r#""autoLockMinutes":10"#, r#""autoLockMinutes":61"#),
        text.replace(r#""indexer":"bb-rpc""#, r#""indexer":"x""#),
        text.replace(r#""llm":{"#, r#""llm":{"extra":1,"#),
        text.replace("eip155:999", "solana:mainnet"),
    ] {
        let parsed = yw_json::parse(bad.as_bytes(), &LIMITS).unwrap();
        assert_eq!(SecuritySnapshot::from_json(&parsed), None, "{bad}");
    }

    // In the meta: optional on read (older files), written when present, round trip.
    let mut meta = Meta::default();
    let plain = parse_meta(&meta.to_json()).unwrap().meta;
    assert_eq!(plain.security.snapshot, None);
    assert_eq!(plain.security.vault_generation_seen, 0);
    meta.security.snapshot = Some(snapshot);
    meta.security.vault_generation_seen = 7;
    let bytes = meta.to_json();
    let parsed = parse_meta(&bytes).unwrap().meta;
    assert_eq!(parsed, meta);
    assert!(parsed.unknown.is_empty());
    // A damaged snapshot rejects the document like any other known key.
    let damaged = String::from_utf8(bytes)
        .unwrap()
        .replace(r#""autoLockMinutes":10"#, r#""autoLockMinutes":0"#);
    assert!(parse_meta(damaged.as_bytes()).is_err());
}
