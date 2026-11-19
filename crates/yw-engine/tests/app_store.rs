//! `app_store` (spec/15 §11.4 S4 P1, spec/04 §6.3): how a sealed-keys read maps to
//! `(keys, unreadable)`, and that a read's `Debug` shows the variant and a length only. An
//! in-memory store; no file, no seal. Names and keys are fake.
//! (2026-11-20, S4 P1: created with the module.)

use std::cell::RefCell;

use yw_core::secret::Zeroizing;
use yw_core::vault::FileKind;
use yw_engine::apikeys::{APIKEYS_MAGIC, ApiKeys};
use yw_engine::app_store::{AppStore, SealedRead, load_sealed_keys};
use yw_engine::settings::Settings;

/// What the next `read_sealed_keys` returns (a test double; `RefCell` is `Send`).
struct MemStore(RefCell<Option<SealedRead>>);

impl MemStore {
    fn new(read: SealedRead) -> Self {
        Self(RefCell::new(Some(read)))
    }
}

impl AppStore for MemStore {
    fn write_settings(&self, _json: &[u8]) -> bool {
        false
    }

    fn read_sealed_keys(&self) -> SealedRead {
        self.0.borrow_mut().take().unwrap_or(SealedRead::NotFound)
    }

    fn write_sealed_keys(&self, _plain: &[u8]) -> bool {
        false
    }

    fn vault_file_info(&self) -> Option<(u64, u64)> {
        None
    }

    fn prev_exists(&self, _kind: FileKind) -> bool {
        false
    }

    fn reset_candidates(&self, _include_settings: bool) -> Vec<String> {
        Vec::new()
    }
}

fn load(read: SealedRead) -> (ApiKeys, bool) {
    load_sealed_keys(&MemStore::new(read), &Settings::default())
}

fn one_entry(name: &str, value: &str) -> Vec<u8> {
    let mut plain = APIKEYS_MAGIC.to_vec();
    plain.push(1);
    plain.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
    plain.extend_from_slice(name.as_bytes());
    plain.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    plain.extend_from_slice(value.as_bytes());
    plain
}

#[test]
fn a_missing_file_is_no_keys_and_not_unreadable() {
    let (keys, unreadable) = load(SealedRead::NotFound);
    assert!(!unreadable);
    assert_eq!(
        keys.encode().as_slice(),
        ApiKeys::default().encode().as_slice()
    );
}

#[test]
fn an_unreadable_file_or_bad_plaintext_is_no_keys_and_unreadable() {
    let (keys, unreadable) = load(SealedRead::Unreadable);
    assert!(unreadable);
    assert_eq!(
        keys.encode().as_slice(),
        ApiKeys::default().encode().as_slice()
    );
    let (keys, unreadable) = load(SealedRead::Plain(Zeroizing::new(b"not-keys".to_vec())));
    assert!(unreadable);
    assert_eq!(
        keys.encode().as_slice(),
        ApiKeys::default().encode().as_slice()
    );
}

#[test]
fn a_plaintext_decodes_to_its_keys() {
    let plain = one_entry("tpl:alchemy", "FakeAlchemyKey_0123456789");
    let (keys, unreadable) = load(SealedRead::Plain(Zeroizing::new(plain.clone())));
    assert!(!unreadable);
    assert_eq!(keys.encode().as_slice(), plain.as_slice());
}

#[test]
fn a_read_debug_shows_no_bytes() {
    let plain = one_entry("llm", "FakeLlmKey_0123456789");
    let debug = format!("{:?}", SealedRead::Plain(Zeroizing::new(plain.clone())));
    assert_eq!(debug, format!("Plain(len={})", plain.len()));
    assert!(!debug.contains("Fake"));
    assert_eq!(format!("{:?}", SealedRead::NotFound), "NotFound");
    assert_eq!(format!("{:?}", SealedRead::Unreadable), "Unreadable");
}
