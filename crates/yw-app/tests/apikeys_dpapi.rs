//! V-DPAPI at the application level (spec/09 §4.1): the `apikeys.dpapi` plaintext (spec/04 §6.3)
//! sealed with the app's entropy round-trips through yw-win's DPAPI, and the wrong entropy or a
//! flipped byte is refused. Names, tokens and keys are fake.
//! (2026-11-17, spec/15 §11.4 S2 T1: split from `apikeys.rs`, whose plaintext tests moved to
//! yw-engine; this one stays because DPAPI is the Windows platform's seal.)
//! (2026-11-20, S4 P1: the entropy moved to `app_store` with the DPAPI calls; the Windows
//! `AppStore` round trip below runs in its own temp folder.)
//! (2026-11-20, S4 P1 review: the entropy's value is pinned against the spec/04 §6.3 literal;
//! before, every test sealed and opened with the constant itself, so a changed value stayed
//! green while every existing `apikeys.dpapi` became unreadable.)

use std::path::{Path, PathBuf};

use yw_app::app::{Paths, load_apikeys};
use yw_app::app_store::{APIKEYS_ENTROPY, WinAppStore};
use yw_app::settings::Settings;
use yw_core::vault::FileKind;
use yw_engine::app_store::{AppStore, SealedRead, load_sealed_keys};

/// The DPAPI optional entropy every `apikeys.dpapi` was sealed with (spec/04 §6.3: ASCII
/// `your-wallet/v3/apikeys`, 22 bytes). Written out here, never taken from the app.
const SPEC_ENTROPY: &[u8; 22] = b"your-wallet/v3/apikeys";

/// A temp folder of this test binary, removed on drop (also when an assertion fails, so no
/// sealed blob of the fake key stays behind; 2026-11-20, S4 P1 review).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("yw-app-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const NAME: &str = "fake-node";
const TOKEN: &str = "FakeToken_0123456789abcdef";
const KEY: &str = "FakeAlchemyKey_0123456789";

fn entry(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![u8::try_from(name.len()).unwrap_or(u8::MAX)];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out
}

fn plaintext(entries: &[(String, String)]) -> Vec<u8> {
    let mut out = b"YWAPIK01".to_vec();
    out.push(u8::try_from(entries.len()).unwrap_or(u8::MAX));
    for (name, value) in entries {
        out.extend(entry(name, value));
    }
    out
}

fn long_url(tag: usize) -> String {
    let head = format!("https://h{tag}.example/");
    format!("{head}{}", "a".repeat(2_048 - head.len()))
}

fn full_set() -> Vec<(String, String)> {
    let mut entries = vec![
        ("tpl:quicknode".to_owned(), format!("{NAME}:{TOKEN}")),
        ("tpl:alchemy".to_owned(), KEY.to_owned()),
        ("llm".to_owned(), "local-model-key".to_owned()),
    ];
    let mut networks = vec![
        "eip155:1".to_owned(),
        "eip155:11155111".to_owned(),
        "eip155:999".to_owned(),
    ];
    networks.extend((0..32).map(|i| format!("eip155:{}", 10_000 + i)));
    networks.extend(
        [
            "solana:mainnet",
            "solana:devnet",
            "bitcoin:mainnet",
            "bitcoin:testnet4",
        ]
        .map(str::to_owned),
    );
    for (index, network) in networks.into_iter().enumerate() {
        entries.push((format!("rpc:{network}"), long_url(index)));
    }
    entries
}

#[test]
fn dpapi_round_trip_of_the_plaintext() {
    let bytes = plaintext(&full_set());
    let blob = yw_win::dpapi::protect(&bytes, APIKEYS_ENTROPY).unwrap();
    let plain = yw_win::dpapi::unprotect(&blob, APIKEYS_ENTROPY).unwrap();
    assert_eq!(plain.as_slice(), bytes.as_slice());
    assert!(yw_win::dpapi::unprotect(&blob, b"other").is_err());
    let mut tampered = blob;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert!(yw_win::dpapi::unprotect(&tampered, APIKEYS_ENTROPY).is_err());
}

/// S4 P1: the Windows `AppStore` seals with the same entropy (a blob it writes opens with the
/// plain DPAPI call and `APIKEYS_ENTROPY`), maps a missing file to "no keys, not unreadable" and a
/// damaged one to "unreadable", writes `settings.json` in place, and its `Debug` (and that of a
/// read) shows no path and no bytes. Temp folder only, removed on drop (2026-11-20, S4 P1
/// review: before, only at the end, so a failed assertion left it behind).
#[test]
fn the_windows_app_store_keeps_the_file_and_seal() {
    let temp = TempDir::new("keep").unwrap();
    let data = temp.path().to_path_buf();
    let paths = Paths {
        data: data.clone(),
        logs: data.join("logs"),
    };
    let store = WinAppStore::new(&paths);
    let settings = Settings::default();

    assert!(matches!(store.read_sealed_keys(), SealedRead::NotFound));
    let (keys, unreadable) = load_apikeys(&paths, &settings);
    assert!(!unreadable);
    assert_eq!(
        keys.encode().as_slice(),
        yw_app::apikeys::ApiKeys::default().encode().as_slice()
    );

    let entries = vec![("tpl:alchemy".to_owned(), KEY.to_owned())];
    let bytes = plaintext(&entries);
    assert!(store.write_sealed_keys(&bytes));
    let blob = std::fs::read(data.join("apikeys.dpapi")).unwrap();
    let plain = yw_win::dpapi::unprotect(&blob, APIKEYS_ENTROPY).unwrap();
    assert_eq!(plain.as_slice(), bytes.as_slice());
    let read = store.read_sealed_keys();
    assert!(
        matches!(&read, SealedRead::Plain(unsealed) if unsealed.as_slice() == bytes.as_slice())
    );
    assert_eq!(format!("{read:?}"), format!("Plain(len={})", bytes.len()));
    let (keys, unreadable) = load_sealed_keys(&store, &settings);
    assert!(!unreadable);
    assert_eq!(keys.encode().as_slice(), bytes.as_slice());

    let mut damaged = blob;
    let last = damaged.len() - 1;
    damaged[last] ^= 0x80;
    std::fs::write(data.join("apikeys.dpapi"), &damaged).unwrap();
    assert!(matches!(store.read_sealed_keys(), SealedRead::Unreadable));
    assert!(load_apikeys(&paths, &settings).1);

    assert!(store.write_settings(b"{\"version\":1}"));
    assert_eq!(
        std::fs::read(data.join("settings.json")).unwrap(),
        b"{\"version\":1}"
    );
    assert_eq!(store.vault_file_info(), None);
    assert!(!store.prev_exists(FileKind::Vault));
    assert_eq!(
        store.reset_candidates(true),
        vec!["apikeys.dpapi".to_owned(), "settings.json".to_owned()]
    );
    assert!(store.reset_candidates(false).is_empty());

    let debug = format!("{store:?}");
    assert_eq!(debug, "WinAppStore");
    assert!(!debug.contains(&*data.to_string_lossy()));
}

/// S4 P1 review: `APIKEYS_ENTROPY` is the spec/04 §6.3 value, and a file sealed with that
/// literal (as every earlier version wrote it) opens through the Windows `AppStore` and
/// `load_apikeys`. A changed entropy would make every existing `apikeys.dpapi` unreadable and
/// drop the user's RPC and LLM keys. Temp folder only, removed on drop.
#[test]
fn the_entropy_is_the_one_existing_files_were_sealed_with() {
    assert_eq!(APIKEYS_ENTROPY, SPEC_ENTROPY);
    assert_eq!(APIKEYS_ENTROPY.len(), 22);

    let temp = TempDir::new("entropy").unwrap();
    let paths = Paths {
        data: temp.path().to_path_buf(),
        logs: temp.path().join("logs"),
    };
    let entries = vec![("tpl:quicknode".to_owned(), format!("{NAME}:{TOKEN}"))];
    let bytes = plaintext(&entries);
    let blob = yw_win::dpapi::protect(&bytes, SPEC_ENTROPY).unwrap();
    std::fs::write(temp.path().join("apikeys.dpapi"), &blob).unwrap();

    let store = WinAppStore::new(&paths);
    let read = store.read_sealed_keys();
    assert!(matches!(&read, SealedRead::Plain(plain) if plain.as_slice() == bytes.as_slice()));
    let (keys, unreadable) = load_apikeys(&paths, &Settings::default());
    assert!(!unreadable);
    assert_eq!(keys.encode().as_slice(), bytes.as_slice());

    // And the store seals with it: what it writes opens with the literal.
    assert!(store.write_sealed_keys(&bytes));
    let written = std::fs::read(temp.path().join("apikeys.dpapi")).unwrap();
    let plain = yw_win::dpapi::unprotect(&written, SPEC_ENTROPY).unwrap();
    assert_eq!(plain.as_slice(), bytes.as_slice());
}
