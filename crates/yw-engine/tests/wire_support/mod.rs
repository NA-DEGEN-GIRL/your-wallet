//! Test support for the Android wire (2026-11-25 A2-6, spec/15 §3.2): a wallet with no workers,
//! no files and made-up shell facts, on the first-run screen. No yw-app, no window, no network.
#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use yw_core::lang::Lang;
use yw_core::vault::FileKind;
use yw_engine::apikeys::ApiKeys;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::screen::facts::{PipeStatus, PlatformFlags, ScreenFacts};
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::wallet::{AppMode, Screen, Wallet};

/// A manual test clock (monotonic ms; the wall clock a fixed base after it).
pub struct TestClock(pub AtomicU64);

impl yw_platform::clock::Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn now_unix_ms(&self) -> u64 {
        1_800_000_000_000 + self.now_ms()
    }

    fn sleep_ms(&self, _ms: u64) {}
}

/// No files: nothing is read or kept.
pub struct NoFiles;

impl AppStore for NoFiles {
    fn write_settings(&self, _json: &[u8]) -> bool {
        true
    }

    fn read_sealed_keys(&self) -> SealedRead {
        SealedRead::NotFound
    }

    fn write_sealed_keys(&self, _plain: &[u8]) -> bool {
        true
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

/// Made-up shell facts of a platform without the Windows-only parts (the Android flags of
/// spec/15 §17 A2).
pub struct Facts;

/// The flags the Android shell answers (spec/15 §11.3, §17 A2-7 plan).
pub const ANDROID_FLAGS: PlatformFlags = PlatformFlags {
    secret_copy: false,
    secret_word_paste: false,
    rpc_json_import: false,
    browser_extension: false,
    open_folders: false,
    seen_all: true,
};

impl ScreenFacts for Facts {
    fn local_wall_ms(&self, _unix_ms: u64) -> Option<u64> {
        None
    }

    fn data_dir(&self) -> String {
        String::new()
    }

    fn rpc_json_present(&self) -> bool {
        false
    }

    fn extension_dir(&self) -> Option<String> {
        None
    }

    fn expected_extension_dir(&self) -> Option<String> {
        None
    }

    fn pipe(&self) -> PipeStatus {
        PipeStatus {
            server: false,
            error: None,
        }
    }

    fn version_text(&self, _lang: Lang) -> String {
        "test".to_owned()
    }

    fn flags(&self) -> PlatformFlags {
        ANDROID_FLAGS
    }
}

/// A wallet with no workers and no vault, on S01 (first run).
pub fn first_run_wallet() -> Wallet {
    let clock = Arc::new(TestClock(AtomicU64::new(1_000_000)));
    let mut wallet = Wallet::new(
        Box::new(NoFiles),
        Services {
            llm: Arc::new(|_endpoint| None),
            walletconnect: None,
            ua_platform: "test",
        },
        false,
        Settings::default(),
        ApiKeys::default(),
        clock,
        1_000_000,
    );
    wallet.mode = AppMode::NoVault;
    wallet.screen = Screen::FirstRun;
    wallet
}

/// Every effect queued, taken as a shell takes them (each field write resolved), unapplied.
pub fn take_all(wallet: &mut Wallet) -> Vec<yw_engine::effect::Effect> {
    let mut taken = Vec::new();
    while let Some(effect) = wallet.next_effect() {
        taken.push(effect);
    }
    taken
}
