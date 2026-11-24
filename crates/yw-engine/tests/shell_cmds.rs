//! The shell's former named wallet steps as `Cmd`s (2026-11-24, spec/15 §11.4 S5-9 review;
//! spec/04 §1.3, §1.4, §2.21, §4.8): what the wallet does with `Cmd::SecretClip`,
//! `Cmd::Platform`, `Cmd::Main` and S23's presses. The S5-9 commit moved these from the Windows
//! shell into the wallet with no test of their own (the headless `s4_secret` `clear-clip` lines
//! pin the clears' order only: a test build has no main window, so the shell's clear ends before
//! any notice, and the census never presses S23's way back after an open from another screen).
//! The wallet alone, with made-up shell facts: no yw-app, no window, no file, no network, no
//! clipboard.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use yw_core::lang::Lang;
use yw_core::vault::FileKind;
use yw_engine::apikeys::ApiKeys;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::cmd::{ClipNote, Cmd, ExtPress, LinksPress, MainStep, PlatformNote, Press};
use yw_engine::effect::Effect;
use yw_engine::errors::ErrorCode;
use yw_engine::form::PressInput;
use yw_engine::screen::{SettingsSection, Tone};
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::wallet::text::{T_CLIP_CLEARED_LATE, T_CLIP_NOT_CLEARED, T_WER_UNPROTECTED};
use yw_engine::wallet::{AppMode, Banner, Screen, Wallet};

/// A manual test clock (monotonic ms; the wall clock a fixed base after it).
struct TestClock(AtomicU64);

impl yw_platform::clock::Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn now_unix_ms(&self) -> u64 {
        1_800_000_000_000 + self.now_ms()
    }

    fn sleep_ms(&self, _ms: u64) {}
}

/// No files: nothing is read; every write "succeeds" and keeps nothing.
struct NoFiles;

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

/// A made-up `QuickNode` template credential (no real endpoint; never used for a request).
const NODE: &str = "fake-node";
const TOKEN: &str = "FakeToken_0123456789abcdef";

/// Keys holding only the made-up `QuickNode` credential.
fn template_keys() -> ApiKeys {
    let mut keys = ApiKeys::default();
    keys.set_quicknode(NODE, TOKEN);
    keys
}

/// An unlocked wallet with no workers, on S10, in `lang`, holding `apikeys`.
fn wallet_with(lang: Lang, apikeys: ApiKeys) -> Wallet {
    let clock = Arc::new(TestClock(AtomicU64::new(1_000_000)));
    let settings = Settings {
        language: lang,
        ..Settings::default()
    };
    let mut wallet = Wallet::new(
        Box::new(NoFiles),
        Services {
            llm: Arc::new(|_endpoint| None),
            walletconnect: None,
            ua_platform: "test",
        },
        true,
        settings,
        apikeys,
        clock,
        1_000_000,
    );
    wallet.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    wallet.screen = Screen::Main;
    wallet
}

fn unlocked(lang: Lang) -> Wallet {
    wallet_with(lang, ApiKeys::default())
}

/// How many `Effect::Render`s are queued (the queue is emptied, unapplied).
fn renders(wallet: &mut Wallet) -> usize {
    let mut count = 0;
    while let Some(effect) = wallet.next_effect() {
        if matches!(effect, Effect::Render) {
            count += 1;
        }
    }
    count
}

fn banner(text: &str, tone: Tone) -> Banner {
    Banner {
        code: None,
        text: text.to_owned(),
        tone,
    }
}

fn press(wallet: &mut Wallet, press: Press) {
    wallet.on_cmd(Cmd::Press {
        press,
        input: PressInput::default(),
    });
}

/// spec/04 §4.8: each `ClipNote` writes the clip notices the shell wrote before S5-9, in the
/// wallet's language, and lays the screen out again where it did (all but the start's).
#[test]
fn clip_notes_write_the_clip_notices() {
    for lang in [Lang::Ko, Lang::En] {
        let not_cleared = T_CLIP_NOT_CLEARED.get(lang);
        let cleared_late = T_CLIP_CLEARED_LATE.get(lang);
        let other = banner("other", Tone::Info);

        // The clear stayed busy for the notice time: the warning, laid out.
        let mut wallet = unlocked(lang);
        wallet.banners.push(other.clone());
        wallet.on_cmd(Cmd::SecretClip(ClipNote::NotCleared));
        assert_eq!(
            wallet.banners,
            [other.clone(), banner(not_cleared, Tone::Warn)],
            "{lang:?} NotCleared"
        );
        assert_eq!(renders(&mut wallet), 1, "{lang:?} NotCleared lays out");

        // The noticed copy was cleared now: the warning goes, the late-clear notice follows.
        wallet.on_cmd(Cmd::SecretClip(ClipNote::NoticeEnds { cleared: true }));
        assert_eq!(
            wallet.banners,
            [other.clone(), banner(cleared_late, Tone::Info)],
            "{lang:?} NoticeEnds cleared"
        );
        assert_eq!(renders(&mut wallet), 1, "{lang:?} NoticeEnds lays out");

        // The noticed copy is no longer ours: the warning goes, nothing else.
        let mut wallet = unlocked(lang);
        wallet.banners.push(other.clone());
        wallet.on_cmd(Cmd::SecretClip(ClipNote::NotCleared));
        let _ = renders(&mut wallet);
        wallet.on_cmd(Cmd::SecretClip(ClipNote::NoticeEnds { cleared: false }));
        assert_eq!(
            wallet.banners,
            std::slice::from_ref(&other),
            "{lang:?} NoticeEnds not cleared"
        );
        assert_eq!(renders(&mut wallet), 1, "{lang:?} NoticeEnds lays out");

        // The warning in the other language goes too (the language changed meanwhile).
        let mut wallet = unlocked(lang);
        let other_lang = if lang == Lang::Ko { Lang::En } else { Lang::Ko };
        wallet
            .banners
            .push(banner(T_CLIP_NOT_CLEARED.get(other_lang), Tone::Warn));
        wallet.on_cmd(Cmd::SecretClip(ClipNote::NoticeEnds { cleared: false }));
        assert!(wallet.banners.is_empty(), "{lang:?} either language");

        // At start an earlier run's copy was cleared: the notice only, no layout.
        let mut wallet = unlocked(lang);
        wallet.on_cmd(Cmd::SecretClip(ClipNote::EarlierRunCleared));
        assert_eq!(
            wallet.banners,
            [banner(cleared_late, Tone::Info)],
            "{lang:?} EarlierRunCleared"
        );
        assert_eq!(renders(&mut wallet), 0, "{lang:?} EarlierRunCleared");
    }
}

/// spec/04 §1.4: the start's findings and the session registration's last failure as the
/// banners and facts the shell wrote before S5-9.
#[test]
fn platform_notes_write_the_start_findings() {
    // E-APP-001 names the refused keys in the wallet's language.
    for lang in [Lang::Ko, Lang::En] {
        let mut wallet = unlocked(lang);
        wallet.on_cmd(Cmd::Platform(PlatformNote::SettingsRefused(vec![
            "language".to_owned(),
            "theme".to_owned(),
        ])));
        assert_eq!(
            wallet.banners,
            [Banner {
                code: Some(ErrorCode::App001),
                text: ErrorCode::App001.render_in(lang, "language, theme"),
                tone: Tone::Danger,
            }],
            "{lang:?}"
        );
    }
    assert_ne!(
        ErrorCode::App001.render_in(Lang::Ko, "x"),
        ErrorCode::App001.render_in(Lang::En, "x")
    );

    // `apikeys.dpapi` unreadable: E-KEY-001, and the template's gaps stay empty even though a
    // credential is held.
    let mut wallet = wallet_with(Lang::En, template_keys());
    wallet.on_cmd(Cmd::Platform(PlatformNote::ApiKeys { readable: false }));
    assert_eq!(
        wallet.banners,
        [Banner {
            code: Some(ErrorCode::Key001),
            text: ErrorCode::Key001.text_in(Lang::En),
            tone: Tone::Danger,
        }]
    );
    assert!(
        wallet.apikeys.endpoints().is_empty(),
        "no fill when unreadable"
    );

    // Readable: the networks with no address get the template's, and no banner.
    let mut wallet = wallet_with(Lang::En, template_keys());
    wallet.on_cmd(Cmd::Platform(PlatformNote::ApiKeys { readable: true }));
    assert!(wallet.banners.is_empty());
    assert!(
        !wallet.apikeys.endpoints().is_empty(),
        "the template's gaps are filled"
    );

    // WER: the notice and the guard flag.
    let mut wallet = unlocked(Lang::Ko);
    assert!(!wallet.guard.wer_unprotected);
    wallet.on_cmd(Cmd::Platform(PlatformNote::WerUnprotected));
    assert!(wallet.guard.wer_unprotected);
    assert!(
        wallet
            .banners
            .iter()
            .any(|banner| banner.text == T_WER_UNPROTECTED.get(Lang::Ko)),
        "{:?}",
        wallet.banners
    );

    // The installed commit is kept only when it is one.
    let mut wallet = unlocked(Lang::Ko);
    wallet.on_cmd(Cmd::Platform(PlatformNote::InstallCommit(Some(
        "0123abc".to_owned(),
    ))));
    assert_eq!(wallet.install_commit.as_deref(), Some("0123abc"));
    for refused in [Some("not a commit"), Some("0123ABC"), Some("abc"), None] {
        let mut wallet = unlocked(Lang::Ko);
        wallet.on_cmd(Cmd::Platform(PlatformNote::InstallCommit(
            refused.map(str::to_owned),
        )));
        assert_eq!(wallet.install_commit, None, "{refused:?}");
        assert!(wallet.banners.is_empty());
    }

    // The session notifications could not be registered: E-APP-004, once.
    let mut wallet = unlocked(Lang::En);
    for _ in 0..2 {
        wallet.on_cmd(Cmd::Platform(PlatformNote::SessionUnregistered));
    }
    assert_eq!(
        wallet.banners,
        [Banner {
            code: Some(ErrorCode::App004),
            text: ErrorCode::App004.text_in(Lang::En),
            tone: Tone::Danger,
        }]
    );
}

/// spec/04 §2.21: S23's way back is the screen it was opened from; a second open from S23 keeps
/// the first; with nothing recorded it is the mode's home screen. Before S5-9 the shell kept it
/// (`ExtensionUi.back`).
#[test]
fn s23_returns_where_it_was_opened() {
    let section = Screen::Settings(SettingsSection::Other);
    let mut wallet = unlocked(Lang::Ko);
    wallet.screen = section.clone();
    press(&mut wallet, Press::Ext(ExtPress::Open));
    assert_eq!(wallet.screen, Screen::Extension);
    press(&mut wallet, Press::Ext(ExtPress::Open));
    assert_eq!(wallet.screen, Screen::Extension);
    press(&mut wallet, Press::Ext(ExtPress::Back));
    assert_eq!(wallet.screen, section, "back to where it was first opened");

    // Used once: the next way back with nothing recorded is the mode's home screen.
    wallet.screen = Screen::Extension;
    press(&mut wallet, Press::Ext(ExtPress::Back));
    assert_eq!(wallet.screen, Screen::Main, "unlocked");

    let mut wallet = unlocked(Lang::Ko);
    wallet.mode = AppMode::NoVault;
    wallet.screen = Screen::Extension;
    press(&mut wallet, Press::Ext(ExtPress::Back));
    assert_eq!(wallet.screen, Screen::FirstRun, "no vault");
}

/// spec/04 §1.3: a click on the window closes an open drop-down and lays out again; with none
/// open nothing happens. `ClosePickers` closes with no layout, `Relayout` lays out.
#[test]
fn main_steps_close_drop_downs_and_lay_out() {
    let mut wallet = unlocked(Lang::Ko);
    wallet.on_cmd(Cmd::Main(MainStep::Clicked));
    assert_eq!(renders(&mut wallet), 0, "nothing open");

    wallet.account_menu = Some(Press::Links(LinksPress::PickerEvm));
    wallet.on_cmd(Cmd::Main(MainStep::Clicked));
    assert_eq!(wallet.account_menu, None);
    assert_eq!(renders(&mut wallet), 1, "closed and laid out");

    wallet.evm.network_picker = true;
    wallet.on_cmd(Cmd::Main(MainStep::ClosePickers));
    assert!(!wallet.evm.network_picker);
    assert_eq!(renders(&mut wallet), 0, "no layout of its own");

    wallet.on_cmd(Cmd::Main(MainStep::Relayout));
    assert_eq!(renders(&mut wallet), 1);
}
