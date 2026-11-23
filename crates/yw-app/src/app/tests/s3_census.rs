//! S3 characterization (spec/15 §11.4 S3, 2026-11-18): what the main window's logic does for
//! every press, recorded before the `Cmd`/`Effect` split so each S3 commit can prove it changed
//! nothing. Headless: the real `App` without a window, its edits fed through
//! `ControlSet::type_text`, its check boxes through `ControlSet::type_check`, and the shell calls
//! it makes (`refresh`, the send timer, plain copies, edit writes) read from the `cfg(test)`
//! shell-call log of `ControlSet`.
//!
//! Every press starts from a fresh state on the census's own temp folder. Nothing leaves it:
//! `rpc_json_path` and `extension_dir` point into it (AGENTS rules 2 and 4: a press of
//! `rpc.json에서 가져오기` or `rpc.json 지우기` would otherwise read or delete the owner's file),
//! no RPC, `WalletConnect` or LLM worker is ever attached (no connection can start; RPC jobs land
//! in a channel and are named only), explorer links go to `Launcher::Record`, and presses that
//! open a folder, quit or read the clipboard or an image file are skipped ([`SKIPPED`]). The
//! command, edit, check-box and write censuses attach no worker at all: their key queue is
//! drained unrun. The vault-backed A3 steps (the lifecycles of `scenarios.txt`, the dApp-view and
//! no-secret tests) run the real key worker synchronously on the test thread
//! ([`super::Harness`]): Argon2 on the vault files of the census folder, with
//! `yubikey::NoReaders` as the card source (2026-11-18 A1–A3 review).
//!
//! A golden line holds ids, names, counts and hashes only — no address, URL, key or path:
//! before hashing, the census's own paths become `<data>`, `<logs>`, `<ext>`, `<exe>`, `<tmp>`.
//! Regenerate (PowerShell) with `$env:YW_S3_CENSUS_OUT='<folder>'; cargo test -p yw-app --lib
//! s3_census::print --locked --offline -- --ignored` and review the diff; only the S3 phase-A
//! commits may change these files.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};

use super::{App, AppMode, Screen, app_at, unlocked_at};
use crate::app_extension::TOUR_EXTENSION_DIR;
use crate::app_rpc_import::{TEST_RPC_JSON, rpc_json_path};
use crate::explorer_launcher::Launcher;
use crate::ui::command_ids::{fixed, ranges};
use crate::ui::{
    screens, screens_book, screens_btc, screens_evm, screens_explorer, screens_hypercore,
    screens_llm, screens_mnemonics, screens_received, screens_reset, screens_sol,
    screens_walletconnect, screens_yubikey, screens_zec,
};
use yw_engine::meta::Tab;
use yw_engine::screen::SettingsSection;
use yw_engine::testkit::WalletTestExt;
use yw_engine::workers::rpc::RpcJob;

const COMMANDS: &str = include_str!("s3_census/commands.txt");
const EDITS: &str = include_str!("s3_census/edits.txt");
const CHECKS: &str = include_str!("s3_census/checks.txt");
const WRITES: &str = include_str!("s3_census/writes.txt");
const SCENARIOS: &str = include_str!("s3_census/scenarios.txt");

/// The 65 edits of the main window (spec/15 §11.1): 58 plain and the 7 masked credential
/// edits of [`MASKED`].
pub(crate) const EDIT_IDS: [u16; 65] = [
    screens::ids::RENAME_EDIT,
    screens::ids::AUTOLOCK_EDIT,
    screens::ids::QN_NAME_EDIT,
    screens::ids::QN_TOKEN_EDIT,
    screens::ids::ALCHEMY_KEY_EDIT,
    screens::ids::REPLACE_EDIT,
    screens::ids::DONE_QN_EDIT,
    screens_book::ids::ADDR_EDIT,
    screens_book::ids::LABEL_EDIT,
    screens_book::ids::PROMPT_LABEL_EDIT,
    screens_btc::ids::SEND_TO_EDIT,
    screens_btc::ids::SEND_AMOUNT_EDIT,
    screens_btc::ids::FEE_MANUAL_EDIT,
    screens_btc::ids::TYPED_FEE_EDIT,
    screens_btc::ids::BUMP_MANUAL_EDIT,
    screens_btc::ids::BUMP_TYPED_EDIT,
    screens_btc::ids::ESPLORA_MAINNET_EDIT,
    screens_btc::ids::ESPLORA_TESTNET4_EDIT,
    screens_btc::ids::RENAME_EDIT,
    screens_evm::ids::SEND_TO_EDIT,
    screens_evm::ids::SEND_AMOUNT_EDIT,
    screens_evm::ids::TOKEN_ADDR_EDIT,
    screens_evm::ids::TOKEN_LABEL_EDIT,
    screens_evm::ids::CHAIN_ID_EDIT,
    screens_evm::ids::CHAIN_NAME_EDIT,
    screens_evm::ids::CHAIN_SYMBOL_EDIT,
    screens_evm::ids::CHAIN_DECIMALS_EDIT,
    screens_evm::ids::CHAIN_RPC_EDIT,
    screens_evm::ids::CHAIN_EXPLORER_EDIT,
    screens_evm::ids::CAPS_FEE_EDIT,
    screens_evm::ids::CAPS_TIP_EDIT,
    screens_evm::ids::CAPS_TOTAL_EDIT,
    screens_explorer::ids::EDIT_TX,
    screens_explorer::ids::EDIT_ADDRESS,
    screens_hypercore::ids::TO_EDIT,
    screens_hypercore::ids::AMOUNT_EDIT,
    screens_hypercore::ids::API_EDIT,
    screens_llm::ids::ENDPOINT_EDIT,
    screens_llm::ids::MODEL_EDIT,
    screens_llm::ids::MAX_TOKENS_EDIT,
    screens_llm::ids::KEY_EDIT,
    screens_mnemonics::ids::RENAME_EDIT,
    screens_mnemonics::ids::REMOVE_TYPED_EDIT,
    screens_reset::ids::RESET_PHRASE,
    screens_sol::ids::RENAME_EDIT,
    screens_sol::ids::SEND_TO_EDIT,
    screens_sol::ids::SEND_AMOUNT_EDIT,
    screens_sol::ids::FEE_CAP_EDIT,
    screens_sol::ids::CU_PRICE_EDIT,
    screens_walletconnect::ids::URI_EDIT,
    screens_walletconnect::ids::FILE_EDIT,
    screens_walletconnect::ids::PROJECT_EDIT,
    screens_yubikey::ids::SIG_INDEX_EDIT,
    screens_yubikey::ids::AUT_INDEX_EDIT,
    screens_yubikey::ids::SOL_COUNT_EDIT,
    screens_yubikey::ids::SOL_START_EDIT,
    screens_yubikey::ids::RESLOT_SIG_INDEX_EDIT,
    screens_yubikey::ids::RESLOT_AUT_INDEX_EDIT,
    screens_yubikey::ids::CLEAR_CONFIRM_EDIT,
    screens_yubikey::ids::CARD_NAME_EDIT,
    screens_yubikey::ids::RESLOT_LOSS_EDIT,
    screens_yubikey::ids::CLEAR_LOSS_EDIT,
    screens_yubikey::ids::OVERWRITE_EDIT,
    screens_zec::ids::SEND_TO_EDIT,
    screens_zec::ids::SEND_AMOUNT_EDIT,
];

/// The masked credential edits (read once with `text_wiping`, never on `EN_CHANGE`).
pub(crate) const MASKED: [u16; 7] = [
    screens::ids::QN_NAME_EDIT,
    screens::ids::QN_TOKEN_EDIT,
    screens::ids::ALCHEMY_KEY_EDIT,
    screens::ids::REPLACE_EDIT,
    screens::ids::DONE_QN_EDIT,
    screens_evm::ids::CHAIN_RPC_EDIT,
    screens_llm::ids::KEY_EDIT,
];

/// Presses the census never makes: they open a folder (a process), quit, or read the clipboard
/// or an image file. Headless they would do nothing anyway (no window), but a census must not
/// depend on that.
const SKIPPED: [u16; 7] = [
    screens::ids::EXIT,
    screens::ids::OPEN_DATA_FOLDER,
    screens::ids::OPEN_LOG_FOLDER,
    screens_reset::ids::EXT_OPEN_FOLDER,
    screens_walletconnect::ids::CLIPBOARD_QR,
    screens_walletconnect::ids::CLIPBOARD_CONNECT,
    screens_walletconnect::ids::FILE_QR,
];

/// The census's own temp folder; the path overrides point into it while it lives.
pub(crate) struct Census {
    root: PathBuf,
    data: PathBuf,
    /// When kept ([`Census::keep_debug`]): the unhashed `Debug` text of every observation's
    /// items, banners and info, for the no-secret test (T9).
    debug: core::cell::RefCell<Option<Vec<String>>>,
    /// Every control id a press of this census read with `ControlSet::checked`.
    checked: core::cell::RefCell<BTreeSet<u16>>,
}

impl Census {
    pub(crate) fn new(tag: &str) -> Self {
        // One folder per census in this process (tests and their threads run in parallel).
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "yw-s3-census-{tag}-{}-{serial}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let census = Self {
            root,
            data,
            debug: core::cell::RefCell::new(None),
            checked: core::cell::RefCell::default(),
        };
        census.guard();
        census
    }

    /// Points `rpc_json_path` and `extension_dir` into the census folder (thread-locals, set
    /// again before every press) and checks that they stay there.
    pub(crate) fn guard(&self) {
        let rpc_json = self.root.join("rpc.json");
        TEST_RPC_JSON.with(|path| *path.borrow_mut() = Some(rpc_json));
        let ext = self.root.join("extension");
        TOUR_EXTENSION_DIR.with(|dir| *dir.borrow_mut() = Some(ext));
        let path = rpc_json_path().unwrap();
        assert!(path.starts_with(&self.root), "rpc.json outside the census");
        let ext = crate::app_extension::extension_dir().unwrap();
        assert!(
            ext.starts_with(&self.root),
            "extension folder outside the census"
        );
    }

    /// The data folder states are built on (S3 B5: the windowed form test, `ui::tour_forms`,
    /// which is debug-only like the tour; 2026-11-18 S4 A3 review: gated the same way, so
    /// `--release` test builds have no dead code).
    #[cfg(debug_assertions)]
    pub(crate) fn data(&self) -> &std::path::Path {
        &self.data
    }

    /// An empty data folder for the next state (a press may have written settings or keys).
    pub(crate) fn fresh_data(&self) {
        let used =
            std::fs::read_dir(&self.data).map_or(true, |mut entries| entries.next().is_some());
        if used {
            let _ = std::fs::remove_dir_all(&self.data);
            std::fs::create_dir_all(&self.data).unwrap();
        }
    }

    /// A fresh `base` state with an RPC channel; nothing it did while being built is kept.
    pub(crate) fn state(&self, base: Base) -> (App, Receiver<RpcJob>) {
        self.fresh_data();
        self.guard();
        let mut app = base.build(&self.data);
        // 2026-11-20 (S4 P10b): what the build emitted is applied here, so nothing of it is kept.
        app.drain();
        let (tx, rx) = channel();
        app.set_rpc_tx(tx);
        let _ = app.controls.take_shell_log();
        let _ = key_jobs(&app);
        (app, rx)
    }

    /// `text` with the census's machine-dependent paths replaced by fixed tokens (raw and as
    /// `Debug` escapes them).
    pub(crate) fn normalize(&self, text: &str) -> String {
        let mut paths = vec![
            (self.data.join("logs"), "<logs>"),
            (self.data.clone(), "<data>"),
            (self.root.join("extension"), "<ext>"),
        ];
        if let Some(expected) = crate::app_extension::expected_dir() {
            paths.push((expected, "<exe>"));
        }
        paths.push((self.root.clone(), "<tmp>"));
        let mut out = text.to_owned();
        for (path, token) in paths {
            let plain = path.display().to_string();
            let escaped = plain.replace('\\', "\\\\");
            out = out.replace(&escaped, token).replace(&plain, token);
        }
        out
    }

    /// Keeps the unhashed `Debug` text of items, banners and info of every later observation.
    pub(crate) fn keep_debug(&self) {
        *self.debug.borrow_mut() = Some(Vec::new());
    }

    /// The `Debug` text kept since [`Census::keep_debug`].
    pub(crate) fn kept_debug(&self) -> Vec<String> {
        self.debug.borrow_mut().take().unwrap_or_default()
    }

    /// The ids this census's presses read with `ControlSet::checked` (collected by
    /// [`Census::observe`]) since the last call.
    pub(crate) fn checked_reads(&self) -> BTreeSet<u16> {
        self.checked.take()
    }

    /// What the app shows and asked for since the last call.
    pub(crate) fn observe(&self, app: &App, rx: &Receiver<RpcJob>) -> Seen {
        self.observe_with(app, rx, true)
    }

    /// [`Census::observe`]; `keys = false` is a vault-backed step: the key queue is left to the
    /// key worker (`key ~`), and the wall-clock text of the vault file loses its time: the
    /// `vault.ywv` facts line ([`redact_wall_time`]) and a set-aside vault's name
    /// ([`redact_corrupt`]).
    pub(crate) fn observe_with(&self, app: &App, rx: &Receiver<RpcJob>, keys: bool) -> Seen {
        // S3 B5 (debug builds): every credential read so far was captured with its press, with
        // the same units, and the form state never differed from the edits (plan §3.2a).
        #[cfg(debug_assertions)]
        assert_eq!(
            (app.form_mismatch.get(), app.cred_misses()),
            (0, 0),
            "form mismatches, credential misses: {:?}",
            app.controls.take_shell_log()
        );
        let calls = compress(&app.controls.take_shell_log());
        self.checked
            .borrow_mut()
            .extend(app.controls.take_checked_reads());
        let clean = |text: &str| {
            let text = self.normalize(text);
            if keys {
                text
            } else {
                redact_wall_time(&redact_corrupt(&text))
            }
        };
        let items = format!("{:?}", app.items());
        let banners = format!("{:?}", app.banners);
        if let Some(kept) = self.debug.borrow_mut().as_mut() {
            kept.extend([items.clone(), banners.clone()]);
            kept.extend(app.info.clone());
        }
        let items = clean(&items);
        let banners = clean(&banners);
        let info = app.info.as_deref().map(clean);
        // 2026-11-20 (S4 P6): the mark holds the press; its control id is the table's.
        let copied = app.copied.map_or_else(
            || "-".to_owned(),
            |copied| {
                format!(
                    "{}/{}",
                    crate::ui::cmd_table::id_of(copied.anchor),
                    copied.address
                )
            },
        );
        let jobs = if keys { key_jobs(app) } else { Vec::new() };
        let names: Vec<&str> = jobs.iter().map(yw_engine::events::KeyJob::name).collect();
        let rpc: Vec<&str> = rx.try_iter().map(|job| job.name()).collect();
        let launched = match &app.launcher {
            Launcher::Record(urls) => urls.len(),
            Launcher::System => usize::MAX,
        };
        let state = format!(
            "{} | {} | items#{} | banners {} | info {} | copied {} | key {} | rpc {} | launch {}",
            format!("{:?}", app.mode).replace(' ', ""),
            screen_name(&app.screen),
            hash(&items, 16),
            if app.banners.is_empty() {
                "-".to_owned()
            } else {
                format!("{}#{}", app.banners.len(), hash(&banners, 8))
            },
            info.map_or_else(|| "-".to_owned(), |info| hash(&info, 8)),
            copied,
            if keys { list(&names) } else { "~".to_owned() },
            list(&rpc),
            launched,
        );
        Seen {
            state,
            calls: if calls.is_empty() {
                "-".to_owned()
            } else {
                calls
            },
        }
    }
}

/// One observation: the visible state and the job queues, and the shell calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Seen {
    /// Mode, screen, hashes of items, banners and info, the copy mark, jobs, links opened.
    pub(crate) state: String,
    /// The shell calls in order.
    pub(crate) calls: String,
}

impl Seen {
    pub(crate) fn line(&self) -> String {
        format!("{} | {}", self.state, self.calls)
    }
}

impl Drop for Census {
    fn drop(&mut self) {
        TEST_RPC_JSON.with(|path| *path.borrow_mut() = None);
        TOUR_EXTENSION_DIR.with(|dir| *dir.borrow_mut() = None);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// `text` with every local time `YYYY-MM-DD HH:MM` (the `vault.ywv` facts line of S07 and the
/// security settings, `ui::screens::vault_file_text`) replaced by `<time>`.
fn redact_wall_time(text: &str) -> String {
    const SHAPE: &[u8; 16] = b"0000-00-00 00:00";
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut start = 0;
    let mut at = 0;
    while let Some(window) = bytes.get(at..at + SHAPE.len()) {
        let matches = window.iter().zip(SHAPE).all(|(byte, shape)| {
            if *shape == b'0' {
                byte.is_ascii_digit()
            } else {
                byte == shape
            }
        });
        if matches {
            out.push_str(text.get(start..at).unwrap_or_default());
            out.push_str("<time>");
            at += SHAPE.len();
            start = at;
        } else {
            at += 1;
        }
    }
    out.push_str(text.get(start..).unwrap_or_default());
    out
}

/// `text` with the time in a set-aside vault's name (`vault.ywv.corrupt-<time>`) replaced.
fn redact_corrupt(text: &str) -> String {
    const MARK: &str = ".corrupt-";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(MARK) {
        let (head, tail) = rest.split_at(at + MARK.len());
        out.push_str(head);
        out.push_str("<time>");
        rest = tail.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    }
    out.push_str(rest);
    out
}

/// The key jobs queued since the last call (never run: no worker, no card reader).
fn key_jobs(app: &App) -> Vec<yw_engine::events::KeyJob> {
    std::iter::from_fn(|| {
        (!app.key_queue.is_empty())
            .then(|| app.key_queue.pop())
            .flatten()
    })
    .map(|(_, job)| job)
    .collect()
}

fn list(names: &[&str]) -> String {
    if names.is_empty() {
        "-".to_owned()
    } else {
        names.join(",")
    }
}

/// Shell calls in order; a run of equal calls is written once with `*count`.
fn compress(calls: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut index = 0;
    while let Some(call) = calls.get(index) {
        let run = calls
            .get(index..)
            .unwrap_or_default()
            .iter()
            .take_while(|next| *next == call)
            .count();
        out.push(if run > 1 {
            format!("{call}*{run}")
        } else {
            call.clone()
        });
        index += run;
    }
    out.join("; ")
}

/// The first `chars` hex digits of the SHA-256 of `text`.
fn hash(text: &str, chars: usize) -> String {
    let digest = yw_core::codec::sha256(text.as_bytes());
    let mut out = String::new();
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out.truncate(chars);
    out
}

/// The screen's variant; a variant that carries text (an address, a fixed sentence) is named
/// with a hash of its `Debug` instead of the text.
fn screen_name(screen: &Screen) -> String {
    let debug = format!("{screen:?}");
    if debug.contains(['"', ':', '{']) {
        let name: String = debug
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        format!("{name}#{}", hash(&debug, 8))
    } else {
        debug
    }
}

/// A census start state.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Base {
    /// S01: no wallet.
    FirstRun,
    /// S07.
    Locked,
    /// S10 with this tab selected; `true` = a mistyped-passphrase session.
    Main(Tab, bool),
    /// S15 section.
    Settings(SettingsSection),
}

impl Base {
    /// Every state the command census presses in.
    pub(crate) const ALL: [Self; 15] = [
        Self::FirstRun,
        Self::Locked,
        Self::Main(Tab::Evm, false),
        Self::Main(Tab::Sol, false),
        Self::Main(Tab::Btc, false),
        Self::Main(Tab::Zec, false),
        Self::Settings(SettingsSection::Security),
        Self::Settings(SettingsSection::Network),
        Self::Settings(SettingsSection::Other),
        Self::Settings(SettingsSection::Chains),
        Self::Settings(SettingsSection::Solana),
        Self::Settings(SettingsSection::Bitcoin),
        Self::Settings(SettingsSection::Ai),
        Self::Settings(SettingsSection::YubiKey),
        Self::Settings(SettingsSection::Mnemonics),
    ];

    /// The mistyped-passphrase states (only the receive presses are made there).
    pub(crate) const ALT: [Self; 4] = [
        Self::Main(Tab::Evm, true),
        Self::Main(Tab::Sol, true),
        Self::Main(Tab::Btc, true),
        Self::Main(Tab::Zec, true),
    ];

    pub(crate) fn name(self) -> String {
        match self {
            Self::FirstRun => "first".to_owned(),
            Self::Locked => "locked".to_owned(),
            Self::Main(tab, alt) => {
                format!("{}{}", if alt { "alt-" } else { "" }, tab.as_str())
            }
            Self::Settings(section) => format!("set-{section:?}").to_ascii_lowercase(),
        }
    }

    pub(crate) fn build(self, data: &std::path::Path) -> App {
        match self {
            Self::FirstRun => {
                let mut app = app_at(data);
                app.mode = AppMode::NoVault;
                app.screen = Screen::FirstRun;
                app
            }
            Self::Locked => {
                let mut app = app_at(data);
                app.mode = AppMode::Locked;
                app.screen = Screen::Locked;
                app
            }
            Self::Main(tab, alt) => {
                let mut app = unlocked_at(data, alt);
                if let Some(meta) = app.meta.as_mut() {
                    meta.prefs.tab = tab;
                }
                app.settings.bitcoin.enabled = tab == Tab::Btc;
                app.settings.zcash.enabled = tab == Tab::Zec;
                app
            }
            Self::Settings(section) => {
                let mut app = unlocked_at(data, false);
                app.screen = Screen::Settings(section);
                app
            }
        }
    }
}

/// The ids the command census presses: Esc, Enter, every fixed id that is not an edit or
/// skipped, and every id of the first and the last row of every indexed range.
fn command_ids() -> Vec<u16> {
    use crate::app::{IDCANCEL, IDOK};
    let mut ids = vec![IDOK, IDCANCEL];
    for (_, fixed) in fixed() {
        ids.extend(
            fixed
                .iter()
                .copied()
                .filter(|id| !EDIT_IDS.contains(id) && !SKIPPED.contains(id)),
        );
    }
    for range in ranges() {
        let last = range.max_rows.saturating_sub(1);
        for row in [0, last] {
            for offset in 0..range.stride {
                let row = u16::try_from(row).unwrap();
                ids.push(range.base + row * range.stride + offset);
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// One state's section of a golden: its base line, a line for every press that changed what
/// the state shows or queued, and the presses that did not, grouped by their shell calls.
pub(crate) fn section(out: &mut String, census: &Census, base: Base, ids: &[u16], press: PressFn) {
    let name = base.name();
    let (app, rx) = census.state(base);
    let start = census.observe(&app, &rx);
    drop(app);
    let _ = writeln!(out, "## {name} | {}", start.line());
    // Presses that left the state as it was, by their shell calls.
    let mut same: std::collections::BTreeMap<String, Vec<u16>> = std::collections::BTreeMap::new();
    for &id in ids {
        let (mut app, rx) = census.state(base);
        press(&mut app, id);
        let seen = census.observe(&app, &rx);
        drop(app);
        census.guard();
        // `LOG_*` presses need no restore: `logging::set_level` changes nothing until
        // `logging::install` ran, and only the release logger (`log_file.rs`) installs one.
        if seen.state == start.state {
            same.entry(seen.calls).or_default().push(id);
        } else {
            let _ = writeln!(out, "{name} {id} | {}", seen.line());
        }
    }
    for (calls, ids) in same {
        for chunk in ids.chunks(16) {
            let ids: Vec<String> = chunk.iter().map(u16::to_string).collect();
            let _ = writeln!(out, "{name} = {calls} : {}", ids.join(" "));
        }
    }
}

/// How a census presses an id on a state.
pub(crate) type PressFn = fn(&mut App, u16);

/// The sections of `bases` in order, each built on its own thread with its own census folder;
/// the ids their presses read with `ControlSet::checked` are added to `checked`.
pub(crate) fn sections(
    tag: &str,
    bases: &[Base],
    ids: &[u16],
    press: PressFn,
    checked: &mut BTreeSet<u16>,
) -> String {
    let parts: Vec<(String, BTreeSet<u16>)> = std::thread::scope(|scope| {
        let workers: Vec<_> = bases
            .iter()
            .map(|&base| {
                scope.spawn(move || {
                    let census = Census::new(&format!("{tag}-{}", base.name()));
                    let mut out = String::new();
                    section(&mut out, &census, base, ids, press);
                    (out, census.checked_reads())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    });
    let mut out = String::new();
    for (text, read) in parts {
        out.push_str(&text);
        checked.extend(read);
    }
    out
}

/// T2: every press on every census state.
fn commands_golden(checked: &mut BTreeSet<u16>) -> String {
    let ids = command_ids();
    let mut out = String::from(
        "# S3 command census (2026-11-18, spec/15 §11.4 S3): state id | mode | screen | items | \
         banners | info | copied | key jobs | rpc jobs | links opened | shell calls\n",
    );
    out.push_str(&sections(
        "commands",
        &Base::ALL,
        &ids,
        App::on_command,
        checked,
    ));
    // The receive presses where the passphrase was mistyped (they are refused there).
    out.push_str(&sections(
        "commands",
        &Base::ALT,
        &screens::RECEIVE_IDS,
        App::on_command,
        checked,
    ));
    out
}

/// Compares a generated golden with the committed one; on a difference the generated text is
/// written next to the census folders (temp) and the first differing line is named.
pub(crate) fn compare(name: &str, generated: &str, committed: &str) {
    if generated != committed {
        let out = std::env::temp_dir().join(format!("yw-s3-census-{name}.actual.txt"));
        let _ = std::fs::write(&out, generated);
    }
    let line = generated
        .lines()
        .zip(committed.lines())
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| generated.lines().count().min(committed.lines().count()));
    assert!(
        generated == committed,
        "{name}: line {} differs (generated {} lines, committed {}); the generated file is in \
         the temp folder: {:?} vs {:?}",
        line + 1,
        generated.lines().count(),
        committed.lines().count(),
        generated.lines().nth(line),
        committed.lines().nth(line)
    );
}

#[test]
fn edit_ids_are_the_65_fixed_edits() {
    let mut seen = std::collections::BTreeSet::new();
    for id in EDIT_IDS {
        assert!(seen.insert(id), "{id} twice");
        assert!(
            fixed().iter().any(|(_, ids)| ids.contains(&id)),
            "{id} not a fixed id"
        );
    }
    assert!(MASKED.iter().all(|id| EDIT_IDS.contains(id)));
    // Every edit any census state shows is listed.
    let census = Census::new("edits-listed");
    for base in Base::ALL {
        let (app, _rx) = census.state(base);
        for ctl in super::controls(&app.items()) {
            if matches!(ctl.kind, yw_win::ui::controls::ControlKind::Edit { .. }) {
                assert!(EDIT_IDS.contains(&ctl.id), "{base:?}: edit {}", ctl.id);
            }
        }
    }
}

/// T2 (S3 A1): the command census matches `s3_census/commands.txt`.
#[test]
fn command_census_matches_the_golden() {
    let mut checked = BTreeSet::new();
    compare("commands", &commands_golden(&mut checked), COMMANDS);
    assert_checks_listed("commands", &checked);
}

/// Every id a census press read with `ControlSet::checked` is in [`CHECK_IDS`] (2026-11-18 A1–A3
/// review): a check box missed there, or added later, would otherwise drop out of `checks.txt`,
/// the golden that keeps the check-box state of a press exact (plan D-k).
fn assert_checks_listed(census: &str, checked: &BTreeSet<u16>) {
    for id in checked {
        assert!(
            CHECK_IDS.contains(id),
            "{census}: {id} is read with `checked` but is not in CHECK_IDS"
        );
    }
}

/// Regenerates every golden of this module into `YW_S3_CENSUS_OUT` (a folder).
#[test]
#[ignore = "regenerates the S3 census goldens"]
fn print() {
    let out = PathBuf::from(std::env::var_os("YW_S3_CENSUS_OUT").expect("YW_S3_CENSUS_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let mut checked = BTreeSet::new();
    std::fs::write(out.join("commands.txt"), commands_golden(&mut checked)).unwrap();
    std::fs::write(out.join("edits.txt"), edits_golden(&mut checked)).unwrap();
    std::fs::write(out.join("checks.txt"), checks_golden(&mut checked)).unwrap();
    std::fs::write(out.join("writes.txt"), writes_golden()).unwrap();
    std::fs::write(out.join("scenarios.txt"), scenarios_golden()).unwrap();
}

// ----- A2: edits, check boxes, programmatic writes ---------------------------------------

/// The 21 check boxes and radios whose handler reads `ControlSet::checked` (spec/15 §11.1).
pub(crate) const CHECK_IDS: [u16; 21] = [
    screens::ids::MISMATCH_CHECK,
    screens::ids::COPY_TOGGLE,
    screens::ids::LOCALHOST_TOGGLE,
    screens::ids::AUTOLAUNCH_TOGGLE,
    screens::ids::OVERWRITE_CHECK,
    screens_book::ids::VERIFIED,
    screens_book::ids::FAVORITE,
    screens_book::ids::FORM_ACK,
    screens_book::ids::PROMPT_ACK,
    screens_evm::ids::TOKEN_HIDE_ZERO,
    screens_evm::ids::SEND_ACK,
    screens_evm::ids::REPIN_CHECK,
    screens_llm::ids::NOTICE_CHECK,
    screens_llm::ids::ENABLE,
    screens_received::ids::TOGGLE_BASE,
    screens_received::ids::TOGGLE_BASE + 1,
    screens_received::ids::TOGGLE_BASE + 2,
    screens_received::ids::TOGGLE_BASE + 3,
    screens_received::ids::TOGGLE_BASE + 4,
    screens_reset::ids::RESET_SETTINGS_CHECK,
    crate::ui::screens_sidecar::ids::RESET_ACK,
];

/// The edits Enter presses a button from (`enter_primary`), except the image-file path, whose
/// button reads a file.
pub(crate) const ENTER_EDITS: [u16; 31] = [
    screens::ids::RENAME_EDIT,
    screens::ids::AUTOLOCK_EDIT,
    screens::ids::REPLACE_EDIT,
    screens::ids::DONE_QN_EDIT,
    screens_book::ids::ADDR_EDIT,
    screens_book::ids::LABEL_EDIT,
    screens_book::ids::PROMPT_LABEL_EDIT,
    screens_btc::ids::SEND_TO_EDIT,
    screens_btc::ids::SEND_AMOUNT_EDIT,
    screens_btc::ids::FEE_MANUAL_EDIT,
    screens_btc::ids::RENAME_EDIT,
    screens_evm::ids::SEND_TO_EDIT,
    screens_evm::ids::SEND_AMOUNT_EDIT,
    screens_evm::ids::TOKEN_ADDR_EDIT,
    screens_evm::ids::TOKEN_LABEL_EDIT,
    screens_explorer::ids::EDIT_TX,
    screens_explorer::ids::EDIT_ADDRESS,
    screens_llm::ids::ENDPOINT_EDIT,
    screens_llm::ids::MODEL_EDIT,
    screens_llm::ids::MAX_TOKENS_EDIT,
    screens_llm::ids::KEY_EDIT,
    screens_mnemonics::ids::RENAME_EDIT,
    screens_sol::ids::RENAME_EDIT,
    screens_sol::ids::SEND_TO_EDIT,
    screens_sol::ids::SEND_AMOUNT_EDIT,
    screens_walletconnect::ids::URI_EDIT,
    screens_walletconnect::ids::PROJECT_EDIT,
    screens_yubikey::ids::CARD_NAME_EDIT,
    screens_zec::ids::SEND_TO_EDIT,
    screens_zec::ids::SEND_AMOUNT_EDIT,
    screens_walletconnect::ids::FILE_EDIT,
];

fn type_one(app: &mut App, id: u16) {
    app.controls.type_text(id, "1");
    app.on_edit_notify(id);
}

fn type_x(app: &mut App, id: u16) {
    app.controls.type_text(id, "x");
    app.on_edit_notify(id);
}

/// Enter in edit `id` as the window delivers it: only when the edit is shown.
fn enter_shown(app: &mut App, id: u16) {
    if let Some(ctl) = super::ctl(&app.items(), id) {
        app.enter_on(Some(&ctl));
    }
}

fn check_on(app: &mut App, id: u16) {
    app.controls.type_check(id, true);
    app.on_command(id);
}

fn check_off(app: &mut App, id: u16) {
    app.controls.type_check(id, false);
    app.on_command(id);
}

/// T3: every edit typed and notified (`EN_CHANGE`) on every census state, then Enter in every
/// edit Enter presses from.
fn edits_golden(checked: &mut BTreeSet<u16>) -> String {
    let mut ids = EDIT_IDS.to_vec();
    ids.sort_unstable();
    let mut out = String::from(
        "# S3 edit census (2026-11-18): type + EN_CHANGE of every edit, then Enter (shown edits \
         only); fields as in commands.txt\n",
    );
    let typing: [(&str, PressFn); 2] = [("1", type_one), ("x", type_x)];
    for (value, press) in typing {
        let _ = writeln!(out, "# type \"{value}\"");
        out.push_str(&sections("edits", &Base::ALL, &ids, press, checked));
    }
    let mut enter: Vec<u16> = ENTER_EDITS
        .iter()
        .copied()
        .filter(|id| *id != screens_walletconnect::ids::FILE_EDIT)
        .collect();
    enter.sort_unstable();
    let _ = writeln!(out, "# enter");
    out.push_str(&sections("edits", &Base::ALL, &enter, enter_shown, checked));
    out
}

/// T4: every check box read with `checked`, pressed checked, unchecked and without a state.
fn checks_golden(checked: &mut BTreeSet<u16>) -> String {
    let mut ids = CHECK_IDS.to_vec();
    ids.sort_unstable();
    let mut out = String::from(
        "# S3 check-box census (2026-11-18): the press with the box checked, unchecked, and with \
         no state (`checked` = None); fields as in commands.txt\n",
    );
    let variants: [(&str, PressFn); 3] = [
        ("on", check_on),
        ("off", check_off),
        ("none", App::on_command),
    ];
    for (name, press) in variants {
        let _ = writeln!(out, "# check {name}");
        out.push_str(&sections("checks", &Base::ALL, &ids, press, checked));
    }
    out
}

/// One input of a scenario.
#[derive(Clone, Copy)]
pub(crate) enum Step {
    /// A click (`WM_COMMAND` code 0).
    Press(u16),
    /// Text typed into an edit, then its `EN_CHANGE`.
    Type(u16, &'static str),
    /// The same with text built at run time (addresses, credential shapes).
    TypeWith(u16, fn() -> String),
    /// A check box or radio set, then its click.
    Check(u16, bool),
    /// Enter in a shown edit.
    Enter(u16),
    /// A state change the window cannot make (a balance, a quote that arrived).
    Call(&'static str, fn(&mut App)),
}

impl Step {
    /// Runs the step; the golden's description (ids, lengths, names; never the text).
    pub(crate) fn run(self, app: &mut App) -> String {
        match self {
            Self::Press(id) => {
                app.on_command(id);
                format!("press {id}")
            }
            Self::Type(id, text) => Self::typed(app, id, text),
            Self::TypeWith(id, text) => Self::typed(app, id, &text()),
            Self::Check(id, checked) => {
                app.controls.type_check(id, checked);
                app.on_command(id);
                format!("check {id} {checked}")
            }
            Self::Enter(id) => match super::ctl(&app.items(), id) {
                Some(ctl) => {
                    app.enter_on(Some(&ctl));
                    format!("enter {id}")
                }
                None => format!("enter {id} (not shown)"),
            },
            Self::Call(name, call) => {
                call(app);
                format!("call {name}")
            }
        }
    }

    fn typed(app: &mut App, id: u16, text: &str) -> String {
        app.controls.type_text(id, text);
        app.on_edit_notify(id);
        format!("type {id} len={}", text.encode_utf16().count())
    }
}

/// A sequence of inputs from a census state.
pub(crate) struct Scenario {
    pub(crate) name: &'static str,
    pub(crate) base: Base,
    pub(crate) setup: fn(&mut App),
    pub(crate) steps: Vec<Step>,
}

/// Runs `scenario` on `census`: one golden line for the setup and one per step.
pub(crate) fn run_scenario(out: &mut String, census: &Census, scenario: &Scenario) {
    let (mut app, rx) = census.state(scenario.base);
    // 2026-11-20 (S4 P10b): the setup and each step are one entry each: what they emitted is
    // applied (and answered) before the observation, as when `emit` applied each effect at once.
    (scenario.setup)(&mut app);
    app.drain();
    let seen = census.observe(&app, &rx);
    let _ = writeln!(out, "{} 0 setup | {}", scenario.name, seen.line());
    for (index, step) in scenario.steps.iter().enumerate() {
        let what = step.run(&mut app);
        app.drain();
        let seen = census.observe(&app, &rx);
        let _ = writeln!(
            out,
            "{} {} {what} | {}",
            scenario.name,
            index + 1,
            seen.line()
        );
    }
    drop(app);
    census.guard();
}

pub(crate) fn no_setup(_: &mut App) {}

/// The `abandon … about` vector's EVM account 1 (public test data).
const EVM_TO: &str = "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0";
/// The same vector's first BIP84 mainnet receive address (public test data).
const BTC_TO: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
/// A token-shaped value (not a real token).
const QN_TOKEN: &str = "abcdef0123456789abcdef0123456789";

fn sol_to() -> String {
    yw_core::sol::SolAddress::from_bytes([9; 32]).to_base58()
}

fn qn_url() -> String {
    format!("https://my-node.quiknode.pro/{QN_TOKEN}/")
}

fn qn_token() -> String {
    QN_TOKEN.to_owned()
}

fn alchemy_key() -> String {
    "alchemyTestKey0123456789abcdefAB".to_owned()
}

fn llm_key() -> String {
    "test-llm-key-0123456789abcdef".to_owned()
}

fn rpc_url() -> String {
    "https://rpc.example.test/v1".to_owned()
}

pub(crate) fn done_screen(app: &mut App) {
    app.done_imported = true;
    app.set_screen(Screen::Done);
}

/// A Bitcoin mainnet wallet with an endpoint and room in the journal.
pub(crate) fn btc_wallet(app: &mut App) {
    use yw_core::btc::BtcNetwork;
    app.settings.bitcoin.enabled = true;
    app.settings.bitcoin.network = yw_engine::network::BtcNet::Mainnet;
    let account = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(
            "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
        )
        .unwrap(),
        chain_code: [7; 32],
    };
    if let Some(meta) = app.meta.as_mut() {
        meta.btc = Some(Box::new(yw_core::btc::meta::BtcMeta::new(
            BtcNetwork::Mainnet,
            account,
        )));
        meta.prefs.tab = yw_engine::meta::Tab::Btc;
    }
    app.apikeys.set_rpc(
        yw_engine::network::NetworkId::Bitcoin(yw_engine::network::BtcNet::Mainnet),
        &yw_platform::http::HttpsUrl::parse("https://btc.example.test/").unwrap(),
    );
    app.evm.journal = Some(yw_engine::events::JournalView {
        room: true,
        sol_room: true,
        btc_room: true,
        ..yw_engine::events::JournalView::default()
    });
}

/// A native balance of the selected EVM account and a quote for it (as the RPC worker answers).
pub(crate) fn evm_quote(app: &mut App) {
    use yw_core::evm::amount::U256;
    let chain = app.settings.evm_chain_id;
    let owner =
        yw_core::evm::address::parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
    app.evm.balances.insert(
        chain,
        yw_engine::wallet::app_evm::BalanceState {
            snapshot: Some(yw_engine::events::BalanceSnapshot {
                block: 7,
                native: vec![(owner, U256::from_u64(5_000_000_000_000_000))],
                tokens: Vec::new(),
                token_owner: owner,
            }),
            ..yw_engine::wallet::app_evm::BalanceState::default()
        },
    );
    app.evm.send.quote = Some(yw_engine::flow::evm::form::Quote {
        gas_limit: 21_000,
        max_fee_per_gas: U256::from_u64(3_000_000_000),
        max_total: U256::from_u64(63_000_000_000_000),
        cap_violation: None,
        estimate_failed: false,
    });
}

/// The selected EVM account's `HyperCore` balances and a withdrawal form (S-HC).
pub(crate) fn hc_withdraw(app: &mut App) {
    let owner =
        yw_core::evm::address::parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
    app.settings.hypercore.enabled = true;
    app.hypercore.balances = Some((
        yw_core::hypercore::HcNetwork::Mainnet,
        owner,
        yw_engine::hypercore::HcBalances {
            spot: Vec::new(),
            perp: yw_core::hypercore::HcPerpState {
                account_value: "100.0".to_owned(),
                withdrawable: "100.0".to_owned(),
                positions: 0,
            },
        },
    ));
    app.hypercore.form = yw_engine::wallet::app_hypercore::HcForm {
        kind: yw_engine::wallet::app_hypercore::HcFormKind::Withdraw,
        ..yw_engine::wallet::app_hypercore::HcForm::default()
    };
    app.screen = Screen::HyperCore;
}

/// T5: scenarios that reach every programmatic edit write (`set_text` ×13, `clear_text` ×11)
/// and Enter in the forms they open, the masked credential edits included.
#[expect(clippy::too_many_lines, reason = "one scenario per write site")]
pub(crate) fn write_scenarios() -> Vec<Scenario> {
    use crate::ui::{screens_book as book, screens_btc as btc, screens_evm as evm};
    use crate::ui::{screens_hypercore as hc, screens_llm as llm, screens_sol as sol};
    use Step::{Call, Check, Enter, Press, Type, TypeWith};
    vec![
        Scenario {
            name: "llm-preset",
            base: Base::Settings(SettingsSection::Ai),
            setup: no_setup,
            steps: vec![
                Press(llm::ids::PRESET_OPENAI),
                Press(llm::ids::PRESET_OLLAMA),
            ],
        },
        Scenario {
            name: "llm-key-save",
            base: Base::Settings(SettingsSection::Ai),
            setup: no_setup,
            steps: vec![
                TypeWith(llm::ids::KEY_EDIT, llm_key),
                Press(llm::ids::KEY_SAVE),
                Press(llm::ids::KEY_DELETE),
            ],
        },
        Scenario {
            name: "llm-key-enter",
            base: Base::Settings(SettingsSection::Ai),
            setup: no_setup,
            steps: vec![
                TypeWith(llm::ids::KEY_EDIT, llm_key),
                Enter(llm::ids::KEY_EDIT),
                Type(llm::ids::MODEL_EDIT, "test-model"),
                Enter(llm::ids::MODEL_EDIT),
            ],
        },
        Scenario {
            name: "template-quicknode",
            base: Base::Settings(SettingsSection::Network),
            setup: no_setup,
            steps: vec![
                Press(screens::ids::TPL_QUICKNODE),
                Type(screens::ids::QN_NAME_EDIT, "my-node"),
                TypeWith(screens::ids::QN_TOKEN_EDIT, qn_token),
                Press(screens::ids::TPL_SAVE),
            ],
        },
        Scenario {
            name: "template-alchemy",
            base: Base::Settings(SettingsSection::Network),
            setup: no_setup,
            steps: vec![
                Press(screens::ids::TPL_ALCHEMY),
                TypeWith(screens::ids::ALCHEMY_KEY_EDIT, alchemy_key),
                Press(screens::ids::GENERATE),
            ],
        },
        Scenario {
            name: "rpc-replace",
            base: Base::Settings(SettingsSection::Network),
            setup: no_setup,
            steps: vec![
                Press(screens::ids::ROW_BASE),
                TypeWith(screens::ids::REPLACE_EDIT, rpc_url),
                Press(screens::ids::ROW_BASE + 1),
                Press(screens::ids::REPLACE_SAVE),
            ],
        },
        Scenario {
            name: "rpc-replace-enter",
            base: Base::Settings(SettingsSection::Network),
            setup: no_setup,
            steps: vec![
                Press(screens::ids::ROW_BASE),
                TypeWith(screens::ids::REPLACE_EDIT, rpc_url),
                Enter(screens::ids::REPLACE_EDIT),
            ],
        },
        Scenario {
            name: "done-connect",
            base: Base::Main(Tab::Evm, false),
            setup: done_screen,
            steps: vec![
                Press(screens::ids::DONE_CONNECT),
                TypeWith(screens::ids::DONE_QN_EDIT, qn_url),
                Press(screens::ids::DONE_CONNECT),
            ],
        },
        Scenario {
            name: "done-connect-enter",
            base: Base::Main(Tab::Evm, false),
            setup: done_screen,
            steps: vec![
                TypeWith(screens::ids::DONE_QN_EDIT, qn_url),
                Enter(screens::ids::DONE_QN_EDIT),
            ],
        },
        Scenario {
            name: "chain-save",
            base: Base::Settings(SettingsSection::Chains),
            setup: no_setup,
            steps: vec![
                Press(evm::ids::CHAIN_ADD),
                Type(evm::ids::CHAIN_ID_EDIT, "31337"),
                Type(evm::ids::CHAIN_NAME_EDIT, "Local Test"),
                Type(evm::ids::CHAIN_SYMBOL_EDIT, "TST"),
                Type(evm::ids::CHAIN_DECIMALS_EDIT, "18"),
                TypeWith(evm::ids::CHAIN_RPC_EDIT, rpc_url),
                Type(
                    evm::ids::CHAIN_EXPLORER_EDIT,
                    "https://explorer.example.test/",
                ),
                Press(evm::ids::CHAIN_SAVE),
            ],
        },
        Scenario {
            name: "book-evm",
            base: Base::Main(Tab::Evm, false),
            setup: no_setup,
            steps: vec![
                Press(evm::ids::BOOK_OPEN),
                Press(book::ids::ADD_OPEN),
                Type(book::ids::ADDR_EDIT, EVM_TO),
                Type(book::ids::LABEL_EDIT, "Friend"),
                Check(book::ids::VERIFIED, true),
                Check(book::ids::FAVORITE, true),
                Press(book::ids::SAVE),
                Press(evm::ids::SEND_OPEN),
                Press(book::ids::FAV_BASE),
                Press(evm::ids::SEND_PICK),
                Press(evm::ids::SEND_PICK_BASE),
                Type(evm::ids::SEND_AMOUNT_EDIT, "0.001"),
                Enter(evm::ids::SEND_AMOUNT_EDIT),
                Enter(evm::ids::SEND_TO_EDIT),
            ],
        },
        Scenario {
            name: "book-cancel",
            base: Base::Main(Tab::Evm, false),
            setup: no_setup,
            steps: vec![
                Press(evm::ids::BOOK_OPEN),
                Press(book::ids::ADD_OPEN),
                Type(book::ids::ADDR_EDIT, EVM_TO),
                Type(book::ids::LABEL_EDIT, "Friend"),
                Enter(book::ids::LABEL_EDIT),
                Press(book::ids::ADD_OPEN),
                Type(book::ids::ADDR_EDIT, "0x12"),
                Press(book::ids::CANCEL),
            ],
        },
        Scenario {
            name: "book-sol",
            base: Base::Main(Tab::Sol, false),
            setup: no_setup,
            steps: vec![
                Press(evm::ids::BOOK_OPEN),
                Press(book::ids::CHAIN_SOL),
                Press(book::ids::ADD_OPEN),
                TypeWith(book::ids::ADDR_EDIT, sol_to),
                Type(book::ids::LABEL_EDIT, "Friend"),
                Check(book::ids::VERIFIED, true),
                Check(book::ids::FAVORITE, true),
                Press(book::ids::SAVE),
                Press(sol::ids::SEND_OPEN),
                Press(book::ids::FAV_BASE),
                Press(sol::ids::SEND_PICK),
                Press(sol::ids::SEND_PICK_BASE),
                Press(sol::ids::SEND_MAX),
                Enter(sol::ids::SEND_TO_EDIT),
            ],
        },
        Scenario {
            name: "book-btc",
            base: Base::Main(Tab::Btc, false),
            setup: btc_wallet,
            steps: vec![
                Press(evm::ids::BOOK_OPEN),
                Press(book::ids::CHAIN_BTC),
                Press(book::ids::ADD_OPEN),
                Type(book::ids::ADDR_EDIT, BTC_TO),
                Type(book::ids::LABEL_EDIT, "Friend"),
                Check(book::ids::VERIFIED, true),
                Check(book::ids::FAVORITE, true),
                Press(book::ids::SAVE),
                Press(btc::ids::SEND_OPEN),
                Press(book::ids::FAV_BASE),
                Type(btc::ids::SEND_AMOUNT_EDIT, "0.0012"),
                Press(btc::ids::UNIT_SATS),
                Press(btc::ids::UNIT_BTC),
                Press(btc::ids::SEND_MAX),
                Enter(btc::ids::SEND_TO_EDIT),
            ],
        },
        Scenario {
            name: "btc-esplora",
            base: Base::Settings(SettingsSection::Bitcoin),
            setup: no_setup,
            steps: vec![
                Type(
                    btc::ids::ESPLORA_MAINNET_EDIT,
                    "https://esplora.example.test/api",
                ),
                Press(btc::ids::ESPLORA_MAINNET_SAVE),
                Press(btc::ids::ESPLORA_MAINNET_DEFAULT),
                Type(btc::ids::ESPLORA_TESTNET4_EDIT, "x"),
                Press(btc::ids::ESPLORA_TESTNET4_SAVE),
                Press(btc::ids::ESPLORA_TESTNET4_DEFAULT),
            ],
        },
        Scenario {
            name: "evm-send-max",
            base: Base::Main(Tab::Evm, false),
            setup: no_setup,
            steps: vec![
                Press(evm::ids::SEND_OPEN),
                Call("quote", evm_quote),
                Press(evm::ids::SEND_MAX),
            ],
        },
        Scenario {
            name: "hc-max",
            base: Base::Main(Tab::Evm, false),
            setup: hc_withdraw,
            steps: vec![Press(hc::ids::MAX)],
        },
    ]
}

fn writes_golden() -> String {
    let census = Census::new("writes");
    let mut out = String::from(
        "# S3 programmatic writes (2026-11-18): scenario step what | fields as in commands.txt\n",
    );
    for scenario in write_scenarios() {
        run_scenario(&mut out, &census, &scenario);
    }
    out
}

/// The masked credential edits are read once when their button is pressed: their `EN_CHANGE`
/// changes nothing on any state.
#[test]
fn masked_edits_change_nothing_on_en_change() {
    let census = Census::new("masked");
    for base in Base::ALL {
        for id in MASKED {
            let (mut app, rx) = census.state(base);
            let start = census.observe(&app, &rx);
            app.controls.type_text(id, "cred-shaped-value-0123456789");
            app.on_edit_notify(id);
            let seen = census.observe(&app, &rx);
            assert_eq!(seen.state, start.state, "{base:?} {id}");
            assert_eq!(seen.calls, "-", "{base:?} {id}");
        }
    }
}

/// The census's id lists match the code: `ENTER_EDITS` are exactly the edits `enter_primary`
/// maps, and no check box is listed twice or as an edit (that `CHECK_IDS` are exactly the ids
/// the code reads with `checked`: the commands, edits and checks census tests).
#[test]
fn enter_and_check_lists_match_the_code() {
    for id in EDIT_IDS {
        assert_eq!(
            crate::app::enter_primary(id).is_some(),
            ENTER_EDITS.contains(&id),
            "{id}"
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in CHECK_IDS {
        assert!(seen.insert(id), "{id} twice");
        assert!(!EDIT_IDS.contains(&id));
    }
}

/// Table test (5), S3 B5: no check box (its state travels with its click, plan D-k) is the
/// target of a press the logic makes itself — Enter's primary button, the tab and F5/Ctrl+,
/// shortcuts, or Esc's cancel and back buttons (`App::tab_shortcut`, `App::shortcut`,
/// `App::escape_key`). 2026-11-18 (B4–B5 review): the lists are the code's own
/// (`app::logic_presses`), not a copy, so a check box added to one fails here.
#[test]
fn no_check_box_is_pressed_by_the_logic() {
    let inner: Vec<u16> = crate::app::logic_presses::ALL
        .iter()
        .flat_map(|ids| ids.iter().copied())
        .collect();
    assert_eq!(inner.len(), 27);
    for id in inner {
        assert!(!CHECK_IDS.contains(&id), "{id}");
    }
    for id in EDIT_IDS {
        if let Some(primary) = crate::app::enter_primary(id) {
            assert!(!CHECK_IDS.contains(&primary), "{id} → {primary}");
        }
    }
}

/// Table test (8), S3 B5 (debug builds): every credential read happens in a press that
/// captured that field, with the same units (the census asserts 0 misses and mismatches on
/// every observation), and every (press, field) pair `cmd_table::creds_for` lists is reached by
/// one of these scenarios — the write scenarios plus the template and test presses they do not
/// make. A network row's `테스트` counts once (row 0).
#[cfg(debug_assertions)]
#[test]
fn credential_capture_covers_every_read() {
    use crate::ui::cmd_table::creds_for;
    use Step::{Call, Press, Type, TypeWith};
    use yw_engine::form::CredField;
    use yw_engine::network::NetworkId;
    fn replace_evm(app: &mut App) {
        app.replace_target = Some(NetworkId::Eip155(app.settings.evm_chain_id));
    }
    fn replace_sol(app: &mut App) {
        app.replace_target = Some(NetworkId::Solana(app.settings.solana.cluster));
    }
    let network = Base::Settings(SettingsSection::Network);
    let mut scenarios = write_scenarios();
    scenarios.extend([
        Scenario {
            name: "template-quicknode-generate",
            base: network,
            setup: no_setup,
            steps: vec![
                Press(screens::ids::TPL_QUICKNODE),
                Type(screens::ids::QN_NAME_EDIT, "my-node"),
                TypeWith(screens::ids::QN_TOKEN_EDIT, qn_token),
                Press(screens::ids::GENERATE),
            ],
        },
        Scenario {
            name: "template-alchemy-save",
            base: network,
            setup: no_setup,
            steps: vec![
                Press(screens::ids::TPL_ALCHEMY),
                TypeWith(screens::ids::ALCHEMY_KEY_EDIT, alchemy_key),
                Press(screens::ids::TPL_SAVE),
            ],
        },
        Scenario {
            name: "rpc-test-cards",
            base: network,
            setup: no_setup,
            steps: vec![
                Call("replace evm", replace_evm),
                TypeWith(screens::ids::REPLACE_EDIT, rpc_url),
                Press(screens::ids::EVM_RPC_TEST),
                Call("replace sol", replace_sol),
                TypeWith(screens::ids::REPLACE_EDIT, rpc_url),
                Press(screens::ids::SOL_RPC_TEST),
            ],
        },
    ]);
    let census = Census::new("creds");
    let mut reached: BTreeSet<(u16, String)> = BTreeSet::new();
    for scenario in &scenarios {
        let (mut app, rx) = census.state(scenario.base);
        (scenario.setup)(&mut app);
        app.drain();
        for step in &scenario.steps {
            step.run(&mut app);
            app.drain();
            let _ = census.observe(&app, &rx);
        }
        for (id, field) in app.cred_reads.drain(..) {
            reached.insert((id, format!("{field:?}")));
        }
        drop(app);
        census.guard();
    }
    let row_test = screens::ids::ROW_BASE + 1;
    let mut listed: BTreeSet<(u16, String)> = BTreeSet::new();
    for (_, ids) in fixed() {
        for &id in ids {
            for field in creds_for(id) {
                listed.insert((id, format!("{field:?}")));
            }
        }
    }
    listed.insert((row_test, format!("{:?}", CredField::RpcReplace)));
    // `TPL_SAVE`/`GENERATE` read the fields of the chosen template only; both templates ran.
    assert_eq!(reached, listed);
}

/// T3 (S3 A2): `s3_census/edits.txt`.
#[test]
fn edit_census_matches_the_golden() {
    let mut checked = BTreeSet::new();
    compare("edits", &edits_golden(&mut checked), EDITS);
    assert_checks_listed("edits", &checked);
}

/// T4 (S3 A2): `s3_census/checks.txt`; each of [`CHECK_IDS`] is read with `checked` when it is
/// pressed on some census state, and no other id is (with the commands and edits censuses, which
/// assert the same for every other press: [`assert_checks_listed`]).
#[test]
fn check_census_matches_the_golden() {
    let mut checked = BTreeSet::new();
    compare("checks", &checks_golden(&mut checked), CHECKS);
    let listed: BTreeSet<u16> = CHECK_IDS.into_iter().collect();
    assert_eq!(checked, listed);
}

/// T5 (S3 A2): `s3_census/writes.txt`.
#[test]
fn write_scenarios_match_the_golden() {
    compare("writes", &writes_golden(), WRITES);
}

// ----- A3: send timer, copy, dApp view, no secrets, lifecycle --------------------------

/// The secp256k1 generator, compressed (a public constant; a Zcash transparent test key).
const GENERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// A Zcash mainnet account of the default source.
pub(crate) fn zec_wallet(app: &mut App) {
    use yw_core::zec::{ZecAccount, ZecKeySource, ZecNetwork};
    app.settings.zcash.enabled = true;
    app.settings.zcash.network = ZecNetwork::Mainnet;
    let pubkey = yw_core::hex::decode_array::<33>(GENERATOR).unwrap();
    if let Some(meta) = app.meta.as_mut() {
        meta.prefs.tab = Tab::Zec;
        meta.zcash.set(ZecAccount {
            network: ZecNetwork::Mainnet,
            source: ZecKeySource::DEFAULT,
            pubkey,
        });
    }
}

/// [`btc_wallet`] whose account already gave out receive address 0 (the card shows it).
pub(crate) fn btc_wallet_with_address(app: &mut App) {
    btc_wallet(app);
    if let Some(btc) = app.meta.as_mut().and_then(|meta| meta.btc.as_mut()) {
        btc.receive_address().unwrap();
    }
}

/// The send timer fired after the whole pause (the EVM edit is quoted).
fn fire_late(app: &mut App) {
    app.evm.send.dirty_ms = Some(0);
    app.on_send_timer();
}

/// The send timer fired at once (the EVM edit is validated locally and waits again).
fn fire_early(app: &mut App) {
    app.evm.send.dirty_ms = Some(u64::MAX);
    app.on_send_timer();
}

fn fire(app: &mut App) {
    app.on_send_timer();
}

fn reset_phrase() -> String {
    yw_engine::wallet::app_reset::RESET_PHRASE.ko.to_owned()
}

pub(crate) fn two_cards(app: &mut App) {
    app.card.records = super::accounts::owner_cards();
}

/// T6, T7 and the headless lifecycle scenarios (T10 without a vault): the send-form timer, the
/// plain copies with the control they answer at (`command` = the copy mark's anchor), S22's
/// typed phrase and a `YubiKey` card name.
fn timer_copy_scenarios() -> Vec<Scenario> {
    use crate::ui::{screens_btc as btc, screens_evm as evm, screens_sol as sol};
    use crate::ui::{screens_yubikey as yk, screens_zec as zec};
    use Step::{Call, Check, Enter, Press, Type, TypeWith};
    vec![
        Scenario {
            name: "evm-timer",
            base: Base::Main(Tab::Evm, false),
            setup: no_setup,
            steps: vec![
                Press(evm::ids::SEND_OPEN),
                Type(evm::ids::SEND_TO_EDIT, "0x12"),
                Type(evm::ids::SEND_TO_EDIT, EVM_TO),
                Type(evm::ids::SEND_AMOUNT_EDIT, "0."),
                Type(evm::ids::SEND_AMOUNT_EDIT, "0.5"),
                Call("fire-late", fire_late),
                Type(evm::ids::SEND_AMOUNT_EDIT, "0.25"),
                Call("fire-early", fire_early),
                Type(evm::ids::SEND_AMOUNT_EDIT, ""),
            ],
        },
        Scenario {
            name: "sol-timer",
            base: Base::Main(Tab::Sol, false),
            setup: no_setup,
            steps: vec![
                Press(sol::ids::SEND_OPEN),
                Type(sol::ids::SEND_TO_EDIT, "abc"),
                TypeWith(sol::ids::SEND_TO_EDIT, sol_to),
                Type(sol::ids::SEND_AMOUNT_EDIT, "0."),
                Type(sol::ids::SEND_AMOUNT_EDIT, "0.1"),
                Call("fire", fire),
            ],
        },
        Scenario {
            name: "copy-evm",
            base: Base::Main(Tab::Evm, false),
            setup: no_setup,
            steps: vec![Press(evm::ids::COPY_ADDRESS), Press(evm::ids::RECEIVE_OPEN)],
        },
        Scenario {
            name: "copy-sol",
            base: Base::Main(Tab::Sol, false),
            setup: no_setup,
            steps: vec![Press(sol::ids::COPY_ADDRESS)],
        },
        Scenario {
            name: "copy-btc",
            base: Base::Main(Tab::Btc, false),
            setup: btc_wallet_with_address,
            steps: vec![Press(btc::ids::CARD_COPY), Press(btc::ids::COPY_ADDRESS)],
        },
        Scenario {
            name: "copy-zec",
            base: Base::Main(Tab::Zec, false),
            setup: zec_wallet,
            steps: vec![Press(zec::ids::CARD_COPY), Press(zec::ids::COPY_ADDRESS)],
        },
        Scenario {
            name: "reset-phrase",
            base: Base::Settings(SettingsSection::Security),
            setup: no_setup,
            steps: vec![
                Press(screens_reset::ids::RESET_OPEN),
                Type(screens_reset::ids::RESET_PHRASE, "wrong"),
                TypeWith(screens_reset::ids::RESET_PHRASE, reset_phrase),
                Check(screens_reset::ids::RESET_SETTINGS_CHECK, true),
                Check(screens_reset::ids::RESET_SETTINGS_CHECK, false),
                Press(screens_reset::ids::RESET_CANCEL),
            ],
        },
        Scenario {
            name: "card-name",
            base: Base::Settings(SettingsSection::YubiKey),
            setup: two_cards,
            steps: vec![
                Press(yk::ids::RENAME_CARD_BASE + 1),
                Type(yk::ids::CARD_NAME_EDIT, "#8800011"),
                Press(yk::ids::CARD_NAME_SAVE),
                Type(yk::ids::CARD_NAME_EDIT, " backup "),
                Enter(yk::ids::CARD_NAME_EDIT),
                Press(yk::ids::RENAME_CARD_BASE),
                Type(yk::ids::CARD_NAME_EDIT, "backup"),
                Press(yk::ids::CARD_NAME_SAVE),
                Press(yk::ids::CARD_NAME_CANCEL),
            ],
        },
    ]
}

/// The same app's last pressed control (the anchor a copy marks), appended to a step.
/// 2026-11-20 (S4 P6, critique B-18): its id from the last press (`cmd_table::id_of`); before,
/// the field `App::command`, which P6 removed (the same id after every press).
fn anchored(out: &mut String, census: &Census, scenario: &Scenario) {
    let (mut app, rx) = census.state(scenario.base);
    // (2026-11-20, S4 P10b: one entry each, as in `run_scenario`.)
    (scenario.setup)(&mut app);
    app.drain();
    let seen = census.observe(&app, &rx);
    let _ = writeln!(out, "{} 0 setup | {}", scenario.name, seen.line());
    for (index, step) in scenario.steps.iter().enumerate() {
        let what = step.run(&mut app);
        app.drain();
        let seen = census.observe(&app, &rx);
        let _ = writeln!(
            out,
            "{} {} {what} | {} | command {}",
            scenario.name,
            index + 1,
            seen.line(),
            crate::ui::cmd_table::id_of(app.last_press())
        );
    }
    drop(app);
    census.guard();
}

/// A vault-backed app on the census folder: the real key worker on this thread
/// ([`super::Harness`]), card readers none, and an RPC channel.
fn harness(census: &Census) -> (super::Harness, Receiver<RpcJob>) {
    census.fresh_data();
    census.guard();
    let mut app = app_at(&census.data);
    let (tx, rx) = channel();
    app.set_rpc_tx(tx);
    let worker = yw_engine::workers::key::KeyWorker::new(&census.data, super::file_deps());
    app.key(yw_engine::events::KeyJob::Load);
    let mut harness = super::Harness {
        app,
        worker,
        dir: census.data.clone(),
        phrase: None,
        address: None,
    };
    harness.pump();
    let _ = harness.app.controls.take_shell_log();
    (harness, rx)
}

/// The observation of a vault-backed step: as [`Census::observe`] but the key queue stays for
/// the key worker (`key ~`).
fn observe_harness(census: &Census, h: &super::Harness, rx: &Receiver<RpcJob>) -> String {
    census.observe_with(&h.app, rx, false).line()
}

/// One golden line of a vault-backed step.
fn harness_step(
    out: &mut String,
    census: &Census,
    h: &super::Harness,
    rx: &Receiver<RpcJob>,
    name: &str,
    step: &str,
) {
    let _ = writeln!(out, "{name} {step} | {}", observe_harness(census, h, rx));
}

/// T10 with a vault (Argon2): `.prev` recovery after payload damage, and a lock while
/// `CreateWallet` runs (the flows of `payload_damage_keeps_prev_recovery_reachable` and
/// `lock_during_create_or_import_reports_the_new_vault`).
fn lifecycle_golden(census: &Census, out: &mut String) {
    use super::{LockReason, PasswordAction, Purpose, WALLET_PW, WRONG};
    let name = "payload-prev";
    let (mut h, rx) = harness(census);
    harness_step(out, census, &h, &rx, name, "0 loaded");
    h.create_and_confirm();
    harness_step(out, census, &h, &rx, name, "1 created");
    // (2026-11-20, S4 P10b: each direct call into the logic is one entry and drains.)
    h.app.lock(LockReason::Manual);
    h.app.drain();
    h.pump();
    harness_step(out, census, &h, &rx, name, "2 lock");
    let mut bytes = std::fs::read(h.vault_file()).unwrap();
    bytes[200] ^= 1;
    std::fs::write(h.vault_file(), &bytes).unwrap();
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    harness_step(out, census, &h, &rx, name, "3 unlock damaged");
    h.pump();
    harness_step(out, census, &h, &rx, name, "4 recovery");
    h.app.on_command(screens::ids::RECOVER);
    h.submit(Purpose::ConfirmPassword(PasswordAction::Recover), &[WRONG]);
    h.pump();
    harness_step(out, census, &h, &rx, name, "5 recover wrong");
    h.submit(
        Purpose::ConfirmPassword(PasswordAction::Recover),
        &[WALLET_PW],
    );
    h.pump();
    harness_step(out, census, &h, &rx, name, "6 recovered");
    drop(h);

    let name = "lock-create";
    let (mut h, rx) = harness(census);
    h.submit(Purpose::CreatePassword, &[WALLET_PW]);
    harness_step(out, census, &h, &rx, name, "1 create");
    let running = h.run_one();
    h.app.lock(LockReason::SessionLock);
    h.app.drain();
    harness_step(out, census, &h, &rx, name, "2 lock");
    h.deliver(running);
    harness_step(out, census, &h, &rx, name, "3 old result");
    h.pump();
    harness_step(out, census, &h, &rx, name, "4 loaded");
    drop(h);
    census.guard();
}

fn scenarios_golden() -> String {
    let census = Census::new("scenarios");
    let mut out = String::from(
        "# S3 scenarios (2026-11-18): send timer, plain copies (command = the copy mark's \
         anchor), S22 phrase, card name; then vault lifecycles (key ~ = jobs left to the worker)\n",
    );
    for scenario in timer_copy_scenarios() {
        anchored(&mut out, &census, &scenario);
    }
    lifecycle_golden(&census, &mut out);
    out
}

/// A dispatcher with no pipe server and no read workers (as `app_browser`'s tests build it).
fn headless_browser() -> yw_engine::wallet::app_browser::BrowserUi {
    use std::sync::Arc;
    let events = Arc::new(yw_engine::events::EventQueue::new(Box::new(|| {})));
    yw_engine::wallet::app_browser::BrowserUi {
        core: yw_engine::browser::BrowserCore::new(
            "abcdefghijklmnopabcdefghijklmnop",
            events as Arc<dyn yw_engine::browser::DappSink>,
            Arc::new(crate::system_clock::SystemClock),
        ),
        reads: Arc::new(yw_engine::browser::read::ReadContext::new(None)),
        connections: 0,
        waiters: std::collections::HashMap::new(),
        broadcasts: std::collections::HashMap::new(),
        sol_broadcasts: std::collections::HashMap::new(),
        dapp_unlock: false,
        unlocked: false,
        locking: false,
        grant_write: yw_engine::wallet::app_browser::GrantWrite::default(),
        site_rows: yw_engine::wallet::app_browser::SiteRows::default(),
    }
}

/// T8 (S3 A3, spec/05 §4.5): with a dApp dispatcher attached, its wallet view equals the UI
/// state after unlock, an account switch, a chain switch, Bitcoin turned on, `잠그기` and unlock
/// again; the test never calls `sync_browser`. Every step but the lock is synced only because
/// `App::refresh` runs `sync_browser` (the path S3 B3 moves into `Effect::Render`); the lock is
/// also synced by `App::browser_lock_begin`, which calls `sync_browser` itself, so its assert is
/// no evidence for `refresh` (2026-11-18 A1–A3 review).
#[test]
fn dapp_view_follows_every_step_without_a_manual_sync() {
    use super::{Purpose, WALLET_PW};
    let census = Census::new("dapp-view");
    let (mut h, _rx) = harness(&census);
    h.app.browser = Some(headless_browser());
    h.create_and_confirm();
    assert!(h.app.browser_view_current(), "after unlock");
    h.app.on_command(screens::ids::ADD_ACCOUNT);
    h.pump();
    h.app.on_command(screens::ids::ACCOUNT_BASE + 1);
    h.pump();
    assert!(h.app.browser_view_current(), "after the account switch");
    h.app.on_command(screens::ids::NETWORK_BASE + 1);
    h.pump();
    assert!(h.app.browser_view_current(), "after the chain switch");
    // Bitcoin on (an endpoint set in memory; nothing is fetched: no RPC worker): its accounts
    // and `btc_enabled` reach the view only through `refresh`.
    assert!(!h.app.settings.bitcoin.enabled);
    let network = h.app.settings.bitcoin.network;
    h.app.apikeys.set_rpc(
        yw_engine::network::NetworkId::Bitcoin(network),
        &yw_platform::http::HttpsUrl::parse("https://btc.example.test/").unwrap(),
    );
    h.app.on_command(screens_btc::ids::SECTION_BTC);
    h.app.on_command(screens_btc::ids::ENABLE);
    h.pump();
    assert!(h.app.settings.bitcoin.enabled);
    assert!(h.app.browser_view_current(), "after Bitcoin is turned on");
    // Also synced by `browser_lock_begin`, not only by `refresh`.
    h.app.on_command(screens::ids::LOCK);
    h.pump();
    assert_eq!(h.app.mode, AppMode::Locked);
    assert!(h.app.browser_view_current(), "after the lock");
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    h.pump();
    assert!(matches!(h.app.mode, AppMode::Unlocked { .. }));
    assert!(h.app.browser_view_current(), "after unlocking again");
}

/// T9 (S3 A3, D13/D28): no password, recovery phrase (or two of its words in a row), template
/// token, Alchemy or LLM key, or typed RPC URL reaches a recorded shell call, a census line, or
/// the unhashed `Debug` text of the screen model (`items()`), the banners or the info line that
/// the census hashes — through create, backup, lock and unlock, and every credential form of the
/// write and timer/copy scenarios. (2026-11-18 A1–A3 review: before, only the hashed lines were
/// scanned, so a secret in the screen model would have been hashed away.)
#[test]
fn no_secret_reaches_a_recorded_line() {
    use super::{Purpose, WALLET_PW};
    let census = Census::new("no-secret");
    census.keep_debug();
    let (mut h, rx) = harness(&census);
    let mut lines = Vec::new();
    h.create_and_confirm();
    lines.extend(h.app.controls.take_shell_log());
    lines.push(observe_harness(&census, &h, &rx));
    h.app.on_command(screens::ids::LOCK);
    h.pump();
    lines.extend(h.app.controls.take_shell_log());
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    h.pump();
    lines.extend(h.app.controls.take_shell_log());
    lines.push(observe_harness(&census, &h, &rx));
    let phrase = h.phrase.clone().unwrap();
    drop(h);
    let mut out = String::new();
    for scenario in write_scenarios() {
        run_scenario(&mut out, &census, &scenario);
    }
    for scenario in timer_copy_scenarios() {
        anchored(&mut out, &census, &scenario);
    }
    lines.extend(out.lines().map(str::to_owned));
    assert!(lines.len() > 100, "{}", lines.len());
    let debug = census.kept_debug();
    assert!(debug.len() > 100, "{}", debug.len());
    lines.extend(debug);
    let words: Vec<&str> = phrase.split(' ').collect();
    let mut secrets: Vec<String> = words.windows(2).map(|pair| pair.join(" ")).collect();
    secrets.extend([
        String::from_utf8(WALLET_PW.to_vec()).unwrap(),
        phrase.clone(),
        QN_TOKEN.to_owned(),
        qn_url(),
        alchemy_key(),
        llm_key(),
        rpc_url(),
    ]);
    for line in &lines {
        for secret in &secrets {
            assert!(
                !line.contains(secret.as_str()),
                "a secret in a recorded line"
            );
        }
    }
}

/// T6, T7, T10 (S3 A3): `s3_census/scenarios.txt`.
#[test]
fn scenarios_match_the_golden() {
    compare("scenarios", &scenarios_golden(), SCENARIOS);
}

#[test]
fn wall_time_and_set_aside_names_are_redacted() {
    assert_eq!(
        redact_wall_time("세대 3 · 2026-11-18 03:04 저장, 2026-11-18 03:0"),
        "세대 3 · <time> 저장, 2026-11-18 03:0"
    );
    assert_eq!(
        redact_corrupt("vault.ywv.corrupt-1789000000000 그리고 meta.ywm.corrupt-7a"),
        "vault.ywv.corrupt-<time> 그리고 meta.ywm.corrupt-<time>"
    );
    assert_eq!(redact_wall_time("no time"), "no time");
}
