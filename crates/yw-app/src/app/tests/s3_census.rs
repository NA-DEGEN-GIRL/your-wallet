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
//! no worker is attached (no RPC, `WalletConnect` relay or LLM connection can start; RPC jobs land
//! in a channel and are named only), explorer links go to `Launcher::Record`, the key queue is
//! drained unrun (no card reader), and presses that open a folder, quit or read the clipboard
//! or an image file are skipped ([`SKIPPED`]).
//!
//! A golden line holds ids, names, counts and hashes only — no address, URL, key or path:
//! before hashing, the census's own paths become `<data>`, `<logs>`, `<ext>`, `<exe>`, `<tmp>`.
//! Regenerate with `YW_S3_CENSUS_OUT=<folder> cargo test -p yw-app --lib s3_census::print --
//! --ignored` and review the diff; only the S3 phase-A commits may change these files.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};

use super::{App, AppMode, Screen, app_at, unlocked_at};
use crate::app::SettingsSection;
use crate::app_explorer::Launcher;
use crate::app_extension::TOUR_EXTENSION_DIR;
use crate::app_rpc_import::{TEST_RPC_JSON, rpc_json_path};
use crate::meta::Tab;
use crate::ui::command_ids::{fixed, ranges};
use crate::ui::{
    screens, screens_book, screens_btc, screens_evm, screens_explorer, screens_hypercore,
    screens_llm, screens_mnemonics, screens_received, screens_reset, screens_sol,
    screens_walletconnect, screens_yubikey, screens_zec,
};
use crate::workers::rpc::RpcJob;

const COMMANDS: &str = include_str!("s3_census/commands.txt");
const EDITS: &str = include_str!("s3_census/edits.txt");
const CHECKS: &str = include_str!("s3_census/checks.txt");
const WRITES: &str = include_str!("s3_census/writes.txt");

/// The 65 edits of the main window (spec/15 §11.1): 58 plain and the 7 masked credential
/// edits of [`MASKED`].
pub(super) const EDIT_IDS: [u16; 65] = [
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
pub(super) const MASKED: [u16; 7] = [
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
pub(super) struct Census {
    root: PathBuf,
    data: PathBuf,
}

impl Census {
    pub(super) fn new(tag: &str) -> Self {
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
        let census = Self { root, data };
        census.guard();
        census
    }

    /// Points `rpc_json_path` and `extension_dir` into the census folder (thread-locals, set
    /// again before every press) and checks that they stay there.
    pub(super) fn guard(&self) {
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

    /// An empty data folder for the next state (a press may have written settings or keys).
    fn fresh_data(&self) {
        let used =
            std::fs::read_dir(&self.data).map_or(true, |mut entries| entries.next().is_some());
        if used {
            let _ = std::fs::remove_dir_all(&self.data);
            std::fs::create_dir_all(&self.data).unwrap();
        }
    }

    /// A fresh `base` state with an RPC channel; nothing it did while being built is kept.
    pub(super) fn state(&self, base: Base) -> (App, Receiver<RpcJob>) {
        self.fresh_data();
        self.guard();
        let mut app = base.build(&self.data);
        let (tx, rx) = channel();
        app.rpc_tx = Some(tx);
        let _ = app.controls.take_shell_log();
        let _ = key_jobs(&app);
        (app, rx)
    }

    /// `text` with the census's machine-dependent paths replaced by fixed tokens (raw and as
    /// `Debug` escapes them).
    pub(super) fn normalize(&self, text: &str) -> String {
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

    /// What the app shows and asked for since the last call.
    pub(super) fn observe(&self, app: &App, rx: &Receiver<RpcJob>) -> Seen {
        let calls = compress(&app.controls.take_shell_log());
        let items = self.normalize(&format!("{:?}", app.items()));
        let banners = self.normalize(&format!("{:?}", app.banners));
        let info = app.info.as_deref().map(|info| self.normalize(info));
        let copied = app.copied.map_or_else(
            || "-".to_owned(),
            |copied| format!("{}/{}", copied.id, copied.address),
        );
        let keys: Vec<&str> = key_jobs(app)
            .iter()
            .map(crate::events::KeyJob::name)
            .collect();
        let rpc: Vec<&str> = rx.try_iter().map(|job| job.name()).collect();
        let launched = match &app.explorer_ui.launcher {
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
            list(&keys),
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
pub(super) struct Seen {
    /// Mode, screen, hashes of items, banners and info, the copy mark, jobs, links opened.
    pub(super) state: String,
    /// The shell calls in order.
    pub(super) calls: String,
}

impl Seen {
    pub(super) fn line(&self) -> String {
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

/// The key jobs queued since the last call (never run: no worker, no card reader).
fn key_jobs(app: &App) -> Vec<crate::events::KeyJob> {
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
pub(super) enum Base {
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
    pub(super) const ALL: [Self; 15] = [
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
    pub(super) const ALT: [Self; 4] = [
        Self::Main(Tab::Evm, true),
        Self::Main(Tab::Sol, true),
        Self::Main(Tab::Btc, true),
        Self::Main(Tab::Zec, true),
    ];

    pub(super) fn name(self) -> String {
        match self {
            Self::FirstRun => "first".to_owned(),
            Self::Locked => "locked".to_owned(),
            Self::Main(tab, alt) => {
                format!("{}{}", if alt { "alt-" } else { "" }, tab.as_str())
            }
            Self::Settings(section) => format!("set-{section:?}").to_ascii_lowercase(),
        }
    }

    fn build(self, data: &std::path::Path) -> App {
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
pub(super) fn section(out: &mut String, census: &Census, base: Base, ids: &[u16], press: PressFn) {
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
        crate::logging::set_level(crate::settings::Settings::default().log_level);
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
pub(super) type PressFn = fn(&mut App, u16);

/// The sections of `bases` in order, each built on its own thread with its own census folder.
pub(super) fn sections(tag: &str, bases: &[Base], ids: &[u16], press: PressFn) -> String {
    std::thread::scope(|scope| {
        let workers: Vec<_> = bases
            .iter()
            .map(|&base| {
                scope.spawn(move || {
                    let census = Census::new(&format!("{tag}-{}", base.name()));
                    let mut out = String::new();
                    section(&mut out, &census, base, ids, press);
                    out
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    })
}

/// T2: every press on every census state.
fn commands_golden() -> String {
    let ids = command_ids();
    let mut out = String::from(
        "# S3 command census (2026-11-18, spec/15 §11.4 S3): state id | mode | screen | items | \
         banners | info | copied | key jobs | rpc jobs | links opened | shell calls\n",
    );
    out.push_str(&sections("commands", &Base::ALL, &ids, App::on_command));
    // The receive presses where the passphrase was mistyped (they are refused there).
    out.push_str(&sections(
        "commands",
        &Base::ALT,
        &screens::RECEIVE_IDS,
        App::on_command,
    ));
    out
}

/// Compares a generated golden with the committed one; on a difference the generated text is
/// written next to the census folders (temp) and the first differing line is named.
pub(super) fn compare(name: &str, generated: &str, committed: &str) {
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
    compare("commands", &commands_golden(), COMMANDS);
}

/// Regenerates every golden of this module into `YW_S3_CENSUS_OUT` (a folder).
#[test]
#[ignore = "regenerates the S3 census goldens"]
fn print() {
    let out = PathBuf::from(std::env::var_os("YW_S3_CENSUS_OUT").expect("YW_S3_CENSUS_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("commands.txt"), commands_golden()).unwrap();
    std::fs::write(out.join("edits.txt"), edits_golden()).unwrap();
    std::fs::write(out.join("checks.txt"), checks_golden()).unwrap();
    std::fs::write(out.join("writes.txt"), writes_golden()).unwrap();
}

// ----- A2: edits, check boxes, programmatic writes ---------------------------------------

/// The 21 check boxes and radios whose handler reads `ControlSet::checked` (spec/15 §11.1).
pub(super) const CHECK_IDS: [u16; 21] = [
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
    crate::app_sidecar::ids::RESET_ACK,
];

/// The edits Enter presses a button from (`enter_primary`), except the image-file path, whose
/// button reads a file.
pub(super) const ENTER_EDITS: [u16; 31] = [
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
fn edits_golden() -> String {
    let mut ids = EDIT_IDS.to_vec();
    ids.sort_unstable();
    let mut out = String::from(
        "# S3 edit census (2026-11-18): type + EN_CHANGE of every edit, then Enter (shown edits \
         only); fields as in commands.txt\n",
    );
    let typing: [(&str, PressFn); 2] = [("1", type_one), ("x", type_x)];
    for (value, press) in typing {
        let _ = writeln!(out, "# type \"{value}\"");
        out.push_str(&sections("edits", &Base::ALL, &ids, press));
    }
    let mut enter: Vec<u16> = ENTER_EDITS
        .iter()
        .copied()
        .filter(|id| *id != screens_walletconnect::ids::FILE_EDIT)
        .collect();
    enter.sort_unstable();
    let _ = writeln!(out, "# enter");
    out.push_str(&sections("edits", &Base::ALL, &enter, enter_shown));
    out
}

/// T4: every check box read with `checked`, pressed checked, unchecked and without a state.
fn checks_golden() -> String {
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
        out.push_str(&sections("checks", &Base::ALL, &ids, press));
    }
    out
}

/// One input of a scenario.
#[derive(Clone, Copy)]
pub(super) enum Step {
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
    pub(super) fn run(self, app: &mut App) -> String {
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
pub(super) struct Scenario {
    pub(super) name: &'static str,
    pub(super) base: Base,
    pub(super) setup: fn(&mut App),
    pub(super) steps: Vec<Step>,
}

/// Runs `scenario` on `census`: one golden line for the setup and one per step.
pub(super) fn run_scenario(out: &mut String, census: &Census, scenario: &Scenario) {
    let (mut app, rx) = census.state(scenario.base);
    (scenario.setup)(&mut app);
    let seen = census.observe(&app, &rx);
    let _ = writeln!(out, "{} 0 setup | {}", scenario.name, seen.line());
    for (index, step) in scenario.steps.iter().enumerate() {
        let what = step.run(&mut app);
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
    crate::logging::set_level(crate::settings::Settings::default().log_level);
}

fn no_setup(_: &mut App) {}

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

fn done_screen(app: &mut App) {
    app.done_imported = true;
    app.set_screen(Screen::Done);
}

/// A Bitcoin mainnet wallet with an endpoint and room in the journal.
fn btc_wallet(app: &mut App) {
    use yw_core::btc::BtcNetwork;
    app.settings.bitcoin.enabled = true;
    app.settings.bitcoin.network = crate::network::BtcNet::Mainnet;
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
        meta.prefs.tab = crate::meta::Tab::Btc;
    }
    app.apikeys.set_rpc(
        crate::network::NetworkId::Bitcoin(crate::network::BtcNet::Mainnet),
        &yw_platform::http::HttpsUrl::parse("https://btc.example.test/").unwrap(),
    );
    app.evm.journal = Some(crate::events::JournalView {
        room: true,
        sol_room: true,
        btc_room: true,
        ..crate::events::JournalView::default()
    });
}

/// A native balance of the selected EVM account and a quote for it (as the RPC worker answers).
fn evm_quote(app: &mut App) {
    use yw_core::evm::amount::U256;
    let chain = app.settings.evm_chain_id;
    let owner =
        yw_core::evm::address::parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
    app.evm.balances.insert(
        chain,
        crate::app_evm::BalanceState {
            snapshot: Some(crate::events::BalanceSnapshot {
                block: 7,
                native: vec![(owner, U256::from_u64(5_000_000_000_000_000))],
                tokens: Vec::new(),
                token_owner: owner,
            }),
            ..crate::app_evm::BalanceState::default()
        },
    );
    app.evm.send.quote = Some(crate::flow::evm::form::Quote {
        gas_limit: 21_000,
        max_fee_per_gas: U256::from_u64(3_000_000_000),
        max_total: U256::from_u64(63_000_000_000_000),
        cap_violation: None,
        estimate_failed: false,
    });
}

/// The selected EVM account's `HyperCore` balances and a withdrawal form (S-HC).
fn hc_withdraw(app: &mut App) {
    let owner =
        yw_core::evm::address::parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
    app.settings.hypercore.enabled = true;
    app.hypercore.balances = Some((
        yw_core::hypercore::HcNetwork::Mainnet,
        owner,
        crate::hypercore::HcBalances {
            spot: Vec::new(),
            perp: yw_core::hypercore::HcPerpState {
                account_value: "100.0".to_owned(),
                withdrawable: "100.0".to_owned(),
                positions: 0,
            },
        },
    ));
    app.hypercore.form = crate::app_hypercore::HcForm {
        kind: crate::app_hypercore::HcFormKind::Withdraw,
        ..crate::app_hypercore::HcForm::default()
    };
    app.screen = Screen::HyperCore;
}

/// T5: scenarios that reach every programmatic edit write (`set_text` ×13, `clear_text` ×11)
/// and Enter in the forms they open, the masked credential edits included.
#[expect(clippy::too_many_lines, reason = "one scenario per write site")]
fn write_scenarios() -> Vec<Scenario> {
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
/// maps, and every check box is a fixed or indexed id.
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

/// T3 (S3 A2): `s3_census/edits.txt`.
#[test]
fn edit_census_matches_the_golden() {
    compare("edits", &edits_golden(), EDITS);
}

/// T4 (S3 A2): `s3_census/checks.txt`.
#[test]
fn check_census_matches_the_golden() {
    compare("checks", &checks_golden(), CHECKS);
}

/// T5 (S3 A2): `s3_census/writes.txt`.
#[test]
fn write_scenarios_match_the_golden() {
    compare("writes", &writes_golden(), WRITES);
}
