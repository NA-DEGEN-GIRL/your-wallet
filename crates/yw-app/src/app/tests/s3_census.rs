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
    screens_llm, screens_mnemonics, screens_reset, screens_sol, screens_walletconnect,
    screens_yubikey, screens_zec,
};
use crate::workers::rpc::RpcJob;

const COMMANDS: &str = include_str!("s3_census/commands.txt");

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
        let root = std::env::temp_dir().join(format!(
            "yw-s3-census-{tag}-{}-{}",
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
pub(super) fn section(
    out: &mut String,
    census: &Census,
    base: Base,
    ids: &[u16],
    press: fn(&mut App, u16),
) {
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

/// The sections of `bases` in order, each built on its own thread with its own census folder.
pub(super) fn sections(tag: &str, bases: &[Base], ids: &[u16], press: fn(&mut App, u16)) -> String {
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
}
