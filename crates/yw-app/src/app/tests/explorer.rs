//! The tests of `app_explorer.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (where every test builds an `App`).
//! A `#[cfg(test)] #[path]` child of `crate::app_explorer`, not of `app::tests`: it keeps the
//! access of the inline module, so no production item of that file is widened.

use std::path::{Path, PathBuf};

use crate::apikeys::ApiKeys;
use crate::app::{App, AppMode, Paths, Screen};
use crate::app_explorer::Launcher;
use crate::explorer::{EXPLORERS_KEY, ExplorerNet, ExplorerOverride, LinkKind, Templates};
use crate::network::{NetworkId, SolCluster};
use crate::settings::{EvmChainDef, Settings};
use crate::ui::screens_explorer::ids;

const HASH: &str = "0x7a329aaf9f457ef8516d5a51631fe5a75e3c12d7d71b6a73a38ce42ad352de2d";

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("yw-app-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn app(dir: &Path, settings: Settings) -> App {
    let mut app = App::new(
        Paths {
            data: dir.to_path_buf(),
            logs: dir.join("logs"),
        },
        true,
        settings,
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    app.screen = Screen::Main;
    app
}

fn user_chain(explorer: Option<&str>) -> EvmChainDef {
    EvmChainDef {
        chain_id: 10,
        name: "Test L2".to_owned(),
        symbol: "ETH".to_owned(),
        decimals: 18,
        quicknode_subdomain: None,
        alchemy_label: None,
        explorer: explorer.map(str::to_owned),
        simulation: yw_core::evm::chain::SimulationSupport::Auto,
        genesis_hash: [7; 32],
    }
}

/// The code of a Rust source without comments and without whitespace outside literals, so a
/// call that rustfmt wraps over several lines reads as one chain (2026-11-20, S4 P3 review:
/// the first scan cut each line at `//` and so missed wrapped calls, calls through a local
/// binding and calls after a `"https://…"` literal). Strings, raw strings and char literals
/// are kept as written (a `//` inside one is not a comment); a lifetime is not a literal.
fn code_only(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '/' && at(i + 1) == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == '*' {
            let mut depth = 0_usize;
            while i < chars.len() {
                if chars[i] == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == 'r'
            && (i == 0
                || !ident(chars[i - 1])
                || (chars[i - 1] == 'b' && (i < 2 || !ident(chars[i - 2]))))
            && {
                let mut j = i + 1;
                while at(j) == '#' {
                    j += 1;
                }
                at(j) == '"'
            }
        {
            // A raw string: `r"…"`, `r#"…"#` (also after `b`).
            let begin = i;
            i += 1;
            let mut hashes = 0;
            while at(i) == '#' {
                hashes += 1;
                i += 1;
            }
            i += 1;
            while i < chars.len() && !(chars[i] == '"' && (1..=hashes).all(|k| at(i + k) == '#')) {
                i += 1;
            }
            i += 1 + hashes;
            out.extend(&chars[begin..i.min(chars.len())]);
        } else if c == '"' {
            let begin = i;
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            out.extend(&chars[begin..i.min(chars.len())]);
        } else if c == '\'' && (at(i + 1) == '\\' || at(i + 2) == '\'') {
            // A char literal (`'x'`, `'\n'`, `'\u{..}'`); a lifetime has no closing quote.
            let begin = i;
            i += if at(i + 1) == '\\' { 3 } else { 2 };
            while i < chars.len() && chars[i] != '\'' {
                i += 1;
            }
            i += 1;
            out.extend(&chars[begin..i.min(chars.len())]);
        } else {
            if !c.is_whitespace() {
                out.push(c);
            }
            i += 1;
        }
    }
    out
}

/// 2026-11-20 (S4 P3): only the effect executor (`app_effects.rs`: `Effect::OpenUrl`,
/// `Effect::OpenFolder`) starts the launcher, and only the launcher (this file) names
/// `explorer.exe`: no handler opens a link or a folder itself. A read-only scan of yw-app's
/// `src` (code without comments and whitespace, [`code_only`]): every `.launch(` /
/// `.open_folder(` call and every `::launch` / `::open_folder` path counts, whatever the
/// receiver (2026-11-20 review: was only `launcher.launch(` / `launcher.open_folder(` within
/// one line). `app_effects.rs` has three: `launcher.open_folder`, `launcher.launch` and the
/// executor's own `self.open_folder` (`App::open_folder`, the shell half). It asserts that the
/// scan sees the shapes the first scan missed and that it found its targets.
#[test]
fn only_the_effect_executor_starts_the_launcher() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    // Split so that this test's own text does not match.
    let calls = [
        [".", "launch("].concat(),
        [".", "open_folder("].concat(),
        [":", ":launch"].concat(),
        [":", ":open_folder"].concat(),
    ];
    let count = |code: &str| -> usize {
        calls
            .iter()
            .map(|pattern| code.matches(pattern.as_str()).count())
            .sum()
    };
    // The shapes the line scan missed: a wrapped chain, a local binding, a call after a URL
    // literal on the same line (and a commented-out call that must not count), a path.
    let wrapped = ["self\n    .launcher\n    .", "launch(&url);"].concat();
    let bound = ["let l = &mut self.launcher; l.", "open_folder(&p);"].concat();
    let after_url = [
        "let u = \"https://x\"; launcher.",
        "launch(u); // l.",
        "launch(u);",
    ]
    .concat();
    let path = ["let f = Launcher:", ":launch;"].concat();
    for sample in [&wrapped, &bound, &after_url, &path] {
        assert_eq!(count(&code_only(sample)), 1, "{sample}");
    }
    assert_eq!(
        code_only("/* a /* b */ c */ x // y\n'a' &'b T br#\"//\"# '\\''"),
        "x'a'&'bTbr#\"//\"#'\\''"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    let program = ["explorer", ".exe"].concat();
    let (mut launch_sites, mut program_sites) = (Vec::new(), Vec::new());
    for file in &files {
        let code = code_only(&std::fs::read_to_string(file).unwrap());
        let name = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let calls = count(&code);
        if calls > 0 {
            launch_sites.push((name.clone(), calls));
        }
        let programs = code.matches(program.as_str()).count();
        if programs > 0 {
            program_sites.push((name, programs));
        }
    }
    assert!(files.len() > 50, "{} files", files.len());
    assert_eq!(launch_sites, [("app_effects.rs".to_owned(), 3)]);
    assert_eq!(program_sites, [("app_explorer.rs".to_owned(), 1)]);
}

#[test]
fn helpers_follow_user_chains_and_overrides_and_open_without_a_browser() {
    let dir = temp_dir("explorer-helpers");
    let mut settings = Settings::default();
    settings
        .evm_chains
        .push(user_chain(Some("https://scan.example")));
    let mut app = app(&dir, settings);
    assert!(matches!(app.launcher, Launcher::Record(_)));
    assert_eq!(
        app.explorer_tx_url(NetworkId::Eip155(10), HASH).as_deref(),
        Some(format!("https://scan.example/tx/{HASH}").as_str())
    );
    assert_eq!(app.explorer_tx_url(NetworkId::Eip155(77), HASH), None);
    assert_eq!(app.explorer_tx_url(NetworkId::Eip155(1), "0x12/../x"), None);
    // (2026-11-20, S4 P10b: each call is one entry; its effects apply when it drains.)
    app.open_explorer_tx(NetworkId::Eip155(10), HASH);
    app.drain();
    app.open_explorer_tx(NetworkId::Eip155(77), HASH);
    app.drain();
    assert_eq!(
        app.info.as_deref(),
        Some(crate::app_explorer::text::EXPLORER_NONE.ko)
    );
    app.open_explorer_address(
        ExplorerNet::HyperCore(yw_core::hypercore::HcNetwork::Testnet),
        "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646",
    );
    app.drain();
    assert_eq!(
        app.launcher,
        Launcher::Record(vec![
            format!("https://scan.example/tx/{HASH}"),
            "https://app.hyperliquid-testnet.xyz/explorer/address/0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646"
                .to_owned(),
        ])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_card_stores_overrides_only_and_resets_them() {
    let dir = temp_dir("explorer-card");
    let mut app = app(&dir, Settings::default());
    let networks = app.explorer_networks();
    assert_eq!(networks.len(), 7 + 2 + 2 + 2 + 2);
    let devnet = ExplorerNet::Solana(SolCluster::Devnet);
    let row = u16::try_from(networks.iter().position(|net| *net == devnet).unwrap()).unwrap();
    let change = ids::ROW_BASE + row * ids::ROW_STRIDE;
    assert!(app.on_explorer_command(change));
    assert_eq!(app.explorer_ui.editing, Some(devnet));
    assert_eq!(
        app.explorer_ui.tx_text,
        "https://solscan.io/tx/{hash}?cluster=devnet"
    );
    // Unchanged defaults: nothing is stored.
    assert!(app.on_explorer_command(ids::SAVE));
    assert!(app.settings.explorers.is_empty());
    // A refused template keeps the form open with the reason.
    assert!(app.on_explorer_command(change));
    app.controls
        .type_text(ids::EDIT_TX, "http://explorer.example/tx/{hash}");
    assert!(app.on_explorer_command(ids::SAVE));
    assert_eq!(app.explorer_ui.editing, Some(devnet));
    assert!(
        app.explorer_ui
            .message
            .as_deref()
            .unwrap()
            .contains("https://")
    );
    assert!(app.settings.explorers.is_empty());
    // A valid one is stored as the transaction override only.
    app.controls.type_text(
        ids::EDIT_TX,
        "https://explorer.solana.com/tx/{hash}?cluster=devnet",
    );
    assert!(app.on_explorer_command(ids::SAVE));
    assert_eq!(app.explorer_ui.editing, None);
    assert_eq!(
        app.settings.explorers,
        [ExplorerOverride {
            net: devnet,
            templates: Templates {
                tx: Some("https://explorer.solana.com/tx/{hash}?cluster=devnet".to_owned()),
                address: None,
            },
        }]
    );
    let written = std::fs::read(dir.join("settings.json")).unwrap();
    let text = String::from_utf8(written.clone()).unwrap();
    assert!(text.contains(&format!("\"{EXPLORERS_KEY}\":{{\"solana:devnet\":")));
    assert_eq!(
        crate::settings::load(Some(&written)).settings.explorers,
        app.settings.explorers
    );
    assert_eq!(
        app.explorer_templates(devnet).get(LinkKind::Address),
        Some("https://solscan.io/account/{address}?cluster=devnet")
    );
    // 기본값으로 removes it; the key is no longer written.
    assert!(app.on_explorer_command(change + 1));
    assert!(app.settings.explorers.is_empty());
    let written = std::fs::read(dir.join("settings.json")).unwrap();
    assert!(!String::from_utf8(written).unwrap().contains(EXPLORERS_KEY));
    // Activity, result and card ids that name nothing do nothing.
    assert!(app.on_explorer_command(ids::BTC_ACTIVITY_BASE));
    assert!(app.on_explorer_command(ids::RESULT_ZEC_OPEN));
    let _ = std::fs::remove_dir_all(&dir);
}

/// spec/14 (2026-11-14): group B's fixed texts in English carry no Hangul — the S15
/// explorer card and form, S17, the send-form notes, the site and extension lines — and
/// every catalogue keeps its placeholders.
#[test]
#[expect(clippy::too_many_lines, reason = "one check per group B text source")]
fn english_explorer_chain_and_site_texts() {
    use yw_core::lang::{Entry, Lang, has_hangul, placeholders};

    use crate::ui::main_window::Item;

    fn strings(items: &[Item], out: &mut Vec<String>) {
        for item in items {
            match item {
                Item::Help(text) | Item::Banner(text, _) | Item::Title(text) => {
                    out.push(text.clone());
                }
                Item::CardStart(Some(text)) => out.push(text.clone()),
                Item::LabeledRow(label, ctls) => {
                    out.push(label.clone());
                    out.extend(ctls.iter().map(|ctl| ctl.text.clone()));
                }
                Item::Row(ctls) => out.extend(ctls.iter().map(|ctl| ctl.text.clone())),
                Item::Badged(_, inner) => strings(core::slice::from_ref(&**inner), out),
                _ => {}
            }
        }
    }

    let dir = temp_dir("explorer-english");
    let mut settings = Settings {
        language: Lang::En,
        ..Settings::default()
    };
    settings
        .evm_chains
        .push(user_chain(Some("https://scan.example")));
    let mut app = app(&dir, settings);
    let mut items = Vec::new();
    app.explorer_settings_card(&mut items);
    app.open_chain_form(None);
    app.chain_edit_screen(&mut items);
    let mut texts = Vec::new();
    strings(&items, &mut texts);
    assert!(texts.len() > 20, "{texts:?}");
    for text in &texts {
        assert!(!has_hangul(text), "{text}");
    }
    let notes = [
        crate::flow::evm::form::AddressNote::SameAsSender,
        crate::flow::evm::form::AddressNote::Book {
            name: "Alice".to_owned(),
            verified: true,
        },
        crate::flow::evm::form::AddressNote::LookAlike {
            name: "Alice".to_owned(),
            history: false,
            prefix: 3,
            suffix: 4,
        },
        crate::flow::evm::form::AddressNote::NotInBook,
        crate::flow::evm::form::AddressNote::Contract,
    ];
    let mut lines: Vec<String> = notes.iter().map(|note| note.text_in(Lang::En)).collect();
    lines.push(crate::app_book::look_alike_note(
        Lang::En,
        &crate::app_book::Resembles::Sent("0x5290".to_owned()),
    ));
    lines.push(crate::ui::screens_evm::browser_status_text(
        Lang::En,
        None,
        None,
    ));
    lines.push(crate::explorer::TemplateError::Placeholder(LinkKind::Tx).text_in(Lang::En));
    lines.push(app.unlock_pending_text().unwrap_or_default());
    lines.push(
        crate::app_extension::ExtensionStatus::Never
            .text_in(Lang::En)
            .to_owned(),
    );
    for line in &lines {
        assert!(!has_hangul(line), "{line}");
    }
    assert_eq!(
        notes[2].text_in(yw_core::lang::Lang::Ko),
        "'Alice'과 앞 3자·끝 4자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."
    );
    let catalogues: [&[Entry]; 13] = [
        crate::app_book::text::ALL,
        crate::app_browser::text::ALL,
        crate::app_chain_sites::text::ALL,
        crate::app_evm::text::ALL,
        crate::app_explorer::text::ALL,
        crate::app_extension::text::ALL,
        crate::app_tokens::text::ALL,
        crate::explorer::text::ALL,
        crate::flow::evm::form::text::ALL,
        crate::flow::evm::user_chain::text::ALL,
        crate::received::evm::text::ALL,
        crate::ui::screens_book::text::ALL,
        crate::ui::screens_evm::text::ALL,
    ];
    let more: [&[Entry]; 2] = [
        crate::ui::screens_explorer::text::ALL,
        crate::ui::screens_sites::text::ALL,
    ];
    for entry in catalogues.into_iter().chain(more).flatten() {
        for template in [entry.ko, entry.en] {
            let mut used = placeholders(template);
            used.sort_unstable();
            used.dedup();
            assert_eq!(used, (0..entry.args).collect::<Vec<_>>(), "{}", entry.name);
        }
        assert!(!has_hangul(entry.en), "{}", entry.name);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
