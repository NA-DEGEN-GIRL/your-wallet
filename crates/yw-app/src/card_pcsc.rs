//! The Windows `YubiKey` transports (spec/10 §4, §5.1): adapters from yw-win's PC/SC card and
//! CNG cipher to the yw-core `CardTransport` / `MgmtCipher` traits, and [`PcscSource`], the
//! [`CardSource`] of the real readers that the key worker gets from `main.rs`.
//!
//! (2026-11-17, spec/15 §11.4 S2: moved unchanged out of `yubikey`, which keeps the card
//! operations, the PIN types, `CardSource` and the emulator source; `yubikey` no longer calls
//! `yw_win`.)

use yw_core::secret::Zeroizing;
use yw_core::yubikey::piv::{MgmtAlgorithm, MgmtCipher};
use yw_core::yubikey::{CardError, CardTransport, TransportFault};
use yw_win::pcsc::{self, PcscFault};

use yw_engine::yubikey::{CardSource, CardVisit};

const fn transport_error(fault: PcscFault) -> CardError {
    match fault {
        PcscFault::NoService => CardError::Transport(TransportFault::NoService),
        PcscFault::NoReader => CardError::Transport(TransportFault::NoReader),
        PcscFault::NoCard => CardError::Transport(TransportFault::NoCard),
        PcscFault::Busy => CardError::Transport(TransportFault::Busy),
        PcscFault::Removed => CardError::CardRemoved,
        PcscFault::Other => CardError::Transport(TransportFault::Io),
    }
}

/// A connected PC/SC card as a [`CardTransport`]. A job that sends anything but a read-only
/// instruction (`yubikey::needs_reset`: VERIFY, management-key authentication, signing, writes)
/// releases the card with a warm reset (spec/10 §5.1), so no PIN stays verified for the next
/// PC/SC client — between the PIN check and the signature, or after any card job.
#[derive(Debug)]
pub struct PcscTransport<'c> {
    card: pcsc::Card<'c>,
}

impl CardTransport for PcscTransport<'_> {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, CardError> {
        if yw_core::yubikey::needs_reset(command) {
            // Marked before the frame leaves: a command that fails half way still ends in a
            // reset.
            self.card.reset_on_release();
        }
        self.card
            .transmit(command)
            .map_err(|error| transport_error(pcsc::fault(&error)))
    }
}

/// Windows CNG as the PIV management-key cipher.
#[derive(Clone, Copy, Debug, Default)]
pub struct CngCipher;

impl CngCipher {
    fn run(
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
        encrypt: bool,
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        let cipher = match algorithm {
            MgmtAlgorithm::TripleDes => yw_win::cng::BlockCipher::TripleDes,
            MgmtAlgorithm::Aes128 | MgmtAlgorithm::Aes192 | MgmtAlgorithm::Aes256 => {
                yw_win::cng::BlockCipher::Aes
            }
        };
        if key.len() != algorithm.key_len() {
            return Err(CardError::Internal);
        }
        yw_win::cng::ecb_block(cipher, key, block, encrypt)
            .map(Zeroizing::new)
            .map_err(|_| CardError::Internal)
    }
}

impl MgmtCipher for CngCipher {
    fn encrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        Self::run(algorithm, key, block, true)
    }

    fn decrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        Self::run(algorithm, key, block, false)
    }
}

/// The real readers (PC/SC, user scope).
#[derive(Debug, Default)]
pub struct PcscSource;

impl CardSource for PcscSource {
    fn each_card(&mut self, visit: &mut CardVisit<'_>) -> Result<(), CardError> {
        let context =
            pcsc::Context::establish().map_err(|error| transport_error(pcsc::fault(&error)))?;
        let readers = context
            .readers()
            .map_err(|error| transport_error(pcsc::fault(&error)))?;
        if readers.is_empty() {
            return Err(CardError::Transport(TransportFault::NoReader));
        }
        // A reader without a card is skipped silently; a card another program holds (gpg-agent,
        // scdaemon) or a reader error is remembered and reported when no card could be visited
        // (spec/10 §5.1: "다른 프로그램이 YubiKey를 쓰고 있습니다", not "찾을 수 없습니다").
        let mut fault: Option<PcscFault> = None;
        let mut visited = false;
        let mut note = |found: PcscFault| {
            if found != PcscFault::NoCard && fault != Some(PcscFault::Busy) {
                fault = Some(found);
            }
        };
        for reader in readers {
            let mut card = match context.connect(&reader) {
                Ok(card) => card,
                Err(error) => {
                    note(pcsc::fault(&error));
                    continue;
                }
            };
            if let Err(error) = card.begin_transaction() {
                note(pcsc::fault(&error));
                continue;
            }
            visited = true;
            let mut transport = PcscTransport { card };
            if visit(&mut transport, &CngCipher) {
                break;
            }
        }
        match fault {
            Some(found) if !visited => Err(transport_error(found)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::{Path, PathBuf};

    /// `text` without its inline `#[cfg(test)] [pub(…)] mod name { … }` modules at column 0 (each
    /// ends at the first `}` line at column 0).
    fn without_test_modules(text: &str) -> String {
        let mut kept = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("#[cfg(test)]\n") {
            let after = &rest[start + "#[cfg(test)]\n".len()..];
            let line = after.lines().next().unwrap_or("");
            let item = line
                .strip_prefix("pub(crate) ")
                .or_else(|| line.strip_prefix("pub(super) "))
                .unwrap_or(line);
            if item.starts_with("mod ") && item.ends_with(" {") {
                kept.push_str(&rest[..start]);
                rest = after
                    .find("\n}\n")
                    .map_or("", |end| &after[end + "\n}\n".len()..]);
            } else {
                kept.push_str(&rest[..start + "#[cfg(test)]\n".len()]);
                rest = after;
            }
        }
        kept.push_str(rest);
        kept
    }

    /// The crates under `crates/` that do not and must not depend on yw-engine (2026-11-23, spec/15
    /// §11.4 S5-0, §18 31 (다), 주인 결정(2026-11-23); S5 plan critic C4): the only ones the source
    /// scans leave out. [`every_engine_dependent_crate_is_scanned`] checks that none of them names
    /// yw-engine in a dependency table, so a new crate (the Android shell) is scanned the day it is
    /// added, with no list to update.
    pub(crate) const NO_ENGINE_CRATES: [&str; 5] =
        ["yw-core", "yw-host", "yw-json", "yw-platform", "yw-win"];

    /// The `crates/` folder (the parent of yw-app's, not `yw-app/..`, so yw-app's `src` is the
    /// same path as `CARGO_MANIFEST_DIR/src`, which `testkit_is_named_only_by_tests` strips).
    fn crates_dir() -> PathBuf {
        let app = Path::new(env!("CARGO_MANIFEST_DIR"));
        app.parent().unwrap_or(app).to_path_buf()
    }

    /// The crates the source scans read, by folder name and sorted: every folder of `crates/`
    /// that holds a `Cargo.toml`, but [`NO_ENGINE_CRATES`] (2026-11-23, S5-0). Also the crate list
    /// of `app::tests::s4_results::production_code`.
    pub(crate) fn scanned_crates() -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(crates_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.join("Cargo.toml").is_file())
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .filter(|name| !NO_ENGINE_CRATES.contains(&name.as_str()))
            .collect();
        names.sort();
        names
    }

    /// The source folders the scans read: the `src` of every [`scanned_crates`] crate.
    /// 2026-11-17 (S2 review): yw-app's and yw-engine's (`yubikey.rs` and the key worker moved
    /// there). 2026-11-17 (S2 E3 review): every new crate that depends on yw-engine had to add its
    /// `src` here by hand. 2026-11-23 (spec/15 §11.4 S5-0, §18 31 (다)): every crate but the
    /// no-engine list, so a new shell crate is in the `MockSource`, PC/SC and `testkit` scans
    /// without an edit.
    fn source_roots() -> Vec<PathBuf> {
        let crates = crates_dir();
        let roots: Vec<PathBuf> = scanned_crates()
            .iter()
            .map(|name| crates.join(name).join("src"))
            .filter(|src| src.is_dir())
            .collect();
        for name in ["yw-app", "yw-engine"] {
            assert!(
                roots.contains(&crates.join(name).join("src")),
                "{name} is scanned"
            );
        }
        roots
    }

    /// The key of a TOML key line or dotted key (`engine`, `engine.workspace`, `"engine"`), or
    /// the last part of a table header after its `dependencies.` (`engine` of
    /// `[dependencies.engine]`); `None` for a line with no `=` or a header with nothing after it.
    fn toml_key(line: &str) -> Option<String> {
        let key = if line.starts_with('[') {
            let inner = line.trim_matches(['[', ']']);
            inner.rsplit_once("dependencies.")?.1
        } else {
            line.split_once('=')?.0
        };
        let first = key.trim().split('.').next().unwrap_or("");
        let first = first.trim().trim_matches('"').trim_matches('\'');
        (!first.is_empty()).then(|| first.to_owned())
    }

    /// The keys of the root `[workspace.dependencies]` (its inline entries and its
    /// `[workspace.dependencies.<key>]` tables) whose entry names yw-engine: by key, by
    /// `package = "yw-engine"` or by a path that ends in `yw-engine` (2026-11-23, S5-0 review: a
    /// workspace-level rename, `engine = { package = "yw-engine", … }`, that a member names as
    /// `engine.workspace = true`). Comments are not read.
    fn workspace_engine_keys(root: &str) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        let mut section = String::new();
        let mut table_key: Option<String> = None;
        for line in root.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.starts_with('[') {
                section = line.to_owned();
                table_key = if line.starts_with("[workspace.dependencies.") {
                    toml_key(line)
                } else {
                    None
                };
                if let Some(key) = &table_key
                    && (key.contains("yw-engine") || key.contains("yw_engine"))
                    && !keys.contains(key)
                {
                    keys.push(key.clone());
                }
                continue;
            }
            let key = if section == "[workspace.dependencies]" {
                toml_key(line)
            } else {
                table_key.clone()
            };
            if let Some(key) = key
                && (line.contains("yw-engine") || line.contains("yw_engine"))
                && !keys.contains(&key)
            {
                keys.push(key);
            }
        }
        keys.sort();
        keys
    }

    /// The root `[workspace] members` paths (one line or several).
    fn workspace_members(root: &str) -> Vec<String> {
        let mut members = Vec::new();
        let mut in_workspace = false;
        let mut in_members = false;
        for line in root.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.starts_with('[') && !in_members {
                in_workspace = line == "[workspace]";
                continue;
            }
            let list = if in_members {
                line
            } else if in_workspace
                && let Some((key, value)) = line.split_once('=')
                && key.trim() == "members"
            {
                in_members = true;
                value.trim_start().trim_start_matches('[')
            } else {
                continue;
            };
            let (list, closed) = match list.split_once(']') {
                Some((before, _)) => (before, true),
                None => (list, false),
            };
            members.extend(
                list.split(',')
                    .map(|item| item.trim().trim_matches('"').trim_matches('\''))
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned),
            );
            if closed {
                in_members = false;
            }
        }
        members
    }

    /// Whether `manifest` (a `Cargo.toml`) names yw-engine in a dependency table: any table whose
    /// header holds `dependencies` (`[dependencies]`, `[dev-dependencies]`,
    /// `[build-dependencies]`, `[target.'cfg(…)'.dependencies]`, `[dependencies.yw-engine]`, …),
    /// by its key or by a `package = "yw-engine"` rename (2026-11-23, S5-0, critic C4), or by a
    /// key of `engine_keys`, the root's yw-engine entries of [`workspace_engine_keys`]
    /// (`engine.workspace = true`, `engine = { workspace = true }`, `[dependencies.engine]`;
    /// 2026-11-23, S5-0 review). Comments are not read.
    fn names_engine_dependency(manifest: &str, engine_keys: &[String]) -> bool {
        let names_engine = |line: &str| {
            line.contains("yw-engine")
                || line.contains("yw_engine")
                || toml_key(line).is_some_and(|key| engine_keys.contains(&key))
        };
        let mut in_dependencies = false;
        for line in manifest.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.starts_with('[') {
                in_dependencies = line.contains("dependencies");
                if in_dependencies && names_engine(line) {
                    return true;
                }
                continue;
            }
            if in_dependencies && names_engine(line) {
                return true;
            }
        }
        false
    }

    /// The source scans leave out only crates that cannot reach yw-engine (2026-11-23, spec/15
    /// §11.4 S5-0, §18 31 (다); critic C4): each [`NO_ENGINE_CRATES`] crate exists under
    /// `crates/` and names yw-engine in none of its dependency tables, and every other crate there
    /// (yw-app and yw-engine today) is a [`source_roots`] root and in
    /// `s4_results::production_code`. A crate that starts to depend on yw-engine fails here until
    /// it leaves the no-engine list, and then it is scanned. 2026-11-23 (S5-0 review): every root
    /// `[workspace] members` path is `crates/<dir>` and the members are exactly the crates under
    /// `crates/`, so a member added elsewhere (`android/…`) fails here instead of going unscanned;
    /// and a member that names yw-engine through a renamed `[workspace.dependencies]` key counts.
    #[test]
    fn every_engine_dependent_crate_is_scanned() {
        let crates = crates_dir();
        let root = std::fs::read_to_string(crates.parent().unwrap().join("Cargo.toml")).unwrap();
        let engine_keys = workspace_engine_keys(&root);
        assert!(
            engine_keys.iter().any(|key| key == "yw-engine"),
            "{engine_keys:?}"
        );
        for name in NO_ENGINE_CRATES {
            let manifest = std::fs::read_to_string(crates.join(name).join("Cargo.toml"));
            assert!(manifest.is_ok(), "{name} is a crate under crates/");
            assert!(
                !names_engine_dependency(&manifest.unwrap(), &engine_keys),
                "{name} names yw-engine in a dependency table: scan it (NO_ENGINE_CRATES)"
            );
        }
        let mut all: Vec<String> = std::fs::read_dir(&crates)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.join("Cargo.toml").is_file())
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        all.sort();
        assert!(all.len() >= 7, "{all:?}");
        let mut members: Vec<String> = workspace_members(&root)
            .iter()
            .map(|member| {
                let dir = member.replace('\\', "/");
                let dir = dir.trim_end_matches('/').strip_prefix("crates/");
                assert!(
                    dir.is_some_and(|dir| !dir.is_empty() && !dir.contains(['/', '*', '?'])),
                    "workspace member {member} is not crates/<dir>: the source scans read crates/ only"
                );
                dir.unwrap_or_default().to_owned()
            })
            .collect();
        members.sort();
        assert_eq!(
            members, all,
            "the workspace members are the crates under crates/"
        );
        let scanned = scanned_crates();
        let roots = source_roots();
        for name in &all {
            if NO_ENGINE_CRATES.contains(&name.as_str()) {
                continue;
            }
            assert!(scanned.contains(name), "{name}");
            assert!(roots.contains(&crates.join(name).join("src")), "{name}");
        }
        assert_eq!(scanned, ["yw-app", "yw-engine"], "the scanned crates today");
        let production = crate::app::tests::s4_results::production_crates();
        assert_eq!(
            production, scanned,
            "s4_results::production_code reads the same crates"
        );
    }

    /// [`names_engine_dependency`] on made-up manifests (it can fail).
    #[test]
    fn engine_dependency_on_made_up_manifests() {
        let cases = [
            ("[dependencies]\nyw-core.workspace = true\n", false),
            ("[dependencies]\nyw-engine.workspace = true\n", true),
            (
                "[dev-dependencies]\nyw-engine = { path = \"../yw-engine\" }\n",
                true,
            ),
            (
                "[target.'cfg(target_os = \"android\")'.dependencies]\nyw-engine.workspace = true\n",
                true,
            ),
            (
                "[dependencies]\nengine = { package = \"yw-engine\", path = \"x\" }\n",
                true,
            ),
            ("[dependencies.yw-engine]\npath = \"../yw-engine\"\n", true),
            (
                "[package]\nname = \"yw-engine-docs\"\n[dependencies]\nyw-json = \"1\"\n",
                false,
            ),
            (
                "[dependencies]\n# yw-engine = \"1\" (not yet)\nyw-json = \"1\"\n",
                false,
            ),
            ("[features]\nyw-engine = []\n", false),
            // 2026-11-23 (S5-0 review): a key the root renames to yw-engine.
            ("[dependencies]\nengine.workspace = true\n", true),
            ("[dependencies]\nengine = { workspace = true }\n", true),
            (
                "[target.'cfg(target_os=\"android\")'.dependencies]\nengine.workspace = true\n",
                true,
            ),
            ("[dependencies.engine]\nworkspace = true\n", true),
            ("[dependencies]\nengines.workspace = true\n", false),
            ("[features]\nengine = []\n", false),
        ];
        let engine_keys = ["engine".to_owned(), "yw-engine".to_owned()];
        for (manifest, expected) in cases {
            assert_eq!(
                names_engine_dependency(manifest, &engine_keys),
                expected,
                "{manifest}"
            );
        }
        assert!(!names_engine_dependency(
            "[dependencies]\nengine.workspace = true\n",
            &["yw-engine".to_owned()]
        ));
    }

    /// [`workspace_engine_keys`] and [`workspace_members`] on made-up root manifests (they can
    /// fail; 2026-11-23, S5-0 review).
    #[test]
    fn workspace_keys_and_members_on_made_up_roots() {
        let root = "[workspace]\nmembers = [\n  \"crates/yw-core\", # core\n  \"android/yw-android\",\n]\n\
            exclude = [\"fuzz\"]\n\
            [workspace.dependencies]\n\
            yw-core = { path = \"crates/yw-core\" }\n\
            engine = { package = \"yw-engine\", path = \"crates/yw-engine\" }\n\
            other.path = \"x/yw-engine\"\n\
            # quiet = { package = \"yw-engine\" }\n\
            [workspace.dependencies.core2]\npackage = \"yw-engine\"\n\
            [workspace.dependencies.plain]\npath = \"crates/yw-json\"\n\
            [workspace.lints.rust]\nyw-engine = \"deny\"\n";
        assert_eq!(workspace_engine_keys(root), ["core2", "engine", "other"]);
        assert_eq!(
            workspace_members(root),
            ["crates/yw-core", "android/yw-android"]
        );
        assert_eq!(
            workspace_members("[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n"),
            ["crates/a", "crates/b"]
        );
        assert!(workspace_members("[package]\nmembers = [\"crates/a\"]\n").is_empty());
    }

    /// Every `.rs` under `dir`, test code included.
    fn all_sources(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                all_sources(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                found.push((path, text));
            }
        }
    }

    /// The sources that are not test code: every `.rs` under `dir`, except files named
    /// `tests.rs` or under a `tests` folder, without their inline `#[cfg(test)]` modules.
    fn production_sources(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "tests" {
                    production_sources(&path, found);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && name != "tests.rs"
            {
                let text = std::fs::read_to_string(&path).unwrap();
                found.push((path, without_test_modules(&text)));
            }
        }
    }

    /// The emulator source is always compiled (`yubikey::MockSource`, spec/15 §11.4 S2) but only
    /// test code may build one: production code never constructs or names it outside its own
    /// definition, so the key worker can only get the PC/SC readers. yw-engine's `testkit` (test
    /// helpers, always compiled) builds one; `testkit_is_named_only_by_tests` keeps it out of
    /// production code (2026-11-17, S2 E3).
    #[test]
    fn mock_source_is_built_only_by_tests() {
        let mut sources = Vec::new();
        for root in source_roots() {
            production_sources(&root, &mut sources);
        }
        assert!(sources.len() > 100, "{}", sources.len());
        let mut offenders = Vec::new();
        for (path, text) in &sources {
            if path.ends_with("testkit.rs") {
                continue;
            }
            let allowed: &[&str] = if path.ends_with("yubikey.rs") {
                &[
                    "pub struct MockSource {",
                    "impl CardSource for MockSource {",
                    "impl std::fmt::Debug for MockSource {",
                    "debug_struct(\"MockSource\")",
                ]
            } else {
                &[]
            };
            let mut rest = text.clone();
            for definition in allowed {
                rest = rest.replace(definition, "");
            }
            if rest.contains("MockSource") {
                offenders.push(path.display().to_string());
            }
        }
        assert!(offenders.is_empty(), "{offenders:?}");
    }

    /// Only `main.rs` gives the key worker the machine's PC/SC readers (2026-11-17 S2 review,
    /// AGENTS rule 3): in every source, test code included (`src` and `tests` of yw-app and,
    /// once it exists, yw-engine), `WinKeyPlatform::deps(…)` is called only by `main.rs` and
    /// `PcscSource` is named in code only by its definition and `store.rs` (`deps`). Tests on
    /// real files use `WinKeyPlatform::deps_with_cards` with `yubikey::NoReaders` or the
    /// emulator. Comment lines are not code. (2026-11-19, S4 B1a: `deps` takes the App's clock,
    /// so the scan matches `WinKeyPlatform::deps(`; before, `WinKeyPlatform::deps()`.)
    #[test]
    fn pcsc_readers_only_from_main() {
        let mut sources = Vec::new();
        for root in source_roots() {
            all_sources(&root, &mut sources);
            let tests = root.join("..").join("tests");
            if tests.is_dir() {
                all_sources(&tests, &mut sources);
            }
        }
        assert!(sources.len() > 150, "{}", sources.len());
        let mut offenders = Vec::new();
        for (path, text) in &sources {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let code: String = text
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let pcsc_allowed = name == "card_pcsc.rs" || name == "store.rs";
            let deps_allowed = name == "main.rs" || name == "card_pcsc.rs";
            if (code.contains("PcscSource") && !pcsc_allowed)
                || (code.contains("WinKeyPlatform::deps(") && !deps_allowed)
            {
                offenders.push(path.display().to_string());
            }
        }
        assert!(offenders.is_empty(), "{offenders:?}");
    }

    /// yw-app's `cfg(test)` module files outside a `tests` folder (2026-11-23, S4d E1): the file,
    /// the file that declares it and the declaration (with its `cfg(test)`) found there.
    /// 2026-11-23 (S4d final review): also the three dev-only tour modules of `ui` (the screenshot
    /// tour, the windowed form test and the secret characterization), which reach the wallet's
    /// crate-private steps through `testkit::WalletTestExt` since the review made them
    /// crate-private again.
    const CFG_TEST_FILES: [(&str, &str, &str); 11] = [
        (
            "app/secret_seam.rs",
            "app.rs",
            "#[cfg(test)]
pub(crate) mod secret_seam;",
        ),
        (
            "app_approval_smoke.rs",
            "app_approval.rs",
            "#[cfg(test)]
#[path = \"app_approval_smoke.rs\"]",
        ),
        (
            "app_approval_flow_support.rs",
            "app_approval.rs",
            "#[cfg(test)]
#[path = \"app_approval_flow_support.rs\"]",
        ),
        (
            "app_approval_headless_host.rs",
            "app_approval.rs",
            "#[cfg(test)]
#[path = \"app_approval_headless_host.rs\"]",
        ),
        (
            "app_approval_flow_tests.rs",
            "app_approval.rs",
            "#[cfg(test)]
#[path = \"app_approval_flow_tests.rs\"]",
        ),
        (
            "app_approval_input_tests.rs",
            "app_approval.rs",
            "#[cfg(test)]
#[path = \"app_approval_input_tests.rs\"]",
        ),
        (
            "app_approval_lifecycle_tests.rs",
            "app_approval_flow_tests.rs",
            "#[path = \"app_approval_lifecycle_tests.rs\"]",
        ),
        (
            "app_approval_headless_tests.rs",
            "app_approval_lifecycle_tests.rs",
            "#[path = \"app_approval_headless_tests.rs\"]",
        ),
        (
            "ui/tour.rs",
            "ui/mod.rs",
            "#[cfg(test)]
#[cfg(debug_assertions)]
mod tour;",
        ),
        (
            "ui/tour_forms.rs",
            "ui/mod.rs",
            "#[cfg(test)]
#[cfg(debug_assertions)]
mod tour_forms;",
        ),
        (
            "ui/tour_secrets.rs",
            "ui/mod.rs",
            "#[cfg(test)]
#[cfg(debug_assertions)]
pub(crate) mod tour_secrets;",
        ),
    ];

    /// yw-engine's `testkit` (the `YubiKey` emulator wallet helper, always compiled because
    /// `cfg(test)` does not cross crates, spec/15 §11.4 S2 D-f) is named only by test code: no
    /// production source of yw-app or yw-engine reaches it, except its own declaration in the
    /// engine's `lib.rs` and the module itself. Comment lines are not code. (2026-11-17, S2 E3.)
    /// 2026-11-23 (spec/15 §11.4 S4d E1): yw-app's `cfg(test)` module files that are not under a
    /// `tests` folder ([`CFG_TEST_FILES`]) are test code too: since E1 they reach the wallet's
    /// crate-private steps through `testkit::{WalletTestExt, FlowTestExt}`. Each must still be
    /// declared `#[cfg(test)]` (checked), so a production file cannot hide in the list.
    #[test]
    fn testkit_is_named_only_by_tests() {
        let mut sources = Vec::new();
        for root in source_roots() {
            production_sources(&root, &mut sources);
        }
        assert!(sources.len() > 100, "{}", sources.len());
        let mut offenders = Vec::new();
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for (file, declared_in, declaration) in CFG_TEST_FILES {
            assert!(src.join(file).is_file(), "{file}");
            let parent = std::fs::read_to_string(src.join(declared_in)).unwrap();
            assert!(
                parent.contains(declaration),
                "{file} is declared `{declaration}` in {declared_in}"
            );
        }
        for (path, text) in &sources {
            let engine = path
                .components()
                .any(|part| part.as_os_str() == "yw-engine");
            if engine && path.ends_with("testkit.rs") {
                continue;
            }
            let relative = path
                .strip_prefix(&src)
                .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            if !engine && CFG_TEST_FILES.iter().any(|(file, _, _)| *file == relative) {
                continue;
            }
            let code: String = text
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let rest = if engine && path.ends_with("lib.rs") {
                code.replacen("pub mod testkit;", "", 1)
            } else {
                code
            };
            if rest.contains("testkit") {
                offenders.push(path.display().to_string());
            }
        }
        assert!(offenders.is_empty(), "{offenders:?}");
    }
}
