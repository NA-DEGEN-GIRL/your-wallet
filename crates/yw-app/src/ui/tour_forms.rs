//! Windowed form test — **DEV ONLY** (`#[ignore]`, debug test builds, like the screenshot tour;
//! 2026-11-18, spec/15 §11.4 S3 B5, plan §3.2a): the S3 form state (`App::form`) must equal what
//! the main window's real edits show at every point a handler can read it. The headless census
//! has no window — `refresh` lays nothing out and `set_text` writes nothing — so it cannot see
//! an edit created again by a render, the edit being typed in kept across one, or a
//! programmatic write; this test runs the same states and scenarios with the real main window.
//!
//! What it does, on the census's own throwaway folder (the `rpc.json` and extension-folder paths
//! point into it; nothing outside it is read or written):
//! - every census start state ([`Base::ALL`]): each plain edit that is shown gets text through
//!   the edit itself (`ControlSet::set_text`, focused first as a user's edit is) and its
//!   `EN_CHANGE` (`App::on_edit_notify`); then, on a fresh state each, Enter in every shown edit
//!   Enter presses a button from (not the image-file path, whose button reads a file);
//! - every write scenario of the census (the programmatic writes, the credential forms, Enter
//!   and the address-book, send, Esplora and `HyperCore` forms) and the extra form scenarios
//!   below, step by step, typing into the shown edits as above; a check box is pressed with the
//!   state the window gives it.
//!
//! Enter is a real key (2026-11-20, S4 P4 review): the edit is focused and `IDOK` goes through
//! the shell's `on_command`, which reads the focus and presses what Enter stands for (S4 P4 moved
//! that resolution out of the logic); the press the logic got must be the one
//! `App::enter_target` names, and Enter in the credential forms (`REPLACE_EDIT`, `DONE_QN_EDIT`)
//! and in the account rename must press their button. Before, the test called the census's
//! `App::enter_on`, which skips the key and the focus read.
//!
//! After every step the form state is compared with the window for all 58 plain edits, by the
//! test itself (`Wallet::form_text` against the edit) and, debug builds, by the shell at the end of
//! every drain (`App::check_form_in_step`, which counts a difference in `form_mismatch`; before
//! S4 W3, 2026-11-21, `App::form_text` compared at each read); then a render is forced and the
//! comparison runs again. Credential units the handler took (`Wallet::take_cred`: their length and
//! digest, debug builds) are compared, when the next drain starts, with the shell's own read of
//! the edit made with the press and with the edit then (`App::cred_check`; 2026-11-21, S4 W3
//! review: before, only the two shell reads were compared, so a misrouted take went unseen;
//! before W3, `take_cred` compared the units with the edit itself). The test fails unless
//! `form_mismatch` and the credential misses stay 0; it prints the fields it saw shown and typed.
//!
//! 2026-11-24 (spec/15 §11.3, §11.4 S5-6): the form state is the engine's — no read-back from the
//! edits feeds it any more (`Cmd::Form` at a press and after a render, `Cmd::FieldShown` after a
//! field write are gone); the engine works out what the edits show from `EN_CHANGE`, its own field
//! writes and the models it drew (`form::FormSync`, the Windows keep rule of `ControlSet::sync`).
//! So the comparisons above are what check that rule against the real window (an edit created
//! again by a render, the focused edit kept across one, a programmatic write). It also sums and
//! prints the lowering's `press_mismatch` (S5 plan C18) and fails unless it is 0.
//!
//! The main-window mirror (2026-11-21, S4 W3 review, critique B-10): on one more app, the
//! wallet's `main_hidden()` and a due balance tick with the real main window shown, minimized,
//! shown, hidden and shown again (`main_hidden_follows_the_window`).
//!
//! Safety: no worker is attached (no RPC, `WalletConnect`, LLM or key worker runs; RPC jobs land
//! in a channel that is only dropped, key jobs stay queued), no browser bridge, explorer links go
//! to `Launcher::Record`, no copy, clipboard, folder, file-QR or LLM-test press is made, and no
//! message loop runs (no timer fires). No secret window is opened. The mirror check's balance
//! reads land in the same dropped channel.
//!
//! `cargo test -p yw-app --lib ui::tour_forms -- --ignored --test-threads=1 --nocapture`

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, channel};

use yw_engine::cmd::Press;
use yw_engine::form::EditField;

use crate::app::App;
use crate::app::tests::s3_census::{
    Base, Census, ENTER_EDITS, Scenario, Step, no_setup, write_scenarios,
};
use crate::ui::cmd_table::{IDOK, edit_id_of, press_of};
use crate::ui::screens_walletconnect;
use yw_engine::testkit::WalletTestExt;
use yw_engine::workers::rpc::RpcJob;

/// Totals of one run.
#[derive(Default)]
struct Tally {
    /// Fields whose edit was shown at a check.
    shown: BTreeSet<EditField>,
    /// Fields typed into through their edit.
    typed: BTreeSet<EditField>,
    /// Steps run and comparisons made (each of the 58 fields, twice per step).
    steps: usize,
    checks: usize,
    /// Differences the test saw itself (besides `form_mismatch`).
    differences: Vec<String>,
    /// Sum over all apps of `form_mismatch` and the credential misses.
    form_mismatch: u32,
    cred_misses: u32,
    /// Sum over all apps of `press_mismatch` (2026-11-24, spec/15 §11.4 S5-6, S5 plan C18: the
    /// screen model's lowering drew a press at a control id that maps back to another press, or a
    /// credential edit with text; the census asserts it 0 since S5-4, this test since S5-6).
    press_mismatch: u32,
    /// Steps skipped because their edit or button was not shown.
    skipped: usize,
    /// Enter steps run through the shell (`IDOK`), and the edits where Enter pressed a control
    /// (2026-11-20, S4 P4 review).
    enters: usize,
    enter_pressed: BTreeSet<u16>,
}

/// One app with its real main window, on a fresh state of `census`.
fn open(census: &Census, base: Base, setup: fn(&mut App)) -> (Rc<RefCell<App>>, Receiver<RpcJob>) {
    census.fresh_data();
    census.guard();
    let app = Rc::new(RefCell::new(base.build(census.data())));
    // 2026-11-20 (S4 P10b): each call into the logic here is one entry and drains (what the build
    // emitted applies with no window yet, as before).
    app.borrow_mut().drain();
    let (tx, rx) = channel();
    app.borrow_mut().set_rpc_tx(tx);
    App::create_main_window(&app).unwrap();
    {
        let mut state = app.borrow_mut();
        state.show_main();
        state.drain();
        setup(&mut state);
        state.drain();
        state.refresh();
        state.drain();
    }
    (app, rx)
}

/// Whether edit or button `id` is shown now (a live control).
fn shown(state: &App, id: u16) -> Option<usize> {
    state
        .placed
        .controls
        .iter()
        .position(|(ctl, _)| ctl.id == id)
}

/// Text typed into edit `id` as a user does: focused, its text set through the window, then its
/// `EN_CHANGE` (which the window delivers after the borrow; inside it, it is dropped).
fn type_into(state: &mut App, id: u16, text: &str, tally: &mut Tally) -> bool {
    let Some(index) = shown(state, id) else {
        tally.skipped += 1;
        return false;
    };
    state.controls.focus_at(index);
    state.controls.set_text(id, text);
    state.on_edit_notify(id);
    state.drain();
    if let Some(field) = crate::ui::cmd_table::field_of(id) {
        tally.typed.insert(field);
    }
    true
}

/// The comparison of all 58 plain edits, a forced render, and the comparison again.
fn check(state: &mut App, what: &str, tally: &mut Tally) {
    for pass in ["", " after a render"] {
        if !pass.is_empty() {
            state.refresh();
            state.drain();
        }
        for field in EditField::ALL {
            let window = state.controls.text(edit_id_of(field), field.cap());
            if window.is_some() {
                tally.shown.insert(field);
            }
            let form = state.form_text(field);
            if form != window {
                tally.differences.push(format!("{what}{pass}: {field:?}"));
            }
            tally.checks += 1;
        }
    }
    tally.steps += 1;
}

/// Adds an app's counters to the tally and closes it.
fn close(app: Rc<RefCell<App>>, rx: Receiver<RpcJob>, census: &Census, tally: &mut Tally) {
    {
        let state = app.borrow();
        tally.form_mismatch = tally
            .form_mismatch
            .saturating_add(state.form_mismatch.get());
        tally.cred_misses = tally.cred_misses.saturating_add(state.cred_misses());
        tally.press_mismatch = tally
            .press_mismatch
            .saturating_add(state.press_mismatch.get());
    }
    drop(app);
    drop(rx);
    census.guard();
}

/// Enter in shown edit `id` (at `index`) as the window delivers it (2026-11-20, S4 P4 review):
/// the edit focused, then `IDOK` through the shell's `on_command`, whose `enter_key` reads the
/// focus and presses what it stands for (before, this test called the census's `enter_on`, which
/// skips the key and the focus read). The press the logic got last must be the one
/// `App::enter_target` names for the focused edit before the key (its button's own press), or
/// `Press::Enter` itself when Enter stands for nothing there.
fn enter_key(state: &mut App, id: u16, index: usize, tally: &mut Tally) -> String {
    let what = format!("enter {id}");
    state.controls.focus_at(index);
    if state.controls.focused() != Some(index) {
        tally
            .differences
            .push(format!("{what}: the edit did not take the focus"));
        return what;
    }
    let focus = state.placed.controls.get(index).map(|(ctl, _)| ctl.clone());
    let expected = state
        .enter_target(focus.as_ref())
        .and_then(|target| press_of(target, &state.controls))
        .unwrap_or(Press::Enter);
    Step::Press(IDOK).run(state);
    tally.enters += 1;
    if expected != Press::Enter {
        tally.enter_pressed.insert(id);
    }
    if state.last_press() != expected {
        tally.differences.push(format!(
            "{what}: Enter pressed {:?}, expected {expected:?}",
            state.last_press()
        ));
    }
    what
}

/// A step of a census scenario, with the window: a press as a click, text through the edit,
/// Enter in a shown edit (focused, then `IDOK` through the shell), a check box pressed with the
/// window's own state.
fn run_step(state: &mut App, step: Step, tally: &mut Tally) -> String {
    match step {
        Step::Press(id) | Step::Check(id, _) => {
            if shown(state, id).is_none() {
                tally.skipped += 1;
                return format!("press {id} (not shown)");
            }
            Step::Press(id).run(state)
        }
        Step::Type(id, text) => {
            type_into(state, id, text, tally);
            format!("type {id}")
        }
        Step::TypeWith(id, text) => {
            type_into(state, id, &text(), tally);
            format!("type {id}")
        }
        Step::Enter(id) => {
            let Some(index) = shown(state, id) else {
                tally.skipped += 1;
                return format!("enter {id} (not shown)");
            };
            enter_key(state, id, index, tally)
        }
        Step::Call(..) => {
            let what = step.run(state);
            state.drain();
            state.refresh();
            state.drain();
            what
        }
    }
}

/// Every census state: every shown plain edit typed, then Enter in each shown Enter edit.
fn states(census: &Census, tally: &mut Tally) {
    for base in Base::ALL {
        let name = base.name();
        let (app, rx) = open(census, base, no_setup);
        let mut enter = Vec::new();
        {
            let mut state = app.borrow_mut();
            check(&mut state, &format!("{name} open"), tally);
            for field in EditField::ALL {
                let id = edit_id_of(field);
                // A value past the cap where the cap is small: the read and the state cut it.
                let text = if field.cap() <= 16 {
                    "7".repeat(20)
                } else {
                    "7".to_owned()
                };
                if type_into(&mut state, id, &text, tally) {
                    check(&mut state, &format!("{name} type {field:?}"), tally);
                }
            }
            for id in ENTER_EDITS {
                if id != screens_walletconnect::ids::FILE_EDIT && shown(&state, id).is_some() {
                    enter.push(id);
                }
            }
        }
        close(app, rx, census, tally);
        for id in enter {
            let (app, rx) = open(census, base, no_setup);
            {
                let mut state = app.borrow_mut();
                type_into(&mut state, id, "8", tally);
                let what = run_step(&mut state, Step::Enter(id), tally);
                check(&mut state, &format!("{name} {what}"), tally);
            }
            close(app, rx, census, tally);
        }
    }
}

/// The census's write scenarios and the extra form scenarios, step by step.
fn scenarios(census: &Census, tally: &mut Tally) {
    let mut all: Vec<Scenario> = write_scenarios();
    all.extend(extra_scenarios());
    for scenario in all {
        let (app, rx) = open(census, scenario.base, scenario.setup);
        {
            let mut state = app.borrow_mut();
            check(&mut state, &format!("{} setup", scenario.name), tally);
            for (index, step) in scenario.steps.iter().enumerate() {
                let what = run_step(&mut state, *step, tally);
                check(
                    &mut state,
                    &format!("{} {} {what}", scenario.name, index + 1),
                    tally,
                );
            }
        }
        close(app, rx, census, tally);
    }
}

/// One due EVM balance tick (`evm_balance_tick`, the main timer's): the wallet's main-window
/// mirror must be `hidden`, and the tick reads (and queues its RPC job) exactly when it is not.
/// Returns the RPC jobs it queued.
fn balance_tick(state: &mut App, rx: &Receiver<RpcJob>, hidden: bool, what: &str) -> usize {
    assert_eq!(state.main_hidden(), hidden, "{what}: the wallet's mirror");
    while rx.try_recv().is_ok() {}
    state.evm.next_balance_ms = 0;
    let now = state.clock.now_ms();
    let due = state.evm_balance_tick(now);
    state.drain();
    let jobs = rx.try_iter().count();
    assert_eq!(
        due, !hidden,
        "{what}: a due balance tick reads only while shown"
    );
    if hidden {
        assert_eq!(jobs, 0, "{what}: no read queued");
    } else {
        assert!(jobs > 0, "{what}: the read is queued");
    }
    jobs
}

/// The main-window mirror on a real main window (2026-11-21, S4 W3 review, critique B-10): the
/// wallet's `main_hidden()` (`Cmd::MainHidden`, sent by the shell's `App::sync_main_hidden` when
/// `App::main_hidden_now` differs) is false while the window is shown, true while it is minimized
/// or hidden, and false again once it is shown; a due balance tick reads only while it is shown.
/// The gate does not check a visible window (its tests have none, or a hidden stand-in), and the
/// drain-end debug check compares the mirror with the same live read, so a wrong read would pass
/// both; this is the check of that read on a real window. The minimize's and the hide's `WM_SIZE`
/// or `WM_SHOWWINDOW` come inside this borrow and are dropped by the `Forward`, as the shell's own
/// show's are, so the test then runs what every main window message runs first
/// (`on_main_msg`'s sync); the live read must already ask for the change. Returns the RPC jobs
/// queued by the three shown ticks.
fn main_hidden_follows_the_window(census: &Census, tally: &mut Tally) -> [usize; 3] {
    use yw_engine::cmd::Cmd;
    let (app, rx) = open(
        census,
        Base::Main(yw_engine::meta::Tab::Evm, false),
        no_setup,
    );
    let mut jobs = [0; 3];
    {
        let mut state = app.borrow_mut();
        // `open` showed it (`show_main`).
        assert!(state.main_hidden_answer().is_none(), "shown: in step");
        jobs[0] = balance_tick(&mut state, &rx, false, "shown");
        for (index, how) in ["minimized", "hidden"].into_iter().enumerate() {
            if let Some(main) = state.main.as_ref() {
                if how == "minimized" {
                    main.minimize();
                } else {
                    main.hide();
                }
            }
            assert!(
                matches!(state.main_hidden_answer(), Some(Cmd::MainHidden(true))),
                "{how}: the live read sees it"
            );
            state.sync_main_hidden();
            balance_tick(&mut state, &rx, true, how);
            state.show_main();
            state.drain();
            assert!(state.main_hidden_answer().is_none(), "{how}, shown again");
            jobs[index + 1] = balance_tick(&mut state, &rx, false, &format!("{how}, shown again"));
        }
    }
    close(app, rx, census, tally);
    jobs
}

/// Form scenarios the write scenarios do not cover: screens with plain edits reached by a press
/// or a state change (values are made up; nothing is sent).
#[expect(clippy::too_many_lines, reason = "one scenario per form")]
fn extra_scenarios() -> Vec<Scenario> {
    use crate::ui::{
        screens, screens_btc as btc, screens_evm as evm, screens_explorer as explorer,
        screens_hypercore as hc, screens_reset as reset, screens_sites as sites,
        screens_sol as sol, screens_walletconnect as wc, screens_yubikey as yk,
    };
    use Step::{Call, Enter, Press, Type};
    use yw_engine::meta::Tab;
    use yw_engine::screen::SettingsSection;
    fn advanced(app: &mut App) {
        app.show_advanced = true;
    }
    fn wc_project(app: &mut App) {
        app.settings.walletconnect_project = "0123456789abcdef0123456789abcdef".to_owned();
        app.wc.file_open = true;
    }
    fn open_reset(app: &mut App) {
        app.open_reset();
    }
    fn open_wizard(app: &mut App) {
        app.yk_open_wizard();
    }
    vec![
        Scenario {
            name: "evm-send-token-rename",
            base: Base::Main(Tab::Evm, false),
            setup: no_setup,
            steps: vec![
                Press(screens::ids::RENAME),
                Type(screens::ids::RENAME_EDIT, "Main account"),
                Enter(screens::ids::RENAME_EDIT),
                Press(evm::ids::SEND_OPEN),
                Type(evm::ids::SEND_TO_EDIT, "0x12"),
                Type(evm::ids::SEND_AMOUNT_EDIT, "0.001"),
                Enter(evm::ids::SEND_AMOUNT_EDIT),
                Press(screens::ids::BACK_MAIN),
                Press(evm::ids::TOKEN_OPEN),
                Type(evm::ids::TOKEN_ADDR_EDIT, "0x34"),
                Type(evm::ids::TOKEN_LABEL_EDIT, "Token"),
                Enter(evm::ids::TOKEN_LABEL_EDIT),
            ],
        },
        Scenario {
            name: "evm-caps",
            base: Base::Settings(SettingsSection::Chains),
            setup: advanced,
            steps: vec![
                Press(evm::ids::CAPS_CHAIN_BASE),
                Type(evm::ids::CAPS_FEE_EDIT, "0.01"),
                Type(evm::ids::CAPS_TIP_EDIT, "2"),
                Type(evm::ids::CAPS_TOTAL_EDIT, "0.02"),
                Press(evm::ids::CAPS_SAVE),
                Press(evm::ids::CAPS_DEFAULT),
            ],
        },
        Scenario {
            name: "sol-send-rename",
            base: Base::Main(Tab::Sol, false),
            setup: no_setup,
            steps: vec![
                Press(sol::ids::RENAME),
                Type(sol::ids::RENAME_EDIT, "Sol account"),
                Enter(sol::ids::RENAME_EDIT),
                Press(sol::ids::SEND_OPEN),
                Type(sol::ids::SEND_TO_EDIT, "abc"),
                Type(sol::ids::SEND_AMOUNT_EDIT, "0.5"),
                Enter(sol::ids::SEND_AMOUNT_EDIT),
            ],
        },
        Scenario {
            name: "sol-fees",
            base: Base::Settings(SettingsSection::Solana),
            setup: advanced,
            steps: vec![
                Type(sol::ids::FEE_CAP_EDIT, "20000"),
                Type(sol::ids::CU_PRICE_EDIT, "1000"),
                Enter(sol::ids::FEE_CAP_EDIT),
            ],
        },
        Scenario {
            name: "btc-send-rename",
            base: Base::Main(Tab::Btc, false),
            setup: crate::app::tests::s3_census::btc_wallet,
            steps: vec![
                Press(btc::ids::RENAME),
                Type(btc::ids::RENAME_EDIT, "Btc account"),
                Enter(btc::ids::RENAME_EDIT),
                Press(btc::ids::SEND_OPEN),
                Type(btc::ids::SEND_TO_EDIT, "bc1q"),
                Type(btc::ids::SEND_AMOUNT_EDIT, "0.0001"),
                Press(btc::ids::FEE_MANUAL),
                Type(btc::ids::FEE_MANUAL_EDIT, "12"),
                Enter(btc::ids::FEE_MANUAL_EDIT),
            ],
        },
        Scenario {
            name: "explorer-row",
            base: Base::Settings(SettingsSection::Network),
            setup: no_setup,
            steps: vec![
                Press(explorer::ids::ROW_BASE),
                Type(
                    explorer::ids::EDIT_TX,
                    "https://explorer.example.test/tx/{hash}",
                ),
                Type(
                    explorer::ids::EDIT_ADDRESS,
                    "https://explorer.example.test/address/{address}",
                ),
                Enter(explorer::ids::EDIT_ADDRESS),
            ],
        },
        Scenario {
            name: "explorer-row-other",
            base: Base::Settings(SettingsSection::Other),
            setup: no_setup,
            steps: vec![
                Press(explorer::ids::ROW_BASE),
                Type(
                    explorer::ids::EDIT_TX,
                    "https://explorer.example.test/tx/{hash}",
                ),
                Enter(explorer::ids::EDIT_TX),
            ],
        },
        Scenario {
            name: "reset-phrase",
            base: Base::Settings(SettingsSection::Other),
            setup: no_setup,
            steps: vec![
                Call("open reset", open_reset),
                Type(reset::ids::RESET_PHRASE, "x"),
                Press(reset::ids::RESET_CANCEL),
            ],
        },
        Scenario {
            name: "walletconnect",
            base: Base::Main(Tab::Evm, false),
            setup: no_setup,
            steps: vec![
                Press(sites::ids::SITES_OPEN),
                Type(wc::ids::PROJECT_EDIT, "0123"),
                Call("project", wc_project),
                Type(wc::ids::URI_EDIT, "wc:not-a-link"),
                Type(wc::ids::FILE_EDIT, "not-a-file.png"),
                Type(wc::ids::PROJECT_EDIT, "0123"),
            ],
        },
        Scenario {
            name: "yubikey-wizard",
            base: Base::Settings(SettingsSection::YubiKey),
            setup: no_setup,
            steps: vec![
                Call("open wizard", open_wizard),
                Type(yk::ids::SIG_INDEX_EDIT, "1"),
                Type(yk::ids::AUT_INDEX_EDIT, "2"),
                Type(yk::ids::SOL_COUNT_EDIT, "3"),
                Type(yk::ids::SOL_START_EDIT, "4"),
                Type(yk::ids::OVERWRITE_EDIT, "x"),
            ],
        },
        Scenario {
            name: "hypercore-form",
            base: Base::Main(Tab::Evm, false),
            setup: crate::app::tests::s3_census::hc_withdraw,
            steps: vec![
                Type(hc::ids::TO_EDIT, "0x56"),
                Type(hc::ids::AMOUNT_EDIT, "1.5"),
                Type(hc::ids::API_EDIT, "https://api.example.test"),
            ],
        },
    ]
}

#[test]
#[ignore = "DEV ONLY: opens the main window on the desktop (S3 windowed form test)"]
#[expect(clippy::print_stdout, reason = "the test lists what it covered")]
fn form_state_equals_the_window() {
    super::tour::register_classes();
    let census = Census::new("forms");
    let mut tally = Tally::default();
    states(&census, &mut tally);
    scenarios(&census, &mut tally);
    let mirror_jobs = main_hidden_follows_the_window(&census, &mut tally);
    let not_shown: Vec<EditField> = EditField::ALL
        .into_iter()
        .filter(|field| !tally.shown.contains(field))
        .collect();
    let not_typed: Vec<EditField> = EditField::ALL
        .into_iter()
        .filter(|field| !tally.typed.contains(field))
        .collect();
    println!(
        "tour_forms: {} steps, {} comparisons, {} skipped steps; fields shown {}/58, typed {}/58",
        tally.steps,
        tally.checks,
        tally.skipped,
        tally.shown.len(),
        tally.typed.len()
    );
    println!("tour_forms: never shown: {not_shown:?}");
    println!("tour_forms: never typed: {not_typed:?}");
    println!(
        "tour_forms: form_mismatch = {}, credential misses = {}, differences = {}",
        tally.form_mismatch,
        tally.cred_misses,
        tally.differences.len()
    );
    println!("tour_forms: press_mismatch = {}", tally.press_mismatch);
    println!(
        "tour_forms: Enter through IDOK: {} steps, {} edits where it pressed a control",
        tally.enters,
        tally.enter_pressed.len()
    );
    println!(
        "tour_forms: main window mirror: shown, minimized, hidden, shown again; RPC jobs of the \
         shown ticks {mirror_jobs:?}, none while minimized or hidden"
    );
    for difference in tally.differences.iter().take(40) {
        println!("tour_forms: difference: {difference}");
    }
    assert!(tally.differences.is_empty());
    // The credential Enter forms (S3 K17: the RPC row's `교체`, the done screen's QuickNode URL)
    // and a plain one (the account rename) pressed their button through the shell's key path.
    for id in [
        crate::ui::screens::ids::REPLACE_EDIT,
        crate::ui::screens::ids::DONE_QN_EDIT,
        crate::ui::screens::ids::RENAME_EDIT,
    ] {
        assert!(
            tally.enter_pressed.contains(&id),
            "Enter in {id} pressed nothing"
        );
    }
    assert_eq!((tally.form_mismatch, tally.cred_misses), (0, 0));
    assert_eq!(tally.press_mismatch, 0);
}
