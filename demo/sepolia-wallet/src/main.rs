//! Double-clickable standalone Ethereum Sepolia development wallet.

mod backend;
#[cfg(test)]
mod erc20;
mod headless;
mod rpc;
mod token_store;
mod ui;
mod vault_v2;
mod wallet_secret;

use std::ffi::OsString;

use headless::{HeadlessCheck, HeadlessReport};
use ui::{WalletApp, install_korean_font};

fn main() -> eframe::Result<()> {
    let invocation = parse_invocation(std::env::args_os().skip(1));
    match dispatch(invocation, run_gui)? {
        DispatchOutcome::GuiFinished => Ok(()),
        DispatchOutcome::Headless(report) => {
            println!("{}", report.to_json());
            if report.succeeded() {
                Ok(())
            } else {
                std::process::exit(report.exit_code());
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Invocation {
    Gui,
    Headless(HeadlessCheck),
    InvalidHeadless,
}

enum DispatchOutcome {
    GuiFinished,
    Headless(HeadlessReport),
}

fn parse_invocation(arguments: impl IntoIterator<Item = OsString>) -> Invocation {
    let mut arguments = arguments.into_iter();
    let Some(first) = arguments.next() else {
        return Invocation::Gui;
    };

    if first == "--check-rpc" {
        return if arguments.next().is_none() {
            Invocation::Headless(HeadlessCheck::Rpc)
        } else {
            Invocation::InvalidHeadless
        };
    }
    if first != "--headless" {
        // A misspelled automation argument must never surprise the user by
        // falling through to a visible GUI launch.
        return Invocation::InvalidHeadless;
    }

    let check = match arguments.next().as_deref() {
        Some(value) if value == "smoke" => HeadlessCheck::Smoke,
        Some(value) if value == "rpc" => HeadlessCheck::Rpc,
        Some(value) if value == "all" => HeadlessCheck::All,
        _ => return Invocation::InvalidHeadless,
    };
    if arguments.next().is_some() {
        Invocation::InvalidHeadless
    } else {
        Invocation::Headless(check)
    }
}

fn dispatch(
    invocation: Invocation,
    gui_runner: impl FnOnce() -> eframe::Result<()>,
) -> eframe::Result<DispatchOutcome> {
    match invocation {
        Invocation::Gui => {
            gui_runner()?;
            Ok(DispatchOutcome::GuiFinished)
        }
        Invocation::Headless(check) => Ok(DispatchOutcome::Headless(headless::run(check))),
        Invocation::InvalidHeadless => Ok(DispatchOutcome::Headless(
            HeadlessReport::invalid_arguments(),
        )),
    }
}

fn run_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([900.0, 720.0])
            .with_min_inner_size([720.0, 600.0]),
        ..eframe::NativeOptions::default()
    };
    let backend = backend::build_backend();
    eframe::run_native(
        "Your Wallet — Sepolia 테스트넷",
        options,
        Box::new(move |creation_context| {
            install_korean_font(&creation_context.egui_ctx);
            let app = match backend {
                Ok(backend) => WalletApp::new(backend),
                Err(_error) => WalletApp::unavailable(
                    "테스트 지갑 저장소를 준비하지 못했습니다. 앱을 다시 실행해 주세요.",
                ),
            };
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::ffi::OsString;

    use super::{DispatchOutcome, HeadlessCheck, Invocation, dispatch, parse_invocation};

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn headless_smoke_is_parsed_before_gui_dispatch() {
        assert_eq!(
            parse_invocation(arguments(&["--headless", "smoke"])),
            Invocation::Headless(HeadlessCheck::Smoke)
        );
        assert_eq!(
            parse_invocation(arguments(&["--headless", "rpc"])),
            Invocation::Headless(HeadlessCheck::Rpc)
        );
        assert_eq!(
            parse_invocation(arguments(&["--headless", "all"])),
            Invocation::Headless(HeadlessCheck::All)
        );
    }

    #[test]
    fn invalid_headless_arguments_fail_without_falling_back_to_gui() {
        for values in [
            vec!["--headless"],
            vec!["--headless", "unknown"],
            vec!["--headless", "smoke", "extra"],
            vec!["--check-rpc", "extra"],
            vec!["--headles", "smoke"],
        ] {
            assert_eq!(
                parse_invocation(arguments(&values)),
                Invocation::InvalidHeadless
            );
        }
    }

    #[test]
    fn headless_dispatch_never_calls_gui_runner() -> eframe::Result<()> {
        let gui_called = Cell::new(false);
        let outcome = dispatch(Invocation::Headless(HeadlessCheck::Smoke), || {
            gui_called.set(true);
            Ok(())
        })?;

        assert!(!gui_called.get());
        let DispatchOutcome::Headless(report) = outcome else {
            panic!("headless dispatch must return a headless report");
        };
        assert!(report.succeeded());
        Ok(())
    }
}
