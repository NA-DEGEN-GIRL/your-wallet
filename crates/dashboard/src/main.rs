//! Native non-secret dashboard executable.

use dashboard::{DashboardApp, DashboardSnapshot, WalletStatus};

fn main() {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([720.0, 480.0]),
        ..eframe::NativeOptions::default()
    };
    let snapshot = DashboardSnapshot {
        status: WalletStatus::CanaryGateNotAttested,
        ..DashboardSnapshot::default()
    };
    let result = eframe::run_native(
        "Your Wallet — Private Canary",
        options,
        Box::new(move |_context| Ok(Box::new(DashboardApp::new(snapshot)))),
    );
    if result.is_err() {
        std::process::exit(1);
    }
}
