//! Non-secret native dashboard model.
//!
//! The dashboard receives only public, already-redacted broker snapshots. There
//! is deliberately no vault, signer, secret-input, or approval dependency.

use std::collections::BTreeMap;

/// Broker connection and release-gate state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WalletStatus {
    /// No authenticated local broker session exists.
    #[default]
    Offline,
    /// Broker is running but the Key Agent is locked.
    Locked,
    /// Key Agent is unlocked for the current Windows session.
    Unlocked,
    /// Signing remains fail-closed until Phase-zero evidence is installed.
    CanaryGateNotAttested,
}

/// Public account projection. It contains no derivation secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSummary {
    /// Local user label.
    pub label: String,
    /// Full checksummed public address.
    pub address: String,
    /// Whether this account was selected by the user.
    pub selected: bool,
}

/// Public configured-chain projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSummary {
    /// Local display name.
    pub name: String,
    /// Exact decimal chain identifier.
    pub chain_id: String,
    /// Whether signing rules are verified for the active fork.
    pub rules_verified: bool,
}

/// Public transaction journal projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionSummary {
    /// Local transaction hash or candidate identifier.
    pub identifier: String,
    /// Conservative lifecycle label from the broker.
    pub lifecycle: String,
}

/// Entire non-secret snapshot supplied by the broker.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DashboardSnapshot {
    /// Connection/lock/release state.
    pub status: WalletStatus,
    /// Configured public accounts.
    pub accounts: Vec<AccountSummary>,
    /// Configured chains.
    pub networks: Vec<NetworkSummary>,
    /// Locally watched ERC-20 contract addresses keyed by public label.
    pub watched_tokens: BTreeMap<String, String>,
    /// Conservative local transaction history.
    pub transactions: Vec<TransactionSummary>,
    /// Number of site grants held only by the broker.
    pub connected_site_count: usize,
    /// Whether an independently verified backup check has completed.
    pub backup_verified: bool,
}

/// Commands the dashboard may request from the broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DashboardCommand {
    /// Request an explicit unlock gesture. Broker must separately invoke the Key Agent flow.
    BeginUnlock,
    /// Lock and terminate the Key Agent immediately.
    Lock,
    /// Select a public account.
    SelectAccount(String),
    /// Revoke all permissions for a displayed site identifier.
    RevokeSite(String),
    /// Add a manually watched ERC-20 contract.
    WatchErc20 {
        /// Exact public chain identifier.
        chain_id: String,
        /// Full ERC-20 contract address.
        contract: String,
    },
    /// Start the separate native backup verification flow.
    BeginBackupCheck,
}

/// General dashboard application. It owns no secret material.
#[derive(Debug, Default)]
pub struct DashboardApp {
    snapshot: DashboardSnapshot,
}

impl DashboardApp {
    /// Construct a dashboard from a public broker snapshot.
    #[must_use]
    pub fn new(snapshot: DashboardSnapshot) -> Self {
        Self { snapshot }
    }

    /// Replace the public snapshot atomically.
    pub fn update_snapshot(&mut self, snapshot: DashboardSnapshot) {
        self.snapshot = snapshot;
    }

    /// Borrow the current non-secret snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &DashboardSnapshot {
        &self.snapshot
    }
}

impl eframe::App for DashboardApp {
    fn update(&mut self, context: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        eframe::egui::TopBottomPanel::top("status").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Your Wallet");
                ui.separator();
                ui.strong("PRIVATE MAINNET CANARY — SELF ONLY");
                ui.separator();
                ui.label(status_text(self.snapshot.status));
            });
        });

        eframe::egui::SidePanel::left("navigation").show(context, |ui| {
            ui.heading("Wallet");
            for label in [
                "Accounts",
                "Networks",
                "Transactions",
                "Sites",
                "Backup & recovery",
            ] {
                let _ = ui.selectable_label(label == "Accounts", label);
            }
        });

        eframe::egui::CentralPanel::default().show(context, |ui| {
            ui.heading("Accounts");
            if self.snapshot.accounts.is_empty() {
                ui.label("No public account snapshot is available. Start the protected native unlock flow.");
            }
            for account in &self.snapshot.accounts {
                ui.group(|ui| {
                    ui.strong(&account.label);
                    ui.monospace(&account.address);
                    if account.selected {
                        ui.label("Selected");
                    }
                });
            }

            ui.add_space(12.0);
            ui.heading("Safety status");
            match self.snapshot.status {
                WalletStatus::CanaryGateNotAttested => {
                    ui.colored_label(
                        eframe::egui::Color32::RED,
                        "Signing is disabled: Windows sandbox, helper identity, and release evidence are not attested.",
                    );
                }
                WalletStatus::Unlocked => {
                    ui.colored_label(eframe::egui::Color32::YELLOW, "Unlocked for this Windows session.");
                }
                WalletStatus::Offline | WalletStatus::Locked => {
                    ui.label("No secret is present in this dashboard process.");
                }
            }
        });
    }
}

const fn status_text(status: WalletStatus) -> &'static str {
    match status {
        WalletStatus::Offline => "Broker offline",
        WalletStatus::Locked => "Locked",
        WalletStatus::Unlocked => "Unlocked",
        WalletStatus::CanaryGateNotAttested => "Signing disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::{DashboardApp, DashboardSnapshot, WalletStatus};

    #[test]
    fn default_snapshot_is_offline_and_empty() {
        let application = DashboardApp::default();
        assert_eq!(application.snapshot().status, WalletStatus::Offline);
        assert!(application.snapshot().accounts.is_empty());
        assert!(application.snapshot().transactions.is_empty());
    }

    #[test]
    fn release_gate_state_is_explicit() {
        let snapshot = DashboardSnapshot {
            status: WalletStatus::CanaryGateNotAttested,
            ..DashboardSnapshot::default()
        };
        let application = DashboardApp::new(snapshot);
        assert_eq!(
            application.snapshot().status,
            WalletStatus::CanaryGateNotAttested
        );
    }
}
