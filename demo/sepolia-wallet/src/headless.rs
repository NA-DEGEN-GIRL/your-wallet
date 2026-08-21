//! Window-free checks for the standalone Sepolia demo.
//!
//! These checks are dispatched before `eframe` is initialized. The smoke
//! check uses only an in-memory fake backend; it does not open a vault, touch
//! the filesystem or network, or automate any user input.

use serde::Serialize;

use crate::{
    rpc::{RpcError, SepoliaRpc},
    ui,
};

/// Explicit non-interactive check selected by `--headless`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeadlessCheck {
    Smoke,
    Rpc,
    All,
}

/// Stable, secret-free JSON result written by the command-line entry point.
#[derive(Serialize)]
pub(crate) struct HeadlessReport {
    schema: u8,
    mode: &'static str,
    check: &'static str,
    status: &'static str,
    message_ko: &'static str,
    failure_code: &'static str,
    gui_started: bool,
    mouse_or_keyboard_automation_used: bool,
    network_used: bool,
    filesystem_used: bool,
    transitions_checked: usize,
    backend_routes_checked: usize,
    #[serde(skip)]
    exit_code: i32,
}

impl HeadlessReport {
    pub(crate) fn invalid_arguments() -> Self {
        Self::failure(
            "arguments",
            "인자가 올바르지 않습니다. --headless smoke, rpc 또는 all을 사용하세요.",
            "invalid_arguments",
            false,
            64,
        )
    }

    pub(crate) fn succeeded(&self) -> bool {
        self.exit_code == 0
    }

    pub(crate) fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub(crate) fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"schema":1,"mode":"headless","check":"internal","status":"error","message_ko":"결과를 만들지 못했습니다.","failure_code":"serialization","gui_started":false,"mouse_or_keyboard_automation_used":false,"network_used":false,"filesystem_used":false,"transitions_checked":0,"backend_routes_checked":0}"#.to_owned()
        })
    }

    fn success(
        check: &'static str,
        message_ko: &'static str,
        network_used: bool,
        transitions_checked: usize,
        backend_routes_checked: usize,
    ) -> Self {
        Self {
            schema: 1,
            mode: "headless",
            check,
            status: "ok",
            message_ko,
            failure_code: "none",
            gui_started: false,
            mouse_or_keyboard_automation_used: false,
            network_used,
            filesystem_used: false,
            transitions_checked,
            backend_routes_checked,
            exit_code: 0,
        }
    }

    fn failure(
        check: &'static str,
        message_ko: &'static str,
        failure_code: &'static str,
        network_used: bool,
        exit_code: i32,
    ) -> Self {
        Self {
            schema: 1,
            mode: "headless",
            check,
            status: "error",
            message_ko,
            failure_code,
            gui_started: false,
            mouse_or_keyboard_automation_used: false,
            network_used,
            filesystem_used: false,
            transitions_checked: 0,
            backend_routes_checked: 0,
            exit_code,
        }
    }
}

pub(crate) fn run(check: HeadlessCheck) -> HeadlessReport {
    match check {
        HeadlessCheck::Smoke => run_smoke(),
        HeadlessCheck::Rpc => run_rpc(),
        HeadlessCheck::All => run_all(),
    }
}

fn run_smoke() -> HeadlessReport {
    match ui::run_headless_smoke() {
        Ok(evidence) => HeadlessReport::success(
            "smoke",
            "창 없이 지갑 관리, 커스텀 토큰, 송금 화면 흐름을 확인했습니다.",
            false,
            evidence.transitions_checked,
            evidence.backend_routes_checked,
        ),
        Err(()) => HeadlessReport::failure(
            "smoke",
            "창 없는 지갑 관리와 송금 화면 흐름 확인에 실패했습니다.",
            "state_machine",
            false,
            2,
        ),
    }
}

fn run_rpc() -> HeadlessReport {
    match SepoliaRpc::new().verify_sepolia() {
        Ok(()) => HeadlessReport::success(
            "rpc",
            "고정 Sepolia 체인과 제네시스를 확인했습니다.",
            true,
            0,
            0,
        ),
        Err(error) => HeadlessReport::failure(
            "rpc",
            "Sepolia 연결 확인에 실패했습니다.",
            rpc_failure_code(error),
            true,
            3,
        ),
    }
}

fn run_all() -> HeadlessReport {
    let Ok(evidence) = ui::run_headless_smoke() else {
        return HeadlessReport::failure(
            "all",
            "창 없는 지갑 관리와 송금 화면 흐름 확인에 실패했습니다.",
            "state_machine",
            false,
            2,
        );
    };
    if let Err(error) = SepoliaRpc::new().verify_sepolia() {
        return HeadlessReport::failure(
            "all",
            "화면 흐름은 통과했지만 Sepolia 연결 확인에 실패했습니다.",
            rpc_failure_code(error),
            true,
            3,
        );
    }

    HeadlessReport::success(
        "all",
        "창 없이 화면 흐름과 Sepolia 연결을 모두 확인했습니다.",
        true,
        evidence.transitions_checked,
        evidence.backend_routes_checked,
    )
}

const fn rpc_failure_code(error: RpcError) -> &'static str {
    match error {
        RpcError::Transport => "rpc_transport",
        RpcError::Timeout => "rpc_timeout",
        RpcError::RedirectRejected => "rpc_redirect",
        RpcError::HttpStatus => "rpc_http_status",
        RpcError::RequestTooLarge => "rpc_request_bound",
        RpcError::ResponseTooLarge => "rpc_response_bound",
        RpcError::InvalidResponse => "rpc_invalid_response",
        RpcError::MethodUnavailable => "rpc_method_unavailable",
        RpcError::RemoteRejected => "rpc_remote_rejected",
        RpcError::ChainMismatch => "rpc_chain_mismatch",
        RpcError::ChainNotVerified => "rpc_not_verified",
        RpcError::RawTransactionRejected => "rpc_raw_transaction_policy",
        RpcError::SessionRevoked => "rpc_session_revoked",
        RpcError::NumericOverflow => "rpc_numeric_overflow",
    }
}

#[cfg(test)]
mod tests {
    use super::{HeadlessCheck, rpc_failure_code, run};
    use crate::rpc::RpcError;

    #[test]
    fn smoke_report_is_stable_and_explicitly_window_free() {
        let report = run(HeadlessCheck::Smoke);
        assert!(report.succeeded());
        assert_eq!(report.transitions_checked, 105);
        assert_eq!(report.backend_routes_checked, 37);
        assert!(!report.gui_started);
        assert!(!report.mouse_or_keyboard_automation_used);
        assert!(!report.network_used);
        assert!(!report.filesystem_used);

        let json = report.to_json();
        assert!(json.contains(r#""check":"smoke""#));
        assert!(json.contains(r#""status":"ok""#));
        assert!(!json.contains("0x"));
        assert!(!json.contains("\\Users\\"));
        assert!(!json.contains("headless-recipient"));
        assert!(!json.contains("headless-confirmed"));
    }

    #[test]
    fn rpc_failure_codes_are_stable_and_payload_free() {
        assert_eq!(rpc_failure_code(RpcError::Transport), "rpc_transport");
        assert_eq!(rpc_failure_code(RpcError::Timeout), "rpc_timeout");
        assert_eq!(
            rpc_failure_code(RpcError::ChainMismatch),
            "rpc_chain_mismatch"
        );
        assert_eq!(
            rpc_failure_code(RpcError::InvalidResponse),
            "rpc_invalid_response"
        );
        assert_eq!(
            rpc_failure_code(RpcError::MethodUnavailable),
            "rpc_method_unavailable"
        );
    }
}
