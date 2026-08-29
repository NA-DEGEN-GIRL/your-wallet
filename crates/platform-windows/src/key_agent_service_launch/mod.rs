//! Dormant debug-only composition for direct service-owned LPAC helper launch.
//!
//! One fresh debugger thread composes verified creation, a closed authenticated
//! two-gate channel handoff, exact join, debugger-absence proof, event-alias
//! cleanup, and one retained suspend count. Only the explicit debug-only V2 RPC
//! probe reaches it; no release build, wallet operation, production caller, or
//! signing path does. Event-alias cleanup remains kernel-matrix STOP-SHIP.

#![allow(dead_code)]

mod channel;
mod debug_gate;
mod gate;
mod job;
mod process;
mod rpc_probe;
mod startup;
mod target_profile;

pub(crate) use self::debug_gate::ServiceHelperAdmission;
pub(crate) use self::rpc_probe::run_service_helper_rpc_probe;
pub(crate) use self::target_profile::{
    FixedLpacRpcEndpointProfileSids, derive_fixed_lpac_rpc_endpoint_profile_sids,
};

/// Data-free failure to derive the fixed RPC endpoint package identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FixedLpacRpcEndpointProfileSidError;

// The SCM watchdog is a hard fail-fast bound, not proof that every Windows OS
// call is interruptible. Its terminal-resource components deliberately stay
// independent from the manager response timeout.
const SERVICE_RPC_PROBE_STOP_MARGIN_MILLISECONDS: u64 = 10_000;
pub(crate) const SERVICE_RPC_PROBE_STOP_DEADLINE_MILLISECONDS: u64 =
    debug_gate::MAX_COORDINATION_MILLISECONDS as u64
        + crate::key_agent_service_rpc::EXPECTED_HELPER_QUIESCENCE_MILLISECONDS
        + crate::key_agent_service_rpc::DESKTOP_PROCESS_CLEANUP_WAIT_MILLISECONDS
        + job::SERVICE_PROBE_TERMINATION_MILLISECONDS
        + SERVICE_RPC_PROBE_STOP_MARGIN_MILLISECONDS;
const _: () = assert!(SERVICE_RPC_PROBE_STOP_DEADLINE_MILLISECONDS == 30_000);
