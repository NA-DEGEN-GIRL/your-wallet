//! Dormant debug-only composition for direct service-owned LPAC helper launch.
//!
//! One fresh debugger thread composes verified creation, a closed authenticated
//! two-gate channel handoff, exact join, debugger-absence proof, event-alias
//! cleanup, and one retained suspend count. No production caller, RPC command,
//! release build, wallet operation, or signing path reaches it. Event-alias
//! cleanup remains kernel-matrix STOP-SHIP.

#![allow(dead_code)]

mod channel;
mod debug_gate;
mod gate;
mod job;
mod process;
mod startup;
mod target_profile;
