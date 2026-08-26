//! Debug-only Phase 1 inputs for direct service-owned LPAC helper creation.
//!
//! The module contains a dormant, debug-only pre-event process-creation seam
//! plus its isolated preparation and verification owners. No RPC command,
//! release build, helper protocol, wallet operation, or signing path can reach
//! it yet.

#![allow(dead_code)]

mod channel;
mod job;
mod process;
mod startup;
mod target_profile;
