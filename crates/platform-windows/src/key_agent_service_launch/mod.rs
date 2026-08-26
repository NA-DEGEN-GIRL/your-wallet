//! Debug-only Phase 1 inputs for direct service-owned LPAC helper creation.
//!
//! The module currently contains only isolated, non-launching primitives. It
//! exposes no process-creation, RPC command, helper, wallet, or signing path.

#![allow(dead_code)]

mod job;
mod startup;
mod target_profile;
