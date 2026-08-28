//! Private Key Agent debugger admission and dormant transport composition.
//!
//! The release-bound artifact capability and the debug-only transport are
//! siblings so the safe artifact boundary does not inherit the transport's
//! native-code allowance. Nothing in this umbrella is re-exported.

#[path = "key_agent_debugger_artifact.rs"]
mod artifact;

#[cfg(all(
    windows,
    feature = "key-agent-debugger-transport-feasibility-test-hook",
    debug_assertions
))]
#[path = "key_agent_debugger_transport/mod.rs"]
mod transport;
