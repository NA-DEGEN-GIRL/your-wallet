//! Chain pipelines that run on the RPC worker (spec/03 §3.7, M4): preparation, re-simulation,
//! broadcast, receipt tracking and user-chain checks. They are window-free and take a
//! [`crate::rpc::Transport`] so tests drive them with a fake transport.

pub mod evm;
