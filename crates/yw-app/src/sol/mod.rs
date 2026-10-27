//! Solana in yw-app (spec/07 §2, M7): `sol::rpc` (JSON-RPC calls and their classification),
//! `sol::flow` (preview, pre-sign lookup, broadcast round, balances on the RPC worker) and
//! `sol::scan` (recovery scan). The UI-thread state is `crate::app_sol`.

pub mod flow;
pub mod rpc;
pub mod scan;
