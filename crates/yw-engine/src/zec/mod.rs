//! The Zcash transparent app layer (spec/12): meta `zcash` (the account per network), the node
//! and Blockbook calls, the RPC worker jobs and the journal steps. The core is `yw_core::zec`.

pub mod meta;
pub mod rpc;
pub mod work;
