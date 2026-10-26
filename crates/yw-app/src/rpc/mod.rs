//! RPC clients (spec/04 §1.9). M2: `evm` holds only the `eth_simulateV1` response parser; the
//! shared HTTPS transport (`yw_win::http`) and the remaining calls arrive with M4.

pub mod evm;
