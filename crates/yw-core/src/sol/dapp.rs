//! Solana transactions built by a dApp (spec/07 §20, D38): the strict legacy/v0 parser with
//! re-encoding identity, address lookup tables, and the instruction decoders. The wallet never
//! builds or changes these messages: it fills its own signature slot of the exact bytes the user
//! approved. Everything here is pure; RPC observations (tables, account data) are arguments.
//!
//! Every message this module accepts is also caught by the message-signing guard
//! (`msgsign::looks_like_transaction`, M01): transaction bytes are never signed as a message.
#![deny(clippy::indexing_slicing)]

pub mod alt;
pub mod decode;
pub mod parse;

pub use alt::{AltError, KeyRole, LookupTable, ResolvedKeys};
pub use decode::DecodedIx;
pub use parse::{
    LookupRef, MessageHeader, SOL_TX_MAX_BATCH, SOL_TX_MAX_IX, SOL_TX_MAX_KEYS, SolTxError,
    SolTxMessage, SolTxVersion, SolWireTx, encode_message_any, parse_message_any, parse_wire_tx,
};

#[cfg(test)]
mod tests;
