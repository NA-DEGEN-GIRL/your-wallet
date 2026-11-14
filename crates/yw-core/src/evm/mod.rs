//! EVM (spec/03). Module names follow spec/01 §2.2: `address` (M1) and the M2 modules for
//! amounts, chains, fees, RLP, transactions, signing, ABI/calldata interpretation, EIP-191/712,
//! SIWE, simulation, risk rules and the approval display builders.

pub mod abi;
pub mod address;
pub mod amount;
pub mod chain;
pub mod decode;
pub mod display;
pub mod eip191;
pub mod eip712;
pub mod fee;
pub mod risk;
pub mod rlp;
pub mod sign;
pub mod simulate;
pub mod siwe;
pub mod text;
pub mod tx;

pub use address::{Address, AddressError, parse_address, to_checksum};
