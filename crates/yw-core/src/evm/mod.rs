//! EVM (spec/03). M1 provides only `address`; the remaining modules arrive with M2.

pub mod address;

pub use address::{Address, AddressError, parse_address, to_checksum};
