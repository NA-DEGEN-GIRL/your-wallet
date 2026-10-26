//! yw-core: platform-independent wallet core (keys, vault, chain encoding, policy).
//!
//! No network, GUI, file system, threads, clocks or `unsafe` (spec/01 §2.2, §5.1).
//! Modules are added from M1 following the module table in spec/01 §2.2.
#![forbid(unsafe_code)]
