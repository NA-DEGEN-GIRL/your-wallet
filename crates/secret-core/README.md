# secret-core

This crate contains secret-bearing primitives intended only for the isolated
Your Wallet key-agent process. Secret values deliberately have no `Debug`,
`Display`, Serde, or raw-byte export API outside narrowly documented backup and
key-agent-internal paths.

Vault v1 has a fixed 112-byte, big-endian header. The header freezes password,
KDF, AEAD, and payload profile identifiers and carries the exact Argon2id v1.3
parameters (`m=262144 KiB`, `t=3`, `p=4`). The whole header is AEAD associated
data. Payload decoding is bounded and rejects trailing bytes, unknown tags,
duplicate record IDs, and non-zero reserved bits.

The filesystem boundary is intentionally represented only by
`AtomicVaultStorage`. There is no release-ready `std::fs` implementation:
proving restrictive Windows DACL creation, atomic replacement, file and
metadata durability, and crash recovery requires platform integration outside
safe `std`. Shipping an implementation based only on `rename` would violate the
trait contract.
