# Chain registry security status

Reviewed: 2026-08-13 UTC

This crate is inert compile-time data plus validation policy. It performs no
network I/O, contains no RPC endpoints, and cannot load or select code beyond
the closed `Adapter` enum.

## Included network matrix

- Ethereum Mainnet, Sepolia, Hoodi
- BNB Smart Chain Mainnet and Testnet
- Polygon PoS Mainnet and Amoy
- Avalanche C-Chain Mainnet and Fuji
- Arbitrum One and Arbitrum Sepolia
- OP Mainnet and OP Sepolia
- Base Mainnet and Base Sepolia
- Robinhood Chain Mainnet and Testnet

Ethereum.org currently identifies Sepolia and Hoodi as the maintained public
Ethereum testnets and marks Holesky deprecated. Each other project currently
documents the single testnet listed above.

## Release-blocking unknowns

The following gaps are represented in the Rust types and are signing-ineligible;
none is filled with an inferred value:

1. A wallet-reviewed, immutable genesis hash or equivalent chain fingerprint is
   not yet pinned for BSC, Polygon PoS, Avalanche C-Chain, Arbitrum, OP, Base, or
   Robinhood Chain networks.
2. No built-in entry yet has a release artifact that binds the current network
   fork schedule and transaction rules to a tested signer revision.
3. Chain-specific and rollup finality adapters have not yet completed their
   release review. Local L2 inclusion is never treated as parent-chain finality.
4. DNS names remain provisional until all resolved addresses and the actual
   connected peer are checked as global-unicast. Redirects need the same checks.

Ethereum Mainnet, Sepolia, and Hoodi have official execution genesis hashes
pinned, but remain signing-ineligible because items 2 and 3 are incomplete.

Custom chains are a separate user-trust path: only standard type-0/type-1/type-2
EIP-155 operations, the fixed `GenericEvm155` adapter, no finality claim, and a
mandatory strong warning plus hold-to-confirm. Their session-only RPC URLs are
validated but never retained in the validated registry result.

## Official primary sources

- Ethereum maintained networks:
  <https://ethereum.org/developers/docs/networks/>
- Ethereum Mainnet cross-client configuration:
  <https://github.com/eth-clients/mainnet>
- Sepolia configuration and genesis hash:
  <https://github.com/eth-clients/sepolia>
- Hoodi configuration and genesis hash:
  <https://github.com/eth-clients/hoodi>
- BNB Smart Chain chain IDs:
  <https://docs.bnbchain.org/bnb-smart-chain/developers/json_rpc/json-rpc-endpoint/>
- Polygon PoS network details:
  <https://docs.polygon.technology/pos/reference/rpc-endpoints/>
- Avalanche Primary Network and C-Chain:
  <https://build.avax.network/docs/primary-network>
- Arbitrum chain information:
  <https://docs.arbitrum.io/for-devs/dev-tools-and-resources/chain-info>
- OP Mainnet and OP Sepolia:
  <https://docs.optimism.io/op-mainnet/network-information/connecting-to-op>
- Base network details:
  <https://docs.base.org/base-chain/api-reference/rpc-overview>
- Robinhood Chain network details:
  <https://docs.robinhood.com/chain/connecting/>
- Robinhood Chain Nitro node configuration:
  <https://docs.robinhood.com/chain/run-a-full-node/>
