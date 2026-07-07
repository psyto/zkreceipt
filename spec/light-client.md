# Light client — source finality verification (Simplex BFT, Tempo source)

> **Status: stub.** Covers the **Tempo** source (Simplex BFT). zkReceipt runs
> one consensus light client per source chain — the Ethereum sync-committee
> source would get a sibling spec. To be drafted alongside the `light-client`
> crate, once Tempo's exact Simplex/quorum format is pinned down.

This document will specify:

- Simplex BFT certificate format as emitted by Tempo validators.
- Validator-set initialization rules (genesis trust anchor).
- Validator-set rotation rules (transition certificates, quorum requirements).
- Canonical encoding for finality updates that cross host ↔ SP1 guest boundary.
- Public input layout exposed to the SP1 prover.
- Reference test vectors against Tempo Moderato testnet (chain ID 42431).
- The `no_std` Rust API surface for the verification crate.

See the [README](../README.md) for project overview and architecture.

## Open research items

Items the spec cannot pin until reverse-engineering of Tempo testnet completes:

- Exact signature scheme used by Tempo validators (BLS12-381? Ed25519?).
- Validator-set size and rotation cadence on mainnet vs Moderato.
- Whether finality certificates are accessible via standard `eth_*` RPC or
  require a Tempo-specific namespace.
- Whether the Simplex implementation in Commonware is bit-stable across
  releases (affects light-client upgrade path).
