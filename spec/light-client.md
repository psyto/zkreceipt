# Light client — Simplex BFT finality verification

> **Status: stub.** To be drafted alongside the `zkreceipt/light-client` Rust
> crate, after the `tempoxyz/tempo-foundry` audit pins down Tempo's exact
> Simplex implementation.

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
