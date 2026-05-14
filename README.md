# zkTempo.sol

**ZK-verified Tempo finality, settled on Solana.**

zkTempo.sol is a cross-VM settlement primitive: a zero-knowledge light client that
proves Tempo block finality and makes those proofs verifiable inside Solana programs.
Downstream consumers — payment session protocols, cross-chain intent settlement,
agent commerce rails — can confirm on Solana that a fact about Tempo is true
(e.g. a `PaymentIntent` was emitted and finalized) without trusting a bridge
operator, oracle, or multisig committee.

## Status

**Draft — v0.1.0-rfc.1.** Pre-implementation. No reference code, no testnet
deployment. Specs are subject to breaking change until v0.1.0 final.

## Why

Cross-chain finality attestation today depends on social trust:

- **Multisig bridges** (Wormhole, LayerZero) trust a set of guardians.
- **Oracle networks** (Chainlink CCIP) trust a permissioned node committee.
- **Optimistic bridges** trust that someone will challenge a fraudulent claim within
  the window.

zkTempo.sol replaces social trust with cryptographic proof. A Solana program can
verify Tempo finality from a ~200-byte Groth16 proof using `alt_bn128` syscalls,
with no external attestation required.

## Architecture

```
   Tempo                ZK Prover (off-chain)         Solana
 ┌─────────┐         ┌──────────────────────┐      ┌────────────────┐
 │ Simplex │  cert   │ Tempo light client   │ proof│ zkTempo        │
 │ BFT     ├────────►│ inside SP1 zkVM      ├─────►│ verifier (PDA) │
 │ finality│         │ Groth16 wrap (BN254) │      │ alt_bn128      │
 └─────────┘         └──────────────────────┘      └────────┬───────┘
                                                            │
                                                            ▼
                                                   ┌────────────────┐
                                                   │ state root PDA │
                                                   │ + Merkle proof │
                                                   │ inclusion API  │
                                                   └────────────────┘
```

Three components:

- **Light client** — a `no_std` Rust crate that verifies Simplex BFT finality
  certificates against a known validator set. Deterministic, no I/O.
- **Prover** — an SP1 program that wraps the light client and produces a Groth16
  proof per finalized block, plus an off-chain operator that drives proof
  generation.
- **Verifier** — a Solana Anchor program that checks the Groth16 proof via
  `alt_bn128` syscalls and persists `(slot, state_root)` to a PDA. Downstream
  programs read this PDA to verify storage proofs.

## Scope

In scope:

- Wire format for finality proofs (public inputs, version bytes, canonical encoding).
- Solana verifier program interface and state account layout.
- Light client protocol: initialization, finality updates, validator-set transitions.
- Composition patterns with [mppsol_cpi](https://github.com/mppsol/cpi) for
  cross-VM payment settlement.
- Threat model: validator-set rotation, replay protection, cluster confusion.

Out of scope:

- General-purpose EVM→Solana state proving — zkTempo.sol is specific to Tempo's
  Simplex consensus. Other Reth-based L1s require separate consensus
  implementations.
- Asset bridging — zkTempo.sol proves finality only. Token semantics are
  downstream concerns.
- Liveness guarantees — proofs must be produced by an external operator; the
  verifier is permissionless to call but does not guarantee timely updates.

## Specs

| Document | Purpose |
| --- | --- |
| [`spec/light-client.md`](./spec/light-client.md) | Simplex finality verification rules; certificate format; validator-set transitions |
| [`spec/prover.md`](./spec/prover.md) | SP1 program contract; input/output layout; Groth16 wrapping |
| [`spec/verifier.md`](./spec/verifier.md) | Solana program interface; verification key; state account PDA layout |
| [`spec/composition.md`](./spec/composition.md) | Patterns for downstream programs (mppsol_cpi, payment settlement, intent execution) |
| [`spec/security.md`](./spec/security.md) | Threat model, validator rotation, replay protection, prover liveness |

## Components

This repository is a monorepo. Each top-level folder is one component of
zkTempo.sol.

| Folder | Purpose | Status |
| --- | --- | --- |
| [`spec/`](./spec/) | Protocol specifications. | Draft |
| [`light-client/`](./light-client/) | Rust crate: Simplex BFT finality verification. `no_std`. | Scaffold |
| [`prover/`](./prover/) | Rust crate: SP1 host + (future) guest program at `prover/program/`. | Scaffold |
| [`solana/`](./solana/) | Anchor verifier program (nested workspace). | Scaffold |

## License

Apache-2.0 (with patent grant). See [LICENSE](./LICENSE).

## Maintainer

[psyto](https://github.com/psyto).
