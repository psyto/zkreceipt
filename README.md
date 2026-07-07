# zkReceipt

**A trustless receipt for cross-chain agent payments — proven with ZK, verified on Solana.**

zkReceipt lets a Solana program confirm that a payment finalized on another
chain — an [x402](https://github.com/coinbase/x402) agent payment, a settlement
intent, a merchant charge — **without trusting a bridge operator, oracle, or
multisig committee**. The proof is cryptographic: the receiver checks a ZK proof
of the source chain's finality plus a Merkle inclusion proof that the specific
payment is in that finalized state.

It works in two layers:

1. **Consensus proof** — a zero-knowledge light client proves that a source-chain
   block was finalized, and a Solana verifier program anchors that block's
   `state_root` to a PDA via `alt_bn128` syscalls.
2. **Inclusion proof (the receipt)** — given that anchored `state_root`, the
   receiver verifies an EIP-1186 account+storage proof that a payment landed
   (`paidTo[recipient] >= amount`). That verified fact **is** the zkReceipt.

## Source chains, and the Solana hub

The **receiver layers are source-agnostic**: any chain whose state is an
Ethereum-style Merkle Patricia trie (Ethereum, Reth/OP-stack L2s, Tempo) works
at the `mpt-verify` / `x402-receiver` layer unchanged.

The **consensus layer is source-specific**: each source chain needs its own
light client for its finality rule. Today the implemented source is **Tempo**
(Simplex BFT — its chainspec was reverse-engineered, see
[`spec/tempo-chainspec.md`](./spec/tempo-chainspec.md)). The near-term next
source is **Ethereum** (sync-committee light client), which also unblocks the
fully-trustless path first: Ethereum consensus is public and a proven SP1
implementation ([sp1-helios](https://github.com/succinctlabs/sp1-helios))
already exists, whereas Tempo's aggregate quorum signature format is still being
pinned down.

The **destination is Solana today** — the `alt_bn128` Groth16 verifier that lands
foreign-chain proofs on Solana is the core of the primitive. The design keeps the
destination pluggable; Solana is the first and primary hub, not a hard-coded
assumption.

## Status

**Partial — v0.1.0-rfc.1. Not deployed to any live network.**

| Layer | State |
| --- | --- |
| `mpt-verify` (inclusion proof) | **Working** — validated against a real Tempo Moderato `eth_getProof` fixture bound to a real block `state_root`. |
| `x402-receiver` (402 flow + trust ladder) | **Working** — `FixedAnchor` (T0) live; `LightClientAnchor` (T1/T2) decodes the on-chain PDA. |
| `solana` verifier | **Partial** — `bootstrap` + `update_light_client` state-binding live; **Groth16 proof verification itself still stubbed** (proof accepted as-is pending vkey + `alt_bn128` wiring). |
| `light-client` (Tempo Simplex) | **Partial** — Ed25519 proposer + structural checks live; **BFT aggregate quorum signature still `unimplemented!()`** (blocked on Tempo consensus format). |
| `prover` (SP1) | **Scaffold** — guest wired end-to-end; no real proof generated yet. |

32 tests green across the workspace. The headline "trustless" property is real by
design but **not yet fully delivered** — the two crypto leaves (Groth16 verify,
BFT quorum aggregate) are the remaining work.

## Why

Cross-chain payment attestation today depends on social trust:

- **Multisig bridges** (Wormhole, LayerZero) trust a set of guardians.
- **Oracle networks** (Chainlink CCIP) trust a permissioned node committee.
- **Facilitators** (x402 merchant infra) trust an operator to route and confirm.

zkReceipt replaces social trust with cryptographic proof. A Solana program
verifies source-chain finality from a ~200-byte Groth16 proof plus an MPT
inclusion proof — no external attestation, no operator in the trust path.

## Architecture

```
  source chain            ZK Prover (off-chain)          Solana
 (Ethereum-MPT)        ┌──────────────────────┐      ┌────────────────┐
 ┌─────────┐   cert    │ source light client  │ proof│ zkReceipt      │
 │ finality├──────────►│ inside SP1 zkVM      ├─────►│ verifier (PDA) │
 │  rule   │           │ Groth16 wrap (BN254) │      │ alt_bn128      │
 └─────────┘           └──────────────────────┘      └────────┬───────┘
   Simplex BFT (Tempo, today)                                 │ state_root
   sync-committee (Ethereum, next)                            ▼
                                                     ┌────────────────┐
                                                     │ MPT inclusion  │
                                                     │ proof → the    │
                                                     │ zkReceipt      │
                                                     └────────────────┘
```

Components:

- **Light client** — a `no_std` Rust crate that verifies a source chain's
  finality certificate against its validator set. Deterministic, no I/O.
  Source-specific (Tempo/Simplex implemented; one crate per source).
- **Prover** — an SP1 program that wraps the light client and produces a Groth16
  proof per finalized block, plus an off-chain operator that drives proving.
- **Verifier** — a Solana Anchor program that checks the Groth16 proof via
  `alt_bn128` syscalls and persists `(slot, state_root)` to a PDA.
- **mpt-verify** — verifies EIP-1186 account+storage proofs against an anchored
  `state_root`. Source-agnostic.
- **x402-receiver** — transport-agnostic x402 core: issues 402 challenges and
  admits requests by checking a payment proof against an anchored `state_root`.

## Scope

In scope:

- Any **Ethereum-MPT source chain** at the inclusion/receiver layer.
- Per-source consensus light clients (Tempo/Simplex today; Ethereum
  sync-committee next).
- Solana verifier program interface and state account layout.
- x402 receiver flow (402 challenge, `X-PAYMENT` proof, admit).
- Composition patterns with [mppsol_cpi](https://github.com/mppsol/cpi) for
  cross-VM payment settlement.
- Threat model: validator-set rotation, replay protection, cluster confusion.

Out of scope:

- **Adding a source chain without its consensus light client.** The receiver
  layers are source-agnostic, but proving a new source's finality requires a
  light client for its rule (Simplex done, sync-committee next).
- **Asset bridging** — zkReceipt proves a payment finalized; it moves no tokens.
- **Liveness guarantees** — proofs are produced by an external operator; the
  verifier is permissionless to call but does not guarantee timely updates.

## Specs

| Document | Purpose |
| --- | --- |
| [`spec/light-client.md`](./spec/light-client.md) | Source finality verification rules; certificate format; validator-set transitions |
| [`spec/prover.md`](./spec/prover.md) | SP1 program contract; input/output layout; Groth16 wrapping |
| [`spec/verifier.md`](./spec/verifier.md) | Solana program interface; verification key; state account PDA layout |
| [`spec/composition.md`](./spec/composition.md) | Patterns for downstream programs (mppsol_cpi, payment settlement, intent execution) |
| [`spec/security.md`](./spec/security.md) | Threat model, validator rotation, replay protection, prover liveness |
| [`spec/tempo-chainspec.md`](./spec/tempo-chainspec.md) | Reverse-engineered Moderato observations for the Tempo source: consensus context, 0x76 tx envelope, native stablecoin precompiles, open questions |

## Components

This repository is a monorepo. Each top-level folder is one component of zkReceipt.

| Folder | Purpose | Status |
| --- | --- | --- |
| [`spec/`](./spec/) | Protocol specifications. | Draft |
| [`light-client/`](./light-client/) | Rust crate: source finality verification (Tempo/Simplex). `no_std`. | Partial |
| [`prover/`](./prover/) | Rust host crate (API pinned) + SP1 guest crate at [`prover/program/`](./prover/program/). | Scaffold |
| [`solana/`](./solana/) | Anchor verifier program (nested workspace). | Partial |
| [`mpt-verify/`](./mpt-verify/) | EIP-1186 account+storage proof verification. Source-agnostic. | Working |
| [`x402-receiver/`](./x402-receiver/) | Transport-agnostic x402 receiver core + trust ladder. | Working |

## License

Apache-2.0 (with patent grant). See [LICENSE](./LICENSE).

## Maintainer

[psyto](https://github.com/psyto).
