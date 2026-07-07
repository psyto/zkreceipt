# Security — threat model

> **Status: stub.**

This document will specify:

- **Validator-set compromise.** Trust assumption is honest-majority of the
  source chain's validator set (Tempo's Simplex set, for the implemented
  source). Mitigations under partial compromise; behavior under full compromise
  (out of scope — no recovery).
- **Prover liveness.** What happens to downstream consumers when no operator
  produces a recent finalized root. Stale-root detection patterns.
- **Replay protection.**
  - Within Solana: monotonic slot enforcement at the verifier PDA.
  - Across networks: cluster confusion mitigation (verification key bound to
    `(cluster_genesis_hash, source_chain_id)`).
  - Across forks: the source chain's finalized state is reorg-free by
    construction (e.g. Simplex BFT for Tempo), so cross-fork replay reduces to
    cross-network replay.
- **Public-input binding.** Verification key includes chain identity; proofs
  for the wrong chain fail verification.
- **Operator key compromise.** No on-chain authority; compromise only affects
  liveness, not safety (proofs still verify cryptographically).
- **Known attack vectors and mitigations.**

See the [README](../README.md) for project overview and architecture.

## Inherited threat surface

zkReceipt inherits the security assumptions of:

- **The source chain's consensus** (honest-majority validator set; Tempo's
  Simplex BFT for the implemented source).
- **SP1's zkVM and Groth16 wrapper** (soundness of the proof system; trusted
  setup if applicable).
- **Solana's `alt_bn128` syscalls** (correct curve arithmetic at the runtime
  level).
- **The source chain's Merkle Patricia trie semantics** (state root commits to
  all storage; Ethereum-style).

Failures in any of these layers are out of zkReceipt's scope to mitigate.
