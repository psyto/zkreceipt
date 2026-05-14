# Verifier — Solana Anchor program

> **Status: stub.** To be drafted alongside the `zktempo/solana` Anchor
> workspace.

This document will specify:

- Anchor program interface:
  - `update_light_client(proof, public_inputs)` — verifies a Groth16 proof,
    advances the finalized state.
  - `read_state_root(slot)` — view helper for downstream programs.
  - `bootstrap(genesis_validators)` — one-shot initialization.
- Verification-key serialization strategy (embedded constant vs upgradable PDA).
- State account PDA layout: `(latest_slot, state_root, validator_set_hash,
  last_update_unix_ts)`.
- `alt_bn128` syscall usage and ordering for Groth16 pairing checks.
- CU budget per instruction.
- Replay protection: monotonically increasing slot; reject stale updates.
- Authority model: permissionless `update_light_client` (proof is authority).

See the [README](../README.md) for project overview and architecture.

## Open research items

- Empirical CU cost of full Groth16 verification on Solana mainnet (alt_bn128
  pairing × 3 + scalar mul + arithmetic).
- Whether to expose a single `state_root` PDA (latest only) or a ring buffer
  of recent `(slot, state_root)` pairs for consumers that need historical
  proofs.
- Account size budget for validator-set hash commitments under expected
  rotation cadence.
