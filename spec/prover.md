# Prover — SP1 program contract

> **Status: stub.** To be drafted alongside the `zktempo/prover` Rust crate
> and the off-chain operator implementation.

This document will specify:

- SP1 guest program input/output schema (committed public values, private
  witness layout).
- Groth16 wrapping parameters (BN254 curve, verification key embedding,
  proof serialization format consumable by Solana `alt_bn128` syscalls).
- Off-chain operator responsibilities: liveness SLA, retry behavior,
  batching of finality updates.
- Prover-network vs local-proving deployment modes; cost trade-offs.
- Verification-key versioning and rotation under SP1 upgrades.

See the [README](../README.md) for project overview and architecture.

## Open research items

- Empirical proof generation time on Succinct prover network vs local.
- Cost per proof at expected finality cadence (one update per ~0.5s Tempo block
  is impractical; batched updates per N blocks is the likely shape).
- Whether SP1's evolving Groth16 wrapper is stable enough to commit a
  verification key to mainnet, or whether the verifier must support key
  rotation from day one.
