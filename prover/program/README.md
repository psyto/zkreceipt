# zkreceipt-prover-program

SP1 zkVM **guest crate** for zkReceipt. Compiled to a RISC-V ELF via
`cargo prove build`; the resulting binary is what SP1's prover network
runs to generate Groth16 proofs of source-chain finality.

## Status

**Scaffold.** The call chain is wired end-to-end:

```
ProofInputs (CBOR)
  → sp1_zkvm::io::read_vec
  → serde_cbor::from_slice
  → zkreceipt_light_client::verify_update    ← BFT quorum aggregate still stubbed
  → sp1_zkvm::io::commit_slice (112-byte public output)
```

`verify_update` verifies the Ed25519 proposer signature + structural checks,
then hits `unimplemented!()` at the **BFT aggregate quorum signature** (blocked
on Tempo's Simplex format — see
[`../../spec/light-client.md`](../../spec/light-client.md)). Compiling this guest
succeeds; a real run still panics at that leaf.

## Important: NOT a workspace member

This crate is **excluded** from the outer zkreceipt Cargo workspace (see
the root `Cargo.toml`'s `exclude = ["prover/program"]`). It is built only
via the Succinct rustc toolchain:

```bash
# from anywhere:
cd prover/program
cargo prove build
```

That produces:

```
prover/program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/light_client
```

The host crate (`../`) will eventually consume this ELF through `sp1-build`
in its own `build.rs`, exposing it as the `SP1_ELF_light_client` env var.
That wiring is deferred until the host crate adds `sp1-sdk` deps.

## Structural mirror of sp1-helios

This file's shape mirrors `succinctlabs/sp1-helios/program/src/light_client.rs`
deliberately — the goal is to make the structural port obvious so the
implementation differences (Simplex BFT vs Ethereum sync committee, raw
bytes vs ABI for output) are the only meaningful divergences.

## Output layout (committed public values)

Fixed 112-byte layout for Solana destination consumption:

| Offset | Length | Field |
| --- | --- | --- |
| 0..8   | 8  | `new_slot` (u64 LE) |
| 8..40  | 32 | `new_state_root` |
| 40..48 | 8  | `prev_slot` (u64 LE) |
| 48..80 | 32 | `prev_state_root` |
| 80..112 | 32 | `validator_set_hash` |

The Solana `update_light_client` instruction reads these via direct byte
offsets. Final encoding (likely Borsh, to match Anchor conventions) is
pinned in `spec/prover.md`.
