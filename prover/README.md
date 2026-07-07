# zkreceipt-prover

Off-chain prover for zkReceipt. Generates Groth16 proofs of Tempo
finality by running [`zkreceipt-light-client`](../light-client/) inside the
SP1 zkVM guest, then wrapping the resulting STARK in Groth16 for cheap
verification on Solana via `alt_bn128` syscalls.

## Status

**Scaffold.** Host API (`ProverConfig`, `prove_finality_update`,
`ProofArtifact`, etc.) is pinned. Body is `unimplemented!()` pending:

1. SP1 host SDK version pin (`sp1-sdk = "x.y.z"`).
2. Guest program at [`./program/`](./program/) — not yet created.
3. Groth16 verification key generation + commitment to the Solana verifier.

See [`../spec/prover.md`](../spec/prover.md).

## Architecture

```
                          ┌─────────────────────┐
   LightClientStore       │ zkreceipt-prover      │
   Update              ──▶│ host crate (this)   │
                          │                     │
                          │   reads Tempo RPC   │
                          │   loads guest       │  ┌─────────────────┐
                          │   ─────────────────────▶ SP1 zkVM guest  │
                          │                     │  │  ./program/     │
                          │   wraps Groth16     │  │  imports light- │
                          │   submits to Solana │  │  client crate   │
                          └──────┬──────────────┘  └────────┬────────┘
                                 │                          │
                                 │   ◀───────────────────── │  proof
                                 ▼
                          ┌──────────────────────┐
                          │  Solana verifier     │
                          │  (../solana/)        │
                          │  alt_bn128 syscalls  │
                          └──────────────────────┘
```

## Future structure

```
prover/
├── Cargo.toml          ← this crate (host)
├── README.md
├── src/
│   ├── lib.rs          ← prover API (this scaffold)
│   └── bin/
│       └── operator.rs ← long-running operator binary (TBD)
└── program/            ← SP1 guest crate, separate workspace member
    ├── Cargo.toml
    └── src/
        └── main.rs     ← sp1_zkvm::entrypoint, calls verify_update
```

The guest crate at [`./program/`](./program/) is now scaffolded — it
imports [`zkreceipt-light-client`](../light-client/) and calls
`verify_update` inside the SP1 zkVM. It is **excluded from the outer
zkreceipt Cargo workspace** (uses Succinct's rustc toolchain). Build via:

```bash
cd prover/program
cargo prove build
```

That produces `prover/program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/light_client`.
The host crate (this directory) does not yet consume that ELF — wiring
up `sp1-build` in `prover/build.rs` + adding `sp1-sdk` to the host
`Cargo.toml` is the next step (deferred to avoid the ~4-minute sp1-sdk
compile until the host actually drives proofs).

## License

Apache-2.0. See [../LICENSE](../LICENSE).
