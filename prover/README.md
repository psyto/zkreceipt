# zktempo-prover

Off-chain prover for zkTempo.sol. Generates Groth16 proofs of Tempo
finality by running [`zktempo-light-client`](../light-client/) inside the
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
   LightClientStore       │ zktempo-prover      │
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

The guest crate is omitted from this scaffold because it pulls in
SP1-specific build tooling (`cargo prove build`) and a specific toolchain
version. Both land once the M1 sp1-helios spike confirms versions.

## License

Apache-2.0. See [../LICENSE](../LICENSE).
