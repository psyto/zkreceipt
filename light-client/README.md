# zkreceipt-light-client

The **Tempo** source adapter: Simplex BFT finality verification. zkReceipt
uses one consensus light client per source chain.

This crate is zkReceipt's **Tempo** source light client: it verifies finality
certificates emitted by Tempo's validator set and returns the new finalized
state root. Each source chain has its own light client (Ethereum sync-committee
is the planned next); the receiver layers ([`../mpt-verify/`](../mpt-verify/),
[`../x402-receiver/`](../x402-receiver/)) sit above it and are source-agnostic.
It is `no_std`-compatible by default (opt into `std` via feature flag), so it
links into SP1's zkVM guest program at [`../prover/`](../prover/) and into
native Rust hosts unchanged.

## Status

**Partial.** The public API is pinned and `verify_update` verifies the
Ed25519 proposer signature plus all structural checks (slot/epoch/view
monotonicity, validator-set membership + hash). The **BFT aggregate quorum
signature** is still `unimplemented!()`, blocked on Tempo's consensus format.
See [`../spec/light-client.md`](../spec/light-client.md) for the protocol
design and open research items.

## Usage

```rust
use zkreceipt_light_client::{LightClientStore, Update, verify_update};

let store: LightClientStore = /* loaded from verifier PDA */;
let update: Update = /* fetched from off-chain prover */;
let new_root = verify_update(&store, &update)?;
```

## Features

- `std` (default) — enables the standard library. Disable for `no_std`
  (e.g. when building inside SP1's guest).

## Dependencies

Under the `verify` feature (see `Cargo.toml`):

- `ed25519-dalek` — Tempo proposer signatures (confirmed Ed25519, 32-byte keys)
- `sha2` — validator-set hashing
- `serde-big-array` — `[u8; 64]` signature workaround for serde's 32-element cap

Always-on: `serde` (`no_std` + `alloc`) for the public-output codec.

## License

Apache-2.0. See [../LICENSE](../LICENSE).
