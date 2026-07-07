# zkreceipt-light-client

Simplex BFT finality verification for Tempo.

This crate verifies finality certificates emitted by Tempo's validator set
and returns the new finalized state root. It is `no_std`-compatible by
default (opt into `std` via feature flag), so it links into SP1's zkVM
guest program at [`../prover/`](../prover/) and into native Rust hosts
unchanged.

## Status

**Scaffold.** Type signatures and the public API are pinned; the
verification logic is `unimplemented!()`. See
[`../spec/light-client.md`](../spec/light-client.md) for the protocol
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

Intentionally minimal pending consensus pin-down. Future additions are
expected to include:

- `sha2` — domain-separated hashing
- A signature crate matching Tempo's scheme (BLS12-381 or Ed25519 — TBD)
- `borsh` or `postcard` — `no_std` serialization

## License

Apache-2.0. See [../LICENSE](../LICENSE).
