# zktempo-prover guest program

Placeholder. The SP1 zkVM guest program lives here when implemented.

It will be a **separate crate** (its own `Cargo.toml`) with `sp1-zkvm` as a
dependency, compiled via `cargo prove build`. The guest will read
`LightClientStore` and `Update` from stdin, call
[`zktempo_light_client::verify_update`](../../light-client/), and commit
the resulting `FinalizedRoot` + validator-set hash as public inputs.

Sketch (do not build — illustrative only):

```rust
// program/src/main.rs (future)
#![no_main]
sp1_zkvm::entrypoint!(main);

use zktempo_light_client::{LightClientStore, Update, verify_update};

pub fn main() {
    let store: LightClientStore = sp1_zkvm::io::read();
    let update: Update = sp1_zkvm::io::read();
    let new_root = verify_update(&store, &update).expect("verification failed");
    sp1_zkvm::io::commit(&new_root.slot);
    sp1_zkvm::io::commit(&new_root.state_root);
    sp1_zkvm::io::commit(&store.validator_set_hash);
}
```

See [`../README.md`](../README.md) and
[`../../spec/prover.md`](../../spec/prover.md) for the surrounding design.

The crate is omitted from the workspace until SP1 toolchain versions are
pinned during the M1 milestone (sp1-helios spike).
