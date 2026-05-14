//! SP1 zkVM guest program for zkTempo.sol — the `light_client` binary.
//!
//! Reads a serde_cbor-encoded [`ProofInputs`] from the SP1 host, calls
//! [`verify_update`] from `zktempo-light-client`, and commits the
//! resulting finalized root + validator-set hash as the proof's public
//! outputs.
//!
//! Structurally mirrors `sp1-helios/program/src/light_client.rs` — the
//! canonical reference for an SP1 light-client guest. The differences:
//!
//! - **Consensus engine.** Calls `zktempo_light_client::verify_update`
//!   instead of `helios_consensus_core::verify_finality_update` etc.
//! - **Output encoding.** Commits raw little-endian bytes for a
//!   Solana-program consumer rather than ABI-encoded structs for an EVM
//!   Solidity verifier. Final encoding (likely Borsh) pinned in
//!   `spec/prover.md`.
//!
//! ## Status
//!
//! Scaffold. The body of `verify_update` in `zktempo-light-client` is
//! `unimplemented!()` until Tempo's Simplex BFT details are pinned. This
//! guest will panic at runtime; it exists to make the call chain compile
//! and document the intended structure.

#![no_main]

extern crate alloc;

sp1_zkvm::entrypoint!(main);

use alloc::vec::Vec;
use zktempo_light_client::{verify_update, ProofInputs};

pub fn main() {
    // 1. Read host-supplied inputs (CBOR over a single read_vec). Using
    //    `ciborium` (maintained) rather than `serde_cbor` (which
    //    sp1-helios pins; unmaintained and incompatible with modern
    //    serde_core).
    let encoded = sp1_zkvm::io::read_vec();
    let inputs: ProofInputs =
        ciborium::from_reader(&encoded[..]).expect("ProofInputs CBOR decode failed");

    // 2. Capture prior state for the public-output binding.
    let prev_slot = inputs.store.latest.slot;
    let prev_state_root = inputs.store.latest.state_root;
    let validator_set_hash = inputs.store.validator_set_hash;

    // 3. Run light-client verification. Panics if invalid; this is
    //    what makes the proof bind to a valid consensus transition.
    let new_root = verify_update(&inputs.store, &inputs.update)
        .expect("finality verification failed");

    // 4. Commit public outputs. Format (fixed-layout, 112 bytes):
    //      [0..8)    new_slot (u64, LE)
    //      [8..40)   new_state_root ([u8; 32])
    //      [40..48)  prev_slot (u64, LE)
    //      [48..80)  prev_state_root ([u8; 32])
    //      [80..112) validator_set_hash ([u8; 32])
    //
    //    Solana-side `update_light_client` reads this layout via direct
    //    byte offsets. Final encoding (likely Borsh) is pinned in
    //    spec/prover.md.
    let mut output = Vec::with_capacity(112);
    output.extend_from_slice(&new_root.slot.to_le_bytes());
    output.extend_from_slice(&new_root.state_root);
    output.extend_from_slice(&prev_slot.to_le_bytes());
    output.extend_from_slice(&prev_state_root);
    output.extend_from_slice(&validator_set_hash);

    sp1_zkvm::io::commit_slice(&output);
}
