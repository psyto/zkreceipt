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

sp1_zkvm::entrypoint!(main);

use zktempo_light_client::{encode_public_output, verify_update, ProofInputs};

pub fn main() {
    // 1. Read host-supplied inputs (CBOR over a single read_vec). Using
    //    `ciborium` (maintained) rather than `serde_cbor` (which
    //    sp1-helios pins; unmaintained and incompatible with modern
    //    serde_core).
    let encoded = sp1_zkvm::io::read_vec();
    let inputs: ProofInputs =
        ciborium::from_reader(&encoded[..]).expect("ProofInputs CBOR decode failed");

    // 2. Capture prior state for the public-output binding.
    let prev_root = inputs.store.latest.clone();
    let validator_set_hash = inputs.store.validator_set_hash;

    // 3. Run light-client verification. Panics if invalid; this is what
    //    makes the proof bind to a valid consensus transition.
    let new_root = verify_update(&inputs.store, &inputs.update)
        .expect("finality verification failed");

    // 4. Commit public outputs via the canonical encoder. The byte layout
    //    is defined and tested in `zktempo_light_client::encode_public_output`
    //    so guest + Solana verifier share one source of truth.
    let output = encode_public_output(&new_root, &prev_root, &validator_set_hash);
    sp1_zkvm::io::commit_slice(&output);
}
