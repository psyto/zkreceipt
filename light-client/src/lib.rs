//! # zktempo-light-client
//!
//! Simplex BFT finality verification for Tempo, designed to run inside SP1's
//! zkVM guest as well as on native Rust hosts.
//!
//! ## Status
//!
//! Scaffold. The verification logic is not yet implemented; this crate
//! currently defines only the API surface that will be filled in once
//! Tempo's Simplex consensus details (signature scheme, certificate
//! encoding, validator-set rotation rules) are confirmed. See
//! `../../spec/light-client.md` for the protocol design and open research
//! items.
//!
//! ## Composition
//!
//! Types here cross the SP1 guest↔host boundary:
//! - The host serializes [`ProofInputs`] (containing [`LightClientStore`]
//!   and [`Update`]) via `ciborium` (CBOR) and passes them to the guest.
//! - The guest deserializes, calls [`verify_update`], and commits the
//!   resulting [`FinalizedRoot`] as part of the proof's public outputs.
//! - The Solana verifier program reads the public outputs and persists the
//!   new root to its `LightClientState` PDA.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A finalized Tempo state root and the block it commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedRoot {
    /// Tempo block number this root was finalized at.
    pub slot: u64,
    /// 32-byte state root commitment.
    pub state_root: [u8; 32],
}

/// Persistent light-client state. Held by the verifier (Solana PDA on the
/// destination chain); passed into [`verify_update`] as the prior state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientStore {
    /// Most recently verified finalized root.
    pub latest: FinalizedRoot,
    /// Hash commitment of the currently authorized validator set.
    pub validator_set_hash: [u8; 32],
}

/// A finality update: a new certificate plus optional validator-set
/// rotation payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Update {
    /// New finalized header + certificate bytes. Encoding pinned in
    /// `spec/light-client.md`.
    pub certificate: Vec<u8>,
    /// Present only when the certificate crosses a validator-set rotation
    /// boundary.
    pub next_validator_set: Option<Vec<u8>>,
}

/// Errors returned by [`verify_update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyError {
    /// Certificate failed signature aggregation / quorum check.
    InvalidCertificate,
    /// Certificate's claimed slot is not strictly greater than the store's
    /// latest finalized slot.
    NonMonotonicSlot,
    /// Validator-set rotation rules were violated (e.g. transition without
    /// quorum from the outgoing set).
    InvalidValidatorSetTransition,
    /// Certificate or update bytes failed to decode.
    DecodingError,
}

/// SP1 guest input bundle. Serialized via `ciborium` (CBOR) on the host,
/// deserialized inside the guest via `ciborium::from_reader` over
/// `sp1_zkvm::io::read_vec()`. Matches the `ProofInputs` pattern in
/// `succinctlabs/sp1-helios`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInputs {
    /// Prior light-client state.
    pub store: LightClientStore,
    /// The finality update to verify and apply.
    pub update: Update,
}

/// Length in bytes of the SP1 guest's committed public output.
pub const PUBLIC_OUTPUT_LEN: usize = 112;

/// Pack the guest's committed public output into the canonical fixed-size
/// 112-byte layout consumed by the Solana verifier program.
///
/// Layout:
///
/// | offset  | length | field                            |
/// |---------|--------|----------------------------------|
/// | 0..8    |   8    | `new_root.slot` (u64 LE)         |
/// | 8..40   |  32    | `new_root.state_root`            |
/// | 40..48  |   8    | `prev_root.slot` (u64 LE)        |
/// | 48..80  |  32    | `prev_root.state_root`           |
/// | 80..112 |  32    | `validator_set_hash`             |
///
/// Both the SP1 guest and the Solana verifier MUST use this function (or
/// its inverse) as the single source of truth for the layout. Any offset
/// change is a wire-breaking change.
pub fn encode_public_output(
    new_root: &FinalizedRoot,
    prev_root: &FinalizedRoot,
    validator_set_hash: &[u8; 32],
) -> [u8; PUBLIC_OUTPUT_LEN] {
    let mut out = [0u8; PUBLIC_OUTPUT_LEN];
    out[0..8].copy_from_slice(&new_root.slot.to_le_bytes());
    out[8..40].copy_from_slice(&new_root.state_root);
    out[40..48].copy_from_slice(&prev_root.slot.to_le_bytes());
    out[48..80].copy_from_slice(&prev_root.state_root);
    out[80..112].copy_from_slice(validator_set_hash);
    out
}

/// Verify a finality update against the current store. On success, returns
/// the new [`FinalizedRoot`]; the caller is responsible for persisting it.
/// This crate is stateless.
///
/// # Stubbed
///
/// Not yet implemented. The signature is pinned so downstream callers
/// (prover, verifier) can be wired against the final API; the body will be
/// filled once consensus details are confirmed.
pub fn verify_update(
    _store: &LightClientStore,
    _update: &Update,
) -> Result<FinalizedRoot, VerifyError> {
    unimplemented!(
        "Simplex BFT verification not yet implemented; see spec/light-client.md"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_inputs() -> ProofInputs {
        ProofInputs {
            store: LightClientStore {
                latest: FinalizedRoot {
                    slot: 42,
                    state_root: [0x11; 32],
                },
                validator_set_hash: [0x22; 32],
            },
            update: Update {
                certificate: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
                next_validator_set: Some(vec![0x01, 0x02, 0x03]),
            },
        }
    }

    #[test]
    fn types_compile() {
        let _ = fixture_inputs();
    }

    /// ProofInputs survives the CBOR round-trip used at the SP1 host↔guest
    /// boundary. Catches regressions in serde derives, field ordering, and
    /// host/guest decoder compatibility (the host will use `ciborium` to
    /// encode; the guest decodes via the same crate).
    #[test]
    fn proof_inputs_cbor_roundtrip() {
        let original = fixture_inputs();
        let mut buf = Vec::new();
        ciborium::into_writer(&original, &mut buf).expect("CBOR encode");
        let decoded: ProofInputs =
            ciborium::from_reader(&buf[..]).expect("CBOR decode");
        assert_eq!(original, decoded);
    }

    /// Locks down the wire-breaking byte layout of [`encode_public_output`].
    /// The Solana verifier reads these offsets directly; any reordering
    /// here silently breaks downstream consumption.
    #[test]
    fn public_output_layout_is_stable() {
        let new_root = FinalizedRoot {
            slot: 0x0102_0304_0506_0708,
            state_root: [0xAA; 32],
        };
        let prev_root = FinalizedRoot {
            slot: 0x1112_1314_1516_1718,
            state_root: [0xBB; 32],
        };
        let validator_set_hash = [0xCC; 32];

        let out = encode_public_output(&new_root, &prev_root, &validator_set_hash);

        // Total length is exactly PUBLIC_OUTPUT_LEN (112).
        assert_eq!(out.len(), PUBLIC_OUTPUT_LEN);

        // 0..8: new_root.slot, little-endian.
        assert_eq!(&out[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        // 8..40: new_root.state_root.
        assert_eq!(&out[8..40], &[0xAA; 32]);
        // 40..48: prev_root.slot, little-endian.
        assert_eq!(&out[40..48], &0x1112_1314_1516_1718u64.to_le_bytes());
        // 48..80: prev_root.state_root.
        assert_eq!(&out[48..80], &[0xBB; 32]);
        // 80..112: validator_set_hash.
        assert_eq!(&out[80..112], &[0xCC; 32]);
    }
}
