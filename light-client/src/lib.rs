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

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

/// A finalized Tempo state root and the block it commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedRoot {
    /// Tempo block number this root was finalized at.
    pub slot: u64,
    /// 32-byte state root commitment.
    pub state_root: [u8; 32],
}

/// Persistent light-client state. Held by the verifier (Solana PDA on the
/// destination chain); passed into [`verify_update`] as the prior state.
#[derive(Debug, Clone)]
pub struct LightClientStore {
    /// Most recently verified finalized root.
    pub latest: FinalizedRoot,
    /// Hash commitment of the currently authorized validator set.
    pub validator_set_hash: [u8; 32],
}

/// A finality update: a new certificate plus optional validator-set
/// rotation payload.
#[derive(Debug, Clone)]
pub struct Update {
    /// New finalized header + certificate bytes. Encoding pinned in
    /// `spec/light-client.md`.
    pub certificate: Vec<u8>,
    /// Present only when the certificate crosses a validator-set rotation
    /// boundary.
    pub next_validator_set: Option<Vec<u8>>,
}

/// Errors returned by [`verify_update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    #[test]
    fn types_compile() {
        let _store = LightClientStore {
            latest: FinalizedRoot { slot: 0, state_root: [0u8; 32] },
            validator_set_hash: [0u8; 32],
        };
        let _update = Update {
            certificate: Vec::new(),
            next_validator_set: None,
        };
    }
}
