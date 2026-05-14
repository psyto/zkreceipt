//! # zktempo-prover
//!
//! Off-chain prover for zkTempo.sol. Generates Groth16 (over BN254) proofs
//! of Tempo finality by running [`zktempo_light_client`] inside the SP1
//! zkVM guest, then wrapping the resulting STARK in Groth16 for cheap
//! on-chain verification on Solana via `alt_bn128` syscalls.
//!
//! ## Status
//!
//! Scaffold. The host-side API surface is pinned; the proving body is
//! `unimplemented!()` pending SP1 version pin-down and the guest program
//! at `./program/`. See `../spec/prover.md` for the design.

#![deny(missing_docs)]

use zktempo_light_client::{FinalizedRoot, LightClientStore, Update};

/// Configuration for the prover host.
#[derive(Debug, Clone)]
pub struct ProverConfig {
    /// Tempo JSON-RPC endpoint. Used by the operator to fetch finality
    /// certificates from a Tempo node.
    pub tempo_rpc: String,
    /// Solana JSON-RPC endpoint. Used to read verifier-PDA state and to
    /// submit proof-bearing transactions.
    pub solana_rpc: String,
    /// Proving backend selection.
    pub mode: ProverMode,
}

/// Where proof generation runs.
#[derive(Debug, Clone)]
pub enum ProverMode {
    /// Local proving on the host machine. Slower, no external service
    /// dependency. Useful for development and tests.
    Local,
    /// Succinct prover network. Fast, requires API access; cost amortizes
    /// across many proofs.
    SuccinctNetwork {
        /// API endpoint URL for the prover network.
        endpoint: String,
    },
}

/// Public inputs committed by the SP1 guest. These are the values the
/// on-chain verifier checks the Groth16 proof against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs {
    /// New finalized state root (32 bytes).
    pub new_state_root: [u8; 32],
    /// New finalized slot number.
    pub new_slot: u64,
    /// Hash commitment of the validator set authorized to sign the
    /// certificate proved.
    pub validator_set_hash: [u8; 32],
}

/// A proof artifact ready for on-chain submission.
#[derive(Debug, Clone)]
pub struct ProofArtifact {
    /// Groth16 proof bytes, BN254-encoded for the Solana `alt_bn128`
    /// verifier.
    pub groth16_proof: Vec<u8>,
    /// Public inputs the proof commits to.
    pub public_inputs: PublicInputs,
    /// The finalized root derived inside the guest. Also encoded in
    /// `public_inputs`; exposed separately for caller convenience.
    pub finalized_root: FinalizedRoot,
}

/// Errors returned by the prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProverError {
    /// Light-client verification of the input update failed before proving
    /// started. The wrapped error came from [`zktempo_light_client`].
    LightClientRejected(zktempo_light_client::VerifyError),
    /// SP1 zkVM execution failed — guest panicked, aborted, or returned an
    /// invalid commitment.
    GuestExecutionFailed(String),
    /// Groth16 wrapping of the STARK proof failed.
    Groth16Failed(String),
    /// Network error talking to the Tempo RPC, Solana RPC, or the Succinct
    /// prover network.
    NetworkError(String),
}

/// Generate a Groth16 proof for a single finality update.
///
/// Runs [`zktempo_light_client::verify_update`] inside the SP1 guest,
/// commits the resulting [`FinalizedRoot`] and validator-set hash as
/// public inputs, then wraps the STARK proof in Groth16.
///
/// # Stubbed
///
/// Not yet implemented. Requires (in order):
/// 1. SP1 host SDK pin (`sp1-sdk = "x.y.z"`).
/// 2. Guest program at `program/` with `sp1_zkvm::entrypoint!`.
/// 3. Groth16 verification key generated and embedded into the Solana
///    verifier program.
pub fn prove_finality_update(
    _config: &ProverConfig,
    _store: &LightClientStore,
    _update: &Update,
) -> Result<ProofArtifact, ProverError> {
    unimplemented!(
        "SP1 proving not yet wired in; see spec/prover.md and program/"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_compose_with_light_client() {
        let _config = ProverConfig {
            tempo_rpc: "https://rpc.moderato.tempo.xyz".into(),
            solana_rpc: "https://api.devnet.solana.com".into(),
            mode: ProverMode::Local,
        };
        let _inputs = PublicInputs {
            new_state_root: [0u8; 32],
            new_slot: 1,
            validator_set_hash: [0u8; 32],
        };
        let _err = ProverError::LightClientRejected(
            zktempo_light_client::VerifyError::InvalidCertificate,
        );
    }
}
