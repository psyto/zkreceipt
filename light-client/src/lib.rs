//! # zktempo-light-client
//!
//! Simplex BFT finality verification for Tempo. Designed to run inside
//! SP1's zkVM guest, on native Rust hosts, and (with `verify` disabled)
//! on Solana's BPF target as part of the downstream verifier program.
//!
//! ## Feature flags
//!
//! - `std` (default) — links the standard library.
//! - `verify` (default) — enables the consensus verification surface
//!   (`verify_update`, `CertificateHeader`, `Update`, `ProofInputs`,
//!   `LightClientStore`, signature payload + validator-set hashing).
//!   Pulls in `ed25519-dalek`, `sha2`, `serde-big-array`.
//!
//! With **`default-features = false`** the crate exposes only the
//! always-on **public-output codec** (`FinalizedRoot`, `ProofOutputs`,
//! `encode_public_output`, `decode_public_output`, `DecodeError`,
//! `PUBLIC_OUTPUT_LEN`) — sufficient for the Solana verifier program to
//! parse the 112-byte committed output without compiling Ed25519 to BPF.
//!
//! ## Status
//!
//! **Partial implementation.** When `verify` is enabled, structural
//! checks (monotonic slot, epoch transitions, proposer-in-set,
//! validator-set hash) plus the proposer's Ed25519 signature are
//! verified. The aggregate quorum signature path is explicitly `TODO`
//! pending Tempo's confirmation of where aggregate signatures live and
//! how they're encoded (see `../../spec/tempo-chainspec.md` §3.3 and
//! §12.1).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use serde::{Deserialize, Serialize};

// ═════════════════════════════════════════════════════════════════════════
// Always-on: public-output codec.
//
// These types and functions are available regardless of features. They
// describe the wire format committed by the SP1 guest as the proof's
// public values and consumed by the destination-chain verifier program.
// ═════════════════════════════════════════════════════════════════════════

/// A finalized Tempo state root and the block it commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedRoot {
    /// Tempo block number this root was finalized at.
    pub slot: u64,
    /// 32-byte state root commitment.
    pub state_root: [u8; 32],
}

/// SP1 guest public outputs. What the zkVM commits to the proof and what
/// the destination-chain verifier consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOutputs {
    /// New finalized root after applying the update.
    pub new_root: FinalizedRoot,
    /// Prior finalized root. Binds the proof to a specific transition,
    /// preventing replay across non-contiguous state-root pairs.
    pub prev_root: FinalizedRoot,
    /// Validator-set hash active during this verification.
    pub validator_set_hash: [u8; 32],
}

/// Length in bytes of the SP1 guest's committed public output.
pub const PUBLIC_OUTPUT_LEN: usize = 112;

/// Errors returned by [`decode_public_output`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodeError {
    /// Input slice was not exactly [`PUBLIC_OUTPUT_LEN`] bytes.
    InvalidLength,
}

/// Pack [`ProofOutputs`] into the canonical fixed-size 112-byte layout
/// consumed by the Solana verifier program.
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
/// SP1 guest (encoder) and Solana verifier (decoder, via
/// [`decode_public_output`]) MUST use this function as the single source
/// of truth.
pub fn encode_public_output(outputs: &ProofOutputs) -> [u8; PUBLIC_OUTPUT_LEN] {
    let mut out = [0u8; PUBLIC_OUTPUT_LEN];
    out[0..8].copy_from_slice(&outputs.new_root.slot.to_le_bytes());
    out[8..40].copy_from_slice(&outputs.new_root.state_root);
    out[40..48].copy_from_slice(&outputs.prev_root.slot.to_le_bytes());
    out[48..80].copy_from_slice(&outputs.prev_root.state_root);
    out[80..112].copy_from_slice(&outputs.validator_set_hash);
    out
}

/// Inverse of [`encode_public_output`].
pub fn decode_public_output(bytes: &[u8]) -> Result<ProofOutputs, DecodeError> {
    if bytes.len() != PUBLIC_OUTPUT_LEN {
        return Err(DecodeError::InvalidLength);
    }

    let new_slot = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let mut new_state_root = [0u8; 32];
    new_state_root.copy_from_slice(&bytes[8..40]);

    let prev_slot = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let mut prev_state_root = [0u8; 32];
    prev_state_root.copy_from_slice(&bytes[48..80]);

    let mut validator_set_hash = [0u8; 32];
    validator_set_hash.copy_from_slice(&bytes[80..112]);

    Ok(ProofOutputs {
        new_root: FinalizedRoot {
            slot: new_slot,
            state_root: new_state_root,
        },
        prev_root: FinalizedRoot {
            slot: prev_slot,
            state_root: prev_state_root,
        },
        validator_set_hash,
    })
}

// ═════════════════════════════════════════════════════════════════════════
// Verify-only: consensus types + Simplex BFT verification.
//
// Gated behind the `verify` feature. Pulls Ed25519, SHA-256, and the
// big-array serde derive workaround. Consumers that only need the codec
// (e.g. the Solana verifier program) should set `default-features = false`
// to skip this whole layer.
// ═════════════════════════════════════════════════════════════════════════

/// Length of a Tempo validator public key (Ed25519).
#[cfg(feature = "verify")]
pub const PUBKEY_LEN: usize = 32;

/// Length of an Ed25519 signature.
#[cfg(feature = "verify")]
pub const SIGNATURE_LEN: usize = 64;

/// Length of the proposer's canonical signing payload.
#[cfg(feature = "verify")]
pub const SIGNING_PAYLOAD_LEN: usize = 8 + 32 + 8 + 8 + 8;

/// Tempo validator public key (Ed25519).
#[cfg(feature = "verify")]
pub type ValidatorPubkey = [u8; PUBKEY_LEN];

/// Ed25519 signature.
#[cfg(feature = "verify")]
pub type Sig = [u8; SIGNATURE_LEN];

#[cfg(feature = "verify")]
use serde_big_array::BigArray;

/// Persistent light-client state. Held by the verifier (Solana PDA on the
/// destination chain); passed into [`verify_update`] as the prior state.
#[cfg(feature = "verify")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientStore {
    /// Most recently verified finalized root.
    pub latest: FinalizedRoot,
    /// Epoch of the most recently verified update.
    pub current_epoch: u64,
    /// View of the most recently verified update.
    pub current_view: u64,
    /// Currently authorized validator set (Ed25519 pubkeys).
    pub validator_set: alloc::vec::Vec<ValidatorPubkey>,
    /// SHA-256 over the concatenated `validator_set`.
    pub validator_set_hash: [u8; 32],
}

/// A single block's certificate header, mirroring Tempo's `consensusContext`
/// block-header field (`spec/tempo-chainspec.md` §3.1).
#[cfg(feature = "verify")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateHeader {
    /// Tempo block number.
    pub slot: u64,
    /// State root finalized at this block.
    pub state_root: [u8; 32],
    /// Simplex epoch.
    pub epoch: u64,
    /// Simplex view (per-epoch, resets at boundary).
    pub view: u64,
    /// Prior block's view.
    pub parent_view: u64,
    /// Block proposer's Ed25519 public key.
    pub proposer: ValidatorPubkey,
    /// Proposer's Ed25519 signature over [`canonical_signing_payload`].
    #[serde(with = "BigArray")]
    pub proposer_signature: Sig,
}

/// Validator-set rotation payload.
///
/// **NOTE on `authorization`:** the exact format and verification rules
/// for the aggregate signature authorizing this rotation are pending
/// Tempo confirmation (`spec/tempo-chainspec.md` §12.1, §12.3).
#[cfg(feature = "verify")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetTransition {
    /// Epoch this transition activates.
    pub new_epoch: u64,
    /// The new validator set, in canonical order.
    pub new_validators: alloc::vec::Vec<ValidatorPubkey>,
    /// Aggregate signature from the prior validator set.
    pub authorization: alloc::vec::Vec<u8>,
}

/// A finality update.
#[cfg(feature = "verify")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Update {
    /// The block being finalized.
    pub header: CertificateHeader,
    /// Aggregate quorum signature from the active validator set.
    /// Format pending Tempo confirmation (`spec/tempo-chainspec.md` §3.3).
    pub quorum_signature: alloc::vec::Vec<u8>,
    /// Present only when this update crosses an epoch boundary.
    pub validator_set_transition: Option<ValidatorSetTransition>,
}

/// Errors returned by [`verify_update`].
#[cfg(feature = "verify")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyError {
    /// Slot did not strictly increase relative to the store's `latest.slot`.
    NonMonotonicSlot,
    /// Within-epoch view did not strictly increase, or epoch advanced by
    /// more than 1, or other epoch/view-rule violation.
    InvalidEpochView,
    /// Proposer pubkey is not a member of the currently authorized
    /// validator set.
    ProposerNotInSet,
    /// `validator_set` and `validator_set_hash` in the store disagree.
    ValidatorSetHashMismatch,
    /// Proposer's Ed25519 signature failed to verify.
    InvalidProposerSignature,
    /// Validator-set rotation rules were violated.
    InvalidValidatorSetTransition,
    /// Aggregate quorum signature failed (path currently TODO).
    InvalidQuorumSignature,
    /// Certificate or update bytes failed to decode.
    DecodingError,
}

/// SP1 guest input bundle.
#[cfg(feature = "verify")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInputs {
    /// Prior light-client state.
    pub store: LightClientStore,
    /// The finality update to verify and apply.
    pub update: Update,
}

/// Canonical bytes that a block proposer signs over.
///
/// Layout (64 bytes):
///
/// | offset  | length | field                  |
/// |---------|--------|------------------------|
/// | 0..8    |   8    | `slot` (u64 LE)        |
/// | 8..40   |  32    | `state_root`           |
/// | 40..48  |   8    | `epoch` (u64 LE)       |
/// | 48..56  |   8    | `view` (u64 LE)        |
/// | 56..64  |   8    | `parent_view` (u64 LE) |
///
/// **SPECULATIVE — Tempo has not published the exact signing payload
/// format.** Reconcile with Tempo's confirmation once available
/// (`spec/tempo-chainspec.md` §12.1).
#[cfg(feature = "verify")]
pub fn canonical_signing_payload(header: &CertificateHeader) -> [u8; SIGNING_PAYLOAD_LEN] {
    let mut out = [0u8; SIGNING_PAYLOAD_LEN];
    out[0..8].copy_from_slice(&header.slot.to_le_bytes());
    out[8..40].copy_from_slice(&header.state_root);
    out[40..48].copy_from_slice(&header.epoch.to_le_bytes());
    out[48..56].copy_from_slice(&header.view.to_le_bytes());
    out[56..64].copy_from_slice(&header.parent_view.to_le_bytes());
    out
}

/// SHA-256 over the concatenated validator pubkeys.
#[cfg(feature = "verify")]
pub fn compute_validator_set_hash(validators: &[ValidatorPubkey]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for v in validators {
        hasher.update(v);
    }
    hasher.finalize().into()
}

/// Verify a finality update. See module docs for what is and isn't checked.
#[cfg(feature = "verify")]
pub fn verify_update(
    store: &LightClientStore,
    update: &Update,
) -> Result<FinalizedRoot, VerifyError> {
    let header = &update.header;

    // 1. Slot monotonicity.
    if header.slot <= store.latest.slot {
        return Err(VerifyError::NonMonotonicSlot);
    }

    // 2. Epoch / view rules.
    if header.epoch == store.current_epoch {
        if header.view <= store.current_view {
            return Err(VerifyError::InvalidEpochView);
        }
        if header.parent_view >= header.view {
            return Err(VerifyError::InvalidEpochView);
        }
    } else if header.epoch == store.current_epoch + 1 {
        let transition = update
            .validator_set_transition
            .as_ref()
            .ok_or(VerifyError::InvalidValidatorSetTransition)?;
        if transition.new_epoch != header.epoch {
            return Err(VerifyError::InvalidValidatorSetTransition);
        }
        // TODO: verify `transition.authorization` against the prior validator
        // set (spec/tempo-chainspec.md §12.1).
    } else {
        return Err(VerifyError::InvalidEpochView);
    }

    // 3. Proposer must be in the currently authorized validator set.
    if !store.validator_set.iter().any(|v| v == &header.proposer) {
        return Err(VerifyError::ProposerNotInSet);
    }

    // 4. Defense-in-depth: validator set + stored hash agree.
    if compute_validator_set_hash(&store.validator_set) != store.validator_set_hash {
        return Err(VerifyError::ValidatorSetHashMismatch);
    }

    // 5. Proposer's Ed25519 signature over the canonical payload.
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&header.proposer)
        .map_err(|_| VerifyError::InvalidProposerSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&header.proposer_signature);
    let payload = canonical_signing_payload(header);
    vk.verify_strict(&payload, &sig)
        .map_err(|_| VerifyError::InvalidProposerSignature)?;

    // 6. TODO: verify `update.quorum_signature` against `store.validator_set`.
    //    Blocked on Tempo confirmation (`spec/tempo-chainspec.md` §3.3, §12.1).

    Ok(FinalizedRoot {
        slot: header.slot,
        state_root: header.state_root,
    })
}

// ═════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn fixture_outputs() -> ProofOutputs {
        ProofOutputs {
            new_root: FinalizedRoot {
                slot: 0x0102_0304_0506_0708,
                state_root: [0xAA; 32],
            },
            prev_root: FinalizedRoot {
                slot: 0x1112_1314_1516_1718,
                state_root: [0xBB; 32],
            },
            validator_set_hash: [0xCC; 32],
        }
    }

    #[test]
    fn public_output_layout_is_stable() {
        let out = encode_public_output(&fixture_outputs());
        assert_eq!(out.len(), PUBLIC_OUTPUT_LEN);
        assert_eq!(&out[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&out[8..40], &[0xAA; 32]);
        assert_eq!(&out[40..48], &0x1112_1314_1516_1718u64.to_le_bytes());
        assert_eq!(&out[48..80], &[0xBB; 32]);
        assert_eq!(&out[80..112], &[0xCC; 32]);
    }

    #[test]
    fn public_output_encode_decode_roundtrip() {
        let original = fixture_outputs();
        let encoded = encode_public_output(&original);
        let decoded = decode_public_output(&encoded).expect("valid 112-byte input");
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(decode_public_output(&[]), Err(DecodeError::InvalidLength));
        assert_eq!(
            decode_public_output(&[0u8; PUBLIC_OUTPUT_LEN - 1]),
            Err(DecodeError::InvalidLength)
        );
        assert_eq!(
            decode_public_output(&[0u8; PUBLIC_OUTPUT_LEN + 1]),
            Err(DecodeError::InvalidLength)
        );
    }

    // ─── verify-feature-gated tests ─────────────────────────────────────

    #[cfg(feature = "verify")]
    mod verify_tests {
        use super::super::*;
        use alloc::vec;
        use alloc::vec::Vec;
        use ed25519_dalek::{Signer, SigningKey};

        fn keypair(seed: u8) -> (SigningKey, ValidatorPubkey) {
            let sk = SigningKey::from_bytes(&[seed; 32]);
            let pk = sk.verifying_key().to_bytes();
            (sk, pk)
        }

        fn fixture_store() -> (Vec<SigningKey>, LightClientStore) {
            let (sk0, pk0) = keypair(0xA0);
            let (sk1, pk1) = keypair(0xA1);
            let (sk2, pk2) = keypair(0xA2);
            let validators = vec![pk0, pk1, pk2];
            let validator_set_hash = compute_validator_set_hash(&validators);
            let store = LightClientStore {
                latest: FinalizedRoot {
                    slot: 100,
                    state_root: [0u8; 32],
                },
                current_epoch: 1,
                current_view: 5,
                validator_set: validators,
                validator_set_hash,
            };
            (vec![sk0, sk1, sk2], store)
        }

        fn signed_header(
            sk: &SigningKey,
            slot: u64,
            epoch: u64,
            view: u64,
            parent_view: u64,
        ) -> CertificateHeader {
            let mut header = CertificateHeader {
                slot,
                state_root: [42u8; 32],
                epoch,
                view,
                parent_view,
                proposer: sk.verifying_key().to_bytes(),
                proposer_signature: [0u8; 64],
            };
            let payload = canonical_signing_payload(&header);
            let sig = sk.sign(&payload);
            header.proposer_signature = sig.to_bytes();
            header
        }

        fn intra_epoch_update(sk: &SigningKey) -> Update {
            Update {
                header: signed_header(sk, 101, 1, 6, 5),
                quorum_signature: Vec::new(),
                validator_set_transition: None,
            }
        }

        #[test]
        fn proof_inputs_cbor_roundtrip() {
            let (sks, store) = fixture_store();
            let original = ProofInputs {
                store,
                update: intra_epoch_update(&sks[0]),
            };
            let mut buf = Vec::new();
            ciborium::into_writer(&original, &mut buf).expect("CBOR encode");
            let decoded: ProofInputs =
                ciborium::from_reader(&buf[..]).expect("CBOR decode");
            assert_eq!(original, decoded);
        }

        #[test]
        fn verify_accepts_valid_same_epoch_update() {
            let (sks, store) = fixture_store();
            let update = intra_epoch_update(&sks[1]);
            let new_root = verify_update(&store, &update).expect("should verify");
            assert_eq!(new_root.slot, 101);
            assert_eq!(new_root.state_root, [42u8; 32]);
        }

        #[test]
        fn verify_rejects_non_monotonic_slot() {
            let (sks, store) = fixture_store();
            let update = Update {
                header: signed_header(&sks[0], 100, 1, 6, 5),
                quorum_signature: Vec::new(),
                validator_set_transition: None,
            };
            assert_eq!(verify_update(&store, &update), Err(VerifyError::NonMonotonicSlot));
        }

        #[test]
        fn verify_rejects_view_not_advanced_same_epoch() {
            let (sks, store) = fixture_store();
            let update = Update {
                header: signed_header(&sks[0], 101, 1, 5, 4),
                quorum_signature: Vec::new(),
                validator_set_transition: None,
            };
            assert_eq!(verify_update(&store, &update), Err(VerifyError::InvalidEpochView));
        }

        #[test]
        fn verify_rejects_epoch_skip() {
            let (sks, store) = fixture_store();
            let update = Update {
                header: signed_header(&sks[0], 101, 3, 1, 0),
                quorum_signature: Vec::new(),
                validator_set_transition: Some(ValidatorSetTransition {
                    new_epoch: 3,
                    new_validators: store.validator_set.clone(),
                    authorization: Vec::new(),
                }),
            };
            assert_eq!(verify_update(&store, &update), Err(VerifyError::InvalidEpochView));
        }

        #[test]
        fn verify_rejects_epoch_transition_without_payload() {
            let (sks, store) = fixture_store();
            let update = Update {
                header: signed_header(&sks[0], 101, 2, 1, 0),
                quorum_signature: Vec::new(),
                validator_set_transition: None,
            };
            assert_eq!(
                verify_update(&store, &update),
                Err(VerifyError::InvalidValidatorSetTransition)
            );
        }

        #[test]
        fn verify_rejects_transition_for_wrong_epoch() {
            let (sks, store) = fixture_store();
            let update = Update {
                header: signed_header(&sks[0], 101, 2, 1, 0),
                quorum_signature: Vec::new(),
                validator_set_transition: Some(ValidatorSetTransition {
                    new_epoch: 5,
                    new_validators: store.validator_set.clone(),
                    authorization: Vec::new(),
                }),
            };
            assert_eq!(
                verify_update(&store, &update),
                Err(VerifyError::InvalidValidatorSetTransition)
            );
        }

        #[test]
        fn verify_accepts_valid_epoch_transition_structurally() {
            let (sks, store) = fixture_store();
            let update = Update {
                header: signed_header(&sks[2], 101, 2, 1, 0),
                quorum_signature: Vec::new(),
                validator_set_transition: Some(ValidatorSetTransition {
                    new_epoch: 2,
                    new_validators: store.validator_set.clone(),
                    authorization: Vec::new(),
                }),
            };
            let new_root = verify_update(&store, &update).expect("structural accept");
            assert_eq!(new_root.slot, 101);
        }

        #[test]
        fn verify_rejects_proposer_not_in_set() {
            let (_, store) = fixture_store();
            let (foreign_sk, _) = keypair(0xFF);
            let update = intra_epoch_update(&foreign_sk);
            assert_eq!(verify_update(&store, &update), Err(VerifyError::ProposerNotInSet));
        }

        #[test]
        fn verify_rejects_tampered_signature() {
            let (sks, store) = fixture_store();
            let mut update = intra_epoch_update(&sks[0]);
            update.header.proposer_signature[0] ^= 0x01;
            assert_eq!(
                verify_update(&store, &update),
                Err(VerifyError::InvalidProposerSignature)
            );
        }

        #[test]
        fn verify_rejects_payload_tamper_after_sign() {
            let (sks, store) = fixture_store();
            let mut update = intra_epoch_update(&sks[0]);
            update.header.state_root[0] ^= 0x01;
            assert_eq!(
                verify_update(&store, &update),
                Err(VerifyError::InvalidProposerSignature)
            );
        }

        #[test]
        fn verify_rejects_corrupt_validator_set_hash() {
            let (sks, mut store) = fixture_store();
            store.validator_set_hash[0] ^= 0x01;
            let update = intra_epoch_update(&sks[0]);
            assert_eq!(
                verify_update(&store, &update),
                Err(VerifyError::ValidatorSetHashMismatch)
            );
        }
    }
}
