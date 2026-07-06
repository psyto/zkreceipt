//! Transport-agnostic x402 receiver core.
//!
//! A provider selling metered access uses this to (a) tell an unpaid caller
//! *how* to pay (the HTTP 402 challenge) and (b) admit a caller who returns a
//! payment proof — by verifying, against a zktempo-authenticated `state_root`,
//! that a settlement contract on Tempo credited the provider. No facilitator is
//! trusted: `verify, don't trust`.
//!
//! This crate is deliberately free of any HTTP framework. It speaks in plain
//! data — [`PaymentRequired`] (the 402 body) and [`PaymentProof`] (the
//! `X-PAYMENT` header payload) — plus one decision function, [`Receiver::admit`].
//! An axum/actix layer is a thin adapter over these.
//!
//! ```text
//!   request without proof ─▶ Receiver::challenge() ─▶ 402 + PaymentRequired
//!   request with X-PAYMENT ─▶ Receiver::admit(proof) ─▶ 200 | 402
//! ```

use alloy_primitives::{Address, Bytes, U256};
use serde::{Deserialize, Serialize};
use zktempo_mpt_verify::{verify_payment, TrieAccount, VerifiedPayment, VerifyError};

pub mod anchor;
pub use anchor::{LightClientAnchor, StateRootSource};

/// The scheme tag both sides agree on. Bump on any wire-format change.
pub const SCHEME: &str = "tempo-mpt/v0";

/// The 402 challenge body: everything a caller needs to construct a payment and
/// a proof the receiver will accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequired {
    /// Payment scheme identifier (`SCHEME`).
    pub scheme: String,
    /// Human/URI reference to the anchor that authenticates the state_root
    /// (e.g. the Solana `LightClientState` PDA address). Informational.
    pub anchor: String,
    /// Settlement contract on Tempo holding `mapping(address => uint256) paidTo`.
    pub settlement: Address,
    /// Payment token (e.g. Tempo AlphaUSD).
    pub token: Address,
    /// Declaration slot index of the `paidTo` mapping in the settlement contract.
    pub mapping_index: u64,
    /// The address that must be credited — the provider.
    pub recipient: Address,
    /// Minimum credited amount required to grant access.
    pub price: U256,
    /// What is being paid for (opaque to the protocol).
    pub resource: String,
}

/// The payload a caller returns in the `X-PAYMENT` header (JSON), proving the
/// payment landed in the Tempo state committed to by a finalized slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentProof {
    /// Finalized Tempo slot the proof is built against. Must match the anchor's
    /// authenticated slot.
    pub slot: u64,
    /// Claimed settlement account; `account_proof` binds it to the state_root.
    pub account: TrieAccount,
    /// EIP-1186 account proof (state trie → settlement account).
    pub account_proof: Vec<Bytes>,
    /// Claimed value of `paidTo[recipient]`; `storage_proof` binds it.
    pub credited_amount: U256,
    /// EIP-1186 storage proof (account storage trie → paidTo slot).
    pub storage_proof: Vec<Bytes>,
}

/// The receiver's decision on a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Payment verified and sufficient — serve the resource.
    Paid(VerifiedPayment),
    /// The proof targets a slot this anchor does not authenticate — the caller
    /// should refetch against the current finalized slot and retry.
    Unanchored { slot: u64 },
    /// The proof is against an authenticated state_root but does not verify (or
    /// underpays).
    Invalid(VerifyError),
}

impl Outcome {
    /// HTTP status a transport adapter should map this to. `Unanchored` and
    /// `Invalid` both re-issue the 402 challenge (payment still required).
    pub fn http_status(&self) -> u16 {
        match self {
            Outcome::Paid(_) => 200,
            Outcome::Unanchored { .. } | Outcome::Invalid(_) => 402,
        }
    }

    pub fn is_paid(&self) -> bool {
        matches!(self, Outcome::Paid(_))
    }
}

/// A metered resource guarded by an x402 payment, anchored to a source of
/// authenticated state_roots `S`.
#[derive(Debug, Clone)]
pub struct Receiver<S: StateRootSource> {
    pub source: S,
    pub settlement: Address,
    pub token: Address,
    pub mapping_index: u64,
    pub recipient: Address,
    pub price: U256,
    pub resource: String,
    pub anchor_ref: String,
}

impl<S: StateRootSource> Receiver<S> {
    /// Build the 402 challenge for an unpaid request.
    pub fn challenge(&self) -> PaymentRequired {
        PaymentRequired {
            scheme: SCHEME.to_string(),
            anchor: self.anchor_ref.clone(),
            settlement: self.settlement,
            token: self.token,
            mapping_index: self.mapping_index,
            recipient: self.recipient,
            price: self.price,
            resource: self.resource.clone(),
        }
    }

    /// Decide whether a payment proof admits the caller.
    ///
    /// 1. Resolve the authenticated `state_root` for `proof.slot` via the anchor
    ///    (else `Unanchored` — the proof is not against state we trust).
    /// 2. Verify the account+storage proof and sufficiency via [`verify_payment`].
    pub fn admit(&self, proof: &PaymentProof) -> Outcome {
        let state_root = match self.source.authenticated_state_root(proof.slot) {
            Some(root) => root,
            None => return Outcome::Unanchored { slot: proof.slot },
        };
        match verify_payment(
            state_root,
            self.settlement,
            &proof.account,
            &proof.account_proof,
            self.mapping_index,
            self.recipient,
            proof.credited_amount,
            &proof.storage_proof,
            self.price,
        ) {
            Ok(v) => Outcome::Paid(v),
            Err(e) => Outcome::Invalid(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::anchor::{decode_light_client_state, FixedAnchor, LightClientAnchor, LightClientState};
    use super::*;
    use alloy_primitives::{B256, U256};
    use zktempo_mpt_verify::testkit::{payment_fixture, PaymentFixture};

    const SLOT: u64 = 42;

    fn receiver_for<S: StateRootSource>(source: S, f: &PaymentFixture, price: u64) -> Receiver<S> {
        Receiver {
            source,
            settlement: f.settlement,
            token: Address::repeat_byte(0x20),
            mapping_index: f.mapping_index,
            recipient: f.recipient,
            price: U256::from(price),
            resource: "GET /v1/quote".to_string(),
            anchor_ref: "solana:LightClientStatePDA".to_string(),
        }
    }

    fn proof_from(f: &PaymentFixture, slot: u64) -> PaymentProof {
        PaymentProof {
            slot,
            account: f.account.clone(),
            account_proof: f.account_proof.clone(),
            credited_amount: f.amount,
            storage_proof: f.storage_proof.clone(),
        }
    }

    #[test]
    fn challenge_serializes_to_402_body() {
        let f = payment_fixture(U256::from(1_000u64));
        let anchor = FixedAnchor { slot: SLOT, state_root: f.state_root };
        let rx = receiver_for(anchor, &f, 1_000);
        let body = serde_json::to_value(rx.challenge()).unwrap();
        assert_eq!(body["scheme"], SCHEME);
        assert_eq!(body["price"], "0x3e8"); // 1000
        assert_eq!(body["resource"], "GET /v1/quote");
    }

    #[test]
    fn admits_valid_payment_over_fixed_anchor() {
        let f = payment_fixture(U256::from(1_000u64));
        let anchor = FixedAnchor { slot: SLOT, state_root: f.state_root };
        let rx = receiver_for(anchor, &f, 1_000);
        let outcome = rx.admit(&proof_from(&f, SLOT));
        assert!(outcome.is_paid(), "got {outcome:?}");
        assert_eq!(outcome.http_status(), 200);
    }

    #[test]
    fn proof_round_trips_through_json_header() {
        // The client serializes the proof into X-PAYMENT; the receiver parses it.
        let f = payment_fixture(U256::from(1_000u64));
        let wire = serde_json::to_string(&proof_from(&f, SLOT)).unwrap();
        let parsed: PaymentProof = serde_json::from_str(&wire).unwrap();
        let anchor = FixedAnchor { slot: SLOT, state_root: f.state_root };
        let rx = receiver_for(anchor, &f, 1_000);
        assert!(rx.admit(&parsed).is_paid());
    }

    #[test]
    fn rejects_proof_for_unanchored_slot() {
        let f = payment_fixture(U256::from(1_000u64));
        let anchor = FixedAnchor { slot: SLOT, state_root: f.state_root };
        let rx = receiver_for(anchor, &f, 1_000);
        // Proof built against a slot the anchor doesn't authenticate.
        let outcome = rx.admit(&proof_from(&f, SLOT + 1));
        assert_eq!(outcome, Outcome::Unanchored { slot: SLOT + 1 });
        assert_eq!(outcome.http_status(), 402);
    }

    #[test]
    fn rejects_underpayment() {
        let f = payment_fixture(U256::from(1_000u64));
        let anchor = FixedAnchor { slot: SLOT, state_root: f.state_root };
        let rx = receiver_for(anchor, &f, 2_000); // price above credited
        match rx.admit(&proof_from(&f, SLOT)) {
            Outcome::Invalid(VerifyError::Underpaid { .. }) => {}
            other => panic!("expected Underpaid, got {other:?}"),
        }
    }

    #[test]
    fn light_client_pda_decode_round_trips() {
        // Hand-build a PDA account buffer and confirm decode matches.
        let state_root = B256::repeat_byte(0x7a);
        let vsh = B256::repeat_byte(0x5e);
        let mut data = vec![0u8; 8]; // discriminator
        data.extend_from_slice(&7u64.to_le_bytes()); // latest_slot
        data.extend_from_slice(state_root.as_slice());
        data.extend_from_slice(vsh.as_slice());
        data.extend_from_slice(&1_700_000_000i64.to_le_bytes()); // ts
        data.push(0xfd); // bump
        let decoded = decode_light_client_state(&data).unwrap();
        assert_eq!(
            decoded,
            LightClientState {
                latest_slot: 7,
                state_root,
                validator_set_hash: vsh,
                last_update_unix_ts: 1_700_000_000,
                bump: 0xfd,
            }
        );
    }

    #[test]
    fn admits_valid_payment_over_light_client_anchor() {
        // End-to-end at the T1 shape: state_root arrives via a decoded PDA, not
        // a hardcoded value. Build a PDA buffer embedding the fixture's root at
        // slot 7, then admit a proof targeting slot 7.
        let f = payment_fixture(U256::from(5_000u64));
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&7u64.to_le_bytes());
        data.extend_from_slice(f.state_root.as_slice());
        data.extend_from_slice(B256::ZERO.as_slice()); // validator_set_hash (unused here)
        data.extend_from_slice(&0i64.to_le_bytes());
        data.push(0);
        let anchor = LightClientAnchor::from_account_data(&data).unwrap();
        let rx = receiver_for(anchor, &f, 5_000);
        assert!(rx.admit(&proof_from(&f, 7)).is_paid());
        // A proof for the wrong slot is unanchored.
        assert_eq!(rx.admit(&proof_from(&f, 8)), Outcome::Unanchored { slot: 8 });
    }
}
