//! MPT inclusion verification for Tempo-originated payments.
//!
//! Tempo is Reth-based, so its `state_root` is an Ethereum-style two-level
//! Merkle-Patricia Trie: the state trie maps `keccak256(address)` to an account
//! RLP, and each account carries a `storage_root` for its own storage trie
//! mapping `keccak256(slot)` to an RLP value.
//!
//! This crate is the *receiver* half of an x402 flow. The receiver (a provider
//! selling API access) has, via the on-chain zktempo verifier, an
//! **authenticated `state_root`** for a finalized Tempo slot (the
//! `LightClientState` PDA). It does not trust any facilitator's claim that
//! "you were paid" — instead it verifies, against that `state_root`:
//!
//!   1. an **account proof** binding a settlement contract's account (and thus
//!      its `storage_root`) to the authenticated `state_root`, then
//!   2. a **storage proof** binding `paidTo[recipient] == amount` to that
//!      account's `storage_root`.
//!
//! If both proofs verify and `amount >= price`, the payment is real. The whole
//! check is local: `verify, don't trust`.
//!
//! # Trust ladder
//! This crate verifies inclusion *relative to a `state_root`*. Whether that
//! `state_root` is itself trustworthy is the job of the layer below:
//!   - **T0 (demo):** a permissioned updater populates the state_root.
//!   - **T1:** single Tempo proposer Ed25519 signature (works today in the
//!     `zktempo-light-client` crate).
//!   - **T2:** full BFT quorum + on-chain Groth16 (blocked on Tempo §3.3 / SP1
//!     vkey).
//! Swapping the anchor does not change any code here.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{Encodable, RlpEncodable};
use alloy_trie::{proof::verify_proof, Nibbles};

/// A payment the receiver has cryptographically confirmed landed on Tempo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub recipient: Address,
    pub amount: U256,
}

/// Ethereum/Tempo account body, RLP-encoded as `[nonce, balance, storage_root,
/// code_hash]`. The caller supplies the claimed account; the account proof is
/// what actually binds it (including `storage_root`) to the `state_root`.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable)]
pub struct TrieAccount {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
}

/// Reasons a payment proof can fail. Kept coarse on purpose — the receiver only
/// cares "is this payment real and sufficient", not which trie node was off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The account proof did not bind `settlement`'s account to `state_root`.
    AccountProof,
    /// The storage proof did not bind `paidTo[recipient] == amount` to the
    /// account's `storage_root`.
    StorageProof,
    /// Payment is real but smaller than the quoted price.
    Underpaid { credited: U256, price: U256 },
}

/// Storage slot of `mapping(address => uint256) paidTo` for a given key, using
/// Solidity's layout: `slot = keccak256(pad32(key) ++ pad32(mapping_index))`.
pub fn mapping_slot(key: Address, mapping_index: u64) -> B256 {
    let mut buf = [0u8; 64];
    // key: left-padded into the first 32-byte word.
    buf[12..32].copy_from_slice(key.as_slice());
    // mapping declaration index: right-aligned in the second word.
    buf[56..64].copy_from_slice(&mapping_index.to_be_bytes());
    keccak256(buf)
}

/// Verify that, in the Tempo state committed to by `state_root`, the settlement
/// contract credited `recipient` at least `price`, via `paidTo[recipient]`.
///
/// `account` is the claimed settlement account; `account_proof` must bind it to
/// `state_root`. `credited_amount` is the claimed stored value; `storage_proof`
/// must bind it to `account.storage_root`.
#[allow(clippy::too_many_arguments)]
pub fn verify_payment(
    state_root: B256,
    settlement: Address,
    account: &TrieAccount,
    account_proof: &[Bytes],
    mapping_index: u64,
    recipient: Address,
    credited_amount: U256,
    storage_proof: &[Bytes],
    price: U256,
) -> Result<VerifiedPayment, VerifyError> {
    // 1. Account proof: bind the settlement account (incl. its storage_root) to
    //    the authenticated state_root. Until this passes we trust nothing about
    //    the account — not even its storage_root.
    let account_key = Nibbles::unpack(keccak256(settlement.as_slice()));
    let account_rlp = alloy_rlp::encode(account);
    verify_proof(state_root, account_key, Some(account_rlp), account_proof)
        .map_err(|_| VerifyError::AccountProof)?;

    // 2. Storage proof: bind paidTo[recipient] == credited_amount to the
    //    now-trusted storage_root. Storage trie values are RLP(U256), which
    //    trims leading zeros.
    let slot = mapping_slot(recipient, mapping_index);
    let storage_key = Nibbles::unpack(keccak256(slot.as_slice()));
    let value_rlp = alloy_rlp::encode(credited_amount);
    verify_proof(
        account.storage_root,
        storage_key,
        Some(value_rlp),
        storage_proof,
    )
    .map_err(|_| VerifyError::StorageProof)?;

    // 3. Sufficiency: real payment, but is it enough for the quoted price?
    if credited_amount < price {
        return Err(VerifyError::Underpaid {
            credited: credited_amount,
            price,
        });
    }

    Ok(VerifiedPayment {
        recipient,
        amount: credited_amount,
    })
}

// Re-export so downstream (the x402-receiver middleware) can name the value
// encoding without depending on alloy-rlp directly.
#[doc(hidden)]
pub fn rlp_value(v: impl Encodable) -> Vec<u8> {
    alloy_rlp::encode(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::{proof::ProofRetainer, HashBuilder};

    /// Build a trie from `(hashed_key, rlp_value)` entries and return
    /// `(root, proof_for_target)` — a real trie root with branch nodes so the
    /// proof exercises actual traversal, not a single inlined leaf.
    fn build_trie(mut entries: Vec<(B256, Vec<u8>)>, target: B256) -> (B256, Vec<Bytes>) {
        // Leaves must be added in ascending nibble order.
        entries.sort_by(|a, b| Nibbles::unpack(a.0).cmp(&Nibbles::unpack(b.0)));
        let retainer = ProofRetainer::new(vec![Nibbles::unpack(target)]);
        let mut hb = HashBuilder::default().with_proof_retainer(retainer);
        for (kh, val) in &entries {
            hb.add_leaf(Nibbles::unpack(*kh), val.as_slice());
        }
        let root = hb.root();
        let proof: Vec<Bytes> = hb
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node)
            .collect();
        (root, proof)
    }

    /// Distinct hashed keys with spread-out leading nibbles so the trie branches.
    fn decoy(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    struct Fixture {
        state_root: B256,
        settlement: Address,
        account: TrieAccount,
        account_proof: Vec<Bytes>,
        recipient: Address,
        amount: U256,
        storage_proof: Vec<Bytes>,
        mapping_index: u64,
    }

    /// Construct a self-contained, network-free fixture: a settlement contract
    /// whose `paidTo[recipient] = amount`, embedded in a real two-level trie.
    fn fixture(amount: U256) -> Fixture {
        let settlement = Address::repeat_byte(0xa1);
        let recipient = Address::repeat_byte(0xb2);
        let mapping_index = 3u64;

        // --- storage trie: paidTo[recipient] = amount (+ decoys to branch) ---
        let slot = mapping_slot(recipient, mapping_index);
        let storage_key = keccak256(slot.as_slice());
        let (storage_root, storage_proof) = build_trie(
            vec![
                (storage_key, alloy_rlp::encode(amount)),
                (decoy(0x00), alloy_rlp::encode(U256::from(7u64))),
                (decoy(0xff), alloy_rlp::encode(U256::from(9u64))),
            ],
            storage_key,
        );

        // --- account/state trie: settlement account (+ decoys to branch) ---
        let account = TrieAccount {
            nonce: 1,
            balance: U256::ZERO,
            storage_root,
            code_hash: keccak256([0xde, 0xad]),
        };
        let account_key = keccak256(settlement.as_slice());
        let (state_root, account_proof) = build_trie(
            vec![
                (account_key, alloy_rlp::encode(&account)),
                (decoy(0x11), alloy_rlp::encode(U256::from(1u64))),
                (decoy(0xee), alloy_rlp::encode(U256::from(2u64))),
            ],
            account_key,
        );

        Fixture {
            state_root,
            settlement,
            account,
            account_proof,
            recipient,
            amount,
            storage_proof,
            mapping_index,
        }
    }

    #[test]
    fn verifies_a_real_payment() {
        let f = fixture(U256::from(1_000u64));
        let got = verify_payment(
            f.state_root,
            f.settlement,
            &f.account,
            &f.account_proof,
            f.mapping_index,
            f.recipient,
            f.amount,
            &f.storage_proof,
            U256::from(1_000u64),
        )
        .expect("payment should verify");
        assert_eq!(got.recipient, f.recipient);
        assert_eq!(got.amount, U256::from(1_000u64));
    }

    #[test]
    fn rejects_wrong_claimed_amount() {
        // Storage really holds 1000, but the receiver is fed a claim of 5000.
        // The storage proof no longer binds → StorageProof error.
        let f = fixture(U256::from(1_000u64));
        let err = verify_payment(
            f.state_root,
            f.settlement,
            &f.account,
            &f.account_proof,
            f.mapping_index,
            f.recipient,
            U256::from(5_000u64),
            &f.storage_proof,
            U256::from(1_000u64),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::StorageProof);
    }

    #[test]
    fn rejects_underpayment() {
        // Real payment of 1000, but the price is 2000.
        let f = fixture(U256::from(1_000u64));
        let err = verify_payment(
            f.state_root,
            f.settlement,
            &f.account,
            &f.account_proof,
            f.mapping_index,
            f.recipient,
            f.amount,
            &f.storage_proof,
            U256::from(2_000u64),
        )
        .unwrap_err();
        assert_eq!(
            err,
            VerifyError::Underpaid {
                credited: U256::from(1_000u64),
                price: U256::from(2_000u64),
            }
        );
    }

    #[test]
    fn rejects_wrong_state_root() {
        // A state_root the account proof was not built against.
        let f = fixture(U256::from(1_000u64));
        let err = verify_payment(
            B256::repeat_byte(0x42),
            f.settlement,
            &f.account,
            &f.account_proof,
            f.mapping_index,
            f.recipient,
            f.amount,
            &f.storage_proof,
            U256::from(1_000u64),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::AccountProof);
    }

    #[test]
    fn rejects_tampered_account_proof() {
        let mut f = fixture(U256::from(1_000u64));
        // Corrupt the first (root) node of the account proof.
        if let Some(first) = f.account_proof.first_mut() {
            let mut bytes = first.to_vec();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            *first = Bytes::from(bytes);
        }
        let err = verify_payment(
            f.state_root,
            f.settlement,
            &f.account,
            &f.account_proof,
            f.mapping_index,
            f.recipient,
            f.amount,
            &f.storage_proof,
            U256::from(1_000u64),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::AccountProof);
    }

    #[test]
    fn rejects_wrong_recipient() {
        // Prove against a recipient who was never credited: the storage slot is
        // different, so the supplied storage proof (for the real recipient)
        // does not bind → StorageProof error.
        let f = fixture(U256::from(1_000u64));
        let err = verify_payment(
            f.state_root,
            f.settlement,
            &f.account,
            &f.account_proof,
            f.mapping_index,
            Address::repeat_byte(0xc3),
            f.amount,
            &f.storage_proof,
            U256::from(1_000u64),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::StorageProof);
    }
}
