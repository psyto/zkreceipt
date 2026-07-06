//! Ground-truth test against real Tempo Moderato testnet state.
//!
//! The fixture in `tests/fixtures/tempo_moderato_alphausd.json` is a real
//! `eth_getProof` response captured from `rpc.moderato.tempo.xyz` for the
//! AlphaUSD ERC-20 system contract (`0x20c0…0001`), slot 8 = `totalSupply`.
//! Its `state_root` was bound to a real block header (25308316): the account
//! proof's root node hashes to that block's `stateRoot`.
//!
//! This proves the verifier handles *production* Tempo trie structure —
//! multi-node account and storage proofs with real branch/extension nodes and
//! Tempo's actual account RLP encoding — not just self-built toy tries. It is
//! also the concrete confirmation that Tempo (Reth-based) uses Ethereum's
//! account RLP + keccak MPT, which the on-chain-agnostic design assumed.
//!
//! Offline and deterministic: no network access at test time.

use alloy_primitives::{hex, Address, Bytes, B256, U256};
use serde_json::Value;
use zktempo_mpt_verify::{verify_account, verify_storage_slot, TrieAccount};

fn load() -> Value {
    let raw = include_str!("fixtures/tempo_moderato_alphausd.json");
    serde_json::from_str(raw).expect("fixture parses")
}

fn b256(s: &str) -> B256 {
    B256::from_slice(&hex::decode(s).unwrap())
}
fn proof(v: &Value) -> Vec<Bytes> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|n| Bytes::from(hex::decode(n.as_str().unwrap()).unwrap()))
        .collect()
}
fn u256(s: &str) -> U256 {
    U256::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

fn account(f: &Value) -> TrieAccount {
    let a = &f["account"];
    TrieAccount {
        nonce: u64::from_str_radix(a["nonce"].as_str().unwrap().trim_start_matches("0x"), 16)
            .unwrap(),
        balance: u256(a["balance"].as_str().unwrap()),
        storage_root: b256(a["storageHash"].as_str().unwrap()),
        code_hash: b256(a["codeHash"].as_str().unwrap()),
    }
}

#[test]
fn verifies_real_tempo_account_proof() {
    let f = load();
    let state_root = b256(f["state_root"].as_str().unwrap());
    let contract = Address::from_slice(&hex::decode(f["contract"].as_str().unwrap()).unwrap());
    verify_account(
        state_root,
        contract,
        &account(&f),
        &proof(&f["account_proof"]),
    )
    .expect("real Tempo account proof must verify against the block's stateRoot");
}

#[test]
fn verifies_real_tempo_storage_proof() {
    let f = load();
    let acct = account(&f);
    let slot = b256(f["slot"].as_str().unwrap());
    let value = u256(f["storage_value"].as_str().unwrap());
    verify_storage_slot(
        acct.storage_root,
        slot,
        Some(value),
        &proof(&f["storage_proof"]),
    )
    .expect("real Tempo storage proof (totalSupply) must verify against storage_root");
}

#[test]
fn rejects_real_storage_proof_with_wrong_value() {
    // Same real proof, but claim a different totalSupply → must fail to bind.
    let f = load();
    let acct = account(&f);
    let slot = b256(f["slot"].as_str().unwrap());
    let wrong = u256(f["storage_value"].as_str().unwrap()) + U256::from(1u64);
    let res = verify_storage_slot(
        acct.storage_root,
        slot,
        Some(wrong),
        &proof(&f["storage_proof"]),
    );
    assert!(res.is_err(), "a wrong claimed value must not verify");
}
