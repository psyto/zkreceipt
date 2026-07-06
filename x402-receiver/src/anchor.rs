//! Where the authenticated `state_root` comes from — the trust ladder.
//!
//! An x402 receiver never trusts a facilitator's "you were paid". It verifies a
//! payment proof against a `state_root` it considers *authenticated*. This
//! module abstracts that anchor so the same receiver logic runs at every rung:
//!
//!   - **T0 (demo):** [`FixedAnchor`] — a state_root trusted out of band.
//!   - **T1/T2:** [`LightClientAnchor`] — a state_root read from the on-chain
//!     zktempo `LightClientState` PDA (single-proposer today; BFT quorum +
//!     Groth16 once Tempo §3.3 / SP1 vkey land). Swapping the rung changes
//!     nothing in the receiver.

use alloy_primitives::B256;

/// Rust mirror of the on-chain `zktempo-verifier` `LightClientState` account.
///
/// Anchor layout (little-endian, after the 8-byte account discriminator):
/// `latest_slot: u64 | state_root: [u8;32] | validator_set_hash: [u8;32] |
/// last_update_unix_ts: i64 | bump: u8` — 81 bytes of body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientState {
    pub latest_slot: u64,
    pub state_root: B256,
    pub validator_set_hash: B256,
    pub last_update_unix_ts: i64,
    pub bump: u8,
}

/// Body length (excludes the 8-byte Anchor discriminator).
const BODY_LEN: usize = 8 + 32 + 32 + 8 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Account data is shorter than the discriminator + body.
    TooShort { got: usize },
}

/// Decode the raw Solana account data (as returned by `getAccountInfo`) of the
/// zktempo `LightClientState` PDA. The caller does the RPC fetch; this is the
/// pure, testable decode that mirrors the on-chain layout.
pub fn decode_light_client_state(data: &[u8]) -> Result<LightClientState, DecodeError> {
    if data.len() < 8 + BODY_LEN {
        return Err(DecodeError::TooShort { got: data.len() });
    }
    let b = &data[8..]; // skip discriminator
    let latest_slot = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let state_root = B256::from_slice(&b[8..40]);
    let validator_set_hash = B256::from_slice(&b[40..72]);
    let last_update_unix_ts = i64::from_le_bytes(b[72..80].try_into().unwrap());
    let bump = b[80];
    Ok(LightClientState {
        latest_slot,
        state_root,
        validator_set_hash,
        last_update_unix_ts,
        bump,
    })
}

/// Source of an authenticated `state_root` for a given finalized Tempo slot.
pub trait StateRootSource {
    /// The authenticated `state_root` for `slot`, or `None` if that slot is not
    /// (yet) finalized/authenticated by this anchor.
    fn authenticated_state_root(&self, slot: u64) -> Option<B256>;
}

/// T0 anchor: a single out-of-band-trusted `(slot, state_root)`. For demos and
/// tests before the on-chain verifier's crypto path is live.
#[derive(Debug, Clone)]
pub struct FixedAnchor {
    pub slot: u64,
    pub state_root: B256,
}

impl StateRootSource for FixedAnchor {
    fn authenticated_state_root(&self, slot: u64) -> Option<B256> {
        (slot == self.slot).then_some(self.state_root)
    }
}

/// T1/T2 anchor: backed by a decoded zktempo PDA. The PDA holds exactly one
/// finalized `(latest_slot, state_root)`; a proof is honored only if it targets
/// that slot.
#[derive(Debug, Clone)]
pub struct LightClientAnchor {
    pub state: LightClientState,
}

impl LightClientAnchor {
    /// Build from raw PDA account bytes fetched via Solana RPC.
    pub fn from_account_data(data: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            state: decode_light_client_state(data)?,
        })
    }
}

impl StateRootSource for LightClientAnchor {
    fn authenticated_state_root(&self, slot: u64) -> Option<B256> {
        (slot == self.state.latest_slot).then_some(self.state.state_root)
    }
}
