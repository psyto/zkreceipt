# Composition: mppsol_cpi integration

This document specifies how [mppsol_cpi] consumes zkReceipt finality proofs
to authorize Solana-side settlement of payments originated on Tempo. It is
addressed to authors of downstream consumer programs — merchant treasuries,
intent settlers, agent commerce rails — that need to verify a Tempo payment
occurred before releasing value on Solana.

[mppsol_cpi]: https://github.com/mppsol/cpi

## Trust model change

mppsol_cpi v0.1's `verify_paid_result` accepts an **Ed25519 signature** from a
designated server key as evidence that a payment occurred off-chain. The trust
assumption is: the server holding the key has correctly observed the payment.

zkReceipt introduces a parallel verification path that replaces this with
two cryptographic proofs:

1. **Finality** — a specific Tempo block was finalized by Simplex BFT
   consensus. Proved by Groth16 verification at the zkReceipt verifier PDA.
2. **Inclusion** — a specific storage slot or log entry exists in that block's
   state root. Proved by Merkle Patricia inclusion proof, verified inside
   mppsol_cpi.

No external attestation, no permissioned signer. Tempo's validator set is the
only off-Solana trust anchor.

## Data layout

Boundary types crossing into mppsol_cpi:

```rust
/// A finalized state root recorded by zkReceipt.
/// Read from the zkReceipt verifier PDA; not passed by the caller.
pub struct FinalizedRoot {
    pub slot: u64,
    pub state_root: [u8; 32],
}

/// Inclusion proof against `state_root`.
pub struct InclusionProof {
    pub mpt_proof: Vec<Vec<u8>>,
    pub key: Vec<u8>,            // storage key or receipt-trie path
    pub value: Vec<u8>,          // RLP-encoded value
}

/// Decoded Tempo payment intent + its inclusion proof.
pub struct TempoPaymentReceipt {
    pub root: FinalizedRoot,     // referenced, not embedded — PDA is authoritative
    pub inclusion: InclusionProof,
    pub emitter: [u8; 20],       // MPP precompile or emitting contract
    pub intent: PaymentIntent,   // ABI-decoded; canonical form in light-client.md §4
}
```

## Patterns

### Pattern 1 — Direct verification, atomic settlement

A consumer program calls mppsol_cpi inline, verifies, and proceeds with
settlement in the same transaction. No persistent receipt.

```rust
use mppsol_cpi::cpi::{verify_paid_result_zkreceipt, accounts::*};

let receipt: TempoPaymentReceipt = /* constructed off-chain */;
let cpi_ctx = CpiContext::new(
    mppsol_cpi_program.to_account_info(),
    VerifyPaidResultZkReceipt {
        zkreceipt_verifier: zkreceipt_verifier_pda.to_account_info(),
        // ...
    },
);
verify_paid_result_zkreceipt(cpi_ctx, receipt, expected_amount, expected_recipient)?;
release_goods(ctx)?;
```

**Use when** settlement is one-shot and the proof won't be reused. Cheapest
path: no PDA writes, no replay protection (consumer's responsibility if needed).

### Pattern 2 — Persistent receipt for cross-transaction claims

When a single payment is consumed across multiple transactions — streaming
billing, multi-step fulfillment, batched delivery — persist a Receipt PDA so
the expensive verification runs only once.

```rust
verify_paid_result_zkreceipt_with_receipt(
    cpi_ctx,
    receipt,
    expected_amount,
    expected_recipient,
)?;
// PDA: seeds = [b"receipt", intent_hash], stores
// { intent_hash, payer, amount, slot, claimed_amount: 0 }
```

Subsequent transactions read the PDA, increment `claimed_amount`, enforce
`claimed_amount + delta <= amount`. Replay-safe by construction (PDA already
exists ⇒ already claimed up to its recorded amount).

**Use when** metered services, subscriptions, multi-step settlement.

### Pattern 3 — Session-mediated settlement

When the Solana-side relationship pre-exists as a `mppsol_session`, settle the
session by proving a corresponding Tempo payment. The session program records
the linkage and emits a settlement event.

```rust
mppsol_session::cpi::settle_via_zkreceipt(cpi_ctx, session_id, receipt)?;
// Updates session: settled_amount += receipt.intent.amount
// Emits SessionSettled { session_id, tempo_intent_hash, slot }
```

**Use when** long-running merchant relationships, agent service sessions,
recurring billing — the Solana session is the canonical account and Tempo is
the payment rail.

### Pattern 4 — Hybrid attestation (Ed25519 OR zkReceipt)

During the Ed25519 → ZK migration window, consumers may want to accept either
form per-payment:

```rust
pub enum PaymentAuthorization {
    Ed25519 { signature: [u8; 64], signer: Pubkey, payload: Vec<u8> },
    ZkReceipt { receipt: TempoPaymentReceipt },
}
```

Route by enum: small/fast payments accept Ed25519, large/trustless payments
require zkReceipt. mppsol_cpi will not deprecate Ed25519 in v0.1 — both
variants are stable.

**Use when** migrating existing flows, or accepting a permanent trust trade-off
below a payment threshold.

## Cross-program invocation flow

End-to-end sequence for Pattern 1:

```
Off-chain (relayer or end user)
  │
  ├─ 1. Observe Tempo block N finalized (poll explore.tempo.xyz or RPC)
  ├─ 2. Fetch (slot, state_root) for N from zkReceipt verifier PDA
  ├─ 3. Fetch MPT inclusion proof from a Tempo full node (eth_getProof)
  ├─ 4. Construct TempoPaymentReceipt
  ▼

Solana (single transaction)
  consumer_program::settle(...)
    │
    ├─ CPI ─► mppsol_cpi::verify_paid_result_zkreceipt(
    │           receipt, expected_amount, expected_recipient
    │         )
    │           │
    │           ├─ Read zkreceipt_verifier_pda → confirms (slot, state_root) finalized
    │           ├─ Verify receipt.inclusion.mpt_proof against state_root
    │           ├─ Decode receipt.inclusion.value → PaymentIntent
    │           ├─ Assert intent.amount == expected_amount
    │           ├─ Assert intent.recipient == expected_recipient
    │           └─ Return Ok via Solana return data
    │
    └─ Proceed with settlement (release goods, mint receipt token, ...)
```

Preliminary CU budget (pre-implementation):

| Operation | CU (est.) |
| --- | --- |
| Read zkReceipt verifier PDA | ~1,000 |
| MPT inclusion verification | 50,000–150,000 (depth-dependent) |
| ABI decode `PaymentIntent` | ~5,000 |
| **Total mppsol_cpi overhead** | **~60,000–160,000** |

Groth16 verification cost lives in the **zkReceipt verifier program**, not in
mppsol_cpi. It is amortized across all downstream consumers reading the
verifier PDA for the same finalized block.

## Migration from Ed25519

For consumers currently using `mppsol_cpi::verify_paid_result`:

1. Continue calling the Ed25519 variant unchanged for existing flows.
2. For new flows, integrate `verify_paid_result_zkreceipt` (Pattern 1 or 2).
3. mppsol_cpi keeps both variants stable in v0.1; no forced cutover.

Side-by-side:

| | Ed25519 (v0.1 today) | zkReceipt (this spec) |
| --- | --- | --- |
| Authorization | Server signature | Validator-finalized state proof |
| Trust anchor | Server signer key | Tempo validator set + zkReceipt prover liveness |
| Latency to proof | Immediate | One Tempo finality + one prover update (~5–60s) |
| On-chain cost | Ed25519 syscall (~5K CU) | ~60–160K CU (MPT verify) |
| Replay protection | Caller-provided nonce | Receipt PDA (Pattern 2) or caller-provided |

## Open questions

Not yet pinned in this draft:

- **Storage proof vs receipt-trie proof.** Should `InclusionProof` support
  both? Logs are more idiomatic for EVM event emission; storage proofs are
  smaller. Leaning: support both, distinguish via a `ProofKind` tag.
- **`PaymentIntent` canonical encoding.** ABI-encoded matches Tempo's MPP wire
  format directly. Borsh would be more Solana-native but adds a re-encoding
  step. Leaning ABI.
- **Prover liveness as composition concern.** If no prover updates the
  verifier PDA, Pattern 1 fails closed (no recent finalized root). Should
  mppsol_cpi expose a "staleness" check against `Clock::unix_timestamp`?
- **Multi-emitter intents.** Tempo's MPP may emit from any contract address.
  Should mppsol_cpi accept an `emitter` allowlist parameter, or leave that
  policy to the consumer program? Leaning: consumer responsibility.

Comments welcome — open an issue at
[github.com/psyto/zkreceipt/issues](https://github.com/psyto/zkreceipt/issues).
