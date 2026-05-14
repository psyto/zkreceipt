# Tempo Chainspec — Moderato Testnet Reverse-Engineered

> **Status: v0.1 draft, 2026-05-15.** Compiled from probes against the
> public Moderato RPC. Cross-referenced with Tempo's public docs where
> available. No insider information. Independent confirmation by the
> Tempo team is welcome and explicitly requested in the "Open questions"
> section.

## 1. Methodology

All findings derived from public RPC probes against
`https://rpc.moderato.tempo.xyz`. Block range sampled: tip and tip −
100,000 (≈15 hours of history). Probes used Foundry's `cast` plus
hand-crafted `curl` JSON-RPC where `cast` lacks coverage. No transactions
sent — read-only inspection only.

This document is intentionally written from observable behavior. Where a
finding contradicts public Tempo documentation, the doc lists both and
flags the contradiction; we trust observation over docs for everything
verifiable.

## 2. Chain identity

| | Mainnet | Testnet (Moderato) |
| --- | --- | --- |
| RPC | https://rpc.tempo.xyz | https://rpc.moderato.tempo.xyz |
| Chain ID | 4217 | 42431 |
| Client banner | (not probed) | `tempo/v1.7.0-511a7d6/x86_64-unknown-linux-gnu` |
| Block explorer | https://explore.tempo.xyz | https://explore.testnet.tempo.xyz |

The client banner names "tempo" explicitly — Moderato runs Tempo's
production binary, not stock reth.

## 3. Consensus

| Property | Value | Source |
| --- | --- | --- |
| Engine | Simplex BFT (via Commonware) | Public docs |
| Block time | ~555 ms (range 535–613 ms over 10 sampled blocks) | Measured |
| Finality | Deterministic, ≈1 block (no reorgs by construction) | Public docs + measured |
| Epoch length | 21,636 views in epoch 812 (~3.3 hours at 555ms/block) | Measured at boundary 17,560,799→17,560,800 |
| View numbering | Monotonic within epoch, resets to 1 at epoch boundary | Measured |
| Validator-set rotation | Per-epoch (every ~3.3 hours on Moderato) | Inferred from epoch boundary |
| Validator signature scheme | **Ed25519 (32-byte proposer keys)** | Inferred from key length |

### 3.1 `consensusContext` block-header field (Tempo extension)

Every block header carries a non-standard `consensusContext` object:

```json
"consensusContext": {
  "epoch": 813,
  "view": 5669,
  "parentView": 5668,
  "proposer": "0xb332384fc300d539d57b81ba9ce058b65d9e543e65bd5f7a5b80292874b34f5d"
}
```

- `view` advances by 1 per block within an epoch.
- `parentView` always equals `view - 1` within an epoch.
- At an epoch transition, the new epoch's first block has `view = 1`
  and `parentView = 0`.
- `proposer` is 32 bytes — too short for BLS12-381 (48-byte G1 / 96-byte
  G2 compressed), exactly Ed25519 public key length. This is the
  load-bearing signature-scheme signal.

### 3.2 Validator set (Moderato, observed 2026-05-15)

200 consecutive blocks yielded **18 distinct proposers** with roughly
uniform distribution (5–15 proposals per validator, mean ≈11). Public
Tempo docs claim 4 validators on testnet — this is **stale**; the actual
Moderato validator set is 18.

Round-robin or weighted-round-robin election is plausible from the
distribution shape but not confirmed.

### 3.3 Where the finality certificate lives — open question

The standard Ethereum `extraData` header field is **empty** (`0x`) on
every block sampled — Tempo does NOT use `extraData` to carry signatures.
The `consensusContext` exposes the proposer but does **not** include
aggregate quorum signatures. Where these signatures actually live (a
non-RPC-exposed header field? a separate tx? embedded in
`parentBeaconBlockRoot` which is also zero?) is the **central unblocked
question for zkTempo's light-client implementation**.

## 4. Transactions

### 4.1 Tx types observed

| Type | Count visibility | Standard? |
| --- | --- | --- |
| `0x0` | Common | Legacy EVM |
| `0x2` | Common | EIP-1559 |
| `0x76` (118) | Common | **Tempo-custom envelope** |

### 4.2 The `0x76` envelope

The 0x76 envelope is Tempo's native transaction type — extends EIP-1559
with account-abstraction, fee-token, batch-call, and time-bounded
validity. Observed fields:

| Field | Purpose |
| --- | --- |
| `aaAuthorizationList` | Account-abstraction authorizations (EIP-7702-style) |
| `calls` | **Array of (to, value, input) calls** — multi-call native in one tx |
| `feePayer` | Separate account paying gas (sponsored / gasless transactions) |
| `feePayerSignature` | Independent signature for the fee payer |
| `feeToken` | TIP-20 token used for fee payment (any supported stablecoin) |
| `keyAuthorization` | Key delegation / authorization hook |
| `nonceKey` (u256) + `nonce` | **2D nonce** enabling parallel-stream tx ordering |
| `validAfter` / `validBefore` | Time-bounded validity (anti-replay window) |
| `signature.type` | `"secp256k1"` (standard Ethereum sender signing) |

Sample observed tx had `feeToken: 0x20c0...0001` (AlphaUSD), with the
`calls` array containing a single call to AlphaUSD invoking the
`mint(address, uint256)` selector — a testnet faucet operation, paying
its own fee in the same token it mints.

**Validator-vs-sender signing schemes differ:** validators sign blocks
with **Ed25519** (per §3.1); senders sign transactions with **secp256k1**.

## 5. Native value semantics

`BALANCE`, `SELFBALANCE`, `CALLVALUE` opcodes return 0 (per public docs;
not directly probed because no probe contract deployed). Confirmed
indirectly: all `0x76` and `0x2` txs sampled have `value` field of `0x0`
or `null`. Money moves exclusively via TIP-20 stablecoin transfers
(emitting standard ERC20 `Transfer` events).

## 6. Stablecoin precompiles

Native stablecoins live at the `0x20c0...000N` precompile range. Mapped
on Moderato:

| Address | Symbol | Decimals |
| --- | --- | --- |
| `0x20c0000000000000000000000000000000000000` | PathUSD | 6 |
| `0x20c0000000000000000000000000000000000001` | AlphaUSD | 6 |
| `0x20c0000000000000000000000000000000000002` | BetaUSD | 6 |
| `0x20c0000000000000000000000000000000000003` | ThetaUSD | 6 |
| `0x20c0...0004` through `...000f` | (empty) | — |

These are **stateful precompiles** — `cast code` returns `0x` (no EVM
bytecode), yet they answer ERC20 calls (`symbol`, `name`, `decimals`,
`balanceOf`, `transfer`, `mint`) and emit standard `Transfer` events
when touched. Behavior is provided by the Tempo execution client itself,
not by deployed bytecode.

PathUSD is documented as Tempo's primary native USD / FeeAMM base
asset; AlphaUSD/BetaUSD/ThetaUSD appear to be additional testnet-only
denominations.

## 7. Fee market

- 1559 fee market is active (`baseFeePerGas` field populated on every
  block).
- Base fee floored at `0x4a817c800` (20 gwei equivalent) in 5 sampled
  blocks; gas-used ratios consistently <2%, so the market is below
  congestion threshold and base fee isn't moving.
- Priority-fee rewards almost always 0 — confirms low contention.
- Fees denominated in stablecoin per the `0x76` envelope's `feeToken`,
  not in ETH. The FeeAMM (per public docs) converts user-preferred
  fee tokens to validator-preferred receive tokens — not directly
  probed.

## 8. Gas schedule deviations from Ethereum

Per Tempo public docs (not directly probed — would require deploying a
contract):

| Op | Tempo | Ethereum |
| --- | --- | --- |
| `SSTORE` new slot | 250,000 | 20,000 |
| Account creation | 250,000 | 0 |
| Contract creation, per byte | 1,000 | 200 |

These higher costs are a state-growth deterrent — Tempo expects payment
flows, not generic state.

## 9. Block header — full custom-field inventory

Standard Ethereum fields present and conventional: `parentHash`,
`sha3Uncles`, `miner` (20-byte address), `stateRoot`, `transactionsRoot`,
`receiptsRoot`, `logsBloom`, `gasLimit`, `gasUsed`, `timestamp`,
`baseFeePerGas`, `withdrawalsRoot`, `blobGasUsed: 0x0`, `excessBlobGas:
0x0`, `requestsHash` (EIP-7685 present).

PoW-related fields are zeroed: `difficulty: 0x0`, `nonce: 0x0`,
`mixHash: 0x0..0`.

Tempo-specific non-standard fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `consensusContext` | object | Simplex BFT consensus metadata (§3.1) |
| `mainBlockGeneralGasLimit` | hex u64 | Distinct from `gasLimit`; purpose unclear (possibly the limit excluding consensus overhead) |
| `sharedGasLimit` | hex u64 | Zero in all samples — purpose TBD |
| `timestampMillis` | hex u64 | Block time at millisecond precision (vs `timestamp` at second precision) |
| `timestampMillisPart` | hex u8/u16 | Sub-second component? Need confirmation |
| `parentBeaconBlockRoot` | bytes32 | Always zero — Tempo doesn't integrate with Ethereum beacon chain |

## 10. RPC namespace surface

Standard `eth_*` and `web3_*` work. The following namespaces are **not
exposed** on Moderato (return `-32601 method not found`):

- `rpc_modules` (introspection blocked)
- `tempo_*`, `mpp_*`, `payments_*`, `consensus_*`
- `admin_peers`, `admin_nodeInfo`

`debug_*` methods exist but require parameters (`-32602` not `-32601`);
not deeply probed in this draft.

## 11. Implications for zkTempo light client

The findings here directly inform `zktempo-light-client`:

1. **Validator signature scheme is Ed25519** (32-byte proposer pubkeys).
   `zktempo-light-client` should depend on `ed25519-dalek` (or a `no_std`
   equivalent like `ed25519-zebra`), not on a BLS crate.
2. **Per-epoch validator rotation, ~3.3-hour cadence.** The light
   client's `Update` must carry validator-set rotation payloads at every
   epoch boundary; intra-epoch updates do not rotate the set.
3. **View resets at epoch boundary.** Replay protection in the light
   client must key off `(epoch, view)` not view alone.
4. **`consensusContext` in the block header.** Once we know where
   quorum signatures live (open question §3.3), the proposer, view,
   epoch, and parentView fields are already accessible via standard
   `eth_getBlockByNumber`.
5. **Finality cert location is unknown.** Until §3.3 is answered, the
   light-client implementation can pin types and structure but cannot
   verify a real certificate.

## 12. Open questions (Tempo dev outreach)

These are the questions that, if answered, unblock the light-client
implementation. Listed in priority order.

1. **Where are aggregate validator quorum signatures stored?** Not in
   `extraData` (empty), not in `consensusContext` (only single proposer).
   Are they in a non-RPC-exposed header field, a separate "consensus
   envelope" tx type, or only accessible via a Tempo-internal RPC?
2. **Confirm Ed25519 signature scheme** for validators. The 32-byte
   proposer pubkey is strong evidence; explicit confirmation closes the
   risk.
3. **Validator-set rotation mechanism.** Is the set re-elected at every
   epoch, or rotated by a separate on-chain governance action? If
   re-elected, is the election deterministic from prior-epoch state, or
   external?
4. **`mainBlockGeneralGasLimit`** vs `gasLimit` vs `sharedGasLimit`
   semantics.
5. **`debug_*` RPC method signatures** — are there debug methods useful
   for light-client bootstrap (e.g., fetching a finality certificate by
   block number)?
6. **Is the Simplex implementation in Commonware bit-stable across
   minor releases?** Affects light-client upgrade path.

## 13. Probe commands (reproducibility)

For future independent verification, the cast commands used:

```bash
export RPC=https://rpc.moderato.tempo.xyz

# Chain identity
cast chain-id --rpc-url $RPC
cast block-number --rpc-url $RPC
curl -s -X POST $RPC -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}'

# Block + consensus context
cast block latest --rpc-url $RPC --json | jq '.consensusContext'

# Validator distribution over N blocks (set N=200 for our sample)
for i in $(seq 0 199); do
  cast block $(($(cast block-number --rpc-url $RPC) - i)) \
    --rpc-url $RPC --json | jq -r '.consensusContext.proposer'
done | sort | uniq -c | sort -rn

# Stablecoin precompiles
for i in 0 1 2 3 4 5 6 7 8 9; do
  ADDR=$(printf '0x20c000000000000000000000000000000000000%s' $i)
  echo "$ADDR $(cast call $ADDR 'symbol()(string)' --rpc-url $RPC 2>/dev/null)"
done

# 0x76 envelope (find one and inspect)
cast tx $(cast block latest --rpc-url $RPC --json | jq -r '.transactions[0]') \
  --rpc-url $RPC --json
```
