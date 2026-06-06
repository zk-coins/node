# Plonky2 → Plonky3 Wire & Storage Format Migration

**Doc 2 of the Plonky3 migration documentation set.** This document is authoritative on the
**on-disk and on-the-wire byte formats** affected by switching the zkCoins node's proving
backend from Plonky2 (Goldilocks) to Plonky3. It answers one question precisely: *when the
proof system — and possibly the underlying field — changes, which stored/transmitted bytes
change, which stay byte-identical, and what coordination (DB reset, SDK bump) each delta
forces.*

**Companion docs (referenced, not duplicated):**

- **Doc 1 — `PLONKY3_CUTOVER_PLAYBOOK.md`** — the production runbook. It *references this
  doc's conclusions* for the format/field consequences; §3–§4 there give the operational
  procedure (drain, snapshot, genesis reset, rollback). This doc gives the byte-level *why*.
- **Doc 3 — Crypto-audit spec for the carrier-table chain.**
- **Doc 4 — `PLONKY3_UPSTREAM_MAINTENANCE.md`** — pinned revs / fork policy.
- **`MIGRATION_PLONKY3_SPIKE_RESULT.md`** — the Phase-0 feasibility gate and the field
  recommendation (stay Goldilocks for Phases 1–8; defer BabyBear/KoalaBear to Phase 9).
- **`MIGRATION_RESEARCH.md`** §5.3 / §5.4 — hash-function and Schnorr-boundary decisions.
- **`SPEC.md`** §2.1, §13, §D3 — protocol hash, server-side compute, on-chain commitment.

---

## 0. The single load-bearing fact

> **The proof bytes are never posted on-chain, and the on-chain `4242` inscription encodes
> nothing proof-system-specific.** It carries a BIP-340 Schnorr *signature* over a 32-byte
> SHA-256 digest of two protocol hashes. Therefore the proving backend (Plonky2 → Plonky3)
> can change with **zero on-chain wire-format change** — *as long as the 32-byte
> serialisation of the `asth`/`ocr` Poseidon digests is preserved*.

The whole migration's format-safety reduces to that proviso. Keeping **Goldilocks** preserves
the 32-byte serialisation verbatim → the on-chain format and the SDK/Schnorr boundary are
**untouched**. Moving to **BabyBear** changes the field-element byte packing → it ripples into
the Schnorr message and **forces a coordinated `zk-coins/sdk` bump**. The rest of this document
proves both halves of that claim from the code.

---

## 1. What's stored where — concrete inventory

All persistence is Postgres (`node/migrations/0001`–`0016`) plus one on-disk file store. Binary
blobs are `BYTEA`; structured blobs are `bincode`-serialised Rust types.

### 1.1 Proof blobs

| Artifact | Location | Serialisation | Proof-system-specific? |
|---|---|---|---|
| Per-account recursive proof | `accounts.data` `BYTEA` (the bincode of `Account`, whose field `proof: Option<Proof>` — `node/src/account_node.rs:51`) | `bincode` of `Account` ⊃ `Proof` | **YES** |
| Queued / distributed send proofs | `accounts.data` → `Account.coin_queue: Vec<CoinProof>`; and the on-disk file store | `bincode` of `CoinProof` (`node/src/account_node.rs:42`) | **YES** |
| Per-send `CoinProof` files | `PROOFS_DIR/<id>.bin` (`ProofStore`, `node/src/router.rs:552`, `add_proof`/`get_proof` use `bincode::serialize`/`deserialize`) | `bincode` of `CoinProof` | **YES** |
| Circuit digest (control) | `circuit_digest_meta.digest` `BYTEA` (migration `0015`) | `bincode` of `HashOut<GoldilocksField>` (4 field elements) | **YES** |
| `coin_proof_store` table | migration `0008` | groundwork only — **no production INSERT** (see `db.rs:reset_proof_dependent_state_tx` doc-comment) | N/A (empty) |

The proof type itself is the workspace alias:

```
// script-plonky2/src/lib.rs:51
pub type Proof = ProofWithPublicInputs<F, C, D>;   // F = GoldilocksField, C = PoseidonGoldilocksConfig
```

`ProofWithPublicInputs<F, C, D>` serialises its FRI openings, Merkle caps and public inputs **as
field elements of `F`**. Changing `F` (Goldilocks → BabyBear) changes this type's entire
serialised shape. But this blob is **closed-environment only** — it lives in Postgres and on
local disk, is never transmitted to the wallet for verification (the node is the sole verifier,
`SPEC.md` §13 server-side compute), and is **never** placed on-chain.

### 1.2 Account / SMT / MMR state (the hash-rooted state)

| Table | Column | Stores | Encoding |
|---|---|---|---|
| `accounts` | `address` `BYTEA PRIMARY KEY` | 32-byte account address (a Poseidon `HashDigest`) | `digest_to_bytes` (see §2) |
| `accounts` | `data` `BYTEA` | bincode of `Account` (balance, proof, coin_history `SparseMerkleTree`, …) | bincode |
| `smt_state` | `data` `BYTEA` (singleton `id=1`) | global commitment Sparse Merkle Tree | bincode of `SparseMerkleTree` |
| `mmr_state` | `data` `BYTEA` (singleton `id=1`) | global Merkle Mountain Range of SMT roots | bincode of MMR |
| `mmr_root_index` | `prev_mmr_root` `BYTEA PK`, `smt_root` `BYTEA`, `leaf_index` `BIGINT` (migration `0004`) | `prev_mmr_root → (smt_root, leaf_index)` map for building inclusion proofs | each root via `digest_to_bytes` (`db.rs:646–647`, `750–751`, `1430–1431`) |
| `latest_block` | `block_hash` `BYTEA` | scanner resume cursor | raw 32-byte hash (re-derivable from tip) |

The SMT leaves and MMR roots are **Poseidon `HashDigest` values**, serialised to bytes by the
single canonical function in §2. Their byte stability across the migration is therefore *exactly*
the byte stability of `digest_to_bytes` under a field change.

### 1.3 On-chain inscription payload (`4242`)

The on-chain footprint is a single Taproot inscription whose **commit-tx txid is mined to begin
with the prefix `4242`** (`publisher.rs::inscription_txs`, up to 400 000 nonce attempts;
README §"Taproot inscription broadcast"). Its payload is the `bincode` of a `Commitment`:

```
// shared/src/commitment.rs:17
pub struct Commitment {
    pub public_key: secp256k1::PublicKey,   // BIP-340 / secp256k1
    pub signature:  schnorr::Signature,     // BIP-340 Schnorr
    pub message:    Vec<u8>,                // 32-byte digest (see below)
}
```

There is **no proof, no field element, no Plonky2/Plonky3 artifact** in this struct. It is a
secp256k1 public key, a Schnorr signature, and a 32-byte message. The scanner
(`scanner.rs::scan_for_inscriptions`) filters txids by the `4242` prefix, extracts the
inscription content, `bincode`-deserialises it as `Commitment`, and calls `verify()`. Nothing in
that path knows which proof system produced the state being committed.

The `message` is built once, here:

```
// shared/src/lib.rs:85 (ClientAccount::create_commitment)
let combined = hash_concat(account_state_hash, output_coins_root);  // Poseidon two-to-one
Commitment::new(&self.current_private_key(), digest_to_bytes(&combined).to_vec())
```

i.e. `message = digest_to_bytes( H(asth ‖ ocr) )`, a 32-byte value, which `Commitment::new`
signs as a BIP-340 Schnorr message (`SHA256` is applied internally only when `message.len()
!= 32`; here it is exactly 32, so the stored message **is** the signed digest). This matches the
SPEC/cutover statement `SHA256(serialize(asth) ‖ serialize(ocr))` at the protocol level — note
the in-code variant feeds the two digests through one Poseidon `hash_concat` first, then
serialises; either way the inputs are the same two Poseidon digests and the boundary is `serialize
= digest_to_bytes`.

**Conclusion (1.3):** the on-chain format is proof-system-agnostic. Its *only* dependency on the
proving stack is the byte value of `digest_to_bytes(...)` of Poseidon digests — i.e. §2.

---

## 2. The field-element byte encoding — the hinge of the whole migration

Everything above that "depends on the field" depends on exactly one pair of functions
(`program-plonky2/src/hash.rs`):

```
pub type HashDigest = HashOut<F>;            // F = GoldilocksField → 4 × 64-bit limbs = 256 bits

pub fn digest_to_bytes(d: &HashDigest) -> [u8; 32] {
    for (i, e) in d.elements.iter().enumerate() {
        out[i*8 .. (i+1)*8].copy_from_slice(&e.0.to_be_bytes());   // 8 bytes BE per element
    }
}
pub fn digest_from_bytes(bytes: &[u8; 32]) -> HashDigest { /* inverse, 8-byte BE chunks */ }
```

A `HashDigest` is **4 Goldilocks field elements, each emitted as 8 big-endian bytes → exactly
32 bytes**. This 32-byte string is the canonical wire/storage shape used for:

- account addresses (`accounts.address`),
- SMT leaves and MMR roots (`mmr_root_index`, the bincode'd trees),
- the Schnorr message (`create_commitment` → on-chain `4242` inscription),
- the `circuit_digest_meta` digest (bincode of the same `HashOut`).

### Why the field choice changes this

`Goldilocks` is a **64-bit** field (`p < 2^64`), so 4 elements pack naturally into 4 × 8 = 32
bytes, and a 256-bit Poseidon digest is exactly 4 elements. `BabyBear` (and `KoalaBear`) are
**31-bit** fields. To carry the same ~256-bit digest you need **8 elements of ~31 bits**, and a
field element no longer fills an 8-byte lane. Any faithful `digest_to_bytes` for BabyBear must
therefore change: different element count, different limb width (4-byte lanes), different padding.

**The byte string `digest_to_bytes(asth)` is not preserved across a Goldilocks→BabyBear change.**
Because that byte string is (a) the SMT/MMR root encoding *and* (b) one half of the on-chain
Schnorr message, a BabyBear move re-encodes the stored roots **and** changes the on-chain signed
digest — the latter is the SDK-coordination trigger (§4).

`[VERIFY: the exact BabyBear digest→bytes scheme (8×u32-BE? packed-31-bit? domain-tagged?) is a
Phase-9 design decision, not yet written. Whatever it is, it MUST be specified jointly with
zk-coins/sdk because the wallet recomputes the same bytes to sign — see §4.]`

---

## 3. Existing Plonky2 proofs in the DB — can they be migrated?

**No — they are historical-only after cutover, and the only consistent path is a genesis reset.**

### 3.1 Why old proofs cannot be re-verified post-cutover

A stored `Proof` (`accounts.data → Account.proof`, queued `CoinProof`s, `PROOFS_DIR/*.bin`) is a
`ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, D>`. The Plonky3 node ships a
**different verifier** (different proof system; on BabyBear, also a different field). A Plonky3
verifier cannot verify a Plonky2 proof. Worse, zkCoins is **recursive**: each transition feeds
the account's prior proof back as the *inner* proof (`account_node::send_coins_inner`). So a
stale proof is not merely un-verifiable in isolation — the **next** send/mint hands it to the new
circuit's witness generator, which aborts. This exact failure mode is the documented incident
behind migrations `0015`/`0016` (Plonky2 witness generator aborting with a copy-constraint
conflict on a stale `account.proof`).

### 3.2 The three theoretical options

| Option | Feasible? | Verdict |
|---|---|---|
| **(a) Keep old proofs as immutable history + checkpoint** (don't re-verify; reset proof-dependent state to a fresh Plonky3 genesis; preserve append-only log tables as evidence) | **Yes** — already implemented (`reset_proof_dependent_state_tx`, migration `0016`, `self_heal`) | **RECOMMENDED** |
| **(b) Re-prove the old state under Plonky3** | **No** — re-proving needs the original *witness* (spend secrets, in-coin source witnesses), which the node does not retain; only the proof + public outputs survive | Impossible |
| **(c) Dual-verifier window** (Plonky3 circuit verifies a Plonky2 inner proof for one re-anchor transition) | Technically conceivable, but requires an **in-circuit Plonky2 verifier inside a Plonky3 circuit** — a cross-proof-system recursion gadget that does not exist upstream and is research-grade (Doc 1 §4 Option B) | Out of scope for a backend port |

### 3.3 Recommendation (cross-ref Doc 1 §4)

**Adopt (a): a hard checkpoint / genesis reset**, exactly mirroring Doc 1's account-migration
recommendation (Option A). The append-only audit tables (`account_history`,
`state_update_log`, `request_log`, terminal `jobs` rows) are **preserved as immutable history**;
the proof-dependent set (`accounts`, `smt_state`, `mmr_state`, `mmr_root_index`,
`circuit_digest_meta`, `latest_block`, and the `PROOFS_DIR` files) is reset to genesis. The
operator has previously authorised exactly this class of wipe for DEV **and** PRD, both being
closed test environments (CONTRIBUTING § "Closed test environment"; migration `0016` header).

This holds **regardless of field choice**: even staying on Goldilocks — where the *root bytes*
would be byte-stable — the *proofs that attest to those roots* are invalidated by the proof-system
change, and the global SMT/MMR are append-only and shared across accounts (keyed by on-chain
commitment pubkeys in MMR-append order), so they cannot be partially unwound per account without a
global-vs-account soundness mismatch (migration `0015`/`0016` rationale; `node/src/self_heal.rs`).

---

## 4. Field-change serialisation impact — Goldilocks vs BabyBear

The two field options have **very different format blast radii**. The proof blob is invalidated in
both cases (§3); the difference is whether the *digest byte-encoding* — and therefore the on-chain
format and the SDK — also changes.

### 4.1 Goldilocks-on-Plonky3 (recommended for Phases 1–8)

| Item | Changes? | Notes |
|---|---|---|
| `digest_to_bytes` / 32-byte digest shape | **NO** | `F` unchanged → 4 × 8-byte-BE packing identical |
| `accounts.address` bytes | **NO** | same digest encoding |
| SMT leaf / MMR root **byte values** | **NO** (encoding); proofs over them **invalid** | roots survive byte-for-byte but are reset anyway (§3.3) |
| Schnorr message `digest_to_bytes(H(asth‖ocr))` | **NO** | wallet signing is byte-identical |
| On-chain `4242` inscription format | **NO** | `Commitment` is field-agnostic; message bytes unchanged |
| **SDK bump required?** | **NO** | wallet's `createCommitment` produces identical bytes |
| Proof blob (`accounts.data`, `CoinProof`, `PROOFS_DIR`) | **YES** (invalidated) | different proof system; closed-env only, reset by genesis migration |
| `circuit_digest_meta` value | **YES** | new circuit ⇒ new digest; re-baselined by `self_heal` |

→ **Goldilocks reduces the format migration to a proof-blob reset only.** No SDK coordination, no
on-chain change. This is the dominant reason Doc 1 / the Phase-0 gate recommend staying on
Goldilocks for the port.

### 4.2 BabyBear-on-Plonky3 (deferred Phase 9)

| Item | Changes? | Notes |
|---|---|---|
| `digest_to_bytes` / digest shape | **YES** | 31-bit field ⇒ 8 elements, 4-byte lanes; new packing (§2) |
| `accounts.address` bytes | **YES** | re-encoded; reset by genesis migration anyway |
| SMT leaf / MMR root byte encoding | **YES** | Poseidon-over-BabyBear ⇒ different root bytes |
| Schnorr message `digest_to_bytes(H(asth‖ocr))` | **YES** | the **signed bytes change** |
| On-chain `4242` inscription format | **payload bytes change** | the `Commitment.message` (the signed digest) is different; the *envelope/prefix* mechanism is unchanged, but what is signed is not |
| **SDK bump required?** | **YES — coordinated `zk-coins/sdk` release** | the wallet must compute the *same* new digest bytes to sign; a stale SDK signs the old encoding and the node rejects the commitment |
| Proof blob | **YES** (invalidated) | different field + proof system |
| `circuit_digest_meta` value | **YES** | new circuit + new digest type (`HashOut<BabyBear>`) |

→ **BabyBear forces a lock-step `zk-coins/sdk` bump.** The wallet independently reconstructs
`digest_to_bytes(H(asth‖ocr))` to produce its Schnorr signature; if the field encoding changes on
the node but not in the SDK, every commitment the wallet posts is over the wrong 32-byte message
and `Commitment::verify()` in the scanner rejects it. This is the **only** thing in the entire
migration that crosses the wallet boundary — and it is triggered *solely* by the field change, not
by the Plonky2→Plonky3 switch itself.

`[VERIFY: confirm the SDK's commitment-message construction is the only wallet-side consumer of
the field encoding. From the node side, the wallet's sole field-dependent input is the
asth/ocr→32-byte digest it signs; the SDK does not run a verifier. Confirm against the
zk-coins/sdk source (out of this repo's tree) before any Phase-9 field flip.]`

---

## 5. Migration-script sketch

The repo **already ships the canonical breaking-change recovery** — do not hand-write a bespoke
state transform. Reuse migration `0016`'s shape and the `self_heal` boot path.

### 5.1 The reset migration (model on `0016_reset_proof_dependent_state_to_genesis.sql`)

```sql
-- 00NN_reset_proof_dependent_state_for_plonky3_cutover.sql
-- Mirror of reset_proof_dependent_state_tx (node/src/db.rs) and migration 0016.
-- Fires exactly once per database via _sqlx_migrations: develop → DEV, main → PRD.

DELETE FROM accounts;            -- carries the stale Plonky2 account.proof
DELETE FROM smt_state;           -- global commitment SMT (proofs attest to it)
DELETE FROM mmr_state;           -- global MMR of SMT roots
DELETE FROM mmr_root_index;      -- prev_mmr_root → (smt_root, leaf_index) map
DELETE FROM latest_block;        -- scanner cursor, re-derived from the tip
DELETE FROM circuit_digest_meta; -- cleared, NOT rewritten: a SQL migration cannot
                                 -- know the live circuit's runtime-computed digest
-- Deliberately PRESERVED: usernames, account_history, state_update_log,
-- request_log, jobs (terminal rows = history), coin_proof_store (empty groundwork),
-- pending_inscriptions (scanner bookkeeping).
```

### 5.2 Boot path — no new code (`node/src/self_heal.rs`)

After the reset migration runs, the first boot of the Plonky3 image follows the existing
adoption branch — **no new code path is introduced**:

1. `circuit_digest_meta` is empty → `persisted == None`.
2. `self_heal::reset_decision(None, canary)` runs the canary recursion; on the empty
   `accounts` table the canary returns `NoSample` → decision = `Baseline`.
3. `Baseline` records the **new Plonky3 circuit digest** (`HashOut` of the live circuit).
4. `reset_proof_store_dir(PROOFS_DIR)` drops orphaned `*.bin` files; `ProofStore::new` resumes
   `next_id` cleanly (files are id-addressed, no surviving row references them).

```rust
// Conceptual boot sequence (already implemented; shown for orientation, do not re-add):
match self_heal::reset_decision(persisted_digest, account_node.canary_recursion()) {
    ResetDecision::Reset    => { db::reset_proof_dependent_state_tx(&pool, &live_digest).await?;
                                 self_heal::reset_proof_store_dir(&proofs_dir)?; }
    ResetDecision::Baseline => { /* fresh genesis: record live_digest, drop PROOFS_DIR orphans */ }
    ResetDecision::Keep     => { /* unchanged digest: steady state */ }
}
```

### 5.3 Re-anchor

There is no on-chain re-anchor to perform at cutover: the genesis reset starts from an empty SMT/MMR,
and balances re-mint from the publisher on demand. The **first** post-cutover send/mint produces the
first Plonky3-rooted `4242` inscription (Doc 1 §6.3 "point of no return"). Because the inscription
*format* is unchanged for Goldilocks (and only the signed-digest bytes change for BabyBear), the
scanner integrates the new commitments with no scanner-side format change.

### 5.4 BabyBear-only addendum

If (and only if) Phase 9 flips to BabyBear, the cutover release must be **co-released with a
`zk-coins/sdk` version that emits the new `digest_to_bytes` encoding** (§4.2). Sequence: ship the
SDK update to wallets *first* (or gate the node to accept only the new encoding at a known block
height), so no wallet signs the old 32-byte message after the node starts expecting the new one.
This step is **absent** from a Goldilocks cutover.

---

## 6. Compatibility matrix

Artifact × field option × {format change? · SDK bump? · on-chain impact?}.
"Invalidated" = the value cannot be reused and is reset by the genesis migration (§5), independent
of byte-encoding.

| Artifact | Goldilocks-on-Plonky3 | BabyBear-on-Plonky3 |
|---|---|---|
| Proof blob (`accounts.data → Account.proof`, `CoinProof`, `PROOFS_DIR/*.bin`) | **Invalidated** · no SDK bump · no on-chain impact | **Invalidated** · no SDK bump · no on-chain impact |
| `digest_to_bytes` 32-byte encoding | **Unchanged** · no SDK bump · none | **Changed** (8×31-bit packing) · **SDK bump** · changes signed digest |
| `accounts.address` bytes | **Unchanged** (reset anyway) · — · none | **Changed** (reset anyway) · — · none |
| SMT leaf / MMR root encoding (`mmr_root_index`, bincode trees) | **Unchanged encoding**, proofs invalid → reset · no SDK bump · none | **Changed encoding** → reset · no SDK bump · none |
| Schnorr message `digest_to_bytes(H(asth‖ocr))` | **Unchanged** · **no SDK bump** · **on-chain SAFE** | **Changed** · **SDK bump REQUIRED** · signed digest differs |
| On-chain `4242` inscription (`Commitment` envelope + txid prefix) | **Unchanged** · no SDK bump · **SAFE** | Envelope/prefix unchanged; **signed message bytes change** · SDK bump · scanner verifies new bytes |
| `circuit_digest_meta.digest` | **Changed** (new circuit) · no SDK bump · none | **Changed** (new circuit + `HashOut<BabyBear>` type) · no SDK bump · none |
| Append-only history (`account_history`, `state_update_log`, `request_log`, terminal `jobs`) | **Preserved** · — · — | **Preserved** · — · — |

---

## 7. Verdict & open `[VERIFY]` items

**Verdict.**
- **On-chain `4242` format is SAFE across the migration** — the inscription encodes only a
  BIP-340 Schnorr signature, a secp256k1 pubkey, and a 32-byte digest; nothing proof-system-
  specific. It survives the Plonky2→Plonky3 switch with zero format change *provided the
  digest's 32-byte encoding is preserved*.
- **Goldilocks-on-Plonky3 preserves that encoding** → no SDK bump, no on-chain change; the format
  migration collapses to a **proof-blob genesis reset** (already implemented).
- **BabyBear-on-Plonky3 does NOT preserve it** → it re-encodes the asth/ocr digest, changing the
  Schnorr message bytes and **forcing a coordinated `zk-coins/sdk` bump**. This is the *only*
  wallet-crossing consequence in the whole migration, and it is driven purely by the field change,
  not by the proof-system change.

**Open `[VERIFY]` items:**
- `[VERIFY]` The exact BabyBear digest→bytes scheme (element count, limb width, padding,
  domain-tag) — a Phase-9 design decision, to be specified jointly with `zk-coins/sdk` (§2, §4.2).
- `[VERIFY]` That the SDK's commitment-message construction is the sole wallet-side consumer of the
  field encoding, confirmed against the `zk-coins/sdk` source before any field flip (§4.2).
- `[VERIFY]` The `Proof` serialised shape under Plonky3-Goldilocks vs Plonky3-BabyBear (FRI config,
  Merkle cap height) — needed for any future *typed* proof-store schema, but irrelevant to the
  reset path since blobs are wiped (§1.1, §3).
