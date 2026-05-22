# Multi-Asset zkCoins Design

**Status:** Design draft. No code yet. Companion to
[`SPEC.md`](./SPEC.md), [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md),
and [`ROADMAP.md`](./ROADMAP.md). Sibling design docs:
[`BRIDGE_MVP.md`](./BRIDGE_MVP.md),
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md),
[`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md).

**Authoritative source for:** the multi-asset protocol extension —
scope, locked decisions, circuit and state-layer changes, API shape,
phased rollout, non-goals.

**Audience:** Engineers implementing the multi-asset upgrade.
Presupposes `SPEC.md` (single-asset protocol), the project
invariants in [`CONTRIBUTING.md`](./CONTRIBUTING.md) § "Working on
the Plonky2 Migration", and the `MAX_IN_COINS`/`MAX_OUT_COINS`
fixed-shape fanout of the current circuit.

---

## 0. Status

Design draft only. The current protocol is single-asset: `Invoice {
amount, recipient }`, `Account { balance: u64, … }`, no `asset_id`
anywhere. This document specifies the extension to a permissionless
multi-asset system — anyone mints a token by name, the creator keeps
ongoing mint authority, transactions stay single-asset, asset
metadata is name + decimals. Implementation tracking lands in
[`ROADMAP.md`](./ROADMAP.md) once the maintainer approves this draft.

---

## 1. Motivation

zkCoins today serves one asset: the faucet-minted unit returned by
`/api/mint`. The minting account is hard-coded (`MINTING_ADDRESS`,
see [`SPEC.md`](./SPEC.md) §8 "Note on the minting account"), the
`Invoice` and `Coin` types carry only `amount + recipient`, and the
account-server's `balance: u64` is a single scalar.

Multi-asset opens this to any user: anyone mints a new token under a
chosen name, distributes it, and retains the right to issue more.
The shielded-CSV mechanics (per-account history SMT, global
commitment MMR, BIP-340 Schnorr inscription on Bitcoin) carry over
unchanged; the asset identity rides as an extra field on coins, on
invoices, and on the SMT-leaf pre-image.

Two design pressures pull in opposite directions:

- **Privacy** — separate per-asset anonymity pools maximise
  unlinkability across assets but multiply state and circuit cost.
- **Simplicity** — a single SMT with `asset_id` as a public field on
  each commitment keeps the circuit shape unchanged (the only new
  in-circuit constraint is "all coins in this transition share the
  same `asset_id`") and the prover cost roughly flat.

This document picks **simplicity**. The privacy trade-off is
explicit: an outside observer learns which asset moved per
transaction; the sender, recipient, and amount stay private as
before. Per-asset privacy pools are deferred (see §12).

The decision space matches `MIGRATION_RESEARCH.md` §5's pattern:
each constraint below is locked for v1 and reversible only at the
cost of a circuit redesign.

---

## 2. Decisions (locked)

The six decisions below are fixed for v1. Reversing any of them
means a non-trivial protocol-level change.

| # | Decision | Consequence |
| - | -------- | ----------- |
| **M1** | **Token creation is permissionless.** Any account can call `/api/asset/create` and mint a new asset. No whitelist, no admin gate, no fee gate. | The server is a pass-through registrar. Spam pressure is handled by the on-chain inscription fee on the genesis transaction's `Commitment`, not by the server. |
| **M2** | **Creator retains ongoing mint authority.** The asset's genesis transaction pins a `mint_authority_pubkey` (the creator's compressed secp256k1 pubkey). Subsequent `/api/mint` calls require a fresh Schnorr signature verifiable against that pubkey. No fixed-supply rule. | No "burn the key after genesis" mode. Total supply is open-ended; trust in the asset is trust in the creator not to over-issue. Key rotation is out of scope (see §11, §12). |
| **M3** | **Asset namespace is first-come-first-served on `name`.** The first genesis transaction binding a given `name` wins; later attempts return `409 Conflict`. Normalisation is `name.to_lowercase()` to remove the cheapest look-alike attacks; the trade-off is documented in §10. | `assets.name UNIQUE` at the SQL layer is the enforcement point. No retroactive renaming, no namespace governance. |
| **M4** | **Privacy pool is a single shared SMT.** `asset_id` is a public field on each coin commitment and a public input on each state-transition proof. Anonymity-set is per-asset (all `asset_id = X` traffic mixes; `asset_id = Y` is a separate pool). | Circuit complexity unchanged modulo one extra public input + one cross-coin equality constraint. Per-asset trees and per-asset MMRs are deferred. |
| **M5** | **Cross-asset transfers are out of protocol.** Every state transition moves exactly one `asset_id`; no atomic A↔B swap inside zkCoins. A↔B trading is a separate DEX layer (out of scope: BitVM2 bridge, Lightning atomic swap, off-protocol order-book). | The in-circuit invariant is simple: all input coins and all output coins in a transition carry the same `asset_id`. Multi-leg trades are wallet-side UX over multiple proofs, or an external swap protocol. |
| **M6** | **On-chain asset metadata is `name + decimals` only.** `name` is UTF-8, ≤ 32 bytes after normalisation; `decimals` is `u8` (0-18). No logo, URI, description, supply cap, or other fields. | Richer metadata (logo, links, social) lives off-chain — a separate registry the wallet may consult by `asset_id`. The on-chain genesis stays small and immutable; see §6.2. `decimals` is pure UX (no on-chain math change). |

These mirror the lockedness of `MIGRATION_RESEARCH.md` §5 (Plonky2
locked-in decisions) and `BRIDGE_MVP.md` §3 (Bridge locked technical
decisions). Each is testable at 100% coverage per invariant 4 of
[`CONTRIBUTING.md`](./CONTRIBUTING.md).

---

## 3. Glossary additions

Extends `SPEC.md` § Glossary. Terms below are referenced throughout
this document.

| Term | Expansion | Meaning |
| ---- | --------- | ------- |
| **AssetId** | — | `HashDigest`. Deterministic Poseidon digest derived from the genesis pre-image (see §4.2). Public field on every coin commitment and every state-transition proof under the multi-asset extension. |
| **AssetGenesis** | — | The genesis transaction that creates a new asset. Carries `name`, `decimals`, `mint_authority_pubkey`, `initial_supply`, `creator_signature`. Persisted in the `assets` table; published on-chain via the same Schnorr-inscription path as a regular send. |
| **AssetMeta** | — | Off-circuit record holding `(asset_id, name, decimals, mint_authority_pubkey, creator_address, created_at)`. One row per asset in the `assets` table; never mutated after insert (immutable post-genesis). |
| **MintAuthorityKey** | — | The compressed secp256k1 pubkey pinned at genesis. Every subsequent `/api/mint` call for this asset must carry a fresh BIP-340 Schnorr signature verifiable against it. |
| **M1 – M6** | — | Locked design decisions for multi-asset (this document, §2). Mirrors `MIGRATION_RESEARCH.md`'s `D1–D11` numbering scheme. |

---

## 4. Protocol changes

### 4.1 Data structures

The new shape of the core types. Field additions are highlighted in
the diffs below; existing fields keep their semantics from
`SPEC.md`.

```rust
// shared/src/lib.rs

pub struct Invoice {
    pub amount:    Amount,
    pub recipient: Address,
    pub asset_id:  AssetId,        // NEW
}

// program-plonky2/src/types.rs

pub struct Coin {
    pub identifier: HashDigest,
    pub recipient:  Address,
    pub amount:     Amount,
    pub asset_id:   AssetId,       // NEW
}

pub struct CoinTemplate {
    pub recipient: Address,
    pub amount:    Amount,
    pub asset_id:  AssetId,        // NEW
}
```

`Account` (in `server/src/account_server.rs`) gains a per-asset
balance map; the old `balance: u64` collapses to "balance of the
default asset" only for the migration window (see §6.3 — there is
no migration window because state is wiped at cutover, so the field
is replaced outright).

```rust
// server/src/account_server.rs

pub struct Account {
    pub proof:        Option<Proof>,
    pub coin_queue:   Vec<CoinProof>,
    pub coin_history: SparseMerkleTree,
    pub balances:     BTreeMap<AssetId, u64>,   // REPLACES `balance: u64`
}
```

New record type for the asset registry:

```rust
// shared/src/lib.rs

pub struct AssetMeta {
    pub asset_id:              AssetId,
    pub name:                  String,                 // normalised, ≤ 32 bytes UTF-8
    pub decimals:              u8,                     // 0-18
    pub mint_authority_pubkey: bitcoin::PublicKey,
    pub creator_address:       Address,
    pub created_at:            u64,                    // unix seconds
    pub initial_supply:        u64,
}
```

The Plonky2 `AccountState` carried inside the circuit — see
`program-plonky2/src/types.rs::AccountState` — stays single-balance
per-proof: each state-transition proof concerns exactly one
`asset_id` (decision **M5**), so `AccountState.balance` is the
balance of *that* asset for the duration of *this* proof. The
per-asset book-keeping for an account lives off-circuit in
`Account.balances`; the prover witnesses only the balance for the
asset being moved.

This keeps the in-circuit `AccountState` layout (`[owner_limbs(4),
balance_lo, balance_hi, pubkey_x_limbs(4), pubkey_parity]` — see
`SPEC.md` §12.3) almost unchanged. The minimal addition is one new
public input: `asset_id` (4 field elements).

### 4.2 Asset genesis (creation)

An asset genesis is a state-transition proof of a new variant —
call it `AssetGenesisProof` — that mints `initial_supply` units to
the creator's account, binds the asset's `name`, `decimals`, and
`mint_authority_pubkey` into the asset registry, and publishes the
same Schnorr-signed `Commitment` as a regular send.

`AssetId` derivation:

```
asset_id := Poseidon(
    DOMAIN_TAG_ASSET_GENESIS,
    creator_pubkey_limbs(5),
    name_limbs(N),
    decimals,
    timestamp,
)
```

`DOMAIN_TAG_ASSET_GENESIS` is a fixed Goldilocks field element
constant (e.g. `hash_bytes(b"zkcoins:asset-genesis:v1")` taken as a
field element). `timestamp` is the genesis request's unix-seconds
timestamp included to prevent two creators colliding on
`(creator_pubkey, name, decimals)` if they pick identical inputs.

The genesis carries five things into the world:

1. **`name`** — normalised (`to_lowercase()`, validated UTF-8, ≤ 32
   bytes after normalisation). Uniqueness is enforced at the SQL
   layer via the `assets.name UNIQUE` constraint (§6.2). The first
   genesis to commit wins; concurrent attempts return `409
   Conflict` (§10).
2. **`decimals`** — `u8`, 0-18. UX-only; no on-chain math depends on
   it.
3. **`mint_authority_pubkey`** — compressed secp256k1, pinned for
   the life of the asset.
4. **`initial_supply`** — `u64`, minted to the creator's address at
   genesis. May be 0 (the creator can choose to mint later via
   `/api/mint`).
5. **`creator_signature`** — BIP-340 Schnorr over
   `H("zkcoins:asset-genesis" || asset_id || initial_supply_le ||
   timestamp_le)`, verifiable against `mint_authority_pubkey`. This
   binds the genesis transaction to the same key that will sign
   future mints, preventing a separate party from claiming the
   asset's name.

### 4.3 Mint (subsequent issuance)

After genesis, the asset creator may issue further units by calling
`/api/mint { asset_id, recipient, amount, signature, timestamp }`.
The server:

1. Looks up `AssetMeta` by `asset_id`. Rejects if unknown.
2. Verifies the BIP-340 Schnorr signature over
   `H("zkcoins:mint" || asset_id || recipient || amount_le ||
   timestamp_le)` against the asset's stored
   `mint_authority_pubkey`.
3. Rejects if the timestamp is older than 300 s or in the future —
   matches the existing replay window in
   `verify_send_signature` (`server/src/server.rs`).
4. Runs the prover to produce a state-transition proof that moves
   `amount` units of `asset_id` from the asset's mint-authority
   account into a fresh coin for `recipient`. The same circuit
   shape as a normal send; the only branch difference is that the
   in-circuit signature gate fires against `mint_authority_pubkey`
   instead of the sender's commitment pubkey (see §5).

The current `/api/mint` is permissioned only by the server's
faucet config (`feature = "faucet"`, `MINTING_ADDRESS` hard-coded);
under multi-asset it becomes a signed request from any creator for
their own asset.

### 4.4 Send

`/api/send` keeps its current shape, with `asset_id` added to the
`Invoice` and the existing Schnorr signature widened to cover it:

```
H("zkcoins:send"
  || account_address
  || recipient
  || amount_le
  || asset_id
  || timestamp_le)
```

Existing wallets sign over `(account_address, recipient, amount,
timestamp)` — see `verify_send_signature` in `server/src/server.rs`.
The `asset_id` byte addition is a breaking change for the wallet
signature shape; bump `Capabilities.multi_asset` (§7) so wallets
know to include it.

**Single-asset invariant.** In a single transition, all input coins
and all output coins share the same `asset_id`. This is enforced
twice — defense in depth, matching the pattern in
`server/src/account_server.rs::send_coins` (off-circuit pre-check)
and `program-plonky2/src/circuit/main.rs` (in-circuit constraint):

- **Off-circuit (server pre-check):** before paying prove cost,
  iterate `account.coin_queue` and `invoices`, assert every
  `asset_id` equals the transition's claimed `asset_id`. Reject
  with `400 Mixed assets in single transition` on mismatch.
- **In-circuit (ZK constraint):** see §5.2.

### 4.5 Balance

`/api/balance` returns a map of `{ asset_id_hex: amount }` instead
of a single `balance: u64`. Single-asset clients see a one-entry
map under the well-known "default" asset id; multi-asset clients
iterate.

```json
{
  "address": "ab12…",
  "balances": [
    { "asset_id": "00112233…", "amount": 42 },
    { "asset_id": "deadbeef…", "amount": 1000 }
  ]
}
```

Because the response shape changes, bump
`Capabilities.multi_asset = true` so single-asset clients can fall
back gracefully. See §7 for the full API delta.

---

## 5. ZK-circuit changes (Plonky2)

The state-transition circuit lives in
`program-plonky2/src/circuit/main.rs`. The multi-asset extension is
additive: one new public input, one new cross-coin equality
constraint per active in-coin and out-coin slot, no shape change to
the cyclic-recursion plumbing.

### 5.1 New public input

`ProofData` gains an `asset_id` field. Public-input layout becomes:

| slot range | meaning                  |
| ---------- | ------------------------ |
| 0..4       | account_state_hash       |
| 4..8       | output_coins_root        |
| 8..12      | commitment_history_root  |
| 12..16     | coin_history_root        |
| **16..20** | **asset_id (new)**       |

`N_PROOF_DATA_PUBLIC_INPUTS` increases from 16 to 20. Knock-on
effects:

- `ProofData::to_field_elements` (`program-plonky2/src/types.rs`)
  and `ProofData::from_field_elements` extend by one
  `HashDigest`.
- `state_transition_num_pis()` in `circuit/main.rs` recomputes
  to `20 + 4 + 4 * cap_elements`.
- The cyclic-recursion `common_data_for_recursion_c_inner` rebuild
  picks up the new PI count automatically once
  `N_PROOF_DATA_PUBLIC_INPUTS` is bumped; no manual padding tweak
  required, but the `INNER_PAD_BITS_STAGE_5D_NEXT_5` constant
  should be re-verified by `recursion_shape_probe::dump_*` per the
  procedure in `MIGRATION_RESEARCH.md` §7.22 to confirm the
  helper-degree → outer-degree match still holds at the new PI
  count.

### 5.2 New in-circuit constraints

The single-asset invariant (M5) is enforced as a fan-in equality
gate: every active in-coin slot's `coin.asset_id` and every active
out-coin slot's `out_coin.asset_id` is connected to the
transition's `asset_id` public input. Inactive slots are masked by
their `active` bit, identical to the existing balance / recipient
gates in `program-plonky2/src/circuit/main.rs`.

```rust
// Pseudo-code, fits next to the existing per-slot recipient + amount checks
// in the in-coin and out-coin loops in circuit/main.rs.

for slot in in_coin_slots {
    // Existing: `slot.active * (slot.recipient - account.owner) == 0`
    // New:
    //     `slot.active * (slot.asset_id - transition_asset_id) == 0`
    connect_hashes_masked(&mut builder, slot.active, slot.asset_id, transition_asset_id);
}

for slot in out_coin_slots {
    connect_hashes_masked(&mut builder, slot.active, slot.asset_id, transition_asset_id);
}
```

Coin identifier derivation (`calculate_coin_identifier` in
`program-plonky2/src/types.rs`) extends to include `asset_id` so
that the same recipient/amount pair on two different assets
produces distinct identifiers:

```
identifier := Poseidon(account_state_hash, asset_id, u32(coin_index))
```

The SMT leaf pre-image for the coin-history SMT
(`SparseMerkleTree::insert(key, value)` keyed by
`coin.identifier`) automatically inherits the new identifier
shape; no SMT-layer change is required.

### 5.3 Mint-branch signature constraint

The current circuit handles the faucet mint via the
`MINTING_ADDRESS` exception (`SPEC.md` §8 "Note on the minting
account"). Under multi-asset this generalises: the genesis and the
ongoing mint paths take the `AssetGenesisProof` /
`AssetMintProof` branches in `ProofType`, and the in-circuit
constraint becomes "the request is signed by the asset's
`mint_authority_pubkey`".

Two viable architectures, mirroring the recurring trade-off in
`SPEC.md` §12.6:

1. **Off-circuit Schnorr verify (preferred for v1).** The server
   verifies the BIP-340 Schnorr signature with the existing
   `secp.verify_schnorr` call (the same path used by
   `verify_send_signature` in `server/src/server.rs`), and the
   in-circuit branch only enforces that the proof's
   `mint_authority_pubkey` public input matches the
   asset-registry-stored value. The asset registry is server state,
   not on-chain state — the mainnet hardening track decides whether
   this is acceptable (it is for the closed test environment per
   invariant 2 of [`CONTRIBUTING.md`](./CONTRIBUTING.md)).
2. **In-circuit Schnorr verify.** Add a BIP-340 Schnorr gadget to
   the circuit, witness the signature, and verify in-circuit. More
   expensive (Schnorr-on-secp256k1 inside Plonky2 is non-trivial
   — see `MIGRATION_RESEARCH.md` §5.4) and not required for the
   trust model decided in M1 + M2.

→ **v1: option 1.** The mint-authority pubkey is a regular
  public-input on the genesis/mint branches; the signature check is
  off-circuit. Carry the architecture decision under §12 "future
  work" if a future deployment requires the in-circuit version.

### 5.4 Prover cost delta

The per-tx cost delta is **minor**:

- +4 public inputs (one new `HashDigest` worth) per proof.
- +2 × (`MAX_IN_COINS` + `MAX_OUT_COINS`) = +32 masked-equality
  gates per proof. At Goldilocks gate cost these add tens of gates
  total — negligible against the ~50 k-gate outer circuit
  (`INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15` per
  `program-plonky2/src/circuit/main.rs`).
- One extra Poseidon field element in the coin-identifier
  derivation (was `(asth, coin_index)`; now `(asth, asset_id,
  coin_index)`). No additional Poseidon call — the input vector
  for `hash_no_pad` lengthens from 5 to 9 field elements, both
  within the standard sponge rate.

The R2 performance budget from `CONTRIBUTING.md` invariant 3 (warm
≤ 5 s, ≤ 64 GB peak) is not threatened by multi-asset alone.

### 5.5 Cite-points

For implementers, the relevant code sites in the current circuit:

- Public-input count: `program-plonky2/src/circuit/main.rs::N_PROOF_DATA_PUBLIC_INPUTS`.
- Per-slot in-coin processing (where the new `asset_id` equality
  gate lands): the in-coin loop in `build_circuit`.
- Per-slot out-coin processing: the out-coin loop in
  `build_circuit`, alongside the existing identifier-check.
- Coin-identifier derivation: `program-plonky2/src/types.rs::calculate_coin_identifier`.
- Padding constants: `INNER_PAD_BITS_STAGE_5D_NEXT_5`,
  re-verified via `recursion_shape_probe::dump_phase_2a_pad_bits_sweep`.

---

## 6. State layer

### 6.1 SMT changes

Coin commitments include `asset_id` in the pre-image via the new
`calculate_coin_identifier` formula (§5.2). The SMT structure stays
single-tree per **M4**; `asset_id` is just one more field in the
leaf pre-image, so the existing `program-plonky2/src/merkle/sparse_merkle_tree.rs`
needs no structural change. The global commitment-history SMT and
MMR (see `SPEC.md` §5) keep their current shape — they are keyed by
the commitment pubkey, not by `asset_id`, so cross-asset proofs
share the same history root and the same anonymity-set at the
commitment layer.

### 6.2 Postgres schema deltas

New table `assets` — one row per registered asset, immutable
post-insert:

```sql
CREATE TABLE assets (
    asset_id              BYTEA       PRIMARY KEY,
    name                  TEXT        NOT NULL UNIQUE,
    decimals              SMALLINT    NOT NULL,
    mint_authority_pubkey BYTEA       NOT NULL,
    creator_address       BYTEA       NOT NULL,
    initial_supply        BIGINT      NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX assets_name_idx ON assets (name);
```

The `name UNIQUE` constraint is the first-come-first-served
enforcement point (decision M3 / §10).

The `accounts` row needs to hold a per-asset balance. Two options
match the trade-off space of `SPEC.md` §12.8 and `MIGRATION_RESEARCH.md`
§5: simpler vs. more queryable.

**Option (a) — JSONB column on `accounts`:**

```sql
ALTER TABLE accounts ADD COLUMN balances JSONB NOT NULL DEFAULT '{}';
-- Shape: { "<asset_id_hex>": <u64-as-string-or-number>, ... }
```

**Option (b) — separate `account_balances` table:**

```sql
CREATE TABLE account_balances (
    address   BYTEA NOT NULL REFERENCES accounts(address) ON DELETE CASCADE,
    asset_id  BYTEA NOT NULL REFERENCES assets(asset_id),
    amount    BIGINT NOT NULL,
    PRIMARY KEY (address, asset_id)
);
```

→ **v1: option (a).** The bincode-`Account`-in-`BYTEA` pattern
already used for the `accounts` table (see
`CONTRIBUTING.md` § "Persistent State") composes naturally with a
`BTreeMap<AssetId, u64>` field on `Account`; the JSONB column is a
side index for ad-hoc queries (`SELECT … WHERE balances ?
'<asset_id_hex>'` works in Postgres). If the operational team later
needs richer balance queries (top-holders, distribution histograms),
add option (b) as a derived table populated by a trigger; not
needed for the MVP.

The `minting_meta.num_pubkeys` counter that the faucet uses
(`CONTRIBUTING.md` § "Persistent State") becomes per-asset.
Simplest shape: fold it into `assets` as a `num_pubkeys BIGINT NOT
NULL DEFAULT 0` column, advanced atomically per mint.

```sql
ALTER TABLE assets ADD COLUMN num_pubkeys BIGINT NOT NULL DEFAULT 0;
```

The standalone `minting_meta` row is dropped at cutover (no
migration window, see §6.3).

### 6.3 Migration notes

Per [`CONTRIBUTING.md`](./CONTRIBUTING.md) invariant 2 ("Closed
test environment — DEV *and* PRD"), the cutover wipes server state
and starts fresh. No live-migration logic.

The recovery procedure from `CONTRIBUTING.md` § "DEV state
recovery" applies as written: stop the server, truncate every
state-layer table (now including `assets`), drop the proofs
directory, restart. The pre-multi-asset coins are abandoned on-chain
(they're random test data); the new server starts at genesis with
an empty `assets` table.

PR-A1/A2/A3 already left DEV and PRD with empty Postgres state
after the Plonky2 cutover (`SPEC.md` invariant 2; PR
[#73](https://github.com/zk-coins/server/pull/73) finalised the
state-wipe pattern). Multi-asset reuses the same operational
procedure; no new wipe tooling required.

---

## 7. API changes

For each endpoint, the new shape and back-compat note.

### 7.1 `POST /api/asset/create` (new)

Genesis a new asset.

```
Body:
{
  "name":                  "FOO",
  "decimals":              8,
  "initial_supply":        1000000,
  "mint_authority_pubkey": "<33-byte hex>",
  "signature":             "<64-byte BIP-340 Schnorr hex>",
  "timestamp":             1716393600
}

Response (201 Created):
{
  "asset_id": "<32-byte hex>",
  "name":     "foo"
}

Response (409 Conflict):
{ "error": "asset name already taken" }
```

The handler:

1. Normalises `name` (`to_lowercase()`, UTF-8-validate, byte-length
   check ≤ 32).
2. Validates `decimals ∈ [0, 18]`.
3. Verifies the BIP-340 Schnorr signature against
   `mint_authority_pubkey` over
   `H("zkcoins:asset-genesis" || name_normalised || decimals ||
   initial_supply_le || timestamp_le)`.
4. Computes `asset_id` per §4.2.
5. Begins a transaction: `INSERT INTO assets …`. On `unique_violation`
   on the `name` column → return 409. Otherwise, run the prover to
   produce the `AssetGenesisProof`, persist the proof file, and
   advance the SMT.
6. Returns `{ asset_id, name }`.

Suggested handler name: `asset_create_handler`. Suggested request
type: `AssetCreateRequest`.

### 7.2 `GET /api/asset/list` (new)

List every known asset.

```
Response:
{
  "assets": [
    {
      "asset_id":              "<hex>",
      "name":                  "foo",
      "decimals":              8,
      "mint_authority_pubkey": "<33-byte hex>",
      "creator_address":       "<32-byte hex>",
      "initial_supply":        1000000,
      "num_pubkeys":           42,
      "created_at":            "2026-05-22T12:00:00Z"
    },
    …
  ]
}
```

Suggested handler name: `asset_list_handler`. Read-only; serves
straight from the `assets` table; cache headers per the existing
`/api/info` pattern.

### 7.3 `GET /api/asset/info/:id_or_name` (new)

Single-asset lookup. Path parameter is either the lowercased name
or the hex-encoded `asset_id`. Returns one of the records from
`/api/asset/list`'s `assets` array, or `404 Not Found`.

Suggested handler name: `asset_info_handler`.

### 7.4 `POST /api/mint` (modified)

The current faucet semantics
(`feature = "faucet"`, no signature required because the server is
the minter) are removed. The new shape:

```
Body:
{
  "asset_id":  "<hex>",
  "recipient": "<address hex>",
  "amount":    100,
  "signature": "<BIP-340 Schnorr hex>",
  "timestamp": 1716393600
}
```

Handler verifies the signature against the asset's stored
`mint_authority_pubkey` (§4.3). The faucet shortcut survives only
as the "creator never signed away the key, so they can call this"
case — it is no longer privileged.

`feature = "faucet"` is collapsed into the always-on path; the
`Capabilities.faucet` flag stays for back-compat but is wired to
`multi_asset` truthiness (see §7.8).

### 7.5 `POST /api/send` (modified)

Adds `asset_id` to the request body:

```
Body:
{
  "account_address": "<hex>",
  "recipient":       "<hex>",
  "amount":          100,
  "asset_id":        "<hex>",         // NEW
  "public_key":      "<33-byte hex>",
  "signature":       "<BIP-340 Schnorr hex>",
  "timestamp":       1716393600
}
```

The Schnorr-signed message extends to cover `asset_id` (see §4.4).
Existing single-asset wallets break here unless they update to the
new signature shape — gated by `Capabilities.multi_asset`.

### 7.6 `GET /api/balance` (modified — breaking)

Was:

```json
{ "balance": 1234, "username": "alice" }
```

Becomes:

```json
{
  "balances": [
    { "asset_id": "<hex>", "amount": 1234 }
  ],
  "username": "alice"
}
```

This is a breaking change for single-asset wallets. They MUST gate
on `Capabilities.multi_asset` and switch parser. There is no
back-compat shim — the migration is at cutover, the closed
environment makes it safe (invariant 2).

### 7.7 `POST /api/commit` (unchanged)

Shape unchanged. The underlying proof carries `asset_id` because
it is now part of `ProofData`, but the commit endpoint's wire
shape (proof_id + Schnorr commitment) does not.

### 7.8 `GET /api/info` (modified)

`Capabilities` gains `multi_asset`:

```rust
pub struct Capabilities {
    pub address_list: bool,
    pub faucet:       bool,
    pub usernames:    bool,
    pub lnurl:        bool,
    pub multi_asset:  bool,        // NEW
}
```

The `faucet` flag stays for wallet-side back-compat (it has been
`false` since PR [#73](https://github.com/zk-coins/server/pull/73)
on both DEV and PRD anyway) but is functionally subsumed by
`multi_asset = true` once the upgrade lands.

---

## 8. Wallet (client) impact

This document is server-centric. The wallet (`zk-coins/app`)
adapts in four places; full design is out of scope here.

- **Per-asset balance display.** The wallet's home screen renders a
  list of `(asset_meta, amount)` rather than a single balance.
  Drives a `/api/asset/list` fetch on first open and on background
  refresh; `asset_id → AssetMeta` lookup is cached.
- **Asset selection in the send flow.** The send screen gains an
  asset picker. The wallet's existing single-asset send becomes
  "send the default asset"; the new send-flow is "pick asset,
  enter amount, recipient".
- **Create-asset UX.** New screen: name, decimals, initial supply.
  Signs the genesis request with the wallet's existing key
  derivation tree — `mint_authority_pubkey` is the wallet's
  account pubkey, no new key material required.
- **Schnorr signature scope.** The same BIP-340 key signs over the
  extended message (now including `asset_id`); no key-management
  changes.

The current Schnorr-derivation pattern (BIP-32 child key per
commitment, derivation index = `num_pubkeys - 1`) carries over
without modification. `asset_id` is an extra field hashed into the
signed message, not a separate keyspace.

---

## 9. Privacy properties

The trade-off picked by M4 is explicit: per-transaction privacy
narrows from "anyone on the protocol" to "anyone on this asset".

| Observer learns | From | When |
| --------------- | ---- | ---- |
| Transaction exists | On-chain `4242`-prefix inscription | Real-time |
| `asset_id` of the transaction | Public input of the proof, included in `ProofData` and the inscription's commitment message | Real-time |
| Transaction count per asset | Aggregate scanner data | Real-time |
| Total on-chain throughput per asset | Aggregate scanner data | Real-time |

| Observer does **not** learn | Why |
| --------------------------- | --- |
| Sender address | Shielded by the SMT/MMR structure (`SPEC.md` §5) |
| Recipient address | Same |
| Amount | Same |
| Cross-asset linkage | Each transition concerns exactly one asset (M5); the wallet does not bundle transactions across assets |

**Anonymity set:** per asset. All transfers of asset X mix
together; transfers of asset Y are a separate pool because
`asset_id` is public on the commitment. A new asset with low
volume has a small anonymity set on day one and grows with
adoption; this is the privacy/simplicity trade-off the design
accepts under M4.

**Mitigation paths (out of scope for v1):**

- Per-asset privacy pools with a per-asset SMT and a per-asset
  MMR. Multiplies state cost by `n_assets`; deferred (§12).
- Hide `asset_id` behind a commitment (Pedersen `Commitment::commit(asset_id, rand)`)
  in the on-chain inscription. Closes the "asset_id is public"
  leak at the cost of a `Commitment::commit` opening in every
  recipient's proof — same shape as the D2/D10 hiding-recipient
  fix in `SPEC.md` §15.

The two mitigations compose; they are tracked together in §12.

---

## 10. First-come-first-served namespace enforcement

The mechanics behind decision M3.

- **SQL enforcement.** `assets.name UNIQUE` + `INSERT … ON CONFLICT
  (name) DO NOTHING` — the same pattern as the username store
  (see `CONTRIBUTING.md` § "Persistent State" `usernames` row).
  Whichever genesis transaction commits first wins. Concurrent
  attempts on the same name receive `409 Conflict`.
- **No retroactive renaming.** Once `assets.name` is set, it is
  immutable. The `assets` row is never `UPDATE`d after insert;
  there is no admin endpoint to rename.
- **Case-insensitive normalisation.** `name.to_lowercase()` (Rust
  default, locale-independent Unicode lowercasing) is applied at
  validation time and at lookup time. This removes the cheapest
  homograph class (`USDT` vs `usdt` vs `Usdt`) at the cost of
  ruling out distinct names that differ only in case.
- **Trade-off acknowledged.** Full homograph defence
  (`u` vs Cyrillic `u`, zero-width-joiner attacks) is out of scope
  for v1. The same trade-off applies as in `feedback_dns_migration`
  — every name shown in the wallet UI MUST be displayed with both
  `name` and `asset_id` (the asset_id is the trust anchor; the
  name is UX). Wallets that show only `name` carry the homograph
  risk.

Race-handling at the database layer is the canonical solution; do
not rely on application-side locking. Postgres' MVCC guarantees
exactly one writer wins on a `UNIQUE` violation, the other gets
`23505 unique_violation` which the handler translates to HTTP 409.

---

## 11. Mint authority

The mechanics behind decision M2.

- **Genesis pins `mint_authority_pubkey`.** Compressed secp256k1,
  written into the `assets` row at creation, immutable thereafter.
- **Subsequent mint signature.** Every `/api/mint` request carries
  a BIP-340 Schnorr signature over
  `SHA256("zkcoins:mint" || asset_id || recipient || amount_le ||
  timestamp_le)`, verified against the asset's
  `mint_authority_pubkey`. Same secp256k1 primitive as the send
  signature (`verify_send_signature` in `server/src/server.rs`); no
  new crypto primitive.
- **Replay protection.** 5-minute timestamp window
  (`now.abs_diff(timestamp) > 300 → reject`), matching the
  existing pattern.
- **Per-asset request counter.** The `assets.num_pubkeys` column
  advances per mint (§6.2). The minting account's
  `prev_commitment_pubkey` is derived from this counter exactly as
  the existing faucet's `minting_meta.num_pubkeys` does today.
- **No fixed supply.** The protocol does not enforce a hard cap.
  Total supply is `initial_supply + Σ(mint amounts)`. Off-chain
  registries may publish supply caps as a social convention; the
  protocol does not.
- **Key rotation is out of scope.** A creator who loses their
  mint-authority key loses the ability to mint more units. There
  is no admin override, no rotation endpoint, no escape hatch.
  Future work — see §12.

---

## 12. Open questions / future work

Bullets in the same shape as `BRIDGE_MVP.md` §13.

- **Key rotation for mint authority.** If a creator loses their
  signing key (or wants to migrate to a new one), the asset is
  effectively frozen at its current supply. A rotation mechanism
  — signed by the old key, written as an `assets.rotation_pubkey`
  column — is the obvious extension. Out of scope for v1 to keep
  the genesis path immutable.
- **Richer on-chain metadata.** Logos, URIs, descriptions, social
  links. M6 explicitly excludes these — they live in an off-chain
  registry the wallet consults by `asset_id`. The on-chain genesis
  stays small.
- **Cross-asset atomic swap inside zkCoins.** M5 defers this.
  Trading happens on a separate DEX layer; the BitVM2 bridge
  (`BRIDGE_MVP.md`) and the Lightning atomic swap layer
  (`LIGHTNING_ATOMIC_SWAP.md`) are the canonical out-of-protocol
  paths.
- **Per-asset privacy pools.** M4 picks the shared-pool design
  for simplicity. A per-asset SMT + per-asset MMR raises
  anonymity-set per asset to "the asset's own traffic, hidden
  from other assets' traffic" — same as Tornado-style pool
  separation. Cost: multiplies state and Bitcoin-side commitment
  traffic by `n_assets`. Deferred.
- **Hiding `asset_id`.** Combines with the D2/D10 hiding-recipient
  fix in `SPEC.md` §15. Out of scope for v1; tracked alongside the
  mainnet-blocker privacy fixes.
- **Burn (asset deflation).** Not in MVP. If a future creator
  wants explicit burn, the cleanest design is a sentinel
  recipient address (`BURN_ADDRESS = HashDigest::ZERO` or a
  domain-separated constant) that the circuit treats as a coin
  sink with no corresponding `apply_coin`. Adds one branch in
  `account_server::receive_coin`. Defer until a real use case
  arrives.
- **Decimals semantics.** Purely UX-display. The on-chain `amount`
  is a `u64`; the wallet formats with `decimals` for display only.
  No on-chain math change. The protocol does not enforce that
  `amount % 10**decimals` makes sense.
- **In-circuit Schnorr verify.** §5.3 picks off-circuit; if a
  future deployment demands in-circuit (e.g. minting-as-bridge
  semantics), the gadget cost is non-trivial — `MIGRATION_RESEARCH.md`
  §5.4 has the analysis.

---

## 13. Implementation order

Phased rollout, mapped to PR boundaries. Effort estimates are
qualitative (S = small, M = medium, L = large, XL = extra large)
per the convention in `BRIDGE_MVP.md` §12.1.

| Phase | Scope | Effort | Risk |
| ----- | ----- | ------ | ---- |
| **P1 — Shared types + AssetId plumbing** | `shared/src/lib.rs` gains `AssetId`, `AssetMeta`; `Invoice` gains `asset_id`; `program-plonky2/src/types.rs::Coin`/`CoinTemplate` gain `asset_id`. No behaviour change yet — the field is propagated but the server defaults it to a placeholder `DEFAULT_ASSET_ID` so existing tests pass unchanged. Drop in a `MULTI_ASSET_FIXME` comment at every site that will need real handling in P5. | **S** | Low — mechanical |
| **P2 — Circuit extension** | `program-plonky2/src/circuit/main.rs`: bump `N_PROOF_DATA_PUBLIC_INPUTS` to 20, add `asset_id` public input, add per-slot masked-equality gates, extend `calculate_coin_identifier`. Re-run `recursion_shape_probe::dump_phase_2a_pad_bits_sweep` to confirm padding still fits. Coverage gate stays at 100%. The single heaviest lift. | **L** | Medium — cyclic-recursion padding may shift |
| **P3 — Asset registry endpoints** | `POST /api/asset/create`, `GET /api/asset/list`, `GET /api/asset/info/:id_or_name`. New `assets` table migration. SQL `name UNIQUE` enforcement. Handler tests for the 409-on-conflict race. | **M** | Low — standard HTTP API extension |
| **P4 — Mint signature verification** | `POST /api/mint` switches from faucet to signed creator-mint. Per-asset `num_pubkeys` counter. The faucet shortcut is removed; the always-on `Capabilities.faucet` is rewired to `multi_asset`. | **M** | Medium — replaces a known-good code path; tests must cover the per-asset replay protection |
| **P5 — Send + balance + commit shape** | `POST /api/send` extends signed message, `GET /api/balance` becomes per-asset map, single-asset off-circuit pre-check enforces M5, `Capabilities.multi_asset = true`. Backfill the `MULTI_ASSET_FIXME` sites from P1. | **L** | Medium — multiple coupled changes, all wallet-visible |
| **P6 — Wallet adaptation** | `zk-coins/app`: balance display, send-flow asset picker, create-asset UX. Separate PR(s) in the app repo, gated on `Capabilities.multi_asset` from the server's `/api/info`. | **L** | Medium — UX-heavy, parallel to server work |

**Aggregate effort: M + L + M + M + L + L ≈ 4 person-months at
full focus.** Phase 1 can begin immediately; Phase 2 is the heavy
lift and gates Phases 3 onward.

Per [`CONTRIBUTING.md`](./CONTRIBUTING.md) invariant 4, every
phase ships with 100% test coverage on the activated surface
(`cargo llvm-cov --fail-under-lines 100 -- --test-threads=1` from
inside the affected crate). Negative tests — proof rejection when
in-coin `asset_id` differs from out-coin `asset_id`, signature
verification failure on a forged mint, 409 on duplicate name — are
mandatory.

---

## 14. Non-Goals (Restated)

So nobody scope-creeps:

- Migrating existing single-asset state — **not in v1** (closed
  test environment, state-wipe at cutover per invariant 2).
- Per-asset privacy pools — **deferred** (§12, decision M4).
- Cross-asset atomic swaps inside zkCoins — **out of protocol**
  (decision M5; lives in the BitVM bridge / Lightning swap docs).
- Rich on-chain metadata (logo, URI, description) — **excluded**
  (decision M6).
- Mint-authority key rotation — **deferred** (§11, §12).
- Burn / deflationary mechanics — **not in MVP** (§12).
- In-circuit BIP-340 Schnorr verify for the mint branch —
  **deferred** (§5.3).
- Homograph-attack defence beyond `to_lowercase()` normalisation —
  **out of scope** (§10).

---

## 15. References

- [`SPEC.md`](./SPEC.md) — single-asset protocol specification.
  Multi-asset is additive to §3 (Account Model), §4 (Merkle
  Structures), §7 (Program Inputs), §8 (Circuit Logic), §9
  (Public Output).
- [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md) — Plonky2
  rationale, §5 (locked decisions), §7 (lessons learned).
  Multi-asset extends the §5-style decisions list; the §7.22
  cyclic-recursion padding methodology applies to verifying the
  new public-input count against `INNER_PAD_BITS_STAGE_5D_NEXT_5`.
- [`ROADMAP.md`](./ROADMAP.md) — status tracker. Add a row per
  phase from §13 once implementation starts.
- [`BRIDGE_MVP.md`](./BRIDGE_MVP.md) — structural reference for
  this document.
- [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) — the
  out-of-protocol cross-asset trading layer.
- [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md) — the BTC-side
  cross-asset trading layer.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — project invariants,
  decision recipe, pre-push checklist.
- `program-plonky2/src/circuit/main.rs` — circuit entry point;
  see `N_PROOF_DATA_PUBLIC_INPUTS`, `MAX_IN_COINS`, `MAX_OUT_COINS`,
  `INNER_PAD_BITS_STAGE_5D_NEXT_5`.
- `program-plonky2/src/types.rs` — `Coin`, `CoinTemplate`,
  `AccountState`, `ProofData`, `calculate_coin_identifier`.
- `shared/src/lib.rs` — `Invoice`, `ClientAccount::create_commitment`.
- `server/src/account_server.rs` — `Account`, `send_coins`, the
  off-circuit pre-check pattern that the new single-asset
  invariant follows.
- `server/src/server.rs` — `verify_send_signature` (mint signature
  follows the same 5-minute replay window and message-hash
  pattern), `Capabilities`.

---

## 16. Change Log

| Date | Change |
| ---- | ------ |
| 2026-05-22 | Initial draft. |
