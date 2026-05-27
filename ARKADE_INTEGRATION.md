# Arkade × zkCoins Integration — Design Document

**Status:** Design draft. No code yet. Companion to
[`SPEC.md`](./SPEC.md), [`MULTI_ASSET.md`](./MULTI_ASSET.md),
[`BRIDGE_MVP.md`](./BRIDGE_MVP.md),
[`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md), and
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md).

**Authoritative source for:** how Arkade (Ark protocol) and zkCoins
(Shielded CSV protocol) compose; which integration paths are
realistic on which horizons; the canonical Arkade ↔ zkCoins atomic-swap
construction.

**Audience:** Engineers and architects evaluating cross-protocol
integration with Arkade. Presupposes [`SPEC.md`](./SPEC.md), the
swap-design pattern in [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md),
the bridge model in [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md), and the
multi-asset extension in [`MULTI_ASSET.md`](./MULTI_ASSET.md). Familiarity
with the Ark litepaper (Argentieri, Avarikioti, Camilleri, Keer,
Maffei — Ark Labs / TU Wien) and the Shielded CSV ePrint 2025/068
(Nick, Eagen, Linus) is assumed.

---

## 0. Status

Design draft only. The project today has no Arkade integration —
zkCoins runs as documented in [`SPEC.md`](./SPEC.md); Arkade runs as
documented at `docs.arkadeos.com`. The two systems coexist on Bitcoin
L1 without interaction.

[`MULTI_ASSET.md`](./MULTI_ASSET.md) §12.9 names cross-asset trading as
out-of-protocol and points to the BitVM2 bridge
([`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md)) and the Lightning atomic-swap
layer ([`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md)) as the
"canonical out-of-protocol paths." This document adds the **third** such
path — Ark/Arkade — and analyses where the integration is real
engineering, where it is research, and where it is wiring.

This is not an implementation spec. It is an architectural map.
Implementation specs for individual integration paths (e.g., the HTLC
atomic swap of §7) live in follow-up documents once a path is locked
in the ROADMAP.

---

## 1. Scope

This document covers:

- Protocol-mechanics comparison between Arkade VTXOs and zkCoins
  coins (§5).
- Six integration paths, arranged by maturity (§6).
- The canonical HTLC atomic-swap construction between an Arkade VTXO
  and a zkCoins shared account, with full protocol steps and
  failure-mode analysis (§7).
- Pipeline use — BTC onboarding via Arkade boarding, transacting
  inside zkCoins, exit via Arkade settlement (§6.3).
- Bridge convergence — sharing federation infrastructure between the
  zkCoins BitVM2 bridge and an Arkade operator (§6.4).
- Confidential VTXOs as open research (§6.5).
- Cross-asset DEX (Arkade Assets ↔ zkCoins Assets) as the first
  Bitcoin-native cross-protocol multi-asset swap (§6.6).
- Trust-model stacking analysis (§8).
- Honest 6-month / 2-year / research-only assessment (§9).

It does **not** cover:

- Modifications to the zkCoins protocol or circuit. None of the
  integration paths in this document require a divergence from
  [`SPEC.md`](./SPEC.md) §15.
- Modifications to the Ark protocol. The HTLC atomic-swap path uses
  Arkade Script primitives that already ship in `arkade-os/compiler`.
- Implementation in any specific code base. Once a path is locked,
  its implementation spec is a separate sibling document (mirroring
  the relationship of [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md) to
  [`BRIDGE_MVP.md`](./BRIDGE_MVP.md)).
- Generic cross-chain bridges (Liquid, RSK, sidechains). Different
  trust model, different document.

---

## 2. Executive Summary

The most realistic short-term Arkade × zkCoins integration is a
**trustless HTLC atomic swap** between an Arkade VTXO and a zkCoins
2-of-2 shared account. The construction is a direct adaptation of
the Shielded CSV §A.1.2 atomic-swap pattern (also the basis of
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md)) with the
Bitcoin/Lightning side replaced by an Arkade VTXO carrying an
HTLC script-path. Arkade's compiler ships HTLC as a built-in primitive.
Both halves of the construction exist today; what is missing is
wiring.

Three structural facts shape every other path in this document:

1. **Arkade is a Bitcoin-script L2.** A VTXO *is* a presigned
   Bitcoin output with a Taproot lock; only the broadcasting
   is deferred (Ark §4 Definition 4.1). Any Bitcoin-script
   construction — HTLC, escrow, DLC, payment channel — composes
   onto a VTXO with the single constraint that timelocks must
   fit inside the batch expiry `T_e` (Ark §6).
2. **Shielded CSV is not L2 in the same sense.** A zkCoins coin
   has no script, no on-chain UTXO, no spending condition beyond
   `coin.recipient == self.owner` (Shielded CSV §4.2;
   `program/src/lib.rs::apply_coin`). The chain stores only
   64-byte aggregate nullifiers as an availability bulletin
   board. Atomicity cannot live on the coin layer — this is
   load-bearing for the protocol's "64 bytes per tx" property
   and locked at [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) §5.
3. **The two protocols share an institutional orbit but no
   documented unified roadmap.** Robin Linus, Liam Eagen, Jonas
   Nick (Shielded CSV authors) and Zeta Avarikioti, Matteo Maffei
   (Ark co-authors) overlap on adjacent work — BitVM, Glock, Argo —
   but neither paper mentions the other. Integration is implicit
   in the personnel, not declared in the literature. Frame
   accordingly in §9.

The combined stack inherits the union of both protocols' trust
assumptions. Today: Arkade rational-operator + zkCoins federation
(Phase 1). 2026-2028 horizon: Arkade multi-operator + zkCoins BitVM2
bridge (Phase 2). Neither protocol's headline trust-minimisation is
production yet; the combined stack is bottlenecked on whichever
reaches its Phase 2 last.

---

## 3. Decisions (locked)

The decisions below are fixed for this design document. Reversing
any of them is a design-level rethink, not a tweak.

| # | Decision | Consequence |
| - | -------- | ----------- |
| **A1** | **First integration target is the HTLC atomic swap** (§6.2, §7). Hash-Time-Locked Contract preimage swap between an Arkade VTXO and a zkCoins 2-of-2 shared account. | This is the smallest construction that demonstrably uses both protocols for what they are good at, requires no new cryptography, and inherits independent trust assumptions in each leg. Pipeline use (§6.3) is a wallet-side convenience on top; it does not need its own primitive. |
| **A2** | **No protocol changes to zkCoins or Arkade for A1.** The atomic-swap construction uses primitives both papers already specify: Shielded CSV §5.1 (shared accounts), §A.1.1 (time-locked nullifiers), §A.1.2 (atomic swap); Arkade Script HTLC template (`arkade-os/compiler`, `docs.arkadeos.com/learn/smart-contracts/hash-time-locked-contract`). | No 12th divergence to track in [`SPEC.md`](./SPEC.md) §15. No deviation from the Ark whitepaper. The integration adds wiring, not protocol changes. |
| **A3** | **Arkade operator and zkCoins federation remain independent trust domains.** A user holding a VTXO trusts the Arkade operator's rationality (Ark §5 Table 1). A user holding a zkCoins coin pegged to BTC trusts the zkCoins bridge (Phase 1 federation or Phase 2 BitVM2 setup). The two assumptions do not collapse into one; an atomic-swap counterparty may simultaneously occupy both roles, but the trust analyses stay separate. | Operating both an Arkade `arkd` instance and a zkCoins bridge node in the same datacentre is permitted; the security argument tracks each role independently. §8 is the canonical reference for which assumption applies where. |
| **A4** | **No confidential-VTXO work in the integration roadmap.** Bringing ZK privacy to Arkade VTXOs (§6.5) is genuine open research — Pedersen commitments + range proofs + redesigned forfeit mechanism + a PCD-style ZK validity proof per Arkade batch. Estimated 1–2 year paper-stage work; no existing protocol or implementation. | This document records confidential VTXOs as a research direction worth tracking but explicitly out-of-scope for any near-term zkCoins effort. If Arkade ships such a feature upstream, this section becomes a re-evaluation gate. |
| **A5** | **Pipeline use (§6.3) is layered on top of A1, not a separate primitive.** "BTC → Arkade → zkCoins → Arkade → BTC" decomposes into: Arkade boarding (Ark §4.5), an HTLC swap into zkCoins (A1), zkCoins-internal transfers, an HTLC swap back out, Arkade exit. Each step is independently specified and the pipeline composes them. | No new design work for the pipeline as long as A1 lands. The wallet-side UX of routing a user through the pipeline is `zk-coins/app` work, not a node-side primitive. |
| **A6** | **Cross-asset DEX (§6.6) is a v2 follow-up to A1.** A swap between an Arkade Asset (Arkade Labs' native-asset proposal) and a zkCoins asset is structurally identical to A1 with two field substitutions on each side. It does not require new crypto, but it does require the zkCoins multi-asset shared-account semantics from [`MULTI_ASSET.md`](./MULTI_ASSET.md) to be live, and Arkade Assets to be in production beyond beta. | Tracked as a v2 milestone; not in the initial A1 implementation scope. The first integration ships before chasing this. |

These mirror the lockedness pattern of [`MULTI_ASSET.md`](./MULTI_ASSET.md) §2
(decisions M1–M6) and [`BRIDGE_MVP.md`](./BRIDGE_MVP.md) §3 (Bridge
locked technical decisions). Each is testable to the extent the
integration is built; today most are documentation-level decisions
that fix the design space.

---

## 4. Glossary additions

Extends [`SPEC.md`](./SPEC.md) § Glossary and
[`MULTI_ASSET.md`](./MULTI_ASSET.md) § Glossary additions.

| Term | Expansion | Meaning |
| ---- | --------- | ------- |
| **VTXO** | Virtual UTXO | Ark's atomic ownership unit: a presigned Bitcoin tx output `(value, vtxoLockScript)` held off-chain by a VTXO holder, encumbered by a Taproot script with at least one collaborative path (`checkSig(pkO ⊕ pkA)`, user + operator MuSig2) and one unilateral exit path (`checkSig(pkA) ∧ relTimelock(t_v)`). Ark §4 Definition 4.1. |
| **Arkade operator** | — | The coordinating party in an Ark instance. Provides liquidity (its own BTC funds commitments), batches user activity into `commitment_tx`, cosigns Ark transactions and VTXT virtual transactions. Single operator per Arkade instance today (Ark §7). |
| **`commitment_tx`** | Commitment transaction | The single on-chain Bitcoin tx per Arkade batch that anchors a `batch` Taproot output (sweep path after `T_e`, unroll path enforcing the VTXT) and a `connector` Taproot output for the chain of anchor outputs used by forfeit transactions. Ark §4.4, Definition 4.9. |
| **`forfeit_tx`** | Forfeit transaction | Ark batch-swap atomicity primitive: user-signed transaction with SIGHASH_ALL over `(old_vtxo, connector_anchor_ε)`, valid only if the `commitment_tx` containing the connector confirms. Lets the operator claim the old VTXO if the user double-spends. Ark §4.3, Transaction 4. |
| **Batch expiry `T_e`** | — | Ark batch expiration time. After `T_e` the operator may sweep the batch output. Every script-level construction inside a VTXO (HTLC, escrow, DLC, channel) must use timelocks strictly shorter than `T_e` for the cooperative spending path to remain usable. Ark §6 caveat. |
| **Arkade Script** | — | High-level language ([`arkade-os/compiler`](https://github.com/arkade-os/compiler)) compiling to an extended Bitcoin Script targeting Arkade VM. Supports `checkSig`, `checkMultiSig`, `sha256` preimage check, CLTV / CSV, transaction introspection, and automatic generation of cooperative + unilateral exit script paths. Ships HTLC, Escrow, Spilman channel, Dryja-Poon channel, Lightning channel/swap templates. |
| **Arkade Asset** | — | Arkade Labs' native-asset proposal for issuing non-BTC tokens on Bitcoin via Ark batching. Encoded as TLV in `OP_RETURN` (`OP_RETURN <ARK> <0x00> <Length> <Asset_Payload>`); asset identifier is `(genesis_txid, group_index)`; transferred through VTXOs with operator awareness. Arkade Labs blog: *Native Assets on Bitcoin: Introducing Arkade Assets* (Oct 2025). |
| **Confidential VTXO** | — | Hypothetical Arkade extension in which the operator cosigns commitments to amounts and recipients rather than plaintext, with a ZK proof of batch correctness. Open research as of 2026-05; no published proposal. See §6.5. |
| **A1 – A6** | — | Locked design decisions for the Arkade integration (this document, §3). Mirrors the M1–M6 / D1–D11 numbering scheme of [`MULTI_ASSET.md`](./MULTI_ASSET.md) and [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md). |

---

## 5. Protocol-mechanics comparison

The two protocols solve adjacent problems with structurally different
primitives. This section is the side-by-side reference used throughout
the rest of the document.

### 5.1 Atomic unit

| Aspect | Ark / Arkade | Shielded CSV / zkCoins |
| ------ | ------------ | ---------------------- |
| Unit | **VTXO** — `(value, vtxoLockScript)` (Ark §4 Definition 4.1). Mechanically a real Bitcoin output, Taproot-locked, key path unspendable, at least one collaborative + one unilateral exit script path. | **Coin** — `(CoinEssence{address, amount, idx}, tx_hash, nullifier_location, accumulator_value)` (Shielded CSV §4.2). No script, no UTXO, no on-chain output. |
| Where it lives | Off-chain. Realisable on-chain via the unilateral exit script path. | Entirely off-chain. Chain stores only nullifiers (Schnorr half-aggregate, ~64 bytes/tx). |
| Spending condition | Arbitrary Bitcoin Script via the Taproot script paths. Today's MuSig2 cosigning emulates a covenant (Ark §3.2). | None. `apply_coin`'s `coin.recipient == self.owner` is the only check ([`program/src/lib.rs:154`](./program-plonky2/src/circuit/main.rs)). |
| Privacy from external observer | Operator-visible by construction (Ark §2.2). Amounts and recipients exposed to the operator and to anyone who sees the VTXT. | Hidden from everyone except sender and recipient (Shielded CSV §1.1, "Privacy"). PCD proof is zero-knowledge; only `(nullifier_pubkey, signature)` on-chain. |

### 5.2 On-chain artifacts

Per Arkade batch (Ark §4.4, Definition 4.9):

- **`commitment_tx`** — one Bitcoin tx. Inputs: operator funds + any
  boarding txs. Outputs: `batch` (Taproot — sweep after `T_e`, unroll
  enforcing the VTXT), `connector` (Taproot enforcing the anchor-output
  chain), optional outputs for users leaving the Ark.
- **`forfeit_tx`** (off-chain unless needed) — signed by user with
  SIGHASH_ALL over `(old_vtxo, connector_anchor_ε)`; valid only if the
  `commitment_tx` confirms.
- **Cadence** — operator-controlled. Whitepaper does not fix a number;
  current Arkade deployments use sub-second preconfirmations with
  periodic anchoring (typically minutes-to-hours).

Per zkCoins transaction (Shielded CSV §4.2):

- **One aggregate nullifier**: `(nullifier_pubkeys[], NISSHAC
  half-aggregate signature, publisher_address)`. With Schnorr
  half-aggregation, ~64 bytes per transaction regardless of input
  count (Shielded CSV §1.1, Table 1).
- **MVP implementation** wraps this in a Taproot inscription with
  txid prefix `4242` carrying a `Commitment` payload over
  `H(asth ‖ ocr)` ([`SPEC.md`](./SPEC.md) §11). The paper specifies
  raw nullifiers; the wrapping is a deliberate divergence
  ([`SPEC.md`](./SPEC.md) §15).

| Artifact | Arkade | Shielded CSV |
| -------- | ------ | ------------ |
| Per-batch on-chain footprint | 1 `commitment_tx` (constant in #VTXOs in the optimistic case) | n × 64-byte aggregate nullifiers (one per transaction; publisher batches multiple senders' nullifiers into one inscription) |
| Settlement cadence | Operator-controlled batch interval | Per transaction; bounded by aggregator's publication cadence |
| Worst-case exit | `O(log t)` virtual txs for unilateral exit from a VTXT of `t` leaves (Ark §2.3, §4.1) | N/A — no exit, no per-coin on-chain footprint |
| Bitcoin TPS ceiling | Bounded by `commitment_tx` size and frequency | ~100 TPS at current Bitcoin block-size limit (Shielded CSV §1.1) |

### 5.3 Roles and trust

| Role | Arkade operator | zkCoins publisher | zkCoins bridge |
| ---- | --------------- | ----------------- | -------------- |
| What they do | Liquidity provision, batching, MuSig2 cosigning per VTXO holder (Ark §2.2) | Collects nullifiers, half-aggregates, posts the aggregate as a Taproot inscription, claims fees (Shielded CSV §1.1, "Trustless Publishing"). **Permissionless** — anyone can be a publisher. | Custodies BTC against zkCoins-side credits. Phase 1: M-of-N federation multisig ([`BRIDGE_MVP.md`](./BRIDGE_MVP.md)). Phase 2: 1-of-N honesty BitVM2 setup ([`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md)). |
| Centralisation | Single operator today (Ark §7, "Centralisation of Ark Operator" — explicitly named as a future-work axis) | None — anyone with a Bitcoin wallet can publish | Phase 1: M-of-N trusted. Phase 2: 1-of-N honesty at setup ceremony. |
| Liveness assumption | Operator online ⇒ batch swaps and collaborative exits work. Operator offline ⇒ unilateral exit only. | Publisher offline ⇒ another publisher can take the same nullifier. No single point of failure. | Bridge stalls if no operator is willing to front a payout; the user keeps their zkCoins balance. |
| Custody | **Never.** VTXOs are user + operator MuSig2; unilateral exit always available (Ark §2.3). | **Never.** Publisher sees nullifier data only, never plaintext coin data. | **Yes** in Phase 1 (federation holds BTC). **No** in Phase 2 (vault in N-of-N MuSig with pre-signed paths). |

**Critical security property of Arkade:** Ark §5 Table 1 names six
properties under "rational" vs. "malicious" operator. Under a
*malicious* operator the protocol still satisfies onramp liveness
(NL) and offramp liveness (FL); violations of safety properties (NS,
AS, FS) "come only at the cost of the operator, not of users
following the protocol." A malicious Arkade operator cannot steal
user funds; they can only burn their own funds while users still
exit.

**Critical security property of Shielded CSV:** §1.1 ("Permissionless")
— "the protocol does not rely on any trusted party for transaction
execution. All necessary data is directly written to, and retrieved
from, the blockchain." Censorship resistance reduces to Bitcoin's own
censorship resistance. The single trust assumption is the bridging
component, not the protocol.

### 5.4 The fundamental asymmetry

The point worth repeating: **Arkade is a Bitcoin-script L2** in the
strong sense — VTXOs *are* Bitcoin outputs with locking scripts, just
not yet broadcast. **Shielded CSV is not L2 in the same sense** —
coins have no script and no on-chain footprint; the chain is a notary
for ordering and uniqueness, nothing more.

Every integration in §6 is shaped by this asymmetry. The Arkade side
can carry arbitrary Bitcoin Script (HTLC, DLC, channels), and the
zkCoins side cannot. Atomicity always lives on the Arkade VTXO or on
the Bitcoin funding tx of the zkCoins inscription —
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) §5 derives
this for Lightning; the same logic applies here.

---

## 6. Integration paths

Six paths, layered by maturity. Layer 0 is "today, no work." Layer 1
is "this design doc's headline target — 6-12 months engineering."
Layer 2 splits into three independent research directions of varying
maturity.

### 6.1 Layer 0 — independent systems

A user holds an Arkade wallet pointing at some Arkade instance and a
zkCoins wallet pointing at a zkCoins node. The wallets do not
interoperate. The user manually converts between BTC and zkCoins via
the bridge ([`BRIDGE_MVP.md`](./BRIDGE_MVP.md) or
[`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md)) and between BTC and Arkade VTXOs
via boarding/exit (Ark §4.5).

**Cost:** zero engineering. Two wallets, manual juggling, two distinct
BTC custody contexts.

**When it makes sense:** today, for power users who want both privacy
(zkCoins) and shared-UTXO economics (Arkade) without integration risk.

**When it stops being enough:** as soon as a single user flow ("private
payment from a long-term BTC store") needs both protocols. The user
should not have to choose; the system should compose them.

### 6.2 Layer 1 — HTLC atomic swap (the realistic short-term target)

Direct preimage-based atomic swap between an Arkade VTXO carrying an
HTLC encumbrance and a zkCoins 2-of-2 shared account. This is decision
A1; it is detailed end-to-end in §7.

**Why this is realistic in 6-12 months:**

- Shielded CSV §A.1.2 already specifies the exact PTLC + 2-of-2
  shared-account construction for Shielded CSV ↔ Bitcoin atomic
  swaps. The construction is documented, not novel.
- Arkade's compiler ships HTLC as a built-in primitive
  (`arkade-os/compiler` README; `docs.arkadeos.com/learn/smart-contracts/hash-time-locked-contract`).
  Hash-locked outputs on a VTXO are a one-template instantiation.
- Replacing "Bitcoin PTLC" in the Shielded CSV recipe with "Arkade
  VTXO with HTLC script-path" is mechanically straightforward.
- Same engineering surface as [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md);
  the lessons there apply with minimal adaptation.

**What it ships:** a user who holds Arkade BTC can atomically convert
to zkCoins, and vice versa, without either side trusting the other to
honour the swap. The swap counterparty (a swap provider running both
an Arkade wallet and a zkCoins shared account) faces the same
incentive structure as a Boltz operator.

**Failure modes** are exactly the failure modes in §7.5 — bounded by
the `htlc_timeout < T_e` constraint (every script construction on a
VTXO inherits batch expiry per Ark §6) and by the standard HTLC
timing-coordination story.

Three variants of the atomic swap, in order of preference:

1. **Direct two-leg HTLC swap (recommended).** Section 7 below.
2. **Federation-mediated swap.** A zkCoins federation node runs an
   Arkade-watching service and credits zkCoins on observing specific
   Arkade events. Strictly weaker than variant 1 (introduces
   federation trust) without adding capability. Skip in v1.
3. **Lightning hop.** Arkade ↔ Lightning ↔ zkCoins via two HTLC
   rounds. Arkade ships Lightning swap support
   ([`blog.arklabs.xyz` — *Closing the Lightning loop*](https://blog.arklabs.xyz/closing-the-lightning-loop-bitcoins-missing-layer-secretly-goes-live/));
   zkCoins has its own LN design in
   [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md).
   Stacking them works but adds a hop. Useful if liquidity is on the
   other side of the LN graph; otherwise variant 1 is one round
   simpler.

### 6.3 Pipeline use — BTC ↔ Arkade ↔ zkCoins ↔ Arkade ↔ BTC

Composes Layer 1 with Arkade boarding and exit to give a full
end-to-end user flow:

```
User holds BTC on-chain.
↓  boarding_tx (Ark §4.5): Taproot(F, checkSig(pkO⊕pkA), checkSig(pkA)∧relTimelock(t_b))
User holds a VTXO inside Arkade.
↓  Layer 1 HTLC atomic swap (§7): VTXO encumbered by HTLC, zkCoins-side 2-of-2 shared account
User holds shielded coins inside zkCoins.
... user transacts privately at scale inside zkCoins (per-tx ~64 bytes on-chain) ...
↓  Layer 1 HTLC atomic swap reversed: zkCoins burn → fresh Arkade VTXO
User holds a fresh Arkade VTXO.
↓  Arkade unilateral or collaborative exit (Ark §4.5, "Leaving the Ark")
User holds BTC on-chain.
```

**Why this is the killer combination:**

- **Cheap onboarding.** Arkade's `boarding_tx` is a shared
  Taproot output. The on-chain cost of one user's onboarding is
  amortised across a batch.
- **Cheap per-tx scaling.** Inside zkCoins, every transaction
  amortises to ~64 bytes on-chain regardless of value or input
  count.
- **Cheap settlement.** Arkade's `commitment_tx` is one Bitcoin
  tx per batch, and an exit (collaborative) is one transaction.
  Pessimistic exit is `O(log t)` virtual txs.

Neither protocol alone achieves both cheap onboarding and cheap
per-tx scaling. The combined pipeline does. This is the strongest
narrative motivation for the integration; A1 is the protocol step
that unlocks it.

**On-chain footprint per pipeline traversal** (steady-state, ignoring
the initial boarding):

| Step | Bitcoin txs | Notes |
| ---- | ----------- | ----- |
| Boarding (once) | 1 (`boarding_tx`) | Shared, amortised |
| Arkade Ark transaction | 0 | Lives inside Arkade until next `commitment_tx` |
| Arkade `commitment_tx` (periodic) | 1 per batch, amortised across all batch members | — |
| HTLC swap to zkCoins | 0 (uses existing Arkade primitives) + 1 zkCoins nullifier inscription (~64 bytes) | The HTLC sits inside the VTXO; the swap reveals the preimage but does not add an on-chain artifact beyond what zkCoins already publishes |
| zkCoins-internal transaction | ~64 bytes nullifier (per-tx, batched by publisher) | — |
| HTLC swap back to Arkade | 1 zkCoins nullifier (burn) + Arkade VTXO transfer (0 additional) | — |
| Arkade exit (collaborative) | 1 collaborative exit tx via `commitment_tx` add-output (Ark §4.5) | — |
| Arkade exit (unilateral) | `O(log t)` virtual txs | Only if operator stalls |

**Trust assumptions per step:**

- Onboarding / Arkade transfers / Arkade exit: Arkade rational
  operator + 1-of-n MuSig honesty (Ark §5 Table 1).
- HTLC swaps in either direction: standard HTLC trust model
  (no custody handoff possible without preimage reveal), bounded by
  `T_e` on the Arkade side and the publisher's nullifier-publication
  cadence on the zkCoins side.
- zkCoins-internal transfers: per [`SPEC.md`](./SPEC.md) — node-side
  compute correctness + Schnorr signature security.

§8 has the full trust-stacking analysis.

### 6.4 Layer 2a — Ark-aware BitVM bridge (1-2 years)

**[SPEC]** Speculative architectural sketch. Not in any roadmap as of
2026-05.

zkCoins Phase 2 ([`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md)) uses BitVM2 +
Groth16 verification to prove "this operator's payout tx is included
in a finalized Bitcoin chain" and authorise zkCoins-side mints from a
Bitcoin Light Client gadget. Mechanically, the same federation
infrastructure can also operate an Arkade instance:

- The same N-of-N MuSig2 vault key construction works for any
  custody role.
- The same Bitcoin Light Client gadget that verifies "BTC is locked
  in vault" can equally verify "the Arkade `commitment_tx` confirmed
  with batch β."
- An Arkade operator's liquidity-provision role overlaps with the
  BitVM2 operator's "front BTC, get reimbursed later" role.

The integration insight: peg-in becomes an Arkade boarding (cheap,
amortised) instead of a direct BTC tx. Peg-out frontruns an Arkade
VTXO transfer; user can unilateral-exit if the operator stalls. The
bridge's on-chain footprint reduces; the trust model does not change.

**Security model overlap.** Ark's rational-operator assumption gives
onramp safety (NS), Ark safety (AS), offramp safety (FS) without users
losing funds even under malice (Ark §5 Table 1). BitVM2's 1-of-N
setup honesty gives "no operator coalition can spend the vault
outside pre-signed paths" ([`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md) §3.2).
These are **independent** assumptions — Ark's holds for Ark, BitVM2's
holds for the peg. A federation that fails one role does not
compromise the other unless the same key material is at risk.

**Realistic horizon:** 1-2 years, gated on (a) BitVM2 production
maturity and Glock/Argo cost reductions making it economical at scale,
(b) Arkade multi-operator support reducing the operator-side
centralisation risk, (c) demand exceeding what a Layer 1 + Layer 2
bridge can serve. None of these are in zkCoins' control; this is a
"keep an eye on" path, not a sprint candidate.

### 6.5 Layer 2b — Confidential VTXOs (research, 1-2+ years)

**Open research, not engineering.** [SPEC]-grade content.

Arkade VTXOs are operator-visible by construction. The operator sees
plaintext amounts and recipient pubkeys to construct the VTXT, cosign
batches, and manage liquidity. End-to-end-encrypted communication
channels protect against passive observers but not the operator.

The question this section explores: could the operator be reduced to
cosigning *commitments* to amounts and recipients, with a ZK proof of
batch correctness?

A confidential-VTXO scheme would need:

1. **Pedersen commitments (or equivalent) on VTXO amounts.** Mature
   crypto; standard.
2. **Range proofs per VTXO.** Bulletproofs ~700 bytes/VTXO, or
   SNARK-compressed via the same PCD/Plonky2 stack zkCoins already
   uses (Shielded CSV §6.3).
3. **A ZK proof of correctness of the operator's signed batch.**
   "Sum of input commitments = sum of output commitments + fee" and
   "each output commitment is well-formed". The operator signs a
   circuit proof, not plaintext. Mathematically, this is exactly the
   PCD compliance predicate Shielded CSV uses for coins, lifted to
   batches.
4. **A redesigned forfeit mechanism.** The operator must be able to
   claim on double-spend without knowing the amount. This needs
   either a deterministic binding (commit-to-spend) or a separate
   amount-revelation in the forfeit-claim path. Genuinely new
   cryptography; no existing template.

**SP1 as the proving stack** would be the natural choice (zkCoins'
predecessor used SP1, locked at v4.1.2 per institutional memory;
current zkCoins uses Plonky2 per
[`CONTRIBUTING.md`](./CONTRIBUTING.md) invariant 5). A zkCoins-style
PCD layer over Arkade's batching is mathematically sensible — PCD is
the right abstraction for "validity proof composes over a DAG-shaped
state machine," which is exactly what Ark's VTXT is.

**Realistic assessment:**

- Without a Bitcoin soft fork (no Confidential Assets opcode, no
  Mimblewimble in Bitcoin Script) the privacy is *off-chain in Ark*
  but the on-chain `commitment_tx` still exposes the batch's input
  totals.
- The forfeit-mechanism redesign is paper-worthy new cryptography.
- 1-2 year research project. The Shielded CSV authors sit in
  exactly the right ecosystem to attack this; no public proposal as
  of 2026-05.

**This section is descriptive, not prescriptive.** zkCoins does not
take responsibility for confidential VTXOs; if Arkade or an external
research group ships them, the design space in §7 and §6.6 changes
favourably. We track the direction; we do not invest in it.

### 6.6 Layer 2c — Cross-asset DEX (12+ months, engineering not research)

Arkade Labs has launched **Arkade Assets**
([blog.arklabs.xyz — *Native Assets on Bitcoin: Introducing Arkade
Assets*](https://blog.arklabs.xyz/native-assets-on-bitcoin-introducing-arkade-assets/),
Oct 2025): TLV-encoded native assets in `OP_RETURN`, asset identifier
`(genesis_txid, group_index)`, transferred through VTXOs with operator
awareness. zkCoins is becoming permissionless multi-asset via
[`MULTI_ASSET.md`](./MULTI_ASSET.md) — anyone mints a token, identifier
is a Poseidon digest of genesis pre-image, transferred privately.

A swap between Arkade Asset X and zkCoins Asset Y is structurally
**A1 with two field substitutions**:

- The Arkade side encumbers an Arkade Asset (not bare BTC) with an
  HTLC. The Arkade compiler supports asset-flow validation
  (transaction introspection), so the HTLC enforces "send `v` units
  of `asset_id_A` to receiver on preimage reveal."
- The zkCoins side uses a 2-of-2 shared account holding `asset_id_B`.
  Multi-asset shared-account machinery works unchanged from the
  single-asset case ([`MULTI_ASSET.md`](./MULTI_ASSET.md) §4.4 — every
  state transition is single-asset, but shared accounts can hold any
  asset).

**Why this is novel** as a Bitcoin-native primitive:

- First publicly-described BTC-L1-only cross-asset swap involving a
  privacy-preserving asset (zkCoins-asset, hidden amount + sender +
  recipient) and an operator-visible asset (Arkade Asset).
- Composable: any Arkade Asset, any zkCoins asset. The matching
  engine sits off-protocol.
- A natural first cross-protocol DEX primitive for the
  "Bitcoin-native trustless DeFi" thesis.

**Honest framing.** This is **engineering, not research.** The crypto
already exists, the templates exist; what is missing is wiring +
a matching engine. Realistic in ~12 months of focused work after A1
ships and [`MULTI_ASSET.md`](./MULTI_ASSET.md) reaches steady state.
Tracked as decision A6.

---

## 7. Detailed Flow: HTLC Atomic Swap (Arkade BTC ↔ zkCoins)

This section is the implementation-grade specification of decision A1.
It mirrors the structure of
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) §8: detailed
flow, failure modes, trust argument.

### 7.1 Parties and pre-conditions

- **User (Alice):** Arkade wallet pointing at some Arkade instance,
  zkCoins wallet pointing at a zkCoins node, an existing zkCoins
  account.
- **Counterparty (Bob, "swap provider"):** Arkade wallet with VTXO
  inventory, zkCoins node with sufficient inventory in some operator
  account. May be the same operator that runs the Arkade instance and
  the zkCoins node, or a third party; the protocol does not require
  it.
- **Pre-agreed parameters:** swap amount `A`, provider fee `F`, the
  on-Arkade HTLC timeout `T_htlc`, the zkCoins-side recovery timeout
  `T_recovery` with `T_htlc < T_recovery`, both strictly less than the
  Arkade batch expiry `T_e`.

### 7.2 The asymmetry to resolve

Section 5.4 framed it; this section operationalises it.

An Arkade VTXO can encode an arbitrary Bitcoin Script — it is a
Taproot output with at minimum a cooperative path
(`checkSig(pkO ⊕ pkA)`), a unilateral exit path
(`checkSig(pkA) ∧ relTimelock(t_v)`), and any number of additional
script paths. The Arkade compiler ships an HTLC template natively
(`arkade-os/compiler` README):

```text
contract HTLC(pubkey sender, pubkey receiver, bytes hash, int refundTime) {
  function claim(signature receiverSig, bytes preimage) {
    require(checkSig(receiverSig, receiver));
    require(sha256(preimage) == hash);
  }
}
```

The HTLC compiles into a Taproot script-path. The VTXO retains its
operator + user collaborative path (so the operator can sign Alice's
spend cooperatively if she reveals the preimage in-protocol) and its
unilateral exit path (so Alice can take it on-chain if the operator
stalls).

A zkCoins coin **cannot** encode any spending condition. There is no
`script` field on `Coin`; the recipient check is hard-coded
([`program/src/lib.rs::apply_coin`](./program-plonky2/src/circuit/main.rs)).
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) §5.1–5.3
derives why this is load-bearing for the protocol; the conclusion
ports here unchanged.

### 7.3 Where atomicity lives

Per Shielded CSV §A.1.2 and [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md)
§5.4, atomicity for a zkCoins side participant must come from either:

1. **A 2-of-2 shared zkCoins account** with a pre-signed time-locked
   recovery to the original owner. Shielded CSV §5.1 (Shared Accounts)
   + §A.1.1 (Time-locked Transactions) provide the primitives.
2. **The Bitcoin funding transaction of the zkCoins inscription**
   carrying a script lock.

For Arkade ↔ zkCoins, **option 1 is the canonical choice**: it
mirrors the construction Shielded CSV §A.1.2 uses for Shielded-CSV ↔
Bitcoin/L2 atomic swaps, and it does not couple atomicity to the
publisher's inscription mechanics (which would force coordination
between the swap counterparty and the publisher).

Option 2 is preferred for Lightning swaps in
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) §6 because the
on-chain side there is bare Bitcoin without any other lever. For
Arkade swaps the Arkade VTXO is itself the script-bearing side; the
zkCoins side does not need to carry the HTLC.

### 7.4 Protocol steps

**Direction A — Alice has zkCoins, wants Arkade BTC. Bob has Arkade
BTC, wants zkCoins.** Alice generates the preimage.

```
Step 1. Alice generates preimage x ←$ {0,1}^256, computes H = SHA256(x).
        Alice sends to Bob:
          - H
          - alice_arkade_recipient_pubkey (for the VTXO claim)
          - amount A
          - alice_zkcoins_account_pubkey (for the 2-of-2 shared account)

Step 2. Alice and Bob set up the 2-of-2 zkCoins shared account:
          - Construct MuSig2 aggregate pubkey pkA⊕pkB
          - Alice prepares recovery_tx (zkCoins nullifier publication
            that returns the shared account's balance to Alice after
            block height h_recovery = current + T_recovery)
          - Alice signs her half of recovery_tx, sends to Bob
          - Bob signs his half (MuSig2 partial), aggregates
          - Alice now holds a valid recovery_tx she can publish after
            T_recovery

Step 3. Alice publishes the funding nullifier:
          - zkCoins transaction Alice → 2-of-2(pkA⊕pkB), amount A
          - Publisher batches the nullifier; coins land in the shared
            account on next inscription

Step 4. Bob constructs an Arkade VTXO with an HTLC encumbrance:
          - contract HTLC(sender=Bob, receiver=Alice, hash=H,
                          refundTime=current + T_htlc)
          - Cooperative-path: pkO⊕pkB (Bob can cooperate with operator
                              to refund after T_htlc, or to honour an
                              early settle)
          - Unilateral-path: pkB ∧ relTimelock(t_v) (standard Arkade
                              exit)
          - HTLC script-path (per Arkade Script template above) is the
            new addition
          - Bob boards the VTXO collaboratively with the Arkade operator

Step 5. Alice verifies the VTXO:
          - VTXO is in Arkade, value = A
          - HTLC script-path matches: H, refundTime, alice's pubkey as receiver
          - T_htlc < T_recovery (so Bob cannot refund the Arkade side
            after Alice has lost the recovery option)
          - T_htlc < T_e (so the cooperative-path stays live; if T_htlc
                          ≥ T_e the operator's sweep fires first and the
                          HTLC is moot)

        If any check fails, Alice aborts. Alice's funds are in the
        2-of-2 shared account; recovery_tx returns them after
        T_recovery. No loss to Alice.

Step 6. Alice claims the Arkade VTXO by revealing x:
        Option (a) — cooperative claim:
          - Alice asks the operator to cosign an Arkade transaction
            spending the VTXO via the HTLC script-path: input witness
            includes <alice_sig> <x>
          - Operator validates the script-path satisfaction (sha256(x)
            == H), cosigns
          - New VTXO with Alice's pubkey as cooperative-path key

        Option (b) — unilateral claim (if operator stalls):
          - Alice publishes the unilateral chain of Ark transactions
            (O(log t) txs from the batch root to her VTXO leaf)
          - Then publishes a Bitcoin tx spending her leaf VTXO via
            the HTLC script-path

        Either way, x is now public — on the Arkade transcript (option
        a, visible to the operator and any party watching Arkade) or
        on-chain (option b).

Step 7. Bob learns x. Bob uses x to take control of the 2-of-2 zkCoins
        shared account before T_recovery:
          - Bob constructs a zkCoins transaction that nullifies the
            shared account's balance to Bob's own zkCoins account
          - Requires MuSig2 signature with both pkA and pkB; Bob
            already has both pkA's contribution because the
            shared-account setup pre-shared signing material with the
            preimage-bound condition (this mirrors Shielded CSV §A.1.2's
            "Bob learns x, uses it as one factor in the MuSig2
            cooperative signature path")

Step 8. Bob's transaction publishes the nullifier. Shared account
        empty. Swap complete.
```

**Symmetric flow** for direction B (Bob has zkCoins, wants Arkade
BTC) inverts roles — Bob generates the preimage. The construction is
otherwise identical.

### 7.5 Failure modes

| Failure | Who has what | Recovery |
| ------- | ------------ | -------- |
| Alice aborts at Step 5 | Alice has shielded coins in 2-of-2 shared account; Bob has a VTXO encumbered by HTLC | Alice waits `T_recovery` and publishes `recovery_tx`. Bob's VTXO refunds via Arkade HTLC `refundTime`. Both made whole; small fees lost. |
| Bob never boards the HTLC-encumbered VTXO (Step 4) | Alice has funds in shared account, Bob has nothing | Same as above: Alice's `recovery_tx` after `T_recovery`. Bob has nothing to refund. |
| Operator refuses cooperative claim at Step 6(a) | Alice cannot get cooperative settlement | Alice falls back to unilateral claim (Step 6(b)), `O(log t)` virtual txs published on-chain. Preimage `x` becomes public. Bob still proceeds to Step 7. Higher cost to Alice. |
| Alice never claims the VTXO (Step 6 not executed) | Bob has VTXO locked in HTLC; Alice has shielded coins | Bob waits `T_htlc`, refunds the VTXO via Arkade HTLC `refundTime` path (cooperative with operator). Alice waits `T_recovery > T_htlc`, recovers shielded coins via `recovery_tx`. Both whole. |
| Bob never executes Step 7 (refuses to claim shared account after seeing `x`) | Alice has Arkade BTC, Bob has nothing on the zkCoins side; shared account still holds A | Alice's `recovery_tx` after `T_recovery` returns shielded coins to Alice. **Net: Alice has both A worth of Arkade BTC and A worth of shielded coins** — Bob's loss. Asymmetric incentive: Bob has no reason to do this. Documented as provider-side discipline. |
| Bob claims shared account via Step 7 but Alice never sent the VTXO claim | Cannot happen — Step 7 requires `x`, which only becomes public after Step 6 | — |
| Arkade operator goes offline between Step 4 and Step 6 | Same as "Operator refuses cooperative claim" — Alice unilateral-exits | Same recovery. |
| `commitment_tx` carrying the HTLC-VTXO does not confirm before `T_e` | The Arkade batch expires; operator sweeps; HTLC is moot | This is the canonical `htlc_timeout < T_e` constraint from Ark §6. Step 5 verifies it. If misconfigured, Alice's preimage-reveal becomes useless because there's nothing left to claim; she falls back to her zkCoins recovery_tx. |
| Both parties' refund txs race for the same block | Standard fee-management concern | Pre-sign with sufficient fee bumping; not a trust issue. |

### 7.6 Trust assumptions

At no point does either party transfer custody of an asset to the
other party where the other party can withhold reciprocation:

- Alice's funds in the 2-of-2 shared account are recoverable via
  `recovery_tx` after `T_recovery` — Bob cannot block this.
- Bob's VTXO encumbered by HTLC is recoverable via `refundTime`
  after `T_htlc` (cooperative with operator, or unilateral exit) —
  Alice cannot block this.
- `T_htlc < T_recovery` ensures Bob's refund window closes before
  Alice's recovery window opens, so the swap is timing-safe: if Alice
  claims, Bob has time to learn `x` and execute Step 7 before
  `T_recovery`; if Bob refunds, Alice has not yet given up her recovery.

**The trust assumptions are independent in each leg.** Alice trusts
the Arkade operator's rationality for the cooperative-claim path
(falls back to unilateral exit if violated). Alice trusts the zkCoins
publisher's liveness for the inscription publication (falls back to a
different publisher; any party can publish). Alice trusts neither Bob
nor the operator with custody — preimage-bound timeouts enforce
correctness.

### 7.7 Latency and costs

**Latency (happy path, cooperative claim):**

- Step 1–2 (shared-account setup): one round of MuSig2 messages
  (sub-second over the wire).
- Step 3 (funding nullifier): one Schnorr-signed inscription,
  bounded by zkCoins publisher cadence + Bitcoin confirmation depth
  needed for the swap timing model (typically 1–6 confirmations).
- Step 4 (VTXO with HTLC): one Arkade boarding round, bounded by
  Arkade operator's batch cadence.
- Step 6(a) (cooperative claim): one Arkade transaction, sub-second
  preconfirmation.
- Step 7 (shared-account claim): one zkCoins inscription, bounded by
  publisher cadence.

**Total wall-clock for happy path:** dominated by zkCoins inscription
confirmation. Per [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md)
§14 the conservative envelope is on the order of an hour for
end-to-end Bitcoin-confirmation safety; pre-D7 the same envelope
applies here.

**Costs (per swap):**

- Arkade side: one VTXO worth of liquidity locked for `T_htlc`;
  Arkade transaction fees (typically negligible inside Arkade).
- zkCoins side: two inscriptions (funding + claim), each ~64 bytes
  amortised plus the publisher's overhead.
- Counterparty fee `F`: market-set, comparable to Boltz fees.

**Pessimistic path** (unilateral exit, dispute) costs an extra
`O(log t)` virtual transactions on the Arkade side. This is the
standard Ark exit cost (Ark §2.3) and is borne by whoever invokes the
unilateral path.

---

## 8. Trust-model stacking

The combined stack inherits the union of both protocols' trust
assumptions. Understanding what depends on what is the key to
reasoning about real-world security.

### 8.1 Independent assumptions

| Component | Assumption | Effect of violation |
| --------- | ---------- | ------------------- |
| Arkade operator (rational) | Operator follows protocol | Operator loses their own funds, not users'; users still exit (Ark §5 Table 1) |
| Arkade operator (malicious) | Operator deviates | NL, FL still hold; NS, AS, FS violations cost the operator, not users |
| Arkade MuSig2 covenant emulation | 1-of-n VTXO holders + operator follow signing protocol | VTXT well-formed (Ark §3.2, §4 Remark 4.5) |
| zkCoins node-side compute | Node runs the published Plonky2 circuit honestly | Per [`CONTRIBUTING.md`](./CONTRIBUTING.md) invariant 1 + invariant 2; closed test environment today, in-circuit verification long-term |
| zkCoins Schnorr signatures | BIP-340 / secp256k1 secure | Standard Bitcoin cryptographic assumption |
| zkCoins publisher liveness | Some publisher willing to inscribe | Permissionless — alternative publishers can take the nullifier |
| zkCoins bridge Phase 1 (federation) | M-of-N federation honesty ([`BRIDGE_MVP.md`](./BRIDGE_MVP.md)) | M+ colluders can steal BTC reserves; zkCoins-side internal transfers unaffected |
| zkCoins bridge Phase 2 (BitVM2) | 1-of-N setup honesty ([`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md)) | If all N are malicious at setup, vault parameters can be compromised; once setup completes, peg-out paths are public and trustless |
| Bitcoin L1 | Bitcoin's PoW + censorship resistance | Catastrophic for both protocols; outside the design space |

### 8.2 Composition for §7's HTLC swap

The HTLC atomic swap of §7 requires:

- Arkade rational operator (so cooperative claim works; unilateral
  fallback if violated).
- Bitcoin L1 (for confirmation of the inscriptions and any unilateral
  Arkade exit).
- zkCoins node-side compute (so the publisher accepts and processes
  the nullifier).
- BIP-340 Schnorr security (for both sides' signatures).

It does **not** require:

- A zkCoins bridge to be running. The swap is BTC-pegged on the
  Arkade side and uses zkCoins-internal coins on the other side; the
  bridge only matters if one party wants to convert between zkCoins
  shielded coins and real BTC outside the swap.

### 8.3 Composition for §6.3's pipeline

The pipeline composes:

- Arkade onboarding → Arkade rational operator + Bitcoin L1
- §7 HTLC swap into zkCoins → as in §8.2
- zkCoins-internal transfers → zkCoins node-side compute + Schnorr
- §7 HTLC swap out of zkCoins → as in §8.2
- Arkade exit → Arkade rational operator (cooperative) or pure Bitcoin
  L1 (unilateral)

Each step's failure mode is independent; nothing chains a failure
into a worse failure downstream. The pipeline is no less secure than
its weakest leg.

### 8.4 Composition for §6.4's Ark-aware BitVM bridge

If the same federation operates the BitVM2 bridge and an Arkade
instance, both assumptions still apply independently:

- Federation as Arkade operator: rational-operator assumption (Ark
  §5).
- Federation as BitVM2 bridge: 1-of-N setup honesty ([`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md)
  §3.2).

A federation that defects on its Arkade role (steals from itself, since
Ark §5 says the operator can only harm itself under malice) does not
compromise its BitVM2 role unless the same key material is involved.
The design discipline is to keep the key material separate. With
discipline, the trust assumptions do not collapse.

---

## 9. Personnel and ecosystem signal

The author overlap between the two protocol families is real and
load-bearing for the "designed to interlock" hypothesis. Worth
naming explicitly so the implication is not over-claimed.

**Shielded CSV (ePrint 2025/068):** Jonas Nick (Blockstream), Liam
Eagen (Alpen Labs), Robin Linus (ZeroSync; BitVM creator).

**BitVM / BitVM2:** Robin Linus (lead), Lukas Aumayr, Zeta Avarikioti,
Matteo Maffei, Andrea Pelosi, Christos Stefo, Alexei Zamyatin (cited
as ref [1] in Ark whitepaper itself).

**Ark whitepaper:** Marco Argentieri, Zeta Avarikioti, Andrew
Camilleri, Pim Keer, Matteo Maffei (Ark Labs + TU Wien). **Zeta
Avarikioti and Matteo Maffei co-author both the BitVM eprint and the
Ark litepaper.** TU Wien is the institutional connector.

**Glock (Jan 2026):** Robin Linus + Liam Eagen + others (Alpen Labs).
~430× cost reduction over BitVM2.

**Argo (Jan 2026):** Robin Linus, Liam Eagen, Ying Tong Lai. ~2000×
cost reduction over BitVM3.

**Translation.** The same ~5 people — Linus, Eagen, Nick, Avarikioti,
Maffei — are simultaneously authoring the BitVM bridge tech (which
zkCoins Phase 2 depends on), the Shielded CSV protocol (which zkCoins
implements), the Ark batching layer (which Arkade implements), and the
next-generation bridge tech (Glock, Argo) that obsoletes BitVM2 in
1-2 years. They are deliberately building an interlocking stack.

**Public statements explicitly combining Arkade and zkCoins**: none
found as of 2026-05.

- Robin Linus' widely-cited quote — *"Shielded CSV is the most
  interesting thing you can do with BitVM"* — signals the bridge-via-BitVM
  intent that [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md) is built on. It
  does not mention Ark.
- Ark whitepaper §6 lists "escrows, DLCs, payment channels" as Ark
  applications. It does not mention Shielded CSV.
- Shielded CSV paper does not mention Ark.
- Both papers cite each other's adjacent ecosystem work (Lightning,
  BitVM) but not each other.

**The signal is institutional, not textual.** The same labs and people
are shipping both stacks within ~1–2 years of each other; the
integration is implicit in the personnel and the layered protocol
design, not declared in the literature. Frame accordingly: a high
prior that integration tooling will emerge from the same ecosystem,
**not** a documented unified roadmap to cite.

---

## 10. Open Questions

### 10.1 PTLC vs. HTLC for the swap (§7)

§7 uses HTLC (SHA256 preimage). PTLC (point time-locked contract,
Schnorr adaptor signature) would give better on-chain privacy by
making the swap claim indistinguishable from a single-sig spend.

- **Choice in doc:** HTLC. Production-ready toolchain, Arkade compiler
  ships it, identical trustlessness, identical timing logic.
- **Alternative:** PTLC. Better privacy on the Arkade side; requires
  adaptor-signature support in the Arkade compiler (an SDK feature,
  not a Bitcoin Script change).
- **Trade-off:** PTLC reduces the on-chain analysability of swap
  claims but does not change the security argument. Mirror of the
  HTLC-vs-PTLC discussion in [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md)
  §7.3. PTLC is a v2 upgrade once Arkade's compiler ships adaptor
  signatures; not a v1 dependency.

### 10.2 Timing parameter selection (`T_htlc`, `T_recovery`, `T_e`)

§7.1 prescribes `T_htlc < T_recovery < T_e`. Concrete values are
deployment-dependent.

- **Choice in doc:** the inequalities are protocol-required; the
  numeric values are operational.
- **Trade-offs:** longer windows give users more time to act before
  refund/recovery fires (good UX, more fee-bump headroom); shorter
  windows reduce capital-lockup costs for swap counterparties (better
  liquidity efficiency). Arkade's `T_e` is operator-set (Ark §4.4);
  the swap design must adapt to whatever the chosen Arkade instance
  uses. Recommended starting points: `T_e` = 1 week (typical Arkade
  operator default), `T_recovery` = 24 hours, `T_htlc` = 12 hours.
  Operators should publish their chosen values and update wallets
  via capabilities flag.

### 10.3 Counterparty discovery / matching engine

§7 assumes Alice and Bob found each other. In practice, swap
counterparties need a matching engine.

- **Choice in doc:** out of scope for this design doc. Treat as a
  separate piece of infrastructure (analogous to Boltz' role for
  submarine swaps).
- **Trade-off:** centralised matching engines (a website that lists
  liquidity providers) are operationally trivial but introduce a
  liveness dependency. Decentralised matching (DHT-based or LN-routing-style)
  is research. For v1, centralised matching is the obvious choice.

### 10.4 Cooperative vs. unilateral default at Step 6

§7.4 Step 6 distinguishes (a) cooperative Arkade claim via the
operator and (b) unilateral on-chain claim. Cooperative is sub-second
and cheap; unilateral is slow and costs `O(log t)` virtual txs.

- **Choice in doc:** wallet defaults to cooperative, falls back to
  unilateral on operator timeout.
- **Trade-off:** the cooperative path leaks the preimage to the
  Arkade operator (operator sees the script-path satisfaction during
  cosigning); the unilateral path leaks it on-chain to any observer.
  Either way the preimage becomes public, which is what enables Step 7
  — there is no privacy-preserving variant short of PTLC.

### 10.5 Pipeline `recovery_tx` lifecycle

In §6.3's pipeline, the user has a `recovery_tx` pre-signed for each
HTLC swap into and out of zkCoins. These accumulate as the user moves
between systems.

- **Open:** wallet-side hygiene. Should the wallet auto-execute
  `recovery_tx` when it observes the corresponding swap completed
  successfully on the other side? Auto-nullify the recovery to free
  the shared account?
- **Recommendation:** track as `zk-coins/app` wallet UX issue once
  A1 lands; not a node-side concern.

### 10.6 Multi-asset semantics in A1 (vs. A6)

A1 explicitly scopes to BTC-pegged swaps. A6 generalises to Arkade
Asset ↔ zkCoins Asset.

- **Open:** is there a clean upgrade path from A1 to A6, or does the
  multi-asset variant want different swap mechanics?
- **Speculation:** the §7 construction generalises straightforwardly
  if both sides agree on the asset_id mapping out-of-band. The
  matching engine (§10.3) becomes the natural place to declare
  "Arkade Asset X ↔ zkCoins Asset Y" pairs. Confirm during A6 design.

### 10.7 D7 reorg safety dependency

[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) §15 names
D7 reorg safety as a zkCoins-side blocker that lengthens swap
wall-clock time. The same dependency applies to the §7 HTLC swap.

- **Choice in doc:** until D7 lands, the swap design adds Bitcoin
  confirmation-depth requirements before either party considers an
  inscription settled. Tracked as a cross-document dependency; not a
  blocker for the integration design.

---

## 11. Implementation Order

Phased rollout, mapped to discrete milestones. Effort estimates per
the convention in [`BRIDGE_MVP.md`](./BRIDGE_MVP.md) §12.1 (S = small,
M = medium, L = large, XL = extra large). All phases assume A1 has
been locked in this document and a separate implementation spec has
been opened.

| Phase | Scope | Effort | Risk |
| ----- | ----- | ------ | ---- |
| **P0 — Approval of this design** | Maintainer locks A1–A6; this document moves from "draft" to "approved". | **S** | None |
| **P1 — Implementation spec for §7 HTLC swap** | New sibling doc `ARKADE_HTLC_SWAP.md` (or extension to this document) specifying: zkCoins wire-protocol for shared-account funding, Arkade compiler HTLC parameterisation, swap-counterparty API, recovery-tx persistence model, wallet UX. Mirror of the relationship between [`BRIDGE_MVP.md`](./BRIDGE_MVP.md) and [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md). | **M** | Low |
| **P2 — zkCoins shared-account primitive** | Implement 2-of-2 MuSig2 shared accounts in `zk-coins/node` (a prerequisite that does not exist today; [`SPEC.md`](./SPEC.md) §3 single-account-per-pubkey model needs extension). Shielded CSV §5.1 has the protocol-level construction. Persistence, recovery-tx pre-signing, capabilities-flag gating. | **L** | Medium — touches account-state model |
| **P3 — Arkade swap-counterparty service** | Off-protocol service (likely a separate small Rust crate) that runs as a liquidity provider: monitors Arkade for HTLC-encumbered VTXOs matching swap requests, drives the §7 protocol, signs MuSig2 partials, executes claims. Could be merged into `arkd` upstream or live as a separate binary. | **L** | Medium — coordination across two systems |
| **P4 — Wallet integration** | `zk-coins/app` wallet learns the swap UX: pick direction, see liquidity, monitor swap status, auto-execute recovery if needed. Mirror of pattern for [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) wallet integration. | **L** | Medium — UX-heavy |
| **P5 — End-to-end test suite** | Mutinynet + Arkade testnet integration tests, single-counterparty happy path + all failure modes from §7.5. Coverage gate per [`CONTRIBUTING.md`](./CONTRIBUTING.md) invariant 4. | **M** | Low |
| **P6 — Pipeline orchestration (§6.3)** | Wallet-side multi-step flow combining Arkade boarding + swap-in + swap-out + Arkade exit. UX work, no new protocol. | **M** | Low |
| **P7 — A6 multi-asset variant** | Generalise the §7 construction to Arkade Asset ↔ zkCoins Asset. Depends on [`MULTI_ASSET.md`](./MULTI_ASSET.md) reaching steady state and Arkade Assets being beyond beta. | **L** | Medium — combinatorial test surface |
| **P8 — A5 BitVM bridge convergence (optional)** | Design + implementation of the Ark-aware BitVM bridge sketched in §6.4. Depends on Phase 2 BitVM bridge being live and Arkade multi-operator support. | **XL** | High — multi-protocol surgery |

**Aggregate effort for P1–P6 (the A1 implementation path): S + M + L
+ L + L + M + M ≈ 4-6 person-months at focused effort.** P7 and P8
are explicitly post-A1 and gated on external dependencies.

Per [`CONTRIBUTING.md`](./CONTRIBUTING.md) invariant 4, every phase
ships with 100% test coverage on the activated surface. Negative
tests — every failure-mode row in §7.5 must be reproducible in
integration tests — are mandatory.

---

## 12. Non-Goals (Restated)

So nobody scope-creeps:

- **Modifying the Arkade protocol** — not in scope. The integration
  uses Arkade as it ships.
- **Modifying the Shielded CSV protocol or zkCoins circuit** — not
  in scope (decision A2). No 12th divergence in [`SPEC.md`](./SPEC.md)
  §15.
- **Confidential VTXOs** — not in scope (decision A4). Research
  direction tracked; no zkCoins-side investment.
- **Building a decentralised swap-counterparty matching engine** —
  not in scope (§10.3). Centralised matching is fine for v1.
- **PTLC-based swap variant** — not in v1 (§10.1). HTLC ships first;
  PTLC is an upgrade.
- **Federation operating both Arkade and BitVM2 bridge** — not in
  scope as an A1 deliverable (decision A5 + §6.4). Tracked as a
  potential 1-2 year roadmap item, depends on Arkade multi-operator
  maturity.
- **Generic cross-chain swaps** (Liquid, RSK, sidechains) — out of
  scope. Different trust model, different document.

---

## 13. References

**Papers:**

- Argentieri, Avarikioti, Camilleri, Keer, Maffei. *Ark: A UTXO-based
  Transaction Batching Protocol.* Ark Labs & TU Wien, 2024.
  Local: `research/upstream/` or
  [`assets.arklabs.xyz/ark-protocol.pdf`](https://assets.arklabs.xyz/ark-protocol.pdf).
  Cited sections: §2 (overview), §3.2 (covenants), §4 (Ark
  construction; Definition 4.1 VTXO, Definition 4.9 commitment
  transaction), §4.3 (batch swaps, forfeit transactions), §4.4
  (commitment transactions), §4.5 (boarding and leaving), §5
  (security; Table 1), §6 (applications and HTLC/DLC/channel caveat),
  §7 (discussion: centralisation, preconfirmation, liquidity).
- Nick, Eagen, Linus. *Shielded CSV: Private and Efficient Client-Side
  Validation.* ePrint 2025/068.
  Local: `research/shieldedcsv-paper.pdf`.
  Cited sections: §1.1 (privacy, blockchain efficiency, trustless
  publishing), §4.2 (CoinEssence, accumulator value), §5.1 (shared
  accounts), §6 (discussion), §A.1.1 (time-locked transactions),
  §A.1.2 (atomic swap with Bitcoin/L2), §A.1.3 (multi-asset).

**Sibling design docs (this branch):**

- [`SPEC.md`](./SPEC.md) — single-asset zkCoins protocol specification
- [`MULTI_ASSET.md`](./MULTI_ASSET.md) — permissionless multi-asset
  extension (decision M5 defers cross-asset trading; this document is
  one of the three out-of-protocol DEX layers)
- [`BRIDGE_MVP.md`](./BRIDGE_MVP.md) — Phase 1 federation bridge
- [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md) — Phase 2 BitVM2 trustless
  bridge
- [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) — Lightning
  atomic-swap layer (closest structural sibling to this document)
- [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md) — Plonky2 migration
  rationale; §5 (locked decisions) and §7 (lessons learned) supply the
  decision-recipe pattern used in §3 here
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — project invariants,
  pre-push checklist

**External references:**

- Arkade Labs blog — [*Press Start — Arkade Goes Live*](https://blog.arklabs.xyz/press-start-arkade-goes-live/)
- Arkade Labs blog — [*Native Assets on Bitcoin: Introducing Arkade
  Assets*](https://blog.arklabs.xyz/native-assets-on-bitcoin-introducing-arkade-assets/)
- Arkade Labs blog — [*Closing the Lightning Loop*](https://blog.arklabs.xyz/closing-the-lightning-loop-bitcoins-missing-layer-secretly-goes-live/)
- Arkade docs — `docs.arkadeos.com` (HTLC template, Escrow, Spilman
  channel, Dryja-Poon channel, Lightning swaps, Arkade Script)
- Arkade compiler — [arkade-os/compiler](https://github.com/arkade-os/compiler)
- Arkade daemon — [arkade-os/arkd](https://github.com/arkade-os/arkd)
- BitVM bridge whitepaper — [bitvm.org/bitvm_bridge.pdf](https://bitvm.org/bitvm_bridge.pdf)
- Shielded CSV publishing site — [shieldedcsv.org](https://shieldedcsv.org)

---

## 14. Change Log

| Date | Change |
| ---- | ------ |
| 2026-05-23 | Initial draft. Locked decisions A1–A6; HTLC atomic-swap protocol of §7; pipeline use of §6.3; trust-model stacking of §8. |
