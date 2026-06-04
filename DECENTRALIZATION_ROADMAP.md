# Decentralization Roadmap

> **Target state:** zkCoins is **fully trustless and decentralized under the run-your-own-node model** — see the **Trust model** section in [`CONTRIBUTING.md`](./CONTRIBUTING.md). This document is the gap analysis and execution plan to get there, anchored to the divergence list in [`SPEC.md`](./SPEC.md) §15.

## North star

There is no node consensus and no privileged operator. **Bitcoin is the only shared layer.** A self-hosted node:

1. derives all global state (commitment + nullifier history) **itself** by scanning Bitcoin, and
2. **verifies every proof it accepts** — it never trusts another node's assertion.

"The wallet trusts the node" is not a compromise: the node is _yours_, exactly as a Bitcoin wallet trusts your own `bitcoind`. Decentralization work is therefore about making a self-hosted node **fully self-sufficient and verifying** — not about moving logic into the wallet.

Issuance is **native** (a transparent on-protocol act — e.g. minting your own asset). There is **no BTC peg in scope**; pegging real BTC is an orthogonal concern.

## Where we are today (baseline)

- **Single-node-correct.** Mint → send → receive work; soundness holds _within one node's view_.
- **Receive is under-verified.** `account_node.rs::receive_coin_into` checks only the coin's **inclusion proof** against `output_coins_root` taken from the proof's public inputs — it does **not** re-verify the recursive Plonky2 proof, nor that `output_coins_root` is anchored on Bitcoin. Fine when the same node produced the proof; a hole for trustless cross-node receive. (`Prover::verify` exists — [`script-plonky2/src/lib.rs`](./script-plonky2/src/lib.rs) — and the warm prover lives in `AppState`, so verification is wireable.)
- **Permissionless multi-asset shipped (#191).** `asset_id = Poseidon(creator_pubkey, name, decimals)`, per-asset balances — but **off-circuit (trusted) mint**: _"trust in the asset = trust in the creator."_ Supply is not auditable in-circuit.
- **SPEC §15 divergences open:** D2/D10 (recipient plaintext — privacy), D7 (no reorg safety), D8 (no nullifier-accum snapshot — soundness), D11 (hard-coded issuance), D6 (no publisher fee).

## The decentralization invariant

> A self-hosted node must be able to validate everything it relies on from **(Bitcoin it sees itself) + (the proof in hand)** — never from another node's word.

Every strand below moves a guarantee from "trusted because one node said so" to "verified from Bitcoin + a proof."

## Strands

Each strand: problem → SPEC anchor → change → acceptance → depends on.

### S1 — Trustless receive (keystone)

- **Problem:** a receiving node trusts the sender's proof outputs instead of verifying them.
- **Anchor:** implementation gap; consumes the chain-derived state of SPEC §D4 (`SMT(H(pk) → H(asth ‖ ocr))`).
- **Change:** in `receive_coin_into` / the `/api/receive` path:
  1. Verify the recursive proof with the node's `VerifierCircuitData` (`Prover::verify`).
  2. **Anchor it:** require that `H(account_state_hash ‖ output_coins_root)` is present in the node's **chain-derived** commitment SMT at the sender's `H(pk)` — i.e. the outputs were actually committed on Bitcoin, not merely asserted.
  3. Keep the existing inclusion check and coin-history replay check.
- **Acceptance:**
  - A received coin is rejected if (a) the recursive proof fails, (b) `H(asth‖ocr)` is absent from the chain-derived commitment history, (c) inclusion fails, or (d) the coin already exists in coin-history (replay). One negative test per path.
  - A node that did **not** produce the coin can accept it purely from (proof + its own Bitcoin-derived state).
  - 100% coverage on the new surface; heavy tests green.
- **Depends on:** nothing (foundation).

### S2 — Global double-spend defense (D8)

- **Problem:** double-spend is checked only against one node's local view; coins carry no portable nullifier-accumulator snapshot.
- **Anchor:** **D8** — _must-fix pre-mainnet, soundness._
- **Change:** add a `nullifier_accum` snapshot to `Coin`; the receiver verifies the snapshot against its own chain-derived nullifier history; the circuit binds the snapshot.
- **Acceptance:** a coin whose snapshot is not in the receiver's history is rejected; cross-global replay is detected without trusting the sender's node; coverage + heavy tests green.
- **Depends on:** S1.

### S3 — Reorg safety (D7)

- **Problem:** a Bitcoin reorg can silently invalidate a coin's parent commitment.
- **Anchor:** **D7** — _must-fix pre-mainnet, reorg safety._
- **Change:** `conditional_nav` — a tx degrades to a no-op if its claimed nullifier-accum is no longer a prefix of the canonical chain after a reorg.
- **Acceptance:** a simulated-reorg test turns an affected tx into a no-op rather than corrupting state; coverage + heavy tests green.
- **Depends on:** S2.

### S4 — Own chain view (node self-sufficiency)

- **Problem:** the node reads Bitcoin via a (possibly third-party) Esplora; trustless requires your own chain.
- **Anchor:** implementation/infra (not a SPEC divergence).
- **Change:** support an own `bitcoind` + local inscription index as the scanner source; document genesis bootstrap (reconstruct commitment + nullifier history from block 0) with no trusted checkpoint.
- **Acceptance:** a fresh node with an empty DB reconstructs the full commitment + nullifier history from a local Bitcoin node alone; the chain source is a single config value; no remote Esplora is required for correctness.
- **Depends on:** S1 (so reconstructed state is actually verified on use).

### S5 — Trustless emission (D11)

- **Problem:** issuance is an off-circuit signature by a privileged minter; under hidden amounts the supply is not auditable.
- **Anchor:** **D11** — _deferred → now in scope._ Builds on #191's `asset_id`.
- **Change:** replace the off-circuit mint with an in-circuit `issuance(IssuanceProof)` branch; make each issuance a **transparent** event and enforce **conservation** in-circuit so total supply is publicly auditable from the asset's genesis. The mint capability is provably constrained (capped or transparently tracked), not "trust the creator."
- **Acceptance:** total supply of an asset is derivable from public issuance events; no hidden inflation is possible even by the creator; per-asset conservation enforced in-circuit; negative test for over-issuance; coverage + heavy tests green.
- **Depends on:** circuit surface; independent of S1–S4 but shares the public-input layout — coordinate with S2 to avoid churn.

### S6 — Recipient hiding (D2/D10) — privacy track (parallel)

- **Anchor:** **D2/D10** — _must-fix pre-mainnet, privacy._ For a self-hoster privacy already holds (your node); D2/D10 hide the recipient from **other** on-chain observers.
- **Change:** `coin.essence.address = Commitment::commit(acct_id, rand)`; `apply_coin` opens the commitment with witnessed randomness instead of a plaintext equality check.
- **Acceptance:** the recipient is not derivable from on-chain data; coverage + heavy tests green.
- **Depends on:** independent; coordinate circuit changes with S2/S5.

### S7 — Publisher incentive (D6) — censorship economics (later)

- **Anchor:** **D6.** Permissionless publishing needs a fee, else liveness leans on one operator.
- **Change:** `fee` field + reserved `FEE_IDX` payout; permissionless publisher batching.
- **Acceptance:** a third-party publisher can batch + broadcast nullifiers and be paid; censorship by any single node is bypassable.
- **Depends on:** S2 (nullifier model).

## Sequencing

```
S1 trustless receive ─► S2 D8 double-spend ─► S3 D7 reorg ─► S4 own chain view
                              │
S5 D11 trustless emission ── parallel (shares circuit surface) ──┘
S6 D2/D10 recipient hiding ── parallel privacy track
S7 D6 publisher fee ── after S2 (censorship economics)
```

**Rationale:** S1 is the keystone — until the node verifies what it accepts, every other guarantee is only as strong as a trusted peer. S2/S3 complete soundness, S4 removes the last external dependency, S5 makes issuance trustless, S6/S7 round out privacy and censorship-resistance.

## Definition of done ("trustless + decentral")

A self-hosted node, given only its own Bitcoin full node + the coin data it holds:

- verifies every coin it accepts (recursive proof + on-chain anchoring + global non-double-spend), trusting no other node;
- reconstructs all global state from Bitcoin with no trusted checkpoint;
- issues assets whose supply is publicly auditable;
- and the user custodies their own coin data — the one inherent, non-trust trade-off (see the Trust model).

## Out of scope (orthogonal)

- **BTC peg / bridge** — issuance is native; pegging real BTC is a separate concern (BitVM / a Bitcoin soft-fork), not required for protocol trustlessness. See [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md).
- **Cross-node name coordination** — `asset_id` is already coordination-free; a global name registry is tracked separately (#170 P5).
- **Data-availability service** — coin data is self-custodied by design; a DA committee would re-introduce trust.
