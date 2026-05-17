# Lightning ↔ zkCoins Atomic Swap — Design Document

**Status:** Design draft. No code yet. Companion to `SPEC.md`,
`MIGRATION_RESEARCH.md`, and `ROADMAP.md`. Authoritative source for
*how* trustless LN ↔ zkCoins swaps work, *not* for the wider zkCoins
protocol itself.

> **Branch note.** This document presupposes the Plonky2 migration
> currently on `feat/plonky2-migration` (PR #17). `SPEC.md`,
> `MIGRATION_RESEARCH.md`, and `ROADMAP.md` live on that branch and
> will resolve on `develop` only after PR #17 lands. Until then, view
> cross-references against `feat/plonky2-migration`.

**Audience:** Engineers picking up swap implementation. Assumes familiarity
with `SPEC.md` (account model, coin format, inscription mechanics) and
basic Bitcoin/Lightning HTLC mechanics.

---

## 1. Scope

This document specifies the design of **trustless atomic swaps** between
Lightning Network bitcoin and zkCoins. It covers:

- Why the swap mechanism cannot live on the zkCoins coin layer
- Where the atomicity primitive actually lives (the Bitcoin funding tx of
  the `4242`-prefix Taproot inscription)
- Two concrete swap directions (LN → zkCoins, zkCoins → LN) with full
  step-by-step protocols
- Bitcoin script construction and timing coordination
- Failure-mode analysis and recovery paths
- Provider operational considerations
- Privacy analysis
- The single open zkCoins-side dependency (D7 reorg safety) that affects
  swap timing but not swap design

It does **not** cover:

- Generic cross-chain swaps not involving Lightning
- BitVM-style federated bridges (different trust model, different
  document)
- Implementation in any specific language or repository layout

---

## 2. Executive Summary

A trustless atomic swap between LN and zkCoins is **buildable with
today's Bitcoin/Lightning toolchain**, using a standard HTLC on the
Bitcoin funding tx of the zkCoins inscription. The construction is
isomorphic to a Boltz reverse-submarine swap with one twist: instead of
the on-chain side being a P2WSH that pays bitcoin to the user, it is a
P2WSH/P2TR whose spend includes the zkCoins inscription payload in its
witness data.

The swap design is **orthogonal to the Plonky2 migration** (PR #17). The
24-hour LN CLTV budget dwarfs even SP1's minute-scale proof times by
three orders of magnitude; sub-second proofs are nice-to-have, not a
gating factor.

The **only zkCoins-side blocker** is D7 (reorg safety, see `SPEC.md` §15,
`MIGRATION_RESEARCH.md` D7). Until D7 is fixed, the provider must wait
for deep Bitcoin confirmation of the inscription before settling the
Lightning side, lengthening the swap's wall-clock time but not affecting
correctness or trust.

PTLCs (point time-locked contracts) would be an upgrade — better on-chain
privacy, fungibility with normal single-sig spends — but are not
required for trustlessness and not available in production Lightning
implementations as of 2026-05.

---

## 3. Problem Statement

A user wants to convert between Lightning bitcoin and a zkCoins coin
without trusting any single counterparty with custody of either asset at
any point during the swap. Equivalently:

- If the user's funds leave Lightning, zkCoins must arrive in their
  account, or the user can recover the Lightning funds via timeout.
- If the user's zkCoins leave their account, Lightning bitcoin must
  arrive, or the user can recover the zkCoins via some refund path.

Symmetrically for the swap provider.

The "single counterparty" referred to is a swap provider (a liquidity
operator who runs both a zkCoins server and a Lightning node), analogous
to Boltz's role in BTC ↔ LN submarine swaps.

---

## 4. zkCoins Architecture Recap (Constraints Relevant for Swaps)

### 4.1 Coin model

Per `SPEC.md` §3.2 and `program/src/lib.rs::Coin`:

```rust
struct Coin {
    identifier: HashDigest,    // = H(sender_next_asth ‖ u32_be(idx))
    recipient:  HashDigest,    // = H(initial_pubkey) of the recipient account
    amount:     u64,
}
```

There are **no spending conditions, no scripts, no hash-locks, no
time-locks** on a zkCoins coin. The only constraint enforced at receive
time is `apply_coin`'s `coin.recipient == self.owner` check
(`program/src/lib.rs:154`). This matches the upstream Shielded CSV
paper's `CoinEssence` (pure value transfer) — see
`MIGRATION_RESEARCH.md` §2.

**Implication:** a zkCoins coin cannot, by itself, carry HTLC semantics.
There is no protocol-level way to say "this coin can only be spent by
revealing preimage `x` such that `H(x) = H`".

### 4.2 Send mechanics

Per `SPEC.md` §5 and §11:

1. The sender's server generates a state-transition proof (`ProofData`)
   covering balance update, output coin creation, and history extension.
2. The sender's wallet signs `SHA256(serialize(asth) ‖ serialize(ocr))`
   with BIP-340 Schnorr.
3. The server (or any party with the signed `Commitment`) constructs a
   Taproot commit-reveal pair where the commit tx's txid hex begins
   with `4242`, and the reveal tx's witness contains the inscription
   payload (signed `Commitment`).
4. Both txs are broadcast to Bitcoin.
5. The scanner picks up `4242`-prefix commit-txs, extracts inscription
   content from the corresponding reveal-tx, deserialises as
   `Commitment`, verifies the Schnorr signature, and inserts the
   commitment into the global SMT.

**Implication 1:** the inscription publication is a **plain Bitcoin
transaction**. It can have any standard Bitcoin script lock on its
inputs.

**Implication 2:** the "moment of finality" for a zkCoins send is when
the scanner has processed the inscription. That is a function of (a)
the reveal-tx getting sufficient Bitcoin confirmations and (b) the
scanner running. Until then, the send has not happened from the
recipient's perspective.

### 4.3 What the wallet knows vs. what the server knows

- **Wallet:** holds the account commitment private key; signs the
  Schnorr commitment over `SHA256(asth ‖ ocr)`. Holds no Poseidon
  state, no SMT/MMR data.
- **Server:** holds the entire state (SMT + MMR), generates proofs,
  holds the inscription-publishing Bitcoin wallet, runs the scanner.

This split is locked by the server-side-compute architecture decision
(`MIGRATION_RESEARCH.md` §5; `feedback_zkcoins_server_side_compute`).

For swap design this matters because:

- Anything that requires "the wallet signs after seeing something" is
  cheap (one round-trip to wallet).
- Anything that requires "the server constructs and signs a Bitcoin tx
  that publishes the inscription" can be replaced with "the server
  constructs the inscription payload and lets a different party
  publish".

---

## 5. Why Atomicity Cannot Live on the Coin Layer

A naïve design would say: "extend the coin model to carry a hash-lock,
prove preimage knowledge in the circuit, atomic swap solved." This does
not work for three independent reasons.

### 5.1 Protocol-level reason

Adding spending conditions to the coin model would be a 12th divergence
from the published Shielded CSV protocol. The protocol's coin model is
intentionally minimal — `CoinEssence { address, amount, idx }` (see
`ShieldedCSV/ShieldedCSV/src/lib.rs:24`). Departing from this is
appropriate for the MVP only when the divergence has been triaged and
documented (D1–D11). A 12th divergence to enable swaps would need to be
designed alongside D2/D10 (recipient hiding) because both touch the
recipient-side spending check.

### 5.2 Cost reason

Lightning HTLCs use SHA256 preimages. A coin-level hash-lock would
require either:

- **SHA256 in-circuit:** ~262k gates in Plonky2 per hash (see
  [Plonky2 SHA256 benchmarks](https://hackmd.io/@clientsideproving/Plonky2MobileBench)).
  Poseidon-2 hashing two field elements costs ~150–200 constraints.
  Adding SHA256-preimage proof to every send would inflate proof costs
  by ~3 orders of magnitude and destroy the sub-second performance
  target.
- **Poseidon hash-lock:** cheap in-circuit, but Lightning HTLCs are
  SHA256. To bridge them would need a hash-translation provider (a
  trusted party who unlocks the SHA256 HTLC and locks a Poseidon HTLC),
  which negates trustlessness.

### 5.3 Architectural reason

The only on-chain anchor zkCoins has is the Taproot inscription with
txid prefix `4242`. There is no on-chain UTXO representing an individual
coin. Even if a coin had spending conditions in the circuit, enforcement
of those conditions on-chain would require a separate mechanism the
protocol does not have.

### 5.4 Conclusion

Atomicity must come from somewhere else. That somewhere is the **Bitcoin
funding transaction of the inscription reveal**, which is an ordinary
Bitcoin tx and can carry any standard script lock.

---

## 6. Where Atomicity Lives: The Inscription Funding Tx

Every zkCoins send currently requires the publisher to broadcast a
Taproot commit-reveal pair. The commit tx has txid prefix `4242`, the
reveal tx carries the inscription payload (signed `Commitment`) in its
Taproot script-path witness.

**Key observation:** the commit tx's input(s) come from a Bitcoin UTXO
the publisher controls. If that UTXO is locked with an HTLC script, then
the reveal tx is only broadcastable by whoever can satisfy the HTLC's
spending condition.

This is the lever. The swap design rests entirely on coupling the
inscription publication to a Bitcoin script lock that, in turn, is
coupled (via preimage or adapter sig) to a Lightning HTLC/PTLC.

### 6.1 The funding-utxo lock

For an LN → zkCoins reverse submarine swap, the provider locks a UTXO
with a standard reverse-submarine-swap script. The script has two
spending paths:

- **Claim path (recipient):** `user_pubkey + preimage(H)`
- **Refund path (provider):** `provider_pubkey + on_chain_timeout`

The user spends the UTXO via the claim path to publish the inscription;
the provider can recover via the refund path if the user does not claim
in time.

### 6.2 Who broadcasts what

| Action | Pre-swap | Lock confirmed | User claims | Provider claims LN |
| ----- | -------- | -------------- | ----------- | ------------------ |
| LN payment | — | User → Provider HTLC | — | Provider claims, preimage now on LN-side |
| On-chain funding UTXO | Provider creates locked UTXO | UTXO confirmed | User spends with preimage; tx contains inscription | — |
| Inscription | — | — | Published via user's spend tx | Already published in previous step |
| Scanner state | unchanged | unchanged | Updated to include user's new coin | unchanged |

The non-obvious bit is row 3: the user is the one who publishes the
inscription, *not* the provider. The provider has prepared everything
(send proof, inscription payload, Schnorr signature on
`H(asth ‖ ocr)`), but the act of broadcasting is the user's, and that
broadcast is gated on knowledge of the preimage.

---

## 7. Atomicity Primitives — HTLC vs PTLC

### 7.1 HTLC (Hash Time-Locked Contract)

The classical Bitcoin/Lightning primitive. Two parties agree on
`H = SHA256(x)` where `x` is a 32-byte preimage known initially to one
party (the one initiating the swap or the one receiving funds, depending
on direction). The lock is satisfied by revealing `x` such that
`SHA256(x) == H` in the witness; revealing `x` on-chain or via a
Lightning hop's HTLC settlement makes `x` observable to the other
party.

- **Availability:** standard since 2017, supported everywhere.
- **On-chain footprint:** P2WSH with `OP_SHA256 <H> OP_EQUALVERIFY ...`
  or Taproot script path with equivalent semantics. Hash is visible
  on-chain.
- **Privacy:** lookups across chains can correlate by hash. A single
  hash appearing on Bitcoin L1 (in a swap claim) and within a
  Lightning channel state (visible to the channel counterparty) is a
  known privacy leak.

### 7.2 PTLC (Point Time-Locked Contract)

Schnorr-era replacement for HTLC. Two parties agree on a curve point
`Y = y·G` where `y` is a discrete log known initially to one party. The
lock is "satisfied" not by revealing `y` in a witness but by completing
a Schnorr signature whose adaptor was committed to `Y`: the resulting
on-chain signature, combined with the adaptor signature `s'`, reveals
`y = s − s'` to anyone who sees both.

- **Availability:** Bitcoin-side fine (BIP-340 Schnorr is standard
  since Taproot). Lightning-side blocked on widespread PTLC support
  (`lightning-dev` mailing list, ongoing as of 2026-05).
- **On-chain footprint:** indistinguishable from a normal single-sig
  Taproot key-path spend. No script revealed, no hash exposed.
- **Privacy:** strong — neither the swap's existence nor the linkage
  between LN payment and on-chain spend is observable on Bitcoin L1.

### 7.3 Which one to build first

HTLC. Three reasons:

1. Production-ready toolchain (Boltz backend, BOLT-11 invoices, all
   wallets support it).
2. Trustlessness is identical to PTLC for this design — the on-chain
   privacy upgrade does not change the security argument.
3. PTLCs over Lightning depend on third-party progress (LDK, CLN
   maintainers, Lightning Labs roadmap). Building the LN-side ourselves
   is out of scope.

PTLC is a future upgrade tracked as an open item, not a v1 dependency.

---

## 8. Detailed Flow A: LN → zkCoins (User Buys zkCoins with LN Bitcoin)

This is the **reverse submarine** direction by Boltz nomenclature: the
user holds the off-chain asset (LN bitcoin) and wants the on-chain-anchored
asset (zkCoins). The user generates the preimage, the provider locks
the on-chain side.

### 8.1 Parties and pre-conditions

- **User:** Lightning node, zkCoins wallet, has an existing zkCoins
  account (so `recipient = H(initial_pubkey)` is known to them and the
  provider).
- **Provider:** Lightning node with inbound liquidity from the user,
  zkCoins server with sufficient inventory in some operator account,
  Bitcoin wallet for funding UTXO.
- **Pre-agreed:** swap amount `A` (in sats), provider fee `F`, swap
  timeout parameters (`T_lock` for on-chain CLTV, `T_ln` for
  Lightning CLTV-delta — see §12).

### 8.2 Protocol steps

```
Step 1. User generates preimage x ←$ {0,1}^256. Computes H = SHA256(x).
        User sends to provider:
          - H
          - user_zkcoins_recipient_address (an Address = H(pubkey))
          - amount A
          - user_btc_refund_pubkey for the funding UTXO

Step 2. Provider's zkCoins server prepares the send:
          - Loads the operator account state
          - Builds out_coins with one entry: { identifier, recipient =
            user_zkcoins_recipient_address, amount = A }
          - Generates the send proof (SP1 or Plonky2 post-cutover)
          - Computes asth, ocr
          - Provider's wallet signs H(asth ‖ ocr) with the operator
            account's commitment pubkey, producing Schnorr signature σ
          - Assembles full inscription payload P =
            Commitment { public_key, signature: σ, message: asth‖ocr }

Step 3. Provider's Bitcoin wallet creates a funding UTXO with script:

          OP_IF
              OP_SHA256 <H> OP_EQUALVERIFY
              <user_btc_recipient_pubkey> OP_CHECKSIG
          OP_ELSE
              <T_lock> OP_CHECKLOCKTIMEVERIFY OP_DROP
              <provider_btc_pubkey> OP_CHECKSIG
          OP_ENDIF

        funded with exactly (fee_to_pay_for_reveal_tx +
        dust_threshold). Call this UTXO U_lock.

Step 4. Provider constructs the unsigned commit-reveal pair for the
        inscription:
          - Commit tx: spends U_lock + any provider fee inputs, has
            one Taproot output committing to the inscription script
            tree, and a vanity-grind on (input set, output amounts,
            change scripts) to ensure txid prefix = "4242".
          - Reveal tx: spends the commit tx's Taproot output via the
            script path, the script path witness containing inscription
            payload P.

        The commit tx's spend of U_lock requires the IF-branch
        (preimage). Provider hands the user:
          - Unsigned commit tx
          - Reveal tx (unsigned, will be signed by the inscription
            script path which is part of the Taproot output)
          - Provider's pre-signature on the OP_ELSE refund path
            (so the user can verify the refund script is well-formed,
            though the user will never need to use it)

Step 5. User verifies:
          - U_lock is on-chain and matches the script in Step 3 with
            the correct H, T_lock, and pubkeys
          - The unsigned commit-reveal pair, once the user adds their
            preimage + signature to the commit tx's input, would
            broadcast a tx with txid prefix "4242" whose reveal tx
            publishes inscription payload P
          - Inscription payload P contains a Schnorr signature on
            H(asth ‖ ocr) that verifies against the operator's
            commitment pubkey
          - The asth and ocr values, opened by P, are consistent with
            a send proof that creates a coin to user_zkcoins_recipient_address
            of amount A

        If any check fails, the user aborts. No funds at risk —
        nothing has been sent on the LN side yet.

Step 6. User pays the Lightning HTLC:
          - User → Provider, hash H, amount A + F, CLTV-delta T_ln

Step 7. User waits for U_lock to reach the agreed confirmation depth
        (see §12 and §16). Then user broadcasts the commit tx:
          - Witness for U_lock spend: <preimage = x> <user_sig>, IF-branch
          - Commit tx now in mempool

Step 8. Commit tx confirms. User broadcasts the reveal tx, which
        publishes inscription P on-chain.

Step 9. zkCoins scanner picks up the `4242`-prefix commit tx, follows
        through to the reveal tx, extracts P, verifies the Schnorr
        signature, calls State::update([P]). The user's
        zkcoins_recipient_address now holds the new coin.

Step 10. The user's preimage x is now visible on-chain (in the witness
        of the commit tx's spend of U_lock). The provider's Lightning
        node either:
          - Observes the preimage on-chain and uses it to claim the
            LN HTLC (preimage-watch pattern)
          - Or the user explicitly reveals x via off-band channel; the
            user has every incentive to do so since the swap is now
            complete from their perspective and reveal-then-settle
            reduces both parties' channel risk

Step 11. Provider settles the LN HTLC, capturing A + F. Swap complete.
```

### 8.3 What can go wrong

| Failure | Who has what | Recovery |
| ------- | ------------ | -------- |
| User aborts at Step 5 | Provider has funded U_lock; nothing else moved | Provider refunds U_lock at T_lock (Step 3 ELSE branch). Cost: on-chain fee for U_lock creation. |
| User pays LN (Step 6) but never broadcasts commit (Step 7) | Provider has incoming LN HTLC, U_lock still locked | LN HTLC times out at T_ln, user gets LN funds back. Provider refunds U_lock at T_lock. Both whole. |
| User broadcasts commit but it doesn't confirm before T_lock | User has paid LN, U_lock is being refunded by provider; user's tx might or might not eventually confirm | This is the race condition T_lock is designed to prevent. See §12. With margin, this should not happen; if it does, provider claims U_lock refund and user claims LN refund. Provider has zkCoins still in inventory (no send actually happened since inscription never landed). |
| Provider's server crashes between Step 2 and Step 4 | User has H, has not paid anything | User aborts, no loss. |
| Provider's Bitcoin wallet runs out of funds for U_lock | Pre-condition failure | Provider rejects swap initiation. No loss. |
| Provider refuses to settle LN at Step 11 despite preimage visible | Provider has zkCoins inventory still committed, user has zkCoins (Step 9 succeeded), preimage on-chain | LN HTLC will time out and refund to user. User keeps zkCoins **and** gets LN funds back. **Net: provider loses A+F to itself.** This is asymmetric — provider has no incentive to do this. Documented as provider-side discipline. |

### 8.4 Why this is trustless

At no point does either party transfer custody of an asset to the other
party where the other party can withhold reciprocation:

- User commits LN payment **after** seeing the funded U_lock with the
  correct script.
- User claims zkCoins-side **before** revealing preimage (preimage is
  in the spend witness, so revealing happens at the moment of
  on-chain publication).
- Provider's refund path is gated on T_lock, which is shorter than
  T_ln, so provider cannot get U_lock back via timeout while
  simultaneously claiming LN.

The only scenarios where someone loses funds are (a) the user pays LN
and then never claims on-chain, in which case both sides time out and
both are made whole, or (b) one party broadcasts a refund tx with a
fee too low to confirm, which is a fee-management concern not a trust
concern.

---

## 9. Detailed Flow B: zkCoins → LN (User Sells zkCoins for LN Bitcoin)

This is the **forward submarine** direction: the user holds the on-chain
asset (zkCoins) and wants the off-chain asset (LN bitcoin). The
direction matters because the user is the one initiating the
zkCoins-side send, which means the user controls the inscription
publication — flipping who broadcasts what.

### 9.1 The role inversion

In Flow A the user was the inscription broadcaster (Step 7–8). In Flow
B the user is the inscription *originator* (they own the source coins)
but the provider is the LN payer. The naïve "provider generates the
preimage" construction (mirroring Boltz forward submarine swaps)
introduces a non-trustless gap when applied to inscription publication
— see §9.3 for why. The recommended construction is a direct mirror
of Flow A with the swap roles reversed; the preimage generator stays
on the on-chain-asset-acquirer's side. This is detailed in §9.2.

### 9.2 Recommended pattern: mirror of Flow A

```
Step 1. Provider generates preimage x ←$ {0,1}^256. Computes
        H = SHA256(x). Provider sends to user:
          - H
          - provider_zkcoins_recipient_address
          - amount A
          - provider's LN invoice for amount A − F (standard, not hold)

Step 2. User's zkCoins server prepares the send proof to
        provider_zkcoins_recipient_address with amount A. User signs
        Schnorr σ over H(asth ‖ ocr) with their commitment pubkey.

Step 3. User funds a Bitcoin UTXO U_lock' from their own wallet with
        the same Taproot two-leaf construction as Flow A:

          IF-branch (claim):  <provider_sig> + <preimage of H>
          ELSE-branch (refund): <user_sig> after T_lock

        User constructs the unsigned commit-reveal pair such that
        the commit tx spends U_lock' via the IF-branch and the
        reveal tx publishes the inscription containing σ.

Step 4. User hands provider:
          - (asth, ocr, σ)
          - U_lock' outpoint
          - Unsigned commit-reveal pair

Step 5. Provider verifies:
          - σ verifies against user's commitment pubkey
          - asth + ocr describe a send to provider's address of
            amount A
          - U_lock' is on-chain with the correct script
          - Commit tx spends U_lock' and has txid prefix 4242

Step 6. Provider pays the Lightning HTLC to user with hash H,
        amount A − F.

Step 7. User claims the LN HTLC. The settlement reveals x to
        provider via the LN channel mechanics (preimage-watch
        pattern, or explicit reveal off-band).

Step 8. Provider broadcasts the commit tx with witness
        <x> <provider_sig> (IF-branch satisfied).

Step 9. Commit tx confirms. Provider broadcasts reveal tx;
        inscription publishes on-chain; zkCoins scanner picks up
        and credits provider's address.

Step 10. Swap complete.
```

#### Failure modes for Flow B (Pattern 9.2)

| Failure | Who has what | Recovery |
| ------- | ------------ | -------- |
| Provider does not pay LN | U_lock' is locked; nothing else moved | User refunds U_lock' at T_lock. Cost: on-chain fee for U_lock' creation. |
| Provider pays LN, user claims, provider broadcasts | Happy path | Swap completes. |
| User claims LN but provider does not broadcast commit tx | Provider has x and own signature; they can broadcast any time before T_lock. If they don't, U_lock' refunds to user. User keeps LN funds; provider keeps zkCoins inventory (no inscription landed). | Provider has no incentive to withhold — they would forgo the zkCoins inflow they already paid for in LN. Documented as provider-side discipline. |
| User funds U_lock' but never sends provider the commit-reveal pair | Pre-condition failure | User can refund U_lock' at T_lock. No LN payment was made. |
| Commit tx stuck in mempool past T_lock | Race condition | Avoided by the ordering constraint of §12.2; if exhausted, U_lock' refunds to user and provider keeps LN funds. Provider must factor this risk into fee pricing. |

The last failure mode of the table is worth flagging in code: if the
inscription never lands, the zkCoins state never updates. The user's
server-side state shows the send as "prepared" but not "committed",
because the corresponding `Commitment` was never broadcast. The
swap-aware server must release the prepared state if it observes that
the corresponding U_lock' has been refunded, so the user can re-use
those coins for another swap or send.

### 9.3 Why we rejected the "provider generates preimage" pattern

A pattern that more closely mirrors Boltz forward submarine swaps —
where the provider generates the preimage and the user constructs the
locked UTXO — does not yield trustlessness for inscription
publication. The reason is structural:

- If the commit tx is spendable by `<x> <provider_sig>`, then after
  provider claims LN (and learns x), the user cannot broadcast the
  commit tx on the provider's behalf when provider stalls — only
  provider has the signature. T_lock expires, U_lock' refunds, but
  the LN payment was already settled, so the user is out A − F.
- If the commit tx is spendable by `<x> <user_sig>` instead, the user
  can broadcast at any time after learning x — but x is generated by
  provider, so the user only learns it after LN settlement. Same
  asymmetry, flipped: provider could broadcast a fake LN payment
  flow and steal the zkCoins.
- A 2-of-2 IF-branch (`<x> <user_sig> <provider_sig>`) lets either
  party grief: the preimage reveal alone is no longer sufficient to
  unilaterally publish.

A patch using an **LN hold invoice** to make the user the LN
settlement-controller also fails to close the gap cleanly, because
the user's reveal of x to settle the hold invoice and the provider's
broadcast of the commit tx remain two separate events with no
on-chain coupling between them.

Pattern 9.2 avoids all of this by having the same party (provider)
control both the LN claim and the on-chain broadcast — the preimage
reveal through LN settlement directly enables that party to broadcast.

---

## 10. Bitcoin Script Construction

### 10.1 Script template (legacy P2WSH for clarity)

```
OP_IF
    OP_SHA256 <H>               ; H = SHA256(preimage)
    OP_EQUALVERIFY
    <claim_pubkey>              ; whoever can claim via preimage
    OP_CHECKSIG
OP_ELSE
    <T_lock>                    ; absolute or relative timeout
    OP_CHECKLOCKTIMEVERIFY      ; CLTV (absolute) or CSV (relative)
    OP_DROP
    <refund_pubkey>             ; whoever can refund after timeout
    OP_CHECKSIG
OP_ENDIF
```

Bytes: ~83 (claim + refund) for compressed-pubkey + 32-byte hash.

### 10.2 Taproot variant (recommended for production)

Use a Taproot output with two leaves:

- **Leaf A (claim):** `OP_SHA256 <H> OP_EQUALVERIFY <claim_pubkey>
  OP_CHECKSIGVERIFY`
- **Leaf B (refund):** `<T_lock> OP_CHECKLOCKTIMEVERIFY OP_DROP
  <refund_pubkey> OP_CHECKSIGVERIFY`

Internal key: NUMS point (provably-unknown discrete log) or a
2-of-2 MuSig of claim+refund keys (allows cooperative key-path spend
that hides the script entirely — Boltz's V2 swap design does this).

Cooperative key-path spending makes successful swaps look like normal
single-sig Taproot spends, improving fungibility. Script-path is the
fallback for non-cooperative resolution.

### 10.3 Vanity-grinding txid prefix `4242`

The commit tx of the inscription pair must have txid hex starting with
`4242`. This is a 2-byte prefix, so on average 65k brute-force attempts
to find a matching nonce. zkCoins's existing publisher
(`server/src/publisher.rs`) handles this by varying the commit tx's
output amount (sat-level) until the prefix matches.

For the swap design, the variable that can be ground is the commit
tx's change output amount (the difference between U_lock + fee-input
and the Taproot commit output amount, sent back to a change address
controlled by whoever is broadcasting). Either the provider (Flow A
pre-construction) or the user (Flow A Step 7 broadcast time, if the
commit tx is finalised then) handles the grind.

Caveat: changing the change-amount changes the tx hash, but it also
slightly changes the fee, which is fine in mempool. Standardness rules
to watch: the change output must remain ≥ dust threshold (~330 sat for
Taproot).

### 10.4 Funding the U_lock UTXO

In Flow A, the provider funds U_lock from their own Bitcoin wallet.
The amount is just enough to cover the commit tx fee + dust threshold
for the commit tx's outputs. The reveal tx pays for itself from the
Taproot output.

The actual zkCoins coin value (A) is not transferred via Bitcoin —
zkCoins state lives entirely off-chain in the SMT/MMR. The on-chain
piece is the inscription, which is essentially a 64-byte signature
plus envelope overhead. Total on-chain Bitcoin cost per swap is
roughly the same as a Boltz swap minus the actual L1 payout: ~250
sats at current fee rates.

### 10.5 Pubkey choices

- **claim_pubkey:** the user's Bitcoin spending pubkey for Flow A, or
  the provider's for Flow B. Should be a fresh key per swap for
  unlinkability.
- **refund_pubkey:** the counterparty's. Same fresh-key recommendation.

In a Taproot internal-key construction, the cooperative key is a MuSig
of (claim_pubkey, refund_pubkey).

---

## 11. The Inscription Reveal Tx — Anatomy

For completeness, the reveal tx that ultimately publishes the
`Commitment` payload:

- **Input:** the commit tx's Taproot output.
- **Witness:** Taproot script-path spend, providing
  - The inscription script (Ordinals-style envelope: `OP_FALSE OP_IF
    "ord" <payload> OP_ENDIF`, with `<payload>` being the serialised
    `Commitment` plus zkCoins-specific envelope tag)
  - The internal pubkey
  - The control block proving the script is in the Taproot script tree
- **Output:** a P2WPKH or P2TR output of dust value going back to the
  publisher (the reveal tx is a "burn the inscription" tx; the output
  is just there because every tx needs an output).

This is unchanged from the current zkCoins publisher implementation;
the only thing the swap design touches is the commit tx's input
(U_lock), not the reveal tx itself.

---

## 12. Timing Coordination (CLTV Deltas)

### 12.1 The two timeouts

- **`T_lock`:** absolute Bitcoin block height at which the on-chain
  U_lock UTXO becomes refundable to the provider (Flow A) or user
  (Flow B). Set at swap creation time.
- **`T_ln`:** the CLTV-delta of the Lightning HTLC, in blocks. The LN
  payment is refundable to the payer after the HTLC's expiry block,
  which is the most recently locked-in block height + `T_ln`.

### 12.2 The ordering constraint

The fundamental requirement for trustlessness:

```
T_lock < (current_height + T_ln) - safety_margin
```

Equivalently: the on-chain refund path must mature *before* the LN
refund path matures.

Why: imagine the alternative, `T_lock > current_height + T_ln`. Then
LN refunds first. Suppose the user pays LN, never claims on-chain. LN
refunds the user at `T_ln`. Provider's U_lock is still locked until
`T_lock`. But by then, the user has their LN funds back AND can still
broadcast the commit tx (they have the preimage they generated, plus
their claim signature). User publishes inscription, scanner credits
user, user has both LN-refunded funds and new zkCoins. Provider loses
inventory.

With `T_lock < current_height + T_ln − safety_margin`, the order is:
T_lock fires first → provider refunds U_lock → user can no longer
claim → LN refunds at `T_ln` later. Both whole.

### 12.3 Typical values

- LN CLTV-delta: most modern nodes use 40 blocks final + up to 144 per
  hop. End-to-end on a single-hop swap (user ↔ provider direct
  channel) typically ~144 blocks ≈ 24 hours.
- On-chain `T_lock`: should be ~24h or less from now to leave a clear
  margin. Typical Boltz value: 144 blocks from creation.
- Safety margin: at least 6 blocks (~1 hour) to allow for confirmation
  delays at the boundary. Boltz uses ~12-block margin.

### 12.4 Required confirmation depth for U_lock

Before the user broadcasts the claim tx (Flow A Step 7), U_lock must
be confirmed to a depth where the provider cannot RBF or double-spend
it. Standard recommendation: 1 confirmation is sufficient if U_lock's
funding tx is below RBF threshold and confirmed in a non-reorg-prone
context; 2-3 confirmations for higher-value swaps. This is independent
of the D7 reorg-safety question, which concerns confirmation depth of
the *inscription publication*, not U_lock.

### 12.5 The proof-time question

Provider's send proof generation (zkCoins server side):

- SP1 today: tens of seconds to a few minutes warm.
- Plonky2 post-cutover target: ≤1 second warm.

This happens between Step 1 (user requests swap) and Step 4 (provider
hands user the commit-reveal pair). Even with SP1, the proof time
is negligible compared to the 24-hour swap window. **Plonky2 is not
a swap dependency.**

(The proof time *would* matter for some hypothetical
ultra-low-latency swap product — pay LN, get zkCoins balance within
3 seconds. Such a product is not on the roadmap and would require
solving D7 at the same time anyway.)

---

## 13. Failure Modes Matrix (Both Flows)

Summary of all scenarios. "User" and "Provider" refer to the swap
counterparties regardless of direction.

| Scenario | Who lost what | Recovery mechanism |
| -------- | ------------- | ------------------ |
| Both parties cooperate, all txs confirm | Nothing lost; everyone gets expected outcome | Happy path |
| User aborts before LN payment | Provider has funded U_lock + spent proof time | U_lock refund at T_lock; proof time is a sunk cost (~free) |
| LN payment fails to route | No state change | LN-layer retry or refund |
| LN payment succeeds, user fails to claim on-chain (Flow A) | Provider has LN HTLC pending, user has paid LN | LN HTLC times out at T_ln, user refunded; U_lock refunds at T_lock |
| User claims on-chain but commit tx stuck in mempool past T_lock | Race condition | Avoided by §12.2 ordering constraint with margin; if margin exhausted, both refund — provider via U_lock refund, user via LN refund (assuming commit tx also evicted from mempool) |
| Provider's Bitcoin wallet outage between Step 3 and broadcast | Pre-condition failure | Swap not initiated; no loss |
| Bitcoin reorg removes the confirmed commit tx | See §16 (D7 dependency) | Provider waits ≥6 confirms before claiming LN |
| zkCoins scanner is offline | Inscription is on-chain but state lags | Scanner catches up on restart; no swap-mechanism impact |
| Provider claims LN but withholds inscription broadcast (Flow B) | Provider has LN, has not delivered zkCoins | Provider has no incentive — they would forgo the zkCoins inflow they already paid for in LN. If they do withhold past T_lock, U_lock' refunds to user; user keeps LN funds. See §9.2 failure-mode table. |
| Provider sets up Sybil swaps to grief | None directly | DoS mitigation: rate-limit, optionally require small upfront fee or deposit |

---

## 14. Provider Operational Considerations

### 14.1 Liquidity management

The provider needs two inventories simultaneously:

- **LN liquidity (outbound + inbound):** outbound for Flow B (paying
  user), inbound for Flow A (receiving user's payment). Standard LN
  channel management. Boltz publishes inbound/outbound LP rates
  dynamically.
- **zkCoins inventory:** one or more operator accounts with sufficient
  balance in zkCoins to honour Flow A swaps. Inventory rebalances:
  Flow B replenishes the operator account (user sends zkCoins to
  provider's address); Flow A depletes it. Net flows over time should
  be matched by an out-of-band rebalancing flow (provider mints new
  zkCoins by depositing BTC, or burns zkCoins for BTC, via whatever
  L1-zkCoins bridge mechanism is in place).

zkCoins does not currently have a published bridge mechanism. The
MVP-era assumption is that the provider is also the minter (the
holder of `MINTING_ADDRESS`), which trivially provides inventory.
Once the protocol has a real bridge (BitVM-style or otherwise), the
provider can be any party with that bridge's deposit/withdraw
capability.

### 14.2 Fee model

Three components, mirroring Boltz:

- **On-chain fee:** the actual Bitcoin tx fee for the commit-reveal
  pair. Paid out of U_lock funding amount; the user effectively pays
  this since they are the asset-acquirer in Flow A.
- **Routing fee:** LN routing cost on the provider's payment in Flow B,
  or absorbed if Flow A receives a direct payment.
- **Provider margin:** a percentage of swap amount, the actual revenue
  source for the provider.

Typical Boltz total fees: 0.1–0.5% of swap amount + ~250 sat on-chain.

### 14.3 Inventory locked during swap

Between Step 2 (provider prepares send) and Step 9 (inscription
confirms), the provider's zkCoins inventory is committed but
not-yet-published. The provider must not initiate another swap that
would also commit the same balance — server-side concurrency control
required.

Concretely, the operator account's "soft balance" must reflect:
`balance − Σ(pending_swap_amounts)`, where `pending_swap_amounts`
includes all amounts for prepared-but-not-confirmed sends.

This is the "stuck inventory" problem of any submarine swap provider;
Boltz solves it with parallel HTLC tracking. zkCoins-side it requires
the swap-aware server to track prepared swaps until inscription
confirms (or refund completes).

### 14.4 Watching the chain

The provider's Bitcoin watcher must monitor:

- U_lock UTXOs they have created (for refund-at-T_lock)
- Commit txs spending U_lock UTXOs (to extract preimages and claim LN
  in Flow A, or to confirm completion in Flow B)
- Reveal txs (to confirm scanner-pickup)
- Bitcoin reorgs affecting any of the above

LND's `chainntfn` or BTCD's notification API are the standard tools.
Boltz's backend repo (`BoltzExchange/boltz-backend`) has a battle-tested
watcher implementation that could be forked.

### 14.5 The grind for `4242` prefix

The vanity-grind (§10.3) takes time — at 65k attempts average, a
modern CPU can grind a single 4242-prefix tx in ~1 second. Not a
bottleneck, but should be parallelised if the provider expects high
swap volume. Easy to GPU-accelerate; not necessary for v1.

---

## 15. Privacy Analysis

### 15.1 What the provider learns

- **Recipient zkCoins address** (Flow A) or sender's zkCoins address
  (Flow B). The full `Address = H(initial_pubkey)`. Cyrill confirms
  this is acceptable for the DFX-operated provider given Compliance
  needs.
- **Amount.** Necessarily, since it's the swap amount.
- **The user's Bitcoin pubkey** (claim/refund pubkey on U_lock).
  Recommend fresh key per swap.
- **The user's LN node identity** for the LN payment. Single-hop direct
  channel reveals; multi-hop preserves payer anonymity to the same
  extent any LN payment does.

### 15.2 What is on-chain

- The funded U_lock UTXO (a 2-leaf Taproot output).
- The commit tx spending U_lock (Taproot output to inscription, with
  txid prefix `4242`).
- The reveal tx with inscription payload in witness.
- If swap fails: a refund tx spending U_lock via the ELSE branch.

A chain observer sees:
- A Taproot input being spent with either script path (failure case)
  or — if cooperative key-path is used (§10.2) — what looks like a
  normal single-sig Taproot spend
- A subsequent commit tx with txid prefix `4242`, which is
  zkCoins-protocol-specific and identifies the spend as a zkCoins
  send

So the swap, on the Bitcoin side, is publicly identifiable as a zkCoins
send. Whether it's a *swap* (vs. a direct user-initiated send) is
inferable from the U_lock script structure if non-cooperative. With
cooperative key-path resolution, the swap looks identical to a direct
zkCoins send.

### 15.3 What is in Lightning

A standard Lightning HTLC of amount A ± F with hash H. Same privacy
properties as any LN payment of similar size. If the LN counterparty
is the provider directly, the provider sees both ends; if routed
through hops, intermediate hops see the hash and amounts (standard LN
payment privacy).

### 15.4 What PTLCs would change

PTLCs would eliminate (a) the on-chain hash visibility and (b) the LN
hash → on-chain hash correlation. The on-chain spend would be
indistinguishable from any single-sig Taproot key-path spend, and the
LN payment would use a point lock that does not appear on Bitcoin L1
in plaintext.

This is purely an upgrade; HTLC v1 is already trustless.

### 15.5 zkCoins-internal privacy: D2/D10

D2 (plaintext recipient) is a pre-mainnet blocker for general zkCoins
privacy, but for the swap design it does not introduce any new
linkability — the provider already knows the recipient address by
construction (the user told them in Step 1). When D2/D10 are fixed
with hiding commitments, the swap protocol must include the per-coin
randomness in the Step 1 user-to-provider message so the provider can
build a coin opening to the hidden recipient. This is a minor protocol
update, not a redesign.

---

## 16. D7 Reorg Safety — The Open Dependency

### 16.1 What D7 is

From `SPEC.md` §15 and `MIGRATION_RESEARCH.md` §3, D7:

> No conditional-noop path. Paper supports `conditional_nav` — if the
> claimed nullifier-accum is no longer a prefix of the chain's, the tx
> becomes a no-op.

In zkCoins-as-implemented, when the scanner processes an inscription
and updates the SMT, that update is taken as final. If Bitcoin reorgs
and the inscription tx is reorganised out, the scanner has no graceful
way to undo the SMT update. The protocol "trusts" the scanner's
view of the chain.

### 16.2 What this means for swaps

For Flow A, between Step 8 (commit tx confirms) and Step 11 (provider
settles LN), there is a window where:

- Inscription is on-chain at depth `d` (where `d` is small immediately
  after confirmation)
- Provider sees preimage on-chain
- If provider settles LN now and Bitcoin reorgs at depth ≥ d, the
  inscription is no longer in the chain — but the scanner already
  ingested it. zkCoins state has the new coin (assigned to user) but
  the chain does not.

This is a soundness problem for zkCoins (D7), not for the swap. The
swap-level mitigation is: **provider waits for sufficient confirmation
depth before settling LN**.

### 16.3 Required confirmation depth

This is the operationally interesting question. Options:

- **Same as Boltz BTC ↔ LN swaps:** Boltz settles after ~3 BTC
  confirmations. The argument is that 3 confirmations is sufficient
  against routine reorgs; deeper reorgs are rare-enough events that
  the residual risk is absorbed by the provider as part of operational
  cost.
- **More conservative:** wait for 6 confirmations (Bitcoin's
  traditional "confirmed" threshold) to align with bitcoin custodial
  practice.
- **Most conservative:** wait for `CONFIRMS_TO_FINALITY` set by
  zkCoins protocol parameters; could be 6 or 100 depending on threat
  model.

For DFX as provider, I would default to **6 confirmations** (~1 hour
wait) until D7 is fixed. After D7 is fixed (the scanner can gracefully
handle inscription reorg by rolling back state and re-inserting), the
depth can drop back to 3 or even 1 with appropriate scanner logic.

### 16.4 LN CLTV must accommodate this wait

The LN-side `T_ln` must comfortably exceed the wait time. With
6-confirm depth (~1 hour) + safety margin + variable Bitcoin block
times (could be 2x mean), an LN CLTV of 144 blocks (~24h) is more
than sufficient.

### 16.5 D7 fix is tracked separately

D7 is in the Pre-Mainnet Hardening block (`ROADMAP.md`), estimated
4–5 days of work. It is independent of the swap design and required
for mainnet regardless.

The dependency for the swap launch is: **swap can ship before D7 is
fixed, with conservative confirmation-depth gating**. D7 fix later
just allows lower latency.

---

## 17. Plonky2 Relevance (Spoiler: Orthogonal)

The PR #17 Plonky2 migration is **not a blocker** for swap
implementation. Specifically:

- **Performance:** SP1 minute-scale proofs fit comfortably in the
  24-hour LN CLTV window. Plonky2 sub-second proofs reduce
  provider-side inventory-locked-time from minutes to seconds, which
  is a per-swap operational improvement, not a correctness condition.
- **Hash function (Poseidon vs SHA256):** does not touch the swap
  mechanism. SHA256 is used by Lightning (HTLC preimage) and BIP-340
  Schnorr (commitment signature). Poseidon is used internally for
  Merkle structures. The swap construction is hash-agnostic.
- **Coin model:** unchanged by Plonky2. The swap design's core insight
  (atomicity on the Bitcoin funding tx, not the coin layer) is forced
  by the coin model and persists across proof-system migrations.
- **Schnorr signing:** unchanged. The signature on H(asth ‖ ocr) is
  BIP-340 over secp256k1, exactly the signature that goes into the
  inscription payload, exactly the signature the scanner verifies.

Implementation can therefore run in parallel to PR #17 without
contention. The swap code touches `server/` (new endpoints) and adds a
new operational component (Bitcoin script construction, LN node
integration). Neither touches `program-plonky2/` or `program/`.

If swap implementation starts before PR #17 lands, it should be done
behind feature flags or in a side-branch to be merged after the
Plonky2 cutover; this avoids dealing with two simultaneous major
refactors.

---

## 18. Comparison Tables

### 18.1 vs. Boltz BTC ↔ LN

| Property | Boltz BTC ↔ LN | This (LN ↔ zkCoins) |
| -------- | -------------- | ------------------- |
| Trust model | Trustless | Trustless |
| On-chain side primitive | P2WSH/P2TR HTLC | P2WSH/P2TR HTLC gating inscription publication |
| What's swapped on-chain side | Native BTC value | zkCoins coin (off-chain state update triggered by inscription) |
| On-chain footprint per swap | ~250 sat fees | ~250 sat fees |
| LN side | Standard HTLC | Standard HTLC |
| Wait for confirmation depth | ~3 confirms | ~6 confirms (D7 mitigation, until fixed) |
| Provider role | Liquidity provider, custodian of *neither* side | Same |
| PTLC upgrade path | Boltz V3 (announced) | Trivial mirror once LN PTLC matures |

### 18.2 vs. Taproot Assets atomic swaps

| Property | Taproot Assets | This (LN ↔ zkCoins) |
| -------- | -------------- | ------------------- |
| Asset locked on Bitcoin L1 | Yes (in Taproot leaves) | No (zkCoins state is off-chain) |
| Asset issuance | On-chain proofs | Off-chain proofs (PCD) |
| Swap primitive | PSBT-based, atomic | HTLC on inscription funding tx |
| Cross-chain step | None needed (asset lives on BTC) | The "chain" boundary is Bitcoin (LN funds + inscription) ↔ zkCoins state |
| RFQ-style quote mechanism | Yes, native | Easy to add as out-of-band layer |

### 18.3 vs. naïve "trusted DFX swap service"

| Property | Trusted DFX | Trustless HTLC |
| -------- | ----------- | --------------- |
| Trust assumption | DFX honours its claims | None (cryptographic) |
| Bitcoin-script complexity | None | Standard P2TR with 2 leaves |
| Build effort | Low (just an exchange API) | Medium (Boltz-backend fork + zkCoins integration) |
| Risk if provider compromised | User funds at risk | None — cryptographic atomicity |
| Suitable for production | Yes, with appropriate insurance / disclosures | Yes |

---

## 19. Implementation Roadmap

A draft sequence; not a commitment.

### 19.1 Phase 0: prerequisites

- D7 reorg fix in zkCoins (pre-mainnet hardening block; can be deferred
  if conservative confirm-depth gating is used)
- Operator account funded with sufficient zkCoins inventory
- Provider Bitcoin wallet with Lightning channel(s)
- LND or CLN node running (standard HTLC support sufficient; hold
  invoices not required by the recommended Pattern 9.2)

### 19.2 Phase 1: swap engine

- Bitcoin script construction module (P2WSH + P2TR variants, both
  flows)
- Watcher: monitor U_lock UTXOs, commit txs, reveal txs, refund-window
- Vanity-grinder for `4242` prefix (or reuse existing
  `server/src/publisher.rs` logic if it can be extracted)
- Inscription payload generator that can produce a `Commitment` for a
  *specified* recipient and amount, signed by the operator key,
  *without* publishing on-chain — Step 2 of Flow A

### 19.3 Phase 2: API surface

- `POST /api/swap/quote` — user requests quote, provider returns
  amount + fee + expected timeouts
- `POST /api/swap/initiate` (Flow A) — user submits H + recipient
  address + amount + refund pubkey, gets back commit-reveal pair +
  U_lock funded outpoint
- `POST /api/swap/lock` (Flow B) — provider gives user the H and
  provider's claim pubkey; user constructs their side and notifies
- `GET /api/swap/{id}` — status (waiting-for-confirms, settled,
  refunded, etc.)
- WebSocket for live status updates

### 19.4 Phase 3: LN integration

- Hook the swap engine into LND/CLN's HTLC settlement
- Configure routing fee thresholds, channel rebalancing alerts
- Define the rate-card (provider margin)

### 19.5 Phase 4: production hardening

- Rate limits per IP / per user
- Sybil resistance: optional small upfront fee
- Monitoring + alerting (Grafana board for in-flight swaps, alert on
  stuck/expiring swaps)
- Recovery tooling for stuck swaps (manual operator intervention if
  watcher fails)

### 19.6 Estimated effort

- Phase 1: 2–3 weeks
- Phase 2: 1 week
- Phase 3: 1 week
- Phase 4: 1–2 weeks
- Total: 5–7 weeks for a production-grade implementation, assuming
  Boltz-backend code can be partially reused for watcher/grinder

---

## 20. Open Questions

1. **Required confirmation depth for inscription.** Set initially to
   6 confirms (~1 hour wait); re-evaluate after D7 fix lands.

2. **Cooperative key-path for U_lock Taproot internal key.** MuSig of
   (claim_pubkey, refund_pubkey) gives best on-chain privacy but adds
   protocol complexity (round of MuSig key aggregation per swap). For
   v1, recommend NUMS internal key (cheaper, less private). Revisit
   for v2 alongside PTLC.

3. **Where does the operator account's privkey live?** The Schnorr
   signature on H(asth ‖ ocr) (Step 2 of Flow A) needs to happen
   server-side, because the operator is the sender. This means the
   operator account's commitment key is server-resident. Same
   architectural assumption as for any operator-issued zkCoins coin;
   should be documented in ops runbook.

4. **Cross-swap correlation.** If a single operator account is reused
   for many swaps, all those swaps' inscriptions chain through the
   same account state. A chain analyst can correlate them. Mitigation:
   rotate operator accounts periodically. Not a blocker.

5. **D7 fix interaction.** Once D7 lands with `conditional_nav`-style
   logic, the scanner can roll back. The swap design's confirm-depth
   parameter should drop, and the swap engine should subscribe to
   reorg notifications. Sketch the rollback-aware swap state machine
   when D7 is implemented; not now.

6. **Fee market integration.** Should swap quotes include a
   user-selected fee tier (fast/slow Bitcoin confirmation, expected
   wait time)? Boltz does this. Adds UI but not protocol complexity.

7. **Maximum swap size.** Bounded by (a) operator zkCoins inventory,
   (b) operator LN inbound liquidity. Define soft and hard limits.
   Boltz publishes these on an info endpoint.

---

## 21. References

- [Shielded CSV paper (Nick, Eagen, Linus)](https://eprint.iacr.org/2025/068)
- [Shielded CSV reference implementation](https://github.com/ShieldedCSV/ShieldedCSV)
- [Boltz backend (HTLC-based submarine swap reference implementation)](https://github.com/BoltzExchange/boltz-backend)
- [Boltz lifecycle docs](https://github.com/BoltzExchange/boltz-backend/blob/master/docs/lifecycle.md)
- [Boltz blog: Lightning ↔ Liquid via submarine swaps](https://bitcoinmagazine.com/business/between-bitcoin-layers-boltz-builds-trustless-transfers)
- [Submarine Swaps — Lightning Engineering Builder's Guide](https://docs.lightning.engineering/the-lightning-network/multihop-payments/understanding-submarine-swaps)
- [Multi-Party Submarine Swaps (conduition.io)](https://conduition.io/scriptless/multi-party-submarine-swaps/)
- [PTLCs — Bitcoin Optech](https://bitcoinops.org/en/topics/ptlc/)
- [Adaptor signatures — Bitcoin Optech](https://bitcoinops.org/en/topics/adaptor-signatures/)
- [Scriptless Scripts multi-hop locks (BlockstreamResearch)](https://github.com/BlockstreamResearch/scriptless-scripts/blob/master/md/multi-hop-locks.md)
- [Multichain Taprootized Atomic Swaps (Distributed Lab, arXiv 2402.16735)](https://arxiv.org/abs/2402.16735)
- [comit-network/xmr-btc-swap (adaptor-sig atomic swap reference)](https://github.com/comit-network/xmr-btc-swap)
- [Taproot Assets Trustless Swap (Lightning Labs)](https://docs.lightning.engineering/the-lightning-network/taproot-assets/trustless-swap)
- [Taproot Assets RFQ protocol](https://docs.lightning.engineering/lightning-network-tools/taproot-assets/rfq)
- [Plonky2 SHA256 benchmarks](https://hackmd.io/@clientsideproving/Plonky2MobileBench)
- [BIP-340 Schnorr signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-341 Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP-65 OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)

---

## 22. Change Log

| Date       | Change |
| ---------- | ------ |
| 2026-05-17 | Initial draft. |
| 2026-05-17 | Consistency audit pass: add branch note at the top explaining that `SPEC.md` / `MIGRATION_RESEARCH.md` / `ROADMAP.md` currently live on `feat/plonky2-migration` only. |
| 2026-05-17 | Audit round 2: restructure §9 from a stream-of-consciousness exploration of four candidate patterns to a single recommended construction (§9.2 mirror of Flow A) plus a brief §9.3 explaining why the alternatives were rejected. Promote §9.2 to the canonical Flow B; remove §9.3 (LN hold invoice) and §9.4 (renamed to §9.2) as numbered alternatives. Fix four broken internal cross-references (§10/§15 corrected to §12/§16). Renumber open-questions list to drop the gap left after removing the pattern-choice question. |
