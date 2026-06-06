# Plonky3 Upstream Maintenance Plan (Doc 4)

> **Scope.** This document governs how zkCoins consumes the **unaudited, pre-1.0,
> fast-moving** `Plonky3` and `Plonky3-recursion` git dependencies that the Plonky3
> migration (Path 1+5 — custom public-value-emitting *carrier* tables) rides on. It
> covers rev pinning, the safe rev-bump procedure, pinned-rev CI, breaking-change
> detection, upstream issue/PR tracking, re-pin cadence/ownership, and the (excluded)
> fork policy.
>
> **Companion docs.** `../../MIGRATION_PLONKY3.md` (the plan; §16 = hard-stop /
> no-fork rule), `../../MIGRATION_PLONKY3_SPIKE_RESULT.md` (Phase-0 gate + the 21
> probes), `../../MIGRATION_PLONKY3_SOLUTIONS_RESEARCH.md` (the 9-path analysis →
> Path 1+5), Doc 3 (crypto-audit spec for the carrier-table chain).
>
> **Date:** 2026-06-06. **Status:** active for the duration of the Plonky3 port and
> for as long as the production prover depends on these git revs.

---

## 1. Why pinning is mandatory

The Plonky3 family is **not** a stable dependency, and our usage compounds every
reason to pin:

- **Unaudited.** Neither `Plonky3` nor `Plonky3-recursion` has a published security
  audit. Doc 3 audits **our** construction — the carrier-table IVC chain, the
  cross-layer public-value binding, the masking/vk-binding glue — it does **not**
  audit upstream's FRI, batch-STARK prover, circuit builder, or recursion verifier
  internals. **The trusted computing base includes upstream code that no one has
  audited.** Treat every byte of `p3-*` as load-bearing-but-unverified.
- **Pre-1.0, git-only.** The recursion crates are not on crates.io; there is no
  semver contract, no release cadence, no deprecation policy. A `main`-branch HEAD
  can change a public type, a trait bound, or a soundness-relevant default between
  any two commits.
- **Edition 2024.** The spike crate is `edition = "2024"`
  (`spikes/plonky3-recursion-spike/Cargo.toml`). Edition-2024 churn (and the matching
  minimum toolchain) is itself a moving target; a rev bump can raise the required
  `rustc`. [VERIFY: confirm the production `rust-toolchain.toml` / CI toolchain meets
  the edition-2024 minimum before the first real `program-plonky3`/`prover-plonky3`
  port lands — CI is pinned to `1.81.0` today, see §3.]
- **Fast-moving.** Active maintainers, frequent commits, open redesigns. The feature
  our whole approach depends on (PR #407, "support public values") merged
  **2026-03-19**; the bug we route around (#436) is recent. This is a repo in motion.

### The coupled-rev constraint (non-negotiable)

The two revs are **not independent**. From `spikes/plonky3-recursion-spike/Cargo.toml`:

```
Plonky3/Plonky3-recursion @ 524665d0c2e1d294722c064786ae11dff8d9f33b   (HEAD 2026-06-06)
Plonky3/Plonky3           @ 56952503e1401a62982ceaf952c5e4a829b61803
```

> "The Plonky3-main rev is dictated by what Plonky3-recursion was built against (its
> workspace pins exactly this rev); using any other rev would give two incompatible
> copies of the `p3-*` types and break unification."

`Plonky3-recursion`'s own workspace pins exactly the `Plonky3`-main rev it compiles
against, and the recursion crates **share `p3-*` types** with that main rev. If we
pin a *different* `Plonky3`-main rev than the one recursion expects, Cargo resolves
**two incompatible copies** of `p3-field`, `p3-air`, `p3-commit`, etc. — types that
look identical but do not unify, producing either a hard compile error or (worse) a
silent split where a value crosses a boundary it shouldn't. **The two revs move as a
single unit. Never bump one without bumping the other to its matching partner (§2).**

### Reproducible builds

Pinning a git **rev** (not a branch, not a tag) plus a committed `Cargo.lock` is what
makes the prover's binary — and therefore the proofs it emits — reproducible. For a
ZK system this is a soundness-adjacent property: the exact constraint system, the
exact FRI parameters, and the exact verifier semantics are fixed by the rev. A
floating branch would let the proof format and verification semantics drift under us
between builds. **No floating branches. Ever.**

---

## 2. Rev-bump strategy

A rev bump is a **deliberate, reviewed, fully re-tested change** — never a routine
`cargo update`, never automated, never silent.

### When to bump

Bump only for a concrete, named reason:

1. **Security fix.** Upstream lands a fix for a soundness or memory-safety bug that
   touches a code path we use (FRI, batch-STARK prover, recursion verifier,
   public-value binding). This is the only *urgent* class.
2. **A needed feature.** e.g. a future **native cross-layer public-input API** (the
   ergonomic "mark circuit PI as public output" bridge described as Path 2 in
   `MIGRATION_PLONKY3_SOLUTIONS_RESEARCH.md`) that would let us replace or simplify
   the hand-built carrier-table construction; or a value-emitting NPO backend.
3. **Performance.** A measured prover speedup relevant to the ≤5 s warm-prove budget
   (the budget-gating number per the spike is the link-circuit STARK-prove, ≈3.2 s
   class — see `MIGRATION_PLONKY3_SPIKE_RESULT.md`).

Do **not** bump for "newer is better." A bump that buys nothing only adds unaudited
delta to the TCB.

### How to bump SAFELY — checklist

Run this exactly, in order. Stop at the first failure and escalate (§5/§7).

- [ ] **1. Identify the candidate recursion rev.** Note WHY (security / feature /
      perf) and link the upstream commit or PR.
- [ ] **2. Read the recursion rev's workspace to find its matching `Plonky3`-main
      rev.** Open `Cargo.toml` / the workspace manifest at that recursion rev and read
      the exact `Plonky3`-main rev it pins. **This is the partner rev — it is not a
      free choice.** (Today: recursion `524665d…` ↔ main `5695250…`.)
- [ ] **3. Bump BOTH revs together** in every `p3-*` dependency line, recursion → its
      partner main rev. Verify every `git = "…/Plonky3"` line shares one rev and every
      `git = "…/Plonky3-recursion"` line shares the other. (A stray un-bumped line is
      exactly the two-incompatible-copies failure from §1.)
- [ ] **4. Update `Cargo.lock`** (`cargo update -p p3-recursion --precise <rev>` style
      or regenerate) and commit it. The lock is the source of truth (§3).
- [ ] **5. Run the FULL spike suite — all 21 probes:**
      `cargo nextest run -p plonky3-recursion-spike`. All must stay green.
- [ ] **6. WATCH THE PINNED `[0,0,0]` GUARD PROBES SPECIFICALLY.** These three are
      *pinned* assertions (`air_public_targets = [0,0,0]`) that encode the
      primitive-table behavior our carrier construction reasons about:
      - `probe_d_multilayer_carry`
      - `probe_h_option1_air_public_values`
      - `probe_g_fanin_pi_passthrough`

      A flip in any of them means **the primitive-table / public-value plumbing
      changed upstream**. That is not a test to "fix" — it is a **breaking-change
      detector firing**. If one flips: STOP. Re-validate the entire carrier
      construction (Doc 3 audit assumptions) against the new behavior before adopting
      the bump. See §4.
- [ ] **7. Confirm `probe_q_custom_public_value` and `probe_r_carrier_chain` still
      pass.** These prove the **positive** capability our approach relies on (custom-AIR
      public value crosses a batch layer; the depth-4 carrier chain threads
      `V_3 == V_0 + 3`). If `probe_q`/`probe_r` *break* while the `[0,0,0]` guards
      *also* change, the public-values feature (PR #407) may have been reverted or
      reworked — that forces a full re-evaluation of the approach (§4/§5).
- [ ] **8. Check upstream issue #436's status** (multi-layer recursion
      `WitnessConflict` at layer ≥2). If our chain depth grows and #436 is still open,
      re-run the deepest carrier-chain probe (`probe_r_carrier_chain`, and Probe X once
      it exists — the full `MAX_IN_COINS=8` carrier chain) to confirm we don't hit it.
- [ ] **9. Re-run the real-port build** (`program-plonky3` / `prover-plonky3`) and its
      tests against the new pins; re-run the pinned-rev CI job (§3).
- [ ] **10. Record the bump in the decision log** (§6): old→new revs, reason, probe
      results, who approved.

Only after all ten: the bump is adopted.

---

## 3. Pinned-rev CI

Today the spike is **excluded from the root workspace** (`Cargo.toml` `exclude =
[ "spikes/plonky3-recursion-spike", … ]`) and therefore **excluded from main CI** —
the heavy Plonky3 git deps never enter the `node`/`shared` build. That is correct
**for the throwaway spike**.

For the **real port**, `program-plonky3` and `prover-plonky3` will be normal
workspace members that depend on the pinned `p3-*` crates, so CI must build against
the exact pins and **fail on unexpected rev drift**.

### Lock discipline

- **`Cargo.lock` is committed and authoritative.** It records the resolved git rev
  for every `p3-*` crate. A bump is a reviewed change to `Cargo.lock` (§2), never an
  incidental side effect of an unrelated `cargo update`.
- CI builds with **`--locked`** so a dirty/regenerated lock fails the job instead of
  silently resolving a new rev.

### A pinned-rev CI job (shape)

Add a job (e.g. `plonky3-pins`) to `.github/workflows/ci.yaml` that runs only when
`program-plonky3` / `prover-plonky3` or their lock entries change:

1. **Assert the expected revs before building.** Keep the two canonical revs in one
   place (a small `scripts/check-plonky3-pins.sh`, or a workflow `env` block) and grep
   `Cargo.lock` for them; **fail loudly if the resolved rev differs** from the
   expected pin. This is the *unexpected-drift* gate — it catches an accidental bump
   that slipped past review.

   Expected pins (update these only via the §2 procedure):
   ```
   PLONKY3_RECURSION_REV=524665d0c2e1d294722c064786ae11dff8d9f33b
   PLONKY3_MAIN_REV=56952503e1401a62982ceaf952c5e4a829b61803
   ```
2. **Cache the git deps.** CI already caches `~/.cargo/registry` and **`~/.cargo/git`**
   keyed on `hashFiles('**/Cargo.lock')` (see `ci.yaml`). Because the pins are exact
   revs, the cache key changes **only** when the lock changes — i.e. only on a
   deliberate bump — so the expensive `p3-*` git checkout + compile is cached across
   normal runs.
3. **Build + test against the pins, `--locked`:**
   `cargo build -p prover-plonky3 --locked` and the relevant `cargo nextest run`
   targets. [VERIFY: final crate names `program-plonky3` / `prover-plonky3` once the
   port lands.]
4. **Toolchain coupling.** The job pins the same `rustc` the rest of CI uses
   (`dtolnay/rust-toolchain` — `1.81.0` today). A rev bump that needs a newer edition-2024
   toolchain must bump the toolchain in the **same** PR, so the pin and the compiler
   move together. [VERIFY: edition-2024 minimum vs `1.81.0`.]

The drift gate is the point: **CI fails if the built rev is not the reviewed rev.**
A bump is then the *only* way to change what CI builds, and it goes through §2.

---

## 4. Breaking-change detection

We have a built-in canary system and a proactive drift check. Use both.

### The regression-guard probes (canaries)

Three probes are **pinned** to `air_public_targets = [0,0,0]`:
`probe_d_multilayer_carry`, `probe_h_option1_air_public_values`,
`probe_g_fanin_pi_passthrough`. They assert the *current* primitive-table behavior:
that a `CircuitBuilder` circuit's public inputs and a primitive/aggregation leaf's
values are **not** surfaced as AIR public values across a batch layer. Our carrier
construction is designed precisely around that fact (it routes the threaded value
through a **custom** public-value-emitting table instead). **If a guard probe flips
red, the primitive-table behavior changed upstream and the carrier construction's
core assumption may no longer hold** — re-validate against Doc 3's audit assumptions
before trusting any proof built on the new rev.

The positive-capability probes (`probe_q_custom_public_value`,
`probe_r_carrier_chain`) are the other half: they must stay green for the approach to
be viable at all.

### Periodic upstream drift check (monthly)

Independently of any planned bump, run a **monthly "upstream drift check"** to surface
breakage **early, without adopting it**:

1. On a **throwaway branch**, bump the recursion rev to upstream **HEAD** and the main
   rev to HEAD's matching partner (§2 step 2).
2. Run the full 21-probe spike suite.
3. **Read the result, do not merge.** This branch is discarded. Its only job is to
   tell us, weeks ahead of time, whether an upcoming bump will:
   - flip a `[0,0,0]` guard (primitive-table behavior changed),
   - break `probe_q`/`probe_r` (the public-values channel changed/reverted),
   - hit #436 (multi-layer `WitnessConflict`),
   - or raise the toolchain / break compilation.
4. File a tracking note in the decision log (§6) with the HEAD rev tested and the
   outcome.

This converts "upstream surprised us mid-port" into "we saw it a month early."

### Signals that force a re-evaluation

Any one of these halts routine maintenance and triggers a design review:

- **A guard probe flips.** Primitive-table behavior changed → re-validate the carrier
  construction (Doc 3).
- **#436 gets fixed** → the high-level/multi-layer aggregation API may become usable
  → reconsider whether the low-level carrier construction is still the right call (the
  carrier chain exists partly to route *around* #436).
- **PR #407 gets reverted or reworked** → the public-values feature is the foundation
  the **entire** Path 1+5 approach rides on; a change there means the whole approach
  needs review, possibly a fallback to Path 3 (Sonobe) per the solutions research.

---

## 5. Upstream issue/PR tracking

We **depend on** one upstream change and **route around** another. Track both, and
have a process for filing new ones — **never patch in-tree** (§7).

| Upstream item | Repo | Relationship | What it gives / costs us | Action if it changes |
|---|---|---|---|---|
| **PR #407** "feat: support public values" (merged 2026-03-19, in pinned rev `524665d`) | `Plonky3/Plonky3-recursion` | **DEPEND ON** | The per-instance, cross-layer, soundly-bound public-value channel. The carrier construction (Path 1+5) **only exists because of this.** `probe_q` reproduces it. | If reverted/reworked: STOP. Whole approach under review (§4). Re-evaluate Path 3 (Sonobe) fallback. |
| **#436** "Multi-Layer Recursion WitnessConflict at layer ≥2" (closed without MRE) | `Plonky3/Plonky3-recursion` | **AVOID** | The high-level aggregation API bug the carrier chain is built to sidestep. Our carrier chain (`probe_r`) threads explicitly to avoid relying on the broken path. | If genuinely **fixed**: re-evaluate using the high-level API directly (it may simplify or replace the carrier construction). Until then, keep validating our chain doesn't hit it as depth grows. |

[VERIFY: confirm #436's current state (closed/open, fixed or not) before each
re-evaluation — it was "closed without MRE" as of the solutions research.]

### Filing NEW upstream issues (the no-fork process)

When the port hits an upstream gap, bug, or missing-feature:

1. **STOP** — do not patch `p3-*` in-tree, do not vendor, do not fork (§7).
2. **Reproduce minimally** — a small probe or MRE in the spike crate (the spike is the
   right home for upstream-facing reproductions).
3. **File upstream** against `Plonky3/Plonky3-recursion` (or `Plonky3/Plonky3`), with
   the MRE and the exact pinned rev. (Active maintainers; the repo responds.)
4. **Record** the issue/PR number in the tracking table and the decision log (§6).
5. **Escalate to the operator** if the gap blocks the port — the decision to wait,
   re-architect (Path 3), or commission a self-authored upstream PR (Path 2) is an
   **operator decision**, not an in-tree workaround.

---

## 6. Re-pin cadence + ownership

- **Owner.** The Plonky3-migration maintainer owns the pin: the rev pair, the bump
  procedure (§2), the monthly drift check (§4), the upstream tracking table (§5), and
  the decision log. [VERIFY: assign a named CODEOWNERS entry for
  `program-plonky3` / `prover-plonky3` / `docs/migration/` and the pinned-rev CI job.]
- **Review cadence.** Re-review the pin **monthly**, coinciding with the drift check
  (§4). Bump only on a §2 trigger — monthly review does **not** mean monthly bumping;
  most months should conclude "HEAD tested in throwaway, no reason to bump, staying on
  `524665d`/`5695250`."
- **Decision log.** Append-only, in this directory:
  `docs/migration/PLONKY3_PIN_DECISIONS.md` [VERIFY: create on first bump]. Each entry:
  date · old→new rev pair · trigger (security/feature/perf/drift-check) · 21-probe
  result (esp. the three `[0,0,0]` guards + `probe_q`/`probe_r`) · #436 status · who
  approved. The drift-check (no-bump) results land here too, so the log is the single
  history of "what upstream was doing and what we did about it."

---

## 7. Fork policy — forking is EXCLUDED

**Forking `Plonky3` or `Plonky3-recursion` is out of scope, per
`../../MIGRATION_PLONKY3.md` §16 (hard-stop / no-fork rule).** This is restated in the
spike result's escape-route analysis and in the solutions research (Path 8 — "Fork +
maintain" — surfaced only for completeness, ⚠️ excluded by §16, inferior to Path 1+5
which needs no fork and Path 2 which upstreams the change).

Concretely:

- **No in-tree patches** to `p3-*` crates. No `[patch.crates-io]` / `[patch."https://…"]`
  pointing at a private fork. No vendored-and-edited copies.
- An upstream gap is handled by the §5 process: **STOP → reproduce → file upstream →
  escalate to the operator.** The carrier construction (Path 1+5) was chosen
  *specifically* because it needs no fork — everything it touches is public/unsealed
  API on the pinned rev.
- **If upstream truly blocks the port** (a guard probe flips and the carrier
  construction can't be re-validated; #407 is reverted; a needed fix never lands), the
  resolution is an **operator decision** among: hold on the current pin, pursue the
  Path 2 self-authored *upstream* PR, or switch to the Path 3 (Sonobe) IVC fallback —
  **never a silent fork.** Protocol-touching or verification-semantics-touching
  changes are an explicit §16 STOP-and-escalate.

---

### Quick reference — the canonical pin

```
Plonky3/Plonky3-recursion @ 524665d0c2e1d294722c064786ae11dff8d9f33b
Plonky3/Plonky3           @ 56952503e1401a62982ceaf952c5e4a829b61803
```

Bump only via §2. Verified in CI via §3. Watched via §4 (the `[0,0,0]` guards:
`probe_d_multilayer_carry`, `probe_h_option1_air_public_values`,
`probe_g_fanin_pi_passthrough`). Logged via §6. Never forked (§7).
