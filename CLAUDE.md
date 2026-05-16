# CLAUDE.md — Project Onboarding for Agent and Human Sessions

This file is the canonical entry point for anyone — fresh Claude session,
new contributor, security reviewer — picking up work on this branch
without prior context. Read this first, then dive into the linked
documents in the order given below.

If you skip this file and start editing, you will rediscover constraints
the hard way. The whole point of this file is to prevent that.

---

## 1. What this branch is

`feat/plonky2-migration` is migrating the zkCoins server's ZK proving
backend from **SP1 + SHA256** (on `develop`) to **Plonky2 + Poseidon
over Goldilocks** (this branch). The end state replaces the SP1 path
outright; there is no dual-backend phase and no migration of existing
state — see §3 below for why.

This is **not** a "rewrite for fun" branch. It exists because the SP1
path's proof latency is incompatible with the 1-second wallet-UX target,
and SP1 has no on-host (no-cloud, no-GPU) acceleration path on Apple
Silicon. Plonky2 is the bridge stack until the post-MVP Plonky3
evaluation; see [`ROADMAP.md`](./ROADMAP.md) "Post-MVP Path: Plonky3".

---

## 2. Reading order

1. **This file (`CLAUDE.md`)** — invariants, decision recipe, gates.
2. **[`ROADMAP.md`](./ROADMAP.md)** — current status table, per-step
   plans, effort, risk register, post-MVP path. Always-fresh; if a
   commit changes scope and this file isn't updated, the PR is broken.
3. **[`SPEC.md`](./SPEC.md)** — what the protocol *does*. Glossary
   (§Glossary, right after §1), divergences from the paper (§15), full
   circuit specification (§§1–14).
4. **[`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md)** — why we
   chose what we chose. §3 (11 divergences from Shielded CSV paper),
   §5 (6 locked-in design decisions), **§7 Lessons Learned** (11
   gotchas-and-fixes accumulated during implementation — *required
   reading before touching the affected code areas*).
5. **[`program-plonky2/CONTRIBUTING.md`](./program-plonky2/CONTRIBUTING.md)**
    — operational handoff: toolchain, build/test/lint, coverage gate,
   orphan-process cleanup, gadget-authoring pattern.
6. **Source code** — `program-plonky2/src/`. Off-circuit: `hash`,
   `merkle/*`, `types`, `inputs`. In-circuit: `circuit/*`. Each module
   has a `//!` docstring stating its mirror to off-circuit logic where
   applicable.

---

## 3. Project invariants (non-negotiable)

These constraints decided more than once and have to hold across every
PR on this branch. If you find yourself proposing a change that
contradicts one of these, stop and discuss with Cyrill first.

### 3.1 Server-side compute architecture

The server generates every ZK proof, holds every Merkle tree, broadcasts
every Taproot inscription. The wallet holds only the user's private key
and signs BIP-340 Schnorr over `SHA256(serialize(asth) ‖ serialize(ocr))`.

There is **no in-browser Poseidon, no wasm-Plonky2 verifier, no in-app
ZK gadget**. The wallet trusts the server for ZK correctness — that is
the explicit zkCoins UX tradeoff vs. pure self-custody wallets.

Source: `MIGRATION_RESEARCH.md` §5.4 (Schnorr boundary),
`ROADMAP.md` Architecture summary, Step 8 scope.

### 3.2 Closed test environment — DEV *and* PRD

No external users, no real money, no existing user-base to migrate.
Step 7 ([`ROADMAP.md`](./ROADMAP.md)) deletes the SP1 path outright
when Plonky2 is ready. **No Cargo feature flag**, no dual backend, no
compatibility shim, no parallel deploy. Server state files
(`smt.bin`, `mmr.bin`, `accounts.bin`, `latest_block.bin`) are deleted
on cutover; new server starts fresh.

When you see a "shall we migrate X?" question, the answer for v1 is
"no, replace it". Migration logic enters only after the real mainnet
launch (with external users).

Source: `ROADMAP.md` Architecture summary, Step 7 strategy.

### 3.3 Hardware target: Mac Studio M3 Ultra, 96 GB RAM, CPU-only

Single host. **No GPU. No CUDA. No external cloud proving service**
(no Succinct Prover Network, no AWS, no Lambda Labs). If a design
overshoots the performance budget, the design changes — we do not add
hardware.

Performance budget: warm proof ≤ 5 s (target ≤ 1 s), cold-start ≤ 30 s,
memory peak < 64 GB on M3 Ultra. Knobs when missed: reduce
`MAX_IN_COINS`, drop in-coin recursion, switch to folding. **Hardware
escalation is not a knob.**

Source: `ROADMAP.md` Architecture summary, R2 risk, Step 9 budget;
`MIGRATION_RESEARCH.md` §7.11.

### 3.4 MVP = minimal feature surface + 100% test coverage

These are **simultaneous**, not alternative. "Minimal" reduces the
surface; "100%" keeps what remains clean. "MVP" is never an excuse to
skip tests — it's an excuse to skip *features*. Negative tests
asserting bad inputs are rejected are mandatory.

Gate: `cargo llvm-cov --fail-under-lines 100 -- --test-threads=1` from
inside the affected crate. Current state on `program-plonky2`:
**100% lines, 100% functions, 100% regions** (64 tests).

Source: `ROADMAP.md` "Definition of MVP".

### 3.5 Plonky2 is bridge tech; Plonky3 is the long-term destination

But we do **not** preemptively adopt Plonky3's BabyBear / Poseidon2
during this migration — the cost (fork-land deps, custom Poseidon2,
re-typed limb layouts) outweighs the benefit on CPU-only hardware
(`MIGRATION_RESEARCH.md` §7.11). Plonky3 evaluation begins post-Step 9.

Source: `ROADMAP.md` "Post-MVP Path: Plonky3" + "Considered alternative".

---

## 4. Decision recipe — should this go in the MVP?

When you encounter a "should we add X to the MVP?" question, run this
checklist in order. Stop at the first "no".

1. **Is X on the critical path for the one-shot user loop?** (create
   account → mint → send → receive → balance) If no, defer to post-MVP.
2. **Does X compromise §3.1 (server-side compute)?** If yes, redesign
   so all heavy compute is server-side.
3. **Does X require new hardware (§3.3)?** If yes, redesign.
4. **Does X assume migration logic (§3.2)?** If yes, redesign to
   "replace not migrate" or defer until mainnet launch.
5. **Can X be tested to 100% coverage including negative paths?** If
   not, refactor or gate behind a Cargo feature; gated-off code
   doesn't count for coverage.
6. **Does X drift from the divergence list (SPEC §15)?** If yes,
   updating the divergence list is part of the PR.

If all six pass, X enters the MVP. Update `ROADMAP.md` Status-at-a-
Glance and the relevant `### Step N` section *in the same PR*.

---

## 5. Pre-push checklist

Run from inside `program-plonky2/` for changes to that crate. Run from
the workspace root for changes to `program`/`server`/`shared`/`script`.

```bash
cargo build
cargo test -- --test-threads=1
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo llvm-cov --fail-under-lines 100 -- --test-threads=1    # only for program-plonky2 right now
```

All five must pass. If any fail, do not push.

After push: poll CI in the background until it goes green. If red,
investigate and fix — never abandon a red CI run.

---

## 6. Branch hygiene rules

- **No force-pushes**, even to your own side-branches. Once a commit
  is on `origin/feat/plonky2-migration`, it stays in history.
- **No `--no-verify`** on commits. Pre-commit hooks fire for reasons.
- **No squashing by you** — Cyrill squashes at merge time if needed.
- **Cyrill merges PRs**, not you. PRs default to draft
  (`gh pr create --draft`); flip to ready only when Cyrill says so.
- Doc-only commits to `ROADMAP.md` / `SPEC.md` / `MIGRATION_RESEARCH.md`
  / `CONTRIBUTING.md` / `CLAUDE.md` that just correct or extend these
  files are not individually listed in `ROADMAP.md` "Done" — they're
  in `git log`, that's enough.

---

## 7. Where to put new knowledge

When you discover a new gotcha or make a new decision, add it to the
right place:

| Type of knowledge | Where |
| --- | --- |
| Protocol-level fact (new circuit invariant, public-input change) | `SPEC.md` |
| Why we chose / didn't choose something | `MIGRATION_RESEARCH.md` §5 (decisions) or §7 (lessons) |
| New status / new step / new risk | `ROADMAP.md` |
| Toolchain or workflow detail | `program-plonky2/CONTRIBUTING.md` |
| Cross-cutting invariant for the whole project | This file (`CLAUDE.md`) §3 |

If a thing belongs in two places, link from one to the other. Don't
duplicate prose — the second copy will drift.

---

## 8. Current branch state at time of writing

64 tests, all green on `nightly-2025-04-15` + `plonky2 1.1.0`.
100% line/function/region coverage on `program-plonky2`.
Steps 1–4d done; step 4c+ (SMT insert gadget) and step 5 (monolithic
state-transition circuit) are the immediate next work — see ROADMAP.

For the live status, check `ROADMAP.md` § "Status at a Glance" — that
table is the source of truth, this file deliberately gives a snapshot
only.

---

## 9. Common foot-guns (already encountered, recorded as lessons)

These are in [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md) §7, but
worth mentioning here so a fresh session doesn't fall into them:

1. **Don't seed `DEFAULT_HASHES[TREE_DEPTH]` with `ZERO_HASH`** in
   Poseidon SMTs — structural collision (§7.1).
2. **`pw.set_target(t, v)` returns `Result` in plonky2 1.x** — must
   handle (§7.3).
3. **Pack 7 bytes per Goldilocks element, never 8** — modulus safety
   (§7.4).
4. **Use `Option::get().copied().unwrap_or(sentinel)` for defensive
   bounds checks**, not explicit `if/else` — coverage cleanliness
   (§7.9).
5. **Annotate every `#[cfg(test)] mod tests` with
   `#[cfg_attr(coverage_nightly, coverage(off))]`** — required for
   100% coverage gate (§7.10).
6. **No GPU/cloud assumption in performance plans** — single Mac
   Studio M3 Ultra is the only hardware (§7.11).
7. **Kill orphan `cargo test` binaries** after long circuit-test runs
   — they leak 30+ GB of swap (§7.6).
8. **`gh` in background tasks needs `--repo <owner>/<repo>`** — sandbox
   cwd issues otherwise (§7.7).

---

## 10. References to upstream

- Shielded CSV paper: <https://eprint.iacr.org/2025/068>
- Normative reference implementation:
  <https://github.com/ShieldedCSV/ShieldedCSV> — **not**
  `BitVM/zkCoins`, which is a 182-LOC IVC scaffold (§7.8).
- Plonky2: <https://github.com/0xPolygonZero/plonky2>
- This branch is at: <https://github.com/zk-coins/server>, PR `#17`.

---

*Maintain this file. If a future contributor wouldn't be able to take
over without reading it cold, the file is wrong.*
