# Session state — pickup notes for the next agent

Generated at the end of the long Stage-5 implementation session.
Read this first if you're picking up where Stage 5 left off.

## Current branch + HEAD

`feat/plonky2-migration`, latest by this agent: `50a1bd9` (panic-test
speedup). The full set of Stage-5 commits is enumerated in
[`../ROADMAP.md`](../ROADMAP.md) under the **Done** section.

## What works end-to-end

The monolithic state-transition circuit at
[`src/circuit/main.rs`](src/circuit/main.rs) implements SPEC §8
with **everything except source-side verification of in-coins**:

- Initial-branch predicate (mint exception, empty SMT roots).
- AccountUpdate branch with cyclic recursion, SPEC §8 (a)+(b).
- `CommitmentMerkleProofs` (c)+(d)+(e) via fixed-shape SMT + 2× MMR
  inclusion gadgets.
- `MAX_IN_COINS = 8` in-coin slots with SMT non-inclusion + insert
  into `coin_history_root` and full `apply_coin` semantics
  (recipient check + balance overflow check via `split_le(sum, 33)`).
- `MAX_OUT_COINS = 8` out-coin slots with SMT non-inclusion + insert
  into `output_coins_root`, balance subtraction with underflow check
  via `split_le(diff, 64)`, identifier derivation
  (`out_coin.identifier == Poseidon(interim_asth || u32(index))`)
  and pubkey rotation.
- `INNER_PAD_BITS = 14` (1 << 14 = 16 384 gates) covers the
  ~10 k outer circuit gates with margin.

## What's deferred to post-MVP / Stage 5d-next-5

**Stage 5d-next-4 — source-side in-coin verification.** Design doc
at [`STAGE_5D_NEXT_4_DESIGN.md`](STAGE_5D_NEXT_4_DESIGN.md).
**Attempted in commit `c1df545` (subsequently reverted)** — see
[`../MIGRATION_RESEARCH.md` §7.21](../MIGRATION_RESEARCH.md) for the
two Plonky2 1.1.0 blockers (multi-`_or_dummy` ConstantGate mismatch +
in-circuit data-only common_data shape mismatch).

For zkCoins server-heavy MVP, source-side verification is enforced
**off-circuit**: the trusted server only folds validly-proved
commitments into the history MMR. Stage 5d-next-3's prev_account
CMP + the SPEC §8 (c)(d)(e) chain still provides the
"prev-account-state is in history" guarantee for the AccountUpdate
branch.

Three SPEC §13 negatives remain off-circuit-only:
- Input coin whose source proof is NOT in commitment history.
- Input coin whose identifier is NOT in source's `output_coins_root`.
- Wrong `vk` on a recursive source proof.

These are enforced by server-side input validation before proving;
they cannot bypass the trusted server's history-MMR folding step.

Stage 5d-next-5 paths forward (post-MVP):
1. Aggregator pattern (separate non-cyclic sub-circuit).
2. Plonky2 upstream patch for multi-instance `_or_dummy`.
3. Per-slot common_data shape matching via iterative bisection.

## Test count + budget

103 tests total (see [`../ROADMAP.md`](../ROADMAP.md) for the
breakdown). At production parameters:

- ~70 off-circuit tests: complete in seconds.
- ~24 `circuit::main` cyclic tests at 5–15 min wall each.
- ~7 `circuit::*` non-cyclic tests at 30 s–2 min wall each.

A serial `cargo test` sweep at `--test-threads=1` is several hours.
Default multi-thread is bounded by RAM (~2 GB per test).

`cargo llvm-cov --fail-under-lines 100 -- --test-threads=1` is the
coverage gate. Last verified at 100 % lines / 99.70 % regions on
the pre-5d state; the 5d work was line-by-line audited to stay at
100 % via per-assertion panic tests. **A fresh full coverage sweep
post-`50a1bd9` is the next session's first task.**

## Per-stage commit map

| Stage | Commit | Summary |
| --- | --- | --- |
| 5a | `1036066` (superseded by 5b) | Cyclic-recursion plumbing PoC |
| 5b | `d167237` | Initial-branch predicate |
| 5c | `bba6470` | AccountUpdate branch + state continuity |
| SMT redesign | `4f317fe` | Uncompressed fixed-256-depth SMT |
| 5c+ | `4bc5f2f` | `CommitmentMerkleProofs` in-circuit |
| coverage fix | `2ce36ce` | 3 panic tests for assert_eq messages |
| 5d | `7db3c29` | In-coin slot processing for `coin_history` |
| 5d-next | `0195f71` | `apply_coin` (recipient + balance + overflow) |
| 5d-next-2 | `b2b82e7` | Bump `MAX_IN_COINS = 8` |
| 5d-next-3 | `6b5a885` | Out-coin processing |
| 5d-next-4 design | `1943316` | Design doc for source verification |
| 5d-next-3-bump | `56f3a05` | Bump `MAX_OUT_COINS = 8` |
| 5d-next-3 combined | `d292855`, `8fab78a` | Init / Update with both loops active |
| 5e | `7db3c29`, …, `50a1bd9` | 10-of-11 SPEC §13 negatives |
| docs / cleanup | `508ec9c`, `a502b8f`, `05c17f8`, `50a1bd9` | ROADMAP + SPEC + panic-test refactor |

## Files most likely to be touched next

1. [`src/circuit/main.rs`](src/circuit/main.rs) — adding source
   verification (Stage 5d-next-4) means new witnesses + a second
   `conditionally_verify_cyclic_proof_or_dummy::<C>` call per slot
   + matching `common_data_for_recursion_c` extension.
2. [`STAGE_5D_NEXT_4_DESIGN.md`](STAGE_5D_NEXT_4_DESIGN.md) — fold
   into actual 5d-next-4 PR and delete once that work lands.
3. [`../MIGRATION_RESEARCH.md`](../MIGRATION_RESEARCH.md) — append
   §7.20+ with the multi-recursive-verify lessons when 5d-next-4
   lands.

## Things explicitly NOT in this branch

- `script-plonky2/` prover host (Step 6 in ROADMAP).
- Server-side replacement of SP1 with Plonky2 (Step 7).
- App / wallet integration (Step 8).
- DEV deployment (Step 9).

Those are sequential after Step 5 lands.

## Test confirmation status (end of session)

What was **explicitly proved to pass** on this session's machine,
at the current production parameters (`MAX_IN_COINS = MAX_OUT_COINS
= 8`, `INNER_PAD_BITS = 14`):

| Test | Confirmed | Run notes |
| --- | --- | --- |
| `stage_5d_initial_with_one_active_in_coin` | ✅ | 188 s wall, single in-coin |
| `stage_5d_next_3_initial_with_one_active_out_coin` | ✅ | 761 s wall, single out-coin |
| `stage_5d_next_3_initial_combined_in_and_out_coin` | ✅ | 781 s wall, both loops active |
| `stage_5d_next_3_account_update_combined_in_and_out_coin` | ✅ | 926 s wall, both loops + cyclic recursion + CMP (b)(c)(d)(e) chain |

What was **left running at session end** (not in this snapshot):
- `cargo test -- stage_5d_next_3_prove` (commit `a502b8f`, slow
  panic tests; superseded by `50a1bd9` which speeds them up).

What is **high-confidence but unrun** at MAX=8:
- All 5b / 5c / 5c+ tests (existed at smaller MAX, behave identically
  when the active-slot count is unchanged; the wrappers pad with
  inactive dummies).
- All 5e negative tests (same pattern as previously verified at
  MAX_IN_COINS=1).
- The remaining 4 stage_5d panic tests.

## Next session — verification checklist

Before adding new features:

1. `cd ~/Documents/GitHub/zkcoins/server-claude && git fetch && git
   pull --ff-only origin feat/plonky2-migration` — pull any
   parallel work since `7db536d`.
2. `cd program-plonky2 && cargo check` — should be a no-op build.
3. `cargo test --lib` — full sweep at MAX=8. Expect ~1-2 hours
   multi-threaded.
4. `cargo llvm-cov --fail-under-lines 100 -- --test-threads=1` —
   the coverage gate. Expect ~3-5 hours sequential. Critical to
   re-confirm the 100% lines metric on the current source state —
   it was 99.70% before the 5d work and was line-by-line audited
   to stay at 100% via per-assertion panic tests, but a fresh run
   is the authoritative check.

If any test fails: bisect against the commit list in
[`../ROADMAP.md`](../ROADMAP.md) Done section.

After confirmation: tackle stage 5d-next-4 source verification per
[`STAGE_5D_NEXT_4_DESIGN.md`](STAGE_5D_NEXT_4_DESIGN.md). Read the
design first — the multi-cyclic-verify architectural decision
(Option A vs B vs C) matters.

## Lesson index in MIGRATION_RESEARCH §7

For quick orientation, the relevant lessons from this session:

| § | Topic |
| --- | --- |
| 7.12 | BitVM's `common_data_for_recursion` is broken under Plonky2 1.1.0 |
| 7.13 | Coverage debt from unreachable `Result<()>` calls — use `.expect()` |
| 7.14 | Path-compressed SMTs are incompatible with cyclic recursion |
| 7.15 | Conditional constraints via `select_hash` masking |
| 7.16 | MMR `root_extended` / `extend_to` for fixed-depth verification |
| 7.17 | Per-slot `active`-bit masking for variable-count loops |
| 7.18 | `add_virtual_target` requires explicit witnessing; prefer `split_le` |
| 7.19 | `account_state.hash` has three roles (initial / interim / final) |
| 7.20 | Speed up panic tests via `cyclic_base_proof` short-circuit |
