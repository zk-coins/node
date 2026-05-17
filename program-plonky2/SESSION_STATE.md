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

## What's deferred (the one big gap)

**Stage 5d-next-4 — source-side in-coin verification.** Design doc
at [`STAGE_5D_NEXT_4_DESIGN.md`](STAGE_5D_NEXT_4_DESIGN.md).
Implementation effort estimate: 4–8 hours of focused work + multiple
20–40-min test cycles. Three SPEC §13 negatives are blocked by this:

- Input coin whose source proof is NOT in commitment history.
- Input coin whose identifier is NOT in source's `output_coins_root`.
- Wrong `vk` on a recursive source proof.

When you tackle it, **read the design doc first** — the
`common_data_for_recursion_c` shape needs N verify_proof calls
(N = `MAX_IN_COINS + 1` = 9) and `INNER_PAD_BITS` likely climbs to
17. Use a `OnceLock`-cached `StateTransitionCircuit` in tests to
avoid paying the build cost per-test.

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
