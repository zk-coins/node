# Session state — pickup notes for the next agent

Read this first if you're picking up where the previous session
left off.

## Current branch + HEAD

`feat/plonky2-migration`, latest commit on `origin`: see `git log`.
PR [#17](https://github.com/zk-coins/server/pull/17) is the
mergeable migration PR with all 6 CI checks passing (Lint & Build,
Tests, Analyze rust, Analyze actions, CodeQL, Coverage MVP scope).

## Step status summary

- Steps 1–4: ✅ done
- Step 5 (monolithic circuit, all stages through 5d-next-5): ✅
  done. Stage 5d-next-5 source-side verification via aggregator
  pattern landed via PR [#23](https://github.com/zk-coins/server/pull/23)
  — Phase 1 (aggregator skeleton, `cc9c4b6` from PR #22) + Phase 2a
  (outer `verify_proof(aggregator)` + `connect_hashes` vk binding +
  `ConstantGate::new(2)` shape lock) + Phase 2b (per-slot SMT
  inclusion + SPEC §8 (c)(d)(e) chain + OCR coupling + active-bit
  binding) + Phase 3 (3 SPEC §13 source-side negatives). Two
  Plonky2 1.1.0 shape blockers resolved empirically (probe in
  [`src/circuit/recursion_shape_probe.rs`](src/circuit/recursion_shape_probe.rs)),
  end-state documented in
  [`STAGE_5D_NEXT_5_AGGREGATOR.md`](STAGE_5D_NEXT_5_AGGREGATOR.md).
- Step 6 (script-plonky2 prover host wrapper): ✅ done (`d96bb62`)
- Step 7 (server replacement): ✅ done. Workspace toolchain unified
  to nightly. `program/` + `script/` deleted (recoverable via
  `git checkout v0.last-sp1 -- ...`). shared + server fully
  migrated to Plonky2-era modules with the HashDigest type-shift
  handled at all boundaries. `account_server::send_coins` wired to
  the Plonky2 `Prover` wrapper (`c71c9fc`); the initial cut used
  off-circuit source-side validation but with Stage 5d-next-5 Phase
  2b landed, the in-circuit `prove_*_and_sources` API is now
  available — switching `send_coins` over is a Step 7 follow-up.
  Dockerfile re-introduced (`dac0179`). 106 server tests pass on
  the MVP build, 119 with `--all-features` (10 inline error-path
  tests in `d6a3cb9`, 64 ported SP1-era fixtures re-enabled via
  `account_server_tests.rs` + `server_tests.rs` after rewriting
  the `proof.public_values` → `proof.public_inputs` bridge and
  the `[u8;32]` → `HashOut<F>` address casts, plus the
  state-side fix to record MMR roots in their extended form to
  match the Plonky2 circuit invariant).
- Steps 8–9: ⏳ todo (App/Wallet integration + DEV deployment).
  Both require work outside this repo (`zk-coins/app` + deploy
  pipelines + SSH access to dfxdev/dfxprd).

## Smoke test verified

`cargo run --release -p server` boots cleanly:
- `Prover::new()` builds the cyclic state-transition circuit
- REST server binds `0.0.0.0:4242`
- `GET /health` → `ok`
- `GET /api/info` → `{"network":"Mutinynet"}`
- Block scanner connects to Esplora + processes Mutinynet tip
- No panics, no errors

## Active parallel work

None as of the post-PR-#23-merge state. Stage 5d-next-5 is fully
landed.

Step 7 follow-ups (open, not blocking MVP):

1. Wire `account_server::send_coins` to use
   `prove_*_with_in_and_out_coins_and_sources` from PR #23 so the
   source-side validation runs **in-circuit** instead of the
   off-circuit pre-check introduced in `c71c9fc`. The data the
   prove API needs (source `ProofWithPublicInputs`,
   `InclusionProof`, `CommitmentMerkleProofs`) is already in
   `account.coin_queue` — each `CoinProof` carries `.proof`,
   `.inclusion_proof`, and a `.commitment` for the source CMP build.
2. Drop the temporary CI coverage exclusions for `account_server.rs`
   + `server.rs` once (1) lands and brings their coverage back.
3. Optional: include the Stage 5d-next-5 cyclic tests in CI by
   removing `--skip stage_5d --skip stage_5e` and bumping the
   `tests` job's `timeout-minutes` from 30 to ~120 (current local
   wall is ~42 min on M3 with `--test-threads=2`, so single-threaded
   on `ubuntu-latest` is ~80–120 min).
4. Optional: fold `STAGE_5D_NEXT_5_AGGREGATOR.md` content into
   `MIGRATION_RESEARCH.md §7.22` once Step 7 follow-up (1) lands.

## What works end-to-end

The monolithic state-transition circuit at
[`src/circuit/main.rs`](src/circuit/main.rs) implements **the full
SPEC §8 predicate including source-side verification of in-coins**
(Stage 5d-next-5):

- Initial-branch predicate (mint exception, empty SMT roots).
- AccountUpdate branch with cyclic recursion, SPEC §8 (a)+(b).
- Prev-account `CommitmentMerkleProofs` (c)+(d)+(e) via fixed-shape
  SMT + 2× MMR inclusion gadgets.
- `MAX_IN_COINS = 8` in-coin slots with SMT non-inclusion + insert
  into `coin_history_root` and full `apply_coin` semantics
  (recipient check + balance overflow check via `split_le(sum, 33)`).
- **Per in-coin slot — Stage 5d-next-5 Phase 2b — source-side**:
  - Strict `connect(slot.active, aggregator.slot[i].active_pi)` —
    no in-coin can be consumed without a verified source proof.
  - SMT inclusion of `coin.identifier` in
    `source.output_coins_root`.
  - OCR coupling: `source.output_coins_root ==
    source_cmp.commitment_out_coins_root`.
  - SPEC §8 (c)(d)(e) chain for source's commitment in the outer's
    `history_root` (mirrors the prev-account CMP gates).
- `MAX_OUT_COINS = 8` out-coin slots with SMT non-inclusion + insert
  into `output_coins_root`, balance subtraction with underflow check
  via `split_le(diff, 64)`, identifier derivation
  (`out_coin.identifier == Poseidon(interim_asth || u32(index))`)
  and pubkey rotation.
- `INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15` (1 << 15 = 32 768 gates in
  the helper, matching the ~50 k outer circuit gates' degree 16 via
  `helper_degree = pad_bits + 1`).

## What's deferred to post-MVP

Nothing in the state-transition circuit itself is deferred — Stage
5d-next-5 landed (PR [#23](https://github.com/zk-coins/server/pull/23))
and all three previously-off-circuit SPEC §13 source-side negatives
are now covered in-circuit (`stage_5d_next_5_phase_3_*` tests).

Pre-mainnet protocol redesigns remain (see ROADMAP "Pre-mainnet
blockers"): D2/D10 (recipient hiding), D7 (reorg safety), D8
(per-coin nullifier-accum). These are real protocol changes, not
implementation gaps.

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

1. [`../server/src/account_server.rs`](../server/src/account_server.rs)
   `send_coins` — switch from off-circuit source-side validation to
   in-circuit via `prove_*_and_sources` (Step 7 follow-up).
2. [`../.github/workflows/ci.yaml`](../.github/workflows/ci.yaml) —
   optionally include Stage 5d-next-5 cyclic tests in CI (remove
   `--skip stage_5d --skip stage_5e`, bump timeout).
3. [`../MIGRATION_RESEARCH.md`](../MIGRATION_RESEARCH.md) §7.22 —
   fold the empirical insights from
   [`STAGE_5D_NEXT_5_AGGREGATOR.md`](STAGE_5D_NEXT_5_AGGREGATOR.md)
   in once Step 7 follow-up (1) above lands.

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

After confirmation: tackle the Step 7 follow-up to switch
`account_server::send_coins` from off-circuit source-side
validation to in-circuit via `prove_*_and_sources` (see "Files most
likely to be touched next" above). Then Steps 8–9 (App/Wallet +
DEV deployment).

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
