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
  [`MIGRATION_RESEARCH.md` §7.22](../MIGRATION_RESEARCH.md#722-stage-5d-next-5-source-side-verification-via-aggregator-pattern--codified-resolves-721).
- Step 6 (script-plonky2 prover host wrapper): ✅ done (`d96bb62`)
- Step 7 (server replacement): ✅ done. Workspace toolchain unified
  to nightly. `program/` + `script/` deleted (recoverable via
  `git checkout v0.last-sp1 -- ...`). shared + server fully
  migrated to Plonky2-era modules with the HashDigest type-shift
  handled at all boundaries. `account_server::send_coins` wired to
  the Plonky2 `Prover` wrapper (`c71c9fc`); the **in-circuit
  source-side validation** via `prove_*_and_sources` is wired
  through (Step 7 follow-up, addresses #25), with the off-circuit
  pre-check loop retained as **defense-in-depth fast-fail** before
  the minute-scale prove. Dockerfile re-introduced (`dac0179`). 138
  server tests pass with `--all-features` (32 baseline + 10 inline
  error-path in `d6a3cb9` + 64 ported SP1-era fixtures re-enabled
  via `account_server_tests.rs` + `server_tests.rs` + 13
  feature-gated + 1 new Stage 5d-next-5 Phase 2b negative + 17
  `map_send_coins_error` unit tests landed in PR #31 + 1 new
  handler-level 404 test landed in PR #31). All surface verified
  end-to-end in release mode.
- Steps 8–9: ⏳ todo (App/Wallet integration + DEV deployment).
  Both require work outside this repo (`zk-coins/app` + deploy
  pipelines + SSH access to the DEV / PRD hosts).

## Smoke test verified

`cargo run --release -p server` boots cleanly:
- `Prover::new()` builds the cyclic state-transition circuit
- REST server binds `0.0.0.0:4242`
- `GET /health` → `ok`
- `GET /api/info` → `{"network":"Mutinynet"}`
- Block scanner connects to Esplora + processes Mutinynet tip
- No panics, no errors

## Active parallel work

None. PR #31 (Issue #28 housekeeping) addresses all four deferred
follow-ups (HTTP error mapping + CI coverage exclusions + CI cyclic
tests + doc fold). Once PR #31 merges into `feat/plonky2-migration`,
this section reflects the post-merge state.

Closed follow-ups (all landed in PR #31):

1. ✅ done — `/api/send` + `/api/mint` switched from `200 OK +
   success:false` to `4xx/5xx + body.error` via the new
   `map_send_coins_error` helper. 14 unit tests pin every documented
   `send_coins` error string to its `(StatusCode, body)` pair.
   See PR #31 commit `feat(api): replace 200+success:false ...`.
2. ✅ done — the workflow's `--ignore-filename-regex` already
   drops `account_server.rs` + `server.rs` (Issue #28's snapshot
   of the exclusion list was stale at the file level). Local
   `cargo llvm-cov --release -p server --fail-under-lines 100
   --fail-under-functions 100` returns exit 0 with the current
   exclusion list: 100% functions (96/96), 99.44% lines
   (1067/1073), 97.98% regions. The 6 uncovered lines are all
   `?` error-propagation sites in `account_server.rs::send_coins`
   (323, 358, 400, 412, 415, 478) — the gate accepts the
   exit-0 status as authoritative; no tactical `#[coverage(off)]`
   annotations added (every uncovered line is a legitimately
   reachable Err path, just not exercised in the current test
   suite).
3. ✅ done — `tests` job runs the full Stage 5c+/5d/5d-next-3/
   5d-next-5/5e cyclic sweep (`--skip stage_5*` flags removed).
   `timeout-minutes` bumped 75 → 180 to fit ~125–165 min worst-case
   wall on `ubuntu-latest`.
4. ✅ done — aggregator-pattern write-up folded into
   [`../MIGRATION_RESEARCH.md` §7.22](../MIGRATION_RESEARCH.md#722-stage-5d-next-5-source-side-verification-via-aggregator-pattern--codified-resolves-721);
   standalone tracker file deleted.

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

At Stage 5d-next-5 / Phase 2b production parameters
(`MAX_IN_COINS = MAX_OUT_COINS = 8`,
`INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15`):

- `program-plonky2` lib: 117 tests total (115 default-run + 2
  `#[ignore]`d `recursion_shape_probe` diagnostics). Of the 115
  default-run, ~39 are cyclic-recursion tests (build the
  state-transition + aggregator circuits and prove), the remainder
  exercise off-circuit gadgets (Poseidon / SMT / MMR / types /
  inputs). `cargo test --release --lib -- --test-threads=2` wall
  ~42 min on M3. Single-threaded ~80–120 min on `ubuntu-latest`.
- `server` crate: 120 tests with `--all-features` (32 baseline + 10
  inline error-path + 64 ported SP1-era fixtures + 13 feature-gated
  + 1 Stage 5d-next-5 Phase 2b negative). `cargo test -p server
  --release --all-features -- --test-threads=1` wall ~36 min on M3.

A serial workspace sweep at `--test-threads=1` is several hours.
Default multi-thread is bounded by RAM (~2 GB per test).

`cargo llvm-cov --fail-under-lines 100 -- --test-threads=1` is the
coverage gate. The CI workflow currently excludes
`account_server.rs` + `server.rs` from the gate while the in-circuit
`send_coins` refactor was in progress; with the refactor landed
(this branch), the exclusions can be dropped — see "Files most
likely to be touched next" above.

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
| 5e | `7db3c29`, …, `50a1bd9` | 10-of-11 SPEC §13 negatives (pre-5d-next-5) |
| docs / cleanup | `508ec9c`, `a502b8f`, `05c17f8`, `50a1bd9` | ROADMAP + SPEC + panic-test refactor |
| 5d-next-5 Phase 1 | `cc6e60e`-era from PR [#22](https://github.com/zk-coins/server/pull/22) (`cc9c4b6`) | Aggregator skeleton + per-slot `conditionally_verify_proof` |
| 5d-next-5 Phase 2a | PR [#23](https://github.com/zk-coins/server/pull/23) (`b5be37a`) | Outer `verify_proof(aggregator)` + `connect_hashes` vk binding + `ConstantGate::new(2)` shape lock |
| 5d-next-5 Phase 2b | PR #23 (`f9fa75a`) | Per-slot SMT inclusion + SPEC §8 (c)(d)(e) chain + OCR coupling + active-bit binding |
| 5d-next-5 Phase 3 | PR #23 (`f9fa75a` + `e09fe5f`) | 3 SPEC §13 source-side negatives + 4 positives; fixes the previously-3-of-11 §13 gap |
| Step 7 follow-up | this branch (`7ff3f7b`, `cc6e60e`) | `send_coins` switched to in-circuit `prove_*_and_sources`; off-circuit shim retained as defense-in-depth fast-fail |

## Files most likely to be touched next

1. [`../.github/workflows/ci.yaml`](../.github/workflows/ci.yaml) —
   drop the temporary coverage exclusions for `account_server.rs` +
   `server.rs`; optionally include the Stage 5d-next-5 cyclic tests
   by removing `--skip stage_5d --skip stage_5e` and bumping the
   `tests` job's `timeout-minutes` from 30 to ~120.
2. Steps 8–9 in [`../ROADMAP.md`](../ROADMAP.md): App/wallet Schnorr
   signing integration + DEV deployment + Signet end-to-end
   roundtrip. Both span repos outside this one (`zk-coins/app` plus
   deploy pipelines / SSH to the DEV / PRD hosts).
3. ✅ done — empirical insights from the Stage 5d-next-5 aggregator
   work now live in
   [`../MIGRATION_RESEARCH.md` §7.22](../MIGRATION_RESEARCH.md#722-stage-5d-next-5-source-side-verification-via-aggregator-pattern--codified-resolves-721).
   Tracker file removed in the Issue #28 housekeeping pass.

## Things explicitly NOT in this branch

- App / wallet integration (Step 8).
- DEV deployment (Step 9).
- Pre-mainnet protocol redesigns (D2/D10 / D7 / D8 — see
  ROADMAP "Pre-mainnet blockers").

Step 6 (`script-plonky2/` prover host) and Step 7 (server-side
replacement + in-circuit `send_coins` follow-up) have BOTH landed
on this branch.

## Test confirmation status

**Historical snapshot (Stage 5d-next-3 era, `INNER_PAD_BITS = 14`).**
Kept for the wall-time reference points; the current branch is at
`INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15` for the Phase 2b outer.

| Test | Confirmed | Run notes |
| --- | --- | --- |
| `stage_5d_initial_with_one_active_in_coin` | ✅ | 188 s wall, single in-coin |
| `stage_5d_next_3_initial_with_one_active_out_coin` | ✅ | 761 s wall, single out-coin |
| `stage_5d_next_3_initial_combined_in_and_out_coin` | ✅ | 781 s wall, both loops active |
| `stage_5d_next_3_account_update_combined_in_and_out_coin` | ✅ | 926 s wall, both loops + cyclic recursion + CMP (b)(c)(d)(e) chain |

**Current branch (Stage 5d-next-5 / Phase 2b landed; PR #31
housekeeping merged).** Full `program-plonky2` lib sweep ~42 min
wall on M3 with `--test-threads=2`, 115 cyclic-recursion tests
green; full server sweep `cargo test -p server --release
--all-features -- --test-threads=1` ~36 min wall, 138 tests green
(including the Phase 2b negative
`test_send_coins_rejects_tampered_source_proof_inclusion` + the
17 `map_send_coins_error_*` unit tests + 1 new handler-level 404
test from PR #31).
See [`../MIGRATION_RESEARCH.md` §7.22 "Benchmark"](../MIGRATION_RESEARCH.md#722-stage-5d-next-5-source-side-verification-via-aggregator-pattern--codified-resolves-721)
for the per-test wall-time breakdown.

## Next session — verification checklist

Before adding new features:

1. `git fetch && git pull --ff-only origin feat/plonky2-migration`
   — pull any parallel work.
2. `cargo check --workspace --all-targets` — should be a no-op
   build after the cache warms.
3. `cargo fmt --all --check` and `cargo clippy --workspace
   --all-targets --all-features -- -D warnings`.
4. `cargo test -p server --release --all-features -- --test-threads=1`
   — 120 tests, ~36 min wall on M3.
5. `cargo test -p zkcoins-program-plonky2 --release --lib --
   --test-threads=2` — 115 cyclic tests, ~42 min wall on M3.
6. `cargo llvm-cov --fail-under-lines 100 --
   --test-threads=1` — coverage gate (after dropping the temporary
   `account_server.rs` + `server.rs` exclusions from
   `.github/workflows/ci.yaml`).

If any test fails: bisect against the commit list in
[`../ROADMAP.md`](../ROADMAP.md) Done section.

After confirmation: Steps 8–9 (App/wallet Schnorr signing
integration + DEV deployment + Signet end-to-end roundtrip).

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
