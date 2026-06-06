# Plonky2 → Plonky3 Cutover Playbook

**Doc 1 of the Plonky3 migration documentation set.** This is the production-engineering
runbook for switching the zkCoins node's proving backend from Plonky2 (Goldilocks, cyclic
recursion) to Plonky3 (layered carrier-table recursion). It is self-contained: an engineer
executing the cutover months from now should be able to run it end-to-end from this file.

**Companion docs (referenced, not duplicated here):**

- **Doc 2 — Wire / Storage Format Migration.** Authoritative on the on-disk and on-the-wire
  byte formats (proof blobs, SMT/MMR root encoding, `circuit_digest` representation, field
  serialisation Goldilocks↔BabyBear). This playbook *references* its conclusions; it does not
  re-derive them.
- **Doc 3 — Crypto-audit spec for the carrier-table chain.**
- **Doc 4 — Upstream maintenance plan** (pinned revs, fork policy).
- **`MIGRATION_PLONKY3_SPIKE_RESULT.md`** — the Phase-0 feasibility gate (GO via Path 1+5).
- **`MIGRATION_RESEARCH.md`** §5.4 / §7.5 — the Schnorr/Poseidon boundary, on-chain format.

---

## 0. Scope & non-negotiables (read first)

The migration changes the **proving backend only**. The following are **frozen** and any PR
that touches them is out of scope for the cutover and must STOP-and-escalate
(`MIGRATION_RESEARCH.md` §5.4, §7.5, §D3):

1. **On-chain commitment format is invisible to the proof system.** A state change is
   published as a single BIP-340 Schnorr inscription over `H(asth ‖ ocr)` with the Taproot
   inscription txid prefix `4242`. The proof bytes are **never** posted on-chain. Therefore
   the proof system can change with **zero on-chain format change** — this is the property
   that makes the whole cutover feasible.
2. **Schnorr boundary stays at byte serialisation.** The wallet signs
   `SHA256(serialize(asth) ‖ serialize(ocr))` where `asth`/`ocr` are 4-element Poseidon
   outputs serialised to 32 bytes each. There is **no in-circuit SHA256 and no in-circuit
   Schnorr verify** — BIP-340 verification happens off-circuit in the scanner. The cutover
   does not touch `verify_send_signature` in `node/src/router.rs` or the scanner's signature
   path.
3. **Protocol constants must not change**: `MAX_IN_COINS`, `MAX_OUT_COINS`,
   `MMR_PROOF_PATH_LEN` (`zkcoins_program::circuit::main`). These are the cost/parity anchors;
   changing them is a protocol change, not a backend port.
4. **The 32-byte address / hash-digest wire shape stays identical.** Account addresses, SMT
   leaves and MMR roots are 32-byte values on the wire and in `accounts.address`. Whether the
   *underlying field* changes (Goldilocks → BabyBear) and whether that re-encodes the 32-byte
   root is **Doc 2's** question; see §4 below for the cutover consequence.

> **Field decision (from the Phase-0 gate).** The recommended port stays **Goldilocks on
> Plonky3 for the whole port (Phases 1–8)**; KoalaBear/BabyBear is deferred to a separate
> Phase 9 that only runs if the warm-prove budget is missed. **If the port lands on
> Goldilocks, the SMT/MMR root encoding does not change and §4 simplifies to the proof-blob
> reset only.** This playbook covers BOTH cases and flags where they diverge.

---

## 1. Pre-cutover checklist — parity gates that MUST be green

Cutover does not start until **every** box below is green on the exact frozen build. None of
these are advisory.

### 1.1 Frozen build / pins

- [ ] Plonky3 upstream revs pinned and recorded in Doc 4 (the `Plonky3` /
      `Plonky3-recursion` pair must be the matched workspace pair — see
      `MIGRATION_PLONKY3_SPIKE_RESULT.md` §"Pins probed"). **A backend port may not bump these
      mid-cutover.**
- [ ] `rust-toolchain` unchanged (the repo pins it; CI builds with Rust 1.81.0 per
      `.github/workflows/ci.yaml`). `[VERIFY: confirm the Plonky3 crates compile on the pinned
      toolchain — upstream is edition-2024; if a newer toolchain is required, that is a
      separate, reviewed change recorded in Doc 4.]`
- [ ] Dual-prover build flag exists and defaults to **Plonky2** (see §7 for the flag name).
      `[VERIFY: name of the cargo feature / env var that selects the active backend — this is
      created by the Phase-6 node-integration PR; record it here once it lands, e.g.
      `ZKCOINS_PROVER_BACKEND=plonky3` or a `prover-plonky3` cargo feature.]`

### 1.2 Circuit-equivalence parity

- [ ] The Plonky3 circuit test suite passes with the **same assertions** as the Plonky2 suite.
      The Plonky2 circuit crate (`program-plonky2/`) carries **~131 `#[test]` functions**
      `[VERIFY: exact count — the task brief says "121"; `grep -rc '#\[test\]' program-plonky2/src`
      currently reports ~131. Use whichever the Phase-1–5 port is required to mirror 1:1.]`.
      Every ported test must assert the same positive AND negative outcomes (membership /
      non-membership / insert, MMR append+prove, masking, vk-binding). Run:
      ```bash
      cargo nextest run -p zkcoins-program-plonky3 --release   # [VERIFY: the ported crate name]
      ```
- [ ] **Cross-prover proof round-trip.** A proof produced by the Plonky3 prover verifies under
      the Plonky3 verifier and bincode round-trips byte-stable (the spike proved this for the
      recursion proof: `probe_p_serialization`). Confirm at the node integration layer:
      `prove_account_update → serialize → deserialize → verify` returns Ok.

### 1.3 Performance budget

- [ ] **Warm-prove budget ≤ 5 s p50** measured by the bench harness on the reference host,
      using the production parameters (`MAX_IN_COINS`, `MAX_OUT_COINS`, `MMR_PROOF_PATH_LEN`):
      ```bash
      # built against the Plonky3 backend build
      ./target/release/probe_r2 --warm-calls 20 --warm-budget-ms 5000 --persist
      ```
      `probe_r2` (`node/src/bin/probe_r2.rs`) measures warm `prove_account_update` wall,
      cold-start wall and peak RSS against the three ROADMAP step-9 budgets and persists to
      `r2_probe_runs` (migration 0013) when `--persist` is set (`DATABASE_URL` required).
      The Plonky3 number must be **≤** the Plonky2 baseline (Plonky2 reference: warm p50
      ≈ 4.35 s on M5 Max; the fair-bench projects 4–61× headroom — but the budget gate is the
      **real circuit + carrier recursion**, not the bench proxy, so this measurement is
      mandatory, not assumed).
- [ ] Peak RSS < 64 GB; cold-start within its budget (both reported by the same `probe_r2`
      run).

### 1.4 End-to-end parity on a throwaway DB

- [ ] Full node test suite green on the Plonky3 build:
      ```bash
      cargo llvm-cov nextest --release -p node -p shared --all-features \
        --test-threads 8 -E 'not binary(api_remote)'
      ```
      This is the authoritative `CI` heavy gate ("Tests + Coverage Gate"); it must stay at
      100% line + function coverage.
- [ ] **API E2E** (`-E 'binary(api_remote)'`, the 47-test suite) green against a locally-run
      Plonky3 node. This is the same suite the `Deploy DEV` workflow runs as **"API E2E
      against DEV"**.
- [ ] The DEV dry-run rehearsal (§7) has been executed **at least once end-to-end including a
      rollback exercise**.

**Freeze condition:** once all of §1 is green, freeze the merge train. No further commits to
`develop`/`main` except the cutover PR itself until cutover completes or is rolled back.

---

## 2. In-flight proof handling (the async jobs queue)

The node is a **jobs-based async API** (`node/src/job_store.rs`,
`node/src/job_dispatcher.rs`, migration `0014_jobs`). At any instant there may be jobs
mid-flight. They must be drained with the **OLD (Plonky2) prover** before the switch —
a Plonky3 build cannot resume a Plonky2 in-flight proof.

### 2.1 Job states (authoritative, from `job_store.rs::JobStatus`)

| State | Meaning | Drainable? |
|---|---|---|
| `queued` | admitted, not yet picked up | **Cancel** (no work done yet) |
| `proving` | prover running (Plonky2) | **Let finish** under old prover |
| `awaiting_signature` | send job paused waiting for the wallet's `commit` | wallet-blocked; see 2.3 |
| `broadcasting` | proof done, inscription being broadcast | **Let finish** (on-chain side) |
| `completed` | terminal | done |
| `failed` | terminal | done |
| `cancelled` | terminal | done |

`JobKind` is `mint | send`. `JobStatus::is_terminal()` ⇔ `completed | failed | cancelled`.

### 2.2 Quiesce sequence

1. **Stop admitting new jobs.** Put the service into maintenance mode (§5.1) so `jobs_mint` /
   `jobs_send` return 503 and no new rows enter `queued`. `[VERIFY: the service has no built-in
   maintenance flag today (grep found none in node/src). The supported quiesce is at the edge
   — Cloudflare maintenance page / upstream 503 — OR add a one-line "drain mode" env gate in
   the Phase-6 PR. Record which here.]`
2. **Cancel `queued` jobs.** These have done no prove work; cancelling avoids a needless
   minute-scale prove right before the switch. Either let the wallet drive
   `POST /api/jobs/:id/cancel` (`jobs_cancel_handler`, `node/src/router.rs`) or leave them —
   the boot resumer will requeue them, but under the NEW prover they would fail, so prefer
   cancel. Query the live set first:
   ```sql
   SELECT public_id, kind, status FROM jobs
   WHERE status NOT IN ('completed','failed','cancelled')
   ORDER BY created_at;
   ```
3. **Let `proving` / `broadcasting` jobs finish under the old prover.** These are the only
   states that hold real in-flight work. A `proving` job finishes in single-digit seconds
   (warm-prove ≤ 5 s p50); a `broadcasting` job finishes once the inscription is broadcast.
4. **Wait for the queue to reach steady terminal/awaiting state.** Re-run the query in (2)
   until it returns only `awaiting_signature` rows (handled in 2.3) or nothing.

**Max drain time:** dominated by the longest single prove plus broadcast confirmation latency.
Budget **≤ 2 minutes** of active draining for `proving`/`broadcasting` under nominal load.
`awaiting_signature` is **not** time-bounded (it waits on the wallet) — do not block the
cutover on it; see 2.3.

### 2.3 `awaiting_signature` (send jobs paused on the wallet)

A `send` job reaches `awaiting_signature` after its proof is produced; it then waits for the
wallet's `POST /api/jobs/:id/commit` (the dispatcher drains a `commit_wake` Notify). Two
options:

- **Preferred:** these jobs already hold a **completed Plonky2 proof** (`proof_id` populated).
  The `commit` step only signs + broadcasts — it does not re-prove — so it is **safe to leave
  them across the cutover**: the wallet can still commit them after the switch because commit
  does not invoke the prover. **Verify this holds**: `[VERIFY: confirm process_send_resume /
  the commit path does not re-run the prover on a Plonky2-produced proof after a Plonky3 boot.
  If commit re-validates the proof against the live circuit, these must instead be drained or
  cancelled before cutover.]`
- **Conservative fallback:** announce a short pre-cutover window, ask wallets to commit or
  abandon outstanding sends, then cancel any `awaiting_signature` left at T-0. Because the
  genesis reset (§4) wipes proof-dependent state anyway, an uncommitted send is lost work, not
  a correctness hazard.

---

## 3. State-schema migration (does DB state depend on the proof system?)

**Yes — and decisively.** This is the crux of the cutover and the reason it is a hard
checkpoint, not a soft swap.

### 3.1 What the DB stores (migrations `0001`–`0016`, singletons keyed `id=1`)

| Table | Proof-dependent? | Why |
|---|---|---|
| `accounts` | **YES** | Each row carries `account.proof` — a serialised proof blob, fed back as the recursive *inner* proof on the next transition. |
| `smt_state` | **YES** | Global commitment Sparse Merkle Tree; roots are committed inside proofs. |
| `mmr_state` | **YES** | Global Merkle Mountain Range of SMT roots. |
| `mmr_root_index` | **YES** | `prev_mmr_root → (smt_root, leaf_index)` map used to build inclusion proofs. |
| `circuit_digest_meta` | **YES (control)** | Persists the active circuit's digest so boot can detect a breaking change (migration 0015). |
| `latest_block` | derived | scanner resume cursor; re-derivable from the tip. |
| `usernames` | NO | human handles, not proof-dependent. |
| `account_history`, `state_update_log`, `request_log` | NO | append-only historical evidence, never feeds proof construction. |
| `jobs` | NO (terminal rows are history) | dispatcher only acts on non-terminal states. |
| `pending_inscriptions` | NO | scanner-side bookkeeping. |
| `coin_proof_store` | NO | unused schema groundwork, no production INSERT. |
| on-disk `PROOFS_DIR/<id>.bin` | **YES** | per-send `CoinProof` blobs. |

### 3.2 The field-change consequence (cross-ref Doc 2)

The SMT/MMR roots are **hashes**. If the port keeps **Goldilocks** (recommended), the
Poseidon-over-Goldilocks root encoding is unchanged and the 32-byte root bytes are stable —
so the *root values* survive, only the *proofs over them* are invalidated. If the port moves
to **BabyBear/KoalaBear** (deferred Phase 9), the field and hash change and the root **byte
encoding may change**, which would re-encode every SMT leaf and MMR root. **Doc 2 is
authoritative on the exact byte impact;** this playbook only states the cutover consequence:

> **Either way, the proof blobs (`accounts.proof`, queued `CoinProof`s, distributed recipient
> proofs) are ALL invalidated by the backend change.** The repo already proves this is
> unrecoverable per-account: the global SMT/MMR are append-only and shared across accounts,
> keyed by on-chain commitment pubkeys in MMR-append order, so they cannot be partially
> unwound per account without a global-vs-account mismatch that breaks soundness
> (migration 0015/0016 rationale; `node/src/self_heal.rs`).

### 3.3 Migration ordering

The repo already encodes the canonical ordering for a breaking circuit change — **reuse it**:

1. The cutover build ships a **reset migration** modelled on
   `0016_reset_proof_dependent_state_to_genesis.sql`: `DELETE FROM accounts; smt_state;
   mmr_state; mmr_root_index; latest_block; circuit_digest_meta;`. sqlx applies it exactly
   once per database (`_sqlx_migrations`), firing on the first deploy that carries it
   (`develop → DEV`, `main → PRD`).
2. On boot, `node/src/self_heal.rs` sees no persisted digest → runs the canary →
   `NoSample` on the empty `accounts` table → `Baseline` records the **new Plonky3 circuit
   digest**. No new code path is introduced.
3. `PROOFS_DIR` orphans are inert (no surviving row references them) and are garbage-collected
   by `reset_proof_store_dir` on the reset path.

> **Do NOT hand-write a bespoke state transform.** The genesis-reset path is the only
> provably-consistent recovery and it is already integration-tested. If Goldilocks is kept and
> someone argues the roots could be preserved: they cannot, because the *proofs that attest to
> those roots* are invalid, and the node feeds `account.proof` back recursively on the very
> next transition.

---

## 4. Account migration — checkpoint vs dual-verify

Existing accounts have **Plonky2-proof histories** (`account.proof` is a Plonky2 blob, fed
recursively). The question: can they continue under Plonky3, or do they need a re-anchor?

### Option A — Hard checkpoint (genesis reset)  ◀ **RECOMMENDED**

Reset all proof-dependent state to genesis at cutover (§3.3). Every account starts from a
fresh Plonky3-rooted state; balances re-mint from the publisher as needed.

- **Pros:** the only **provably-consistent** path; already implemented and integration-tested
  (`self_heal`, `reset_proof_dependent_state_tx`, migration 0016); zero new circuit code;
  zero dual-prover complexity in steady state.
- **Cons:** discards existing on-chain-anchored balances; requires re-seeding. **Acceptable
  here** because DEV and PRD are **closed test environments** (CONTRIBUTING § "Closed test
  environment") and the operator has previously authorised a PRD genesis wipe for exactly this
  class of breakage (migration 0016 header).

### Option B — Dual-verify transition window

Build a Plonky3 circuit that can verify a Plonky2 inner proof for one transition, so existing
accounts "re-anchor" their first Plonky3 transition on top of their last Plonky2 proof, then
continue pure-Plonky3.

- **Pros:** no balance loss; no re-seed.
- **Cons:** requires an **in-circuit Plonky2 verifier inside the Plonky3 circuit** — a
  cross-proof-system recursion gadget that does not exist upstream and is far beyond a backend
  port (it is a research effort). The Phase-0 gate already showed cross-layer threading is the
  hard part of Plonky3 recursion; bolting a foreign verifier on top multiplies that risk.
  **Out of scope for a backend port.**

### Recommendation

**Choose Option A (hard checkpoint / genesis reset).** It is the repo's established,
provably-consistent, already-tested recovery for a breaking circuit change, and a proof-system
swap is the maximal breaking change. Option B's only benefit (balance continuity) is
irrelevant in closed test environments and its cost (a cross-system in-circuit verifier) is
disproportionate and research-grade. **Re-evaluate Option B only if zkCoins is at mainnet with
real balances that cannot be re-seeded** — a decision for the operator, not the porting team.

---

## 5. Downtime plan

### 5.1 Maintenance mode

`[VERIFY: the node has no internal maintenance flag (grep of node/src found drain/shutdown
plumbing but no admin "maintenance" toggle).]` Achieve maintenance mode by **either**:

- **Edge (no code change):** serve a 503 maintenance page at the Cloudflare layer in front of
  `dev-api.zkcoins.app` / `api.zkcoins.app`, OR
- **Service (preferred, one-line):** add a `ZKCOINS_DRAIN=1` env gate in the Phase-6
  integration PR that makes the admit handlers (`jobs_mint`, `jobs_send`) return 503 while
  read endpoints (`/api/balance`, `/api/history`, `/api/info`, `/health`) stay up. Record the
  chosen mechanism here once it lands.

`/health` (liveness) returns 200 the moment the listener binds; `/health/ready` returns 503
with `prover: warming` during the ~10–30 s prover warmup (`node/src/runtime.rs`,
`AppState::prover_warm`). Rolling deploys rely on this.

### 5.2 Expected window

| Phase | What's unavailable | Expected duration |
|---|---|---|
| Drain (§2) | new mint/send admits | ≤ 2 min active drain |
| Snapshot (§6.1) | writes paused | ~1 min (DB dump) |
| Switch + boot (deploy + genesis-reset migration + prover warmup) | full write path | image pull + `docker compose recreate` + **~10–30 s prover warmup** |
| Smoke (§8) | — (read-only checks) | ~1–2 min |

**Total user-facing write outage: a few minutes**, dominated by deploy/recreate + warmup, not
by proving. **Read endpoints can stay up** the entire time if maintenance mode only gates the
admit handlers.

### 5.3 User-facing messaging

- Pre-announce a maintenance window (T-1d and T-1h) on the wallet status channel.
- During: maintenance 503 body should say "scheduled maintenance, balances will be
  re-initialised" so wallets do not interpret a post-reset zero balance as data loss.
- After: post a "maintenance complete, please re-sync" notice. Because of the genesis reset
  (§4), wallets must treat their local state as stale and re-hydrate `numPubkeys` from
  `/api/balance` (`num_sends`).

---

## 6. Rollback plan

### 6.1 Pre-switch snapshot (mandatory)

Before the switch, snapshot the **old (Plonky2) state** so a rollback restores byte-for-byte:

```bash
# On the deploy host, BEFORE the genesis-reset migration runs:
pg_dump --format=custom "$DATABASE_URL" > zkcoins_pre_cutover_<env>_<utc>.dump
# And the on-disk proof store:
tar czf proofs_pre_cutover_<env>_<utc>.tgz "$PROOFS_DIR"
```

`[VERIFY: exact DATABASE_URL / PROOFS_DIR values are host-side env; do not hardcode. The
deploy host runs a restricted forced-command shell (only allowlisted command names) — the
snapshot must be taken via an allowlisted maintenance command or by the operator with direct
host access, NOT via the CI deploy key.]`

### 6.2 Rollback triggers

Roll back **immediately** on any of:

- A §1 parity gate that was green pre-freeze goes red after the switch (a proof fails to verify
  in production).
- Warm-prove budget blown in production (`probe_r2` or live job latency > 5 s p50 sustained).
- Broadcast / inscription errors from the publisher attributable to the new proofs.
- `self_heal` reset-looping (boot keeps resetting) — indicates the new circuit digest is
  unstable.

### 6.3 Point of no return

**The first Plonky3 proof committed on-chain** (the first `broadcasting → completed` send/mint
after the switch). Before that point: nothing irreversible has happened on-chain; restoring the
Plonky2 snapshot + redeploying the Plonky2 image is a clean revert. After that point: a new
Plonky3-rooted on-chain commitment exists with the `4242` prefix, and reverting to the Plonky2
snapshot means **abandoning** those post-cutover commitments (acceptable in a closed test env;
they become inert history). The on-chain format is identical either way (§0.1), so a rollback
does not strand the scanner.

### 6.4 Reversible vs not

| Reversible | Not reversible (without abandoning post-cutover commits) |
|---|---|
| DB + proof-store state (restore the §6.1 snapshot) | On-chain inscriptions produced by Plonky3 proofs after T-0 |
| The deployed image (redeploy the Plonky2 tag) | — |
| The genesis reset (snapshot pre-dates it) | — |

### 6.5 Revert procedure

1. Stop admitting (maintenance mode).
2. Drain any in-flight Plonky3 jobs (§2, same procedure, Plonky3 prover).
3. Restore the §6.1 snapshot (`pg_restore --clean` + untar `PROOFS_DIR`).
4. Redeploy the **Plonky2 image** — revert the cutover commit on the target branch so the
   normal deploy workflow ships the previous image:
   - DEV: revert on `develop` → `Deploy DEV` workflow fires.
   - PRD: revert on `main` → `Deploy PRD` workflow fires.
   Because the genesis-reset migration is `_sqlx_migrations`-tracked, the **restored** DB
   predates it, so re-deploying the old image does not re-trigger a reset.
5. Boot: `self_heal` sees the restored Plonky2 digest == the Plonky2 build's digest → `Keep`
   fast path. Confirm `/health/ready` → `ready:true`. Smoke (§8).

---

## 7. dfxdev dry-run rehearsal (DEV ONLY — never PRD/dfx01)

Rehearse the **entire** cutover on **DEV (dfxdev, `dev-api.zkcoins.app`, Mutinynet)** before
touching PRD. **Never target PRD (dfxprd) or dfx01 in the rehearsal.** The branch flow is
`feature → staging → develop (→DEV deploy) → main (→PRD deploy)`.

### 7.1 Deploy mechanism (real, from `.github/workflows/`)

- **DEV:** workflow **`Deploy DEV`** (`.github/workflows/deploy-dev.yaml`), trigger:
  `push` to `develop`, **or** `workflow_dispatch` with a boolean input **`reset_state`**.
  The workflow builds `zkcoins/node:beta`, SSHes a single allowlisted command (`zkcoins-node`,
  or `reset-zkcoins-node` when `reset_state=true`), then polls
  `https://dev-api.zkcoins.app/health/ready` until `ready:true`, then runs the
  **"API E2E against DEV"** job (the 47-test `api_remote` suite).
- **PRD:** workflow **`Deploy PRD`** (`.github/workflows/deploy-prd.yaml`), trigger:
  `push` to `main` or `workflow_dispatch`; `cancel-in-progress: false` (PRD deploys queue,
  never killed mid-recreate).
- **CI gate:** workflow **`CI`** (`.github/workflows/ci.yaml`) — Lint & Build + the
  "Tests + Coverage Gate (M3 Ultra, 100% lines + functions)" heavy job.

Trigger a manual DEV reset deploy (the rehearsal's reset step) with:

```bash
gh workflow run "Deploy DEV" --ref develop -f reset_state=true
gh run watch   # follow build → deploy → smoke → API E2E
```

### 7.2 Rehearsal steps

1. **Land the dual-prover build on `develop`** (default backend = Plonky2). The `Deploy DEV`
   workflow ships it to DEV. Confirm `/health/ready` → `ready:true` and "API E2E against DEV"
   is green.
2. **Scripted baseline cycles (Plonky2).** Run a scripted set of mint → send → commit cycles
   against DEV and capture state:
   ```bash
   ZKCOINS_API_URL=https://dev-api.zkcoins.app \
     cargo test -p node --release --all-features --test api_remote -- --test-threads=1 --nocapture
   # plus an explicit balance/history snapshot for continuity comparison:
   curl -s "https://dev-api.zkcoins.app/api/balance?address=0x<acct>"
   curl -s "https://dev-api.zkcoins.app/api/history?address=0x<acct>&limit=50"
   ```
3. **Drain rehearsal (§2).** Enter maintenance mode, cancel `queued`, let `proving`/
   `broadcasting` finish, verify the non-terminal-jobs SQL query returns empty, **and time it**
   (this measurement feeds §5.2 / §8's downtime estimate).
4. **Snapshot (§6.1).** Take the `pg_dump` + `PROOFS_DIR` tar on the DEV host.
5. **Switch.** Flip the backend to Plonky3 (cutover commit on `develop`, which carries the
   genesis-reset migration) and let `Deploy DEV` ship it. Boot path: genesis-reset migration →
   `self_heal` baselines the new digest → prover warmup → `/health/ready` ready.
6. **Verify state continuity / re-seed.** Confirm accounts are at genesis, re-run the scripted
   mint → send → commit cycles **under Plonky3**, confirm they complete and the new on-chain
   `4242` inscriptions appear (scanner picks them up). Run `probe_r2` against the real DEV
   parameters and confirm the warm budget.
7. **Exercise the rollback (§6.5)** on DEV: restore the §7.2.4 snapshot, redeploy the Plonky2
   image (revert on `develop`), confirm `self_heal` takes the `Keep` path and the pre-cutover
   balances/history are back byte-for-byte.
8. **Measure the real downtime window** from step 3 (start of maintenance) to step 6
   (`ready:true` under Plonky3). Record it — this is the number to communicate for the PRD
   window.

**Exit criterion for the rehearsal:** steps 1–8 all pass, the measured downtime is acceptable,
and the rollback restored DEV cleanly. Only then schedule the PRD cutover.

---

## 8. Cutover-day timeline (T-minus runbook)

Times are illustrative; the **drain/warmup numbers come from the §7 DEV rehearsal**. Each PRD
step mirrors a step already rehearsed on DEV.

### T-7d — Freeze

- All §1 parity gates green on the frozen Plonky3 build. Pins recorded in Doc 4.
- Freeze the merge train: no commits to `develop`/`main` except the cutover PR.
- DEV rehearsal (§7) completed end-to-end including rollback.

### T-1d — Final parity + comms

- Re-run §1 in full on the exact image that will deploy to PRD.
- `probe_r2 --warm-calls 20 --persist` on the reference host → budget green.
- Send T-1d maintenance notice (§5.3).
- Confirm the §6.1 snapshot path/command works on the PRD host (dry-run the `pg_dump`).

### T-1h — Pre-flight

- T-1h maintenance notice.
- Confirm `Deploy PRD` workflow is idle and the queue is empty.
- Confirm publisher wallet has UTXOs (the deploy's preflight checks `>= 50_000` sats on DEV;
  PRD needs the same headroom for post-cutover re-seed mints).

### T-0 — Cutover (PRD)

1. **Maintenance mode on** — stop admitting new jobs (§5.1).
2. **Drain** (§2): cancel `queued`; let `proving`/`broadcasting` finish; confirm the
   non-terminal-jobs query is empty (modulo `awaiting_signature`, handled per §2.3).
3. **Snapshot** (§6.1): `pg_dump` + `PROOFS_DIR` tar, taken by the operator on the PRD host
   (NOT via the CI deploy key).
4. **Switch**: merge the cutover commit to `main` → `Deploy PRD` fires (queued, never
   cancelled). The image ships; the genesis-reset migration runs once; `self_heal` baselines
   the new Plonky3 digest; prover warms (~10–30 s).
5. **Smoke** (§8.x): the deploy workflow polls `https://api.zkcoins.app/api/info` (200) — then
   manually confirm `/health/ready` → `ready:true`, run one mint → send → commit, confirm the
   new `4242` inscription is broadcast and the scanner integrates it.
6. **Maintenance mode off** — resume admits.
7. **Point of no return passed** once the first Plonky3 mint/send reaches `completed` on-chain
   (§6.3). Before this, rollback is clean; after, rollback abandons post-cutover commits.

### T+0 to T+1h — Intensive monitoring

- Watch live job latency (`jobs` table `created_at → completed_at`) vs the 5 s warm budget.
- Watch `prover_health` (consecutive `prove failed` count) — any sustained failure arms the
  boot self-heal and is a rollback trigger.
- Watch the publisher / scanner for broadcast errors on the new proofs.
- Confirm no `self_heal` reset-loop on subsequent boots.

### T+1d — Stabilisation

- Re-run `probe_r2 --persist` and confirm the budget holds under real load.
- Confirm DEV and PRD are both on the Plonky3 backend, digests stable.
- Retain the §6.1 snapshots until T+7d, then archive.
- Update Doc 4 with the live pins and close the cutover.

---

## Appendix A — Quick command reference

```bash
# Parity: circuit tests (ported crate)         [VERIFY crate name]
cargo nextest run -p zkcoins-program-plonky3 --release

# Parity: full node heavy gate (CI's authoritative suite)
cargo llvm-cov nextest --release -p node -p shared --all-features \
  --test-threads 8 -E 'not binary(api_remote)'

# Parity: API E2E against a deployed env
ZKCOINS_API_URL=https://dev-api.zkcoins.app \
  cargo test -p node --release --all-features --test api_remote -- --test-threads=1 --nocapture

# Budget: warm-prove harness
./target/release/probe_r2 --warm-calls 20 --warm-budget-ms 5000 --persist

# In-flight jobs (non-terminal)
psql "$DATABASE_URL" -c "SELECT public_id,kind,status FROM jobs \
  WHERE status NOT IN ('completed','failed','cancelled') ORDER BY created_at;"

# Snapshot (operator on host, before reset migration)
pg_dump --format=custom "$DATABASE_URL" > zkcoins_pre_cutover.dump
tar czf proofs_pre_cutover.tgz "$PROOFS_DIR"

# DEV deploy + reset (rehearsal)
gh workflow run "Deploy DEV" --ref develop -f reset_state=true && gh run watch

# PRD deploy = merge to main → "Deploy PRD" fires automatically
```

## Appendix B — `[VERIFY]` items to resolve before execution

1. Exact ported circuit-test count (brief says 121; `program-plonky2` currently ~131).
2. The dual-prover selector name (cargo feature / env var) created by the Phase-6 PR.
3. Plonky3 crates compile on the pinned `rust-toolchain` (edition-2024 upstream).
4. The maintenance/drain mechanism (edge 503 vs a `ZKCOINS_DRAIN`-style env gate).
5. Whether `commit` on an `awaiting_signature` Plonky2 proof re-invokes the prover after a
   Plonky3 boot (governs §2.3 — leave-in-place vs drain).
6. Host-side snapshot command compatible with the restricted forced-command deploy shell
   (snapshot must NOT go through the CI deploy key).
7. Doc 2's verdict on whether a Goldilocks-vs-BabyBear field choice re-encodes the 32-byte
   SMT/MMR roots (governs whether §3/§4 is "proof-blob reset only" or "full root re-encode").
