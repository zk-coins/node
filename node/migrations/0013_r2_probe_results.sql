-- R2 probe result persistence for the `probe_r2` binary.
--
-- The probe (`node/src/bin/probe_r2.rs`) measures the three ROADMAP
-- step 9 budgets on a single run: warm `prove_*` wall, cold-start
-- wall, peak resident-set-size. Until this migration the only output
-- channel was a JSON file on disk plus stdout. That makes regression
-- tracking — "did PR X push warm wall above the 5 s budget?" —
-- a manual grep-through-old-files exercise.
--
-- The schema persists every useful field the probe collects so the
-- operator can answer trend / regression queries with a single SQL
-- against the live node DB. Closed test env, so no privacy boundary
-- on these rows (`feedback_zkcoins_no_privacy_promise`).
--
-- Three tables, 3NF-normalised:
--
--   * `r2_probe_hosts` — one row per (hostname, os, arch, cpu_brand)
--     tuple. Most fields repeat across runs from the same machine;
--     normalising avoids the duplication and lets the convenience
--     view join cleanly.
--   * `r2_probe_runs` — one row per probe execution. Carries every
--     scalar measurement (build wall, cold prove wall, warm
--     percentiles, peak RSS) plus the run-time context (git sha,
--     binary version, rustc version, build profile, allocator,
--     circuit parameters) and the budgets the run was checked
--     against (so a future budget tweak doesn't silently re-classify
--     historical rows). `succeeded` + `error_message` capture the
--     terminal state so failed runs are queryable too.
--   * `r2_probe_warm_calls` — one row per individual warm call.
--     Allows recomputing percentiles or inspecting outliers later.
--     `ON DELETE CASCADE` from the parent row so retention pruning
--     a single run cleans up its children with it.
--
-- Plus a `r2_probe_runs_summary` view that joins host + run and
-- inlines the three budget-pass booleans. Trend queries go through
-- the view; the underlying tables are still queryable for ad-hoc
-- forensics.
--
-- Indices target the common query paths: "last N runs" (`ran_at
-- DESC`), "per-host trend" (`host_id, ran_at DESC`), "regression
-- isolation for a specific commit" (`git_sha`).

CREATE TABLE r2_probe_hosts (
    id              SERIAL       PRIMARY KEY,
    hostname        TEXT         NOT NULL,
    os              TEXT         NOT NULL,
    arch            TEXT         NOT NULL,
    cpu_brand       TEXT         NOT NULL,
    cpu_cores       INT          NOT NULL,
    -- Nullable on purpose: the probe falls back to `None` when the
    -- platform path that reads RAM size is unavailable (Linux without
    -- `/proc/meminfo`, sandboxed macOS). Keeping the column nullable
    -- avoids forging a sentinel value that would lie about the host.
    total_ram_gb    INT,
    first_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (hostname, os, arch, cpu_brand)
);

CREATE TABLE r2_probe_runs (
    id                       BIGSERIAL    PRIMARY KEY,
    ran_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    host_id                  INT          NOT NULL REFERENCES r2_probe_hosts(id),
    git_sha                  TEXT         NOT NULL,
    binary_version           TEXT         NOT NULL,
    rustc_version            TEXT         NOT NULL,
    build_profile            TEXT         NOT NULL,
    allocator                TEXT         NOT NULL,
    max_in_coins             INT          NOT NULL,
    max_out_coins            INT          NOT NULL,
    inner_pad_bits           INT          NOT NULL,
    warm_calls_requested     INT          NOT NULL,
    circuit_build_wall_ms    BIGINT       NOT NULL,
    prove_cold_wall_ms       BIGINT       NOT NULL,
    verify_wall_ms           BIGINT       NOT NULL,
    peak_rss_kb              BIGINT       NOT NULL,
    -- Percentiles are nullable so a `--warm-calls 0` run still
    -- produces a writeable row. The view treats NULL as "no warm
    -- measurement" rather than coercing it to a fake zero.
    prove_warm_p50_ms        BIGINT,
    prove_warm_p90_ms        BIGINT,
    prove_warm_p99_ms        BIGINT,
    succeeded                BOOLEAN      NOT NULL,
    error_message            TEXT,
    notes                    TEXT,
    tags                     TEXT[]       NOT NULL DEFAULT '{}',
    -- Budgets persisted alongside each row so trend queries are
    -- self-contained: a future PR that retunes the budgets does NOT
    -- retroactively flip the pass/fail of historical rows in the
    -- summary view.
    r2_warm_budget_ms        BIGINT       NOT NULL,
    r2_cold_budget_ms        BIGINT       NOT NULL,
    r2_mem_budget_kb         BIGINT       NOT NULL
);

CREATE TABLE r2_probe_warm_calls (
    probe_run_id   BIGINT NOT NULL REFERENCES r2_probe_runs(id) ON DELETE CASCADE,
    call_index     INT    NOT NULL,
    wall_ms        BIGINT NOT NULL,
    PRIMARY KEY (probe_run_id, call_index)
);

CREATE INDEX idx_r2_probe_runs_ran_at  ON r2_probe_runs (ran_at DESC);
CREATE INDEX idx_r2_probe_runs_git_sha ON r2_probe_runs (git_sha);
CREATE INDEX idx_r2_probe_runs_host    ON r2_probe_runs (host_id, ran_at DESC);

-- Convenience view: "last N runs with budget verdicts". The pass
-- columns are computed from the row's own persisted budgets, so they
-- reflect the verdict at the time the run was recorded — see the
-- per-row budget rationale above.
CREATE VIEW r2_probe_runs_summary AS
SELECT
    r.id,
    r.ran_at,
    h.hostname,
    h.cpu_brand,
    r.git_sha,
    r.build_profile,
    r.allocator,
    r.circuit_build_wall_ms,
    r.prove_cold_wall_ms,
    r.prove_warm_p50_ms,
    r.prove_warm_p90_ms,
    r.prove_warm_p99_ms,
    r.peak_rss_kb,
    -- cold-start = build + first prove combined; ROADMAP §Step 9
    -- (`BUDGET_COLD_START_MS = 30_000`). The probe binary computes
    -- the verdict the same way; matching it here keeps the view,
    -- console verdict and trend table semantically aligned.
    ((r.circuit_build_wall_ms + r.prove_cold_wall_ms) <= r.r2_cold_budget_ms) AS r2_cold_pass,
    (r.prove_warm_p50_ms IS NOT NULL
         AND r.prove_warm_p50_ms <= r.r2_warm_budget_ms)                   AS r2_warm_pass,
    (r.peak_rss_kb <= r.r2_mem_budget_kb)                                  AS r2_mem_pass,
    r.succeeded
FROM r2_probe_runs r
JOIN r2_probe_hosts h ON h.id = r.host_id;
