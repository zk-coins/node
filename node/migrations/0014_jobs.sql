-- Job-API state machine table (PR1 of the Job-API refactor).
--
-- The legacy `/api/mint`, `/api/send`, `/api/commit` endpoints were
-- synchronous: the prover ran inside the request, the publisher
-- broadcast inside the request, and a wallet that held the
-- connection open for ~10 seconds wedged every concurrent wallet
-- behind the same axum worker. Three concurrent users were enough
-- to make the experience unusable.
--
-- The Job-API turns each mint/send into a queued unit of work the
-- wallet polls. Routes admit jobs in milliseconds; a single-worker
-- background `Dispatcher` (see `node/src/job_dispatcher.rs`) walks
-- each row through the state machine (`queued → proving → ...
-- → completed | failed | cancelled`); the wallet polls
-- `GET /api/jobs/:id` until a terminal status appears. The status
-- transitions are the same wire-level events the wallet already
-- understands today, just observable instead of opaquely awaited.
--
-- Stripe-style idempotency: every admit-side request carries an
-- `Idempotency-Key` header. A `UNIQUE (account_address,
-- idempotency_key)` index turns "wallet retried the same job"
-- from "second prove" into "look up the first row". The wallet's
-- retry semantics drive progress without amplifying the load.
--
-- Schema notes:
--
--   * `public_id` — UUID surfaced over HTTP. The `BIGSERIAL id` stays
--     internal because exposing it would leak the global mint+send
--     throughput.
--   * `kind` / `status` — enumerated via CHECK constraints so a typo
--     in the application code surfaces as a Postgres violation, not
--     a silent state-machine drift. Same shape as
--     `pending_inscriptions.status` (migration 0003).
--   * `phase` — free-form free-text refinement of `status` so the
--     dispatcher can publish progress milestones without churning the
--     coarse status enum. `'queued'` initially.
--   * `account_address` — `BYTEA` 32 bytes, matching the `accounts`
--     table. CHECK enforces width because reading length errors deep
--     in the dispatcher would surface as 500 long after the admit
--     handler returned 202.
--   * `idempotency_key` — nullable; the dispatcher / resumer paths
--     accept jobs without one (boot-time resume). The partial UNIQUE
--     index only fires when the key is present so the `Some(idem) =>
--     UPSERT` path is race-free without forbidding the `None` shape.
--   * `request_body` / `response_body` — JSONB so the dispatcher can
--     replay the original mint/send payload after a restart (boot-time
--     resumer) and so an idempotent replay returns byte-identical JSON
--     to the second caller.
--   * `response_status` — SMALLINT mirroring `request_log.response_status`.
--   * `proof_id` — links to the on-disk proof file (`proofs/{id}.bin`).
--     Populated when a `send` job transitions to `awaiting_signature`
--     so the wallet's `commit` call can look up the proof to sign.
--   * `error` — free-form message for the failure arm. Mirrors
--     `pending_inscriptions.failure_reason`.
--   * `progress` — best-effort 0-100 percent. The dispatcher updates
--     it at known waypoints; the wallet treats it as a UX hint, not
--     a contract.
--   * `created_at` / `updated_at` / `completed_at` — wall-clock
--     timestamps for forensics + retention pruning.
--
-- Indices target the dispatcher's three hot paths:
--   * `jobs_status_idx` — partial index on non-terminal rows so the
--     resumer's boot-time `SELECT … WHERE status IN ('queued',
--     'awaiting_signature')` is O(pending), not O(total).
--   * `jobs_account_idx` — `(account_address, created_at DESC)` for
--     future "list this account's jobs" admin endpoints.
--   * `jobs_idempotency_idx` — partial UNIQUE so the admit handler
--     can `ON CONFLICT … RETURNING` the existing row without forcing
--     all callers to supply a key.
--   * `jobs_completed_at_idx` — partial index on `completed_at IS NOT
--     NULL` for the future retention sweeper.

CREATE TABLE jobs (
    id              BIGSERIAL    PRIMARY KEY,
    public_id       UUID         NOT NULL UNIQUE,
    kind            TEXT         NOT NULL,
    status          TEXT         NOT NULL,
    phase           TEXT         NOT NULL DEFAULT 'queued',
    account_address BYTEA        NOT NULL,
    idempotency_key TEXT,
    request_body    JSONB        NOT NULL,
    response_body   JSONB,
    response_status SMALLINT,
    proof_id        BIGINT,
    error           TEXT,
    progress        SMALLINT     NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    CHECK (octet_length(account_address) = 32),
    CHECK (status IN ('queued','proving','awaiting_signature','broadcasting','completed','failed','cancelled')),
    CHECK (kind   IN ('mint','send'))
);

CREATE INDEX jobs_status_idx        ON jobs (status) WHERE status NOT IN ('completed','failed','cancelled');
CREATE INDEX jobs_account_idx       ON jobs (account_address, created_at DESC);
CREATE UNIQUE INDEX jobs_idempotency_idx ON jobs (account_address, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX jobs_completed_at_idx  ON jobs (completed_at) WHERE completed_at IS NOT NULL;
