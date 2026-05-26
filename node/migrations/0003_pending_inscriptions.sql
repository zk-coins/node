-- Pending inscriptions state-machine table (Phase B of the publisher
-- crash-recovery hardening, building on PR #105's WS-timeout-race fix
-- and PR #106's CLI recovery tool).
--
-- The publisher constructs a `(commit_tx, reveal_tx)` pair from the
-- current commitment payload, broadcasts the commit, then broadcasts
-- the reveal. Anything that fails between the two broadcasts —
-- container crash, host OOM, lost in-memory `reveal_tx` bytes,
-- transient Esplora outage — leaves the commit UTXO spent at the
-- script-path anchor with no on-chain reveal to claim it. The funds
-- are unrecoverable without re-deriving the exact same `reveal_tx`
-- (PR #106's CLI exists for this case, manually).
--
-- This table closes the gap by persisting the full pair BEFORE the
-- first broadcast attempt, and walking each row through the
-- `constructed → commit_broadcast → reveal_broadcast → complete`
-- state machine as each broadcast lands. A startup-time resumer
-- (`publisher::resume_pending_inscriptions`) loads any row whose
-- status is anything but `complete` and re-drives it: the commit (if
-- not yet sent) or the reveal (if the commit landed but the reveal
-- did not). Esplora's `txn-already-known` / `bad-txns-inputs-
-- missingorspent` responses make every step idempotent.
--
-- Schema notes:
--   * `commit_txid` is `UNIQUE` so a retry of the same (commit, reveal)
--     pair after a transient broadcast failure cannot insert a second
--     row. The publisher computes the txid deterministically from the
--     constructed commit tx, so this is stable across restarts.
--   * `commitment`, `commit_tx`, `reveal_tx` are bincode/consensus-
--     serialized blobs. The resume path deserializes them via the same
--     `bitcoin::consensus::deserialize` shape used by the live
--     broadcast.
--   * `commit_output_value` carries the script-path anchor output's
--     value in sats; needed by `build_reveal_only` if a future
--     rebuilder were to re-derive the reveal from the commitment
--     payload. Today we persist the full `reveal_tx` so the rebuild
--     path is not exercised, but the column is cheap to carry and
--     matches the existing CLI's parameter shape.
--   * The CHECK constraint enumerates every valid state so a typo in
--     the application code surfaces as a Postgres constraint violation
--     instead of a silent state-machine drift.
--   * The partial index on `status <> 'complete'` keeps the resumer's
--     boot-time scan O(pending) instead of O(total). After enough
--     mints this list will be perpetually empty on a healthy server.

CREATE TABLE pending_inscriptions (
    id           BIGSERIAL PRIMARY KEY,
    commit_txid  BYTEA      NOT NULL UNIQUE,
    status       TEXT       NOT NULL,
    commitment   BYTEA      NOT NULL,
    commit_tx    BYTEA      NOT NULL,
    reveal_tx    BYTEA      NOT NULL,
    commit_output_value BIGINT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (status IN ('constructed','commit_broadcast','reveal_broadcast','complete','failed'))
);

CREATE INDEX pending_inscriptions_status_idx
    ON pending_inscriptions (status) WHERE status <> 'complete';
