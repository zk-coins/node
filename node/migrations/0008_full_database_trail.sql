-- Full database trail: every input the node receives and every state
-- transition the node performs lands in a queryable table.
--
-- Rationale: the request_log (0007) covers the HTTP layer, but the
-- node also (a) talks outbound to Esplora, (b) ingests blocks from a
-- WebSocket stream, (c) extracts inscriptions from on-chain witnesses
-- including external ones, (d) advances SMT/MMR state, and (e) errors
-- in places that today only show up in container stdout. None of those
-- live in a queryable shape. This migration adds the missing tables.
--
-- Closed test env (`feedback_zkcoins_closed_test_env`): no backward-
-- compat shims, no retention enforcement here — the operator prunes
-- with simple `DELETE WHERE event_at < NOW() - INTERVAL '…'`.

-- ===========================================================================
-- 0. pending_inscriptions: add failure_reason + reveal_txid
-- ===========================================================================
--
-- failure_reason: today the `failed` status exists in the CHECK
-- constraint but no column captures *why*. The publisher's
-- `create_and_broadcast_inscription` error path now fills this with the
-- chain of Esplora / network errors that triggered the failure, so the
-- operator can answer "why didn't this Send land?" from a single SQL.
--
-- reveal_txid: today only the raw `reveal_tx` blob is persisted; the
-- txid has to be re-derived by deserialising 350+ bytes and running
-- `compute_txid()`. Storing it explicitly lets queries reference the
-- reveal directly and feeds the `/api/inscriptions/:txid` response.

ALTER TABLE pending_inscriptions
    ADD COLUMN failure_reason TEXT,
    ADD COLUMN reveal_txid    BYTEA;

CREATE INDEX pending_inscriptions_reveal_txid_idx
    ON pending_inscriptions (reveal_txid)
    WHERE reveal_txid IS NOT NULL;

-- ===========================================================================
-- 1. esplora_log: every outbound call against the Esplora REST / WS API
-- ===========================================================================
--
-- The publisher and scanner are the two consumers of Esplora; their
-- success or failure determines whether mints / sends land and whether
-- state advances. Today a 503 from Esplora's POST /tx surfaces only as
-- an `eprintln!` line; this table captures the full request/response
-- pair so the operator can correlate publisher failures with upstream
-- outages by `WHERE response_status >= 400`.
--
-- `direction` enumerates the three legs we care about — outbound HTTP
-- (REST), outbound WebSocket subscribe / poll frames, and inbound
-- WebSocket frames (block events). The CHECK pins the vocabulary so
-- typos surface as constraint violations.

CREATE TABLE esplora_log (
    id              BIGSERIAL    PRIMARY KEY,
    occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    direction       TEXT         NOT NULL
        CHECK (direction IN ('outbound_http', 'outbound_ws', 'inbound_ws')),
    method          TEXT,
    url             TEXT         NOT NULL,
    request_body    BYTEA,
    response_status SMALLINT,
    response_body   BYTEA,
    duration_us     BIGINT,
    triggered_by    TEXT
);

CREATE INDEX esplora_log_occurred_at_idx  ON esplora_log (occurred_at DESC);
CREATE INDEX esplora_log_response_idx     ON esplora_log (response_status, occurred_at DESC)
    WHERE response_status IS NOT NULL;

-- ===========================================================================
-- 2. error_log: application errors, structured
-- ===========================================================================
--
-- Today every error path uses `eprintln!`, which puts the message into
-- the container's JSON log driver (capped at 100 MB × 3 files) and
-- nowhere else. After 300 MB of normal logs the original error is
-- gone. This table persists errors at write time with the source
-- module, severity, and a serialisable error chain so post-mortem
-- queries are SQL-shaped.
--
-- `request_log_id` is the optional FK back to `request_log` for
-- errors that surface inside an HTTP handler — the audit middleware
-- already wrote that row before the handler ran, so the FK is safe.

CREATE TABLE error_log (
    id             BIGSERIAL    PRIMARY KEY,
    occurred_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    severity       TEXT         NOT NULL CHECK (severity IN ('warn', 'error', 'fatal')),
    source         TEXT         NOT NULL,
    message        TEXT         NOT NULL,
    error_chain    TEXT,
    request_log_id BIGINT       REFERENCES request_log (id) ON DELETE SET NULL
);

CREATE INDEX error_log_occurred_at_idx  ON error_log (occurred_at DESC);
CREATE INDEX error_log_severity_idx     ON error_log (severity, occurred_at DESC);

-- ===========================================================================
-- 3. block_log: every Bitcoin block the scanner processed
-- ===========================================================================
--
-- The scanner is event-driven (WS); today the only persisted artefact
-- of a processed block is the `latest_block` singleton. There is no
-- history — "did we process block X?" needs to be answered from
-- container logs. This table adds an append-only history of every
-- processed block plus a count of inscriptions extracted from it,
-- which speeds incident triage to a `WHERE block_height BETWEEN ?
-- AND ?` query.

CREATE TABLE block_log (
    id                     BIGSERIAL    PRIMARY KEY,
    block_hash             BYTEA        NOT NULL UNIQUE,
    block_height           BIGINT       NOT NULL,
    received_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    processed_at           TIMESTAMPTZ,
    inscription_count      INTEGER      NOT NULL DEFAULT 0,
    processing_duration_us BIGINT
);

CREATE INDEX block_log_received_at_idx ON block_log (received_at DESC);
CREATE INDEX block_log_height_idx      ON block_log (block_height DESC);

-- ===========================================================================
-- 4. observed_inscriptions: every inscription the scanner ever saw
-- ===========================================================================
--
-- `pending_inscriptions` only tracks the publisher's own outgoing
-- inscriptions. External inscriptions — mints originating from another
-- operator's node, manual recoveries via `recover_inscription` CLI,
-- replays from a re-sync — currently mutate `accounts` / `mmr_root_index`
-- but leave no audit row of the detection event itself. This table
-- closes that gap with a row per extracted commitment, tagged
-- `own` or `external`.
--
-- `public_key` is the 33-byte secp256k1 compressed pubkey lifted from
-- the bincode-deserialised commitment. Surfacing it as a column avoids
-- the bincode round-trip every time the operator wants to filter by
-- account, and makes joins to `accounts` (via SHA256(public_key)) one
-- index step away.

CREATE TABLE observed_inscriptions (
    id             BIGSERIAL    PRIMARY KEY,
    commit_txid    BYTEA        NOT NULL UNIQUE,
    block_hash     BYTEA,
    block_height   BIGINT,
    observed_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    source         TEXT         NOT NULL CHECK (source IN ('own', 'external')),
    commitment     BYTEA        NOT NULL,
    public_key     BYTEA        NOT NULL,
    integrated     BOOLEAN      NOT NULL DEFAULT FALSE,
    integrated_at  TIMESTAMPTZ
);

CREATE INDEX observed_inscriptions_block_height_idx ON observed_inscriptions (block_height DESC);
CREATE INDEX observed_inscriptions_source_idx       ON observed_inscriptions (source, observed_at DESC);
CREATE INDEX observed_inscriptions_public_key_idx   ON observed_inscriptions (public_key);

-- ===========================================================================
-- 5. state_update_log: every State::update transition
-- ===========================================================================
--
-- The MMR/SMT roots advance on every accepted commitment. Today the
-- `mmr_root_index` table holds the (prev_mmr_root, smt_root, leaf_index)
-- triple but not the trigger (mint vs. scanner-replay vs. recovery),
-- the SMT root *before* the update, or the link back to the inscription
-- that caused the transition. This table records the full transition so
-- a state divergence can be traced to the originating event.

CREATE TABLE state_update_log (
    id                BIGSERIAL    PRIMARY KEY,
    applied_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    trigger           TEXT         NOT NULL
        CHECK (trigger IN ('mint', 'send', 'scanner_replay', 'recovery')),
    commit_txid       BYTEA,
    prev_mmr_root     BYTEA        NOT NULL,
    new_mmr_root      BYTEA        NOT NULL,
    smt_root_before   BYTEA        NOT NULL,
    smt_root_after    BYTEA        NOT NULL,
    commitment_count  INTEGER      NOT NULL DEFAULT 1
);

CREATE INDEX state_update_log_applied_at_idx  ON state_update_log (applied_at DESC);
CREATE INDEX state_update_log_commit_txid_idx ON state_update_log (commit_txid)
    WHERE commit_txid IS NOT NULL;

-- ===========================================================================
-- 6. account_history: every change to an account's serialised state
-- ===========================================================================
--
-- `accounts` is overwrite-on-upsert: the row reflects the current
-- state, the previous balance / coin set is gone the moment the next
-- mint or receive lands. This table appends a row for every change
-- with the previous and new blob, so a "show me everything that ever
-- happened to address X" query is one index lookup away.
--
-- The `triggering_*` columns thread the cause back to its origin —
-- the HTTP request that started the mutation or the commit txid that
-- the scanner ingested.

CREATE TABLE account_history (
    id                        BIGSERIAL    PRIMARY KEY,
    changed_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    address                   BYTEA        NOT NULL,
    prev_data                 BYTEA,
    new_data                  BYTEA        NOT NULL,
    source                    TEXT         NOT NULL
        CHECK (source IN ('mint', 'send', 'receive', 'scanner', 'recovery')),
    triggering_commit_txid    BYTEA,
    triggering_request_log_id BIGINT       REFERENCES request_log (id) ON DELETE SET NULL
);

CREATE INDEX account_history_address_idx    ON account_history (address, changed_at DESC);
CREATE INDEX account_history_changed_at_idx ON account_history (changed_at DESC);

-- Postgres trigger: capture every accounts INSERT / UPDATE as an
-- account_history row. Without code-level wiring this gives 100%
-- coverage — any caller (current, future, manual psql, recovery CLI)
-- contributes a history row automatically.
--
-- `source` defaults to 'scanner' because that's the dominant upsert
-- path. Callers that know better (`mint_handler`, `runtime::
-- broadcast_commit_and_deliver`) can override via a per-transaction
-- GUC before the upsert:
--
--     SET LOCAL zkcoins.account_source = 'mint';
--     SET LOCAL zkcoins.account_commit_txid = '\x...';   -- hex bytea
--
-- The trigger reads those via `current_setting(..., true)` (the second
-- arg = missing_ok); unset GUCs fall back to the documented defaults.
CREATE OR REPLACE FUNCTION account_history_capture() RETURNS TRIGGER AS $$
DECLARE
    src TEXT := COALESCE(NULLIF(current_setting('zkcoins.account_source', TRUE), ''), 'scanner');
    commit_txid_hex TEXT := NULLIF(current_setting('zkcoins.account_commit_txid', TRUE), '');
    commit_txid_bytes BYTEA := NULL;
BEGIN
    -- Skip when row content didn't change (UPDATEs that touch only
    -- `updated_at` should not generate history noise).
    IF TG_OP = 'UPDATE' AND OLD.data = NEW.data THEN
        RETURN NEW;
    END IF;

    IF commit_txid_hex IS NOT NULL THEN
        BEGIN
            commit_txid_bytes := decode(commit_txid_hex, 'hex');
        EXCEPTION WHEN OTHERS THEN
            commit_txid_bytes := NULL;
        END;
    END IF;

    INSERT INTO account_history
        (address, prev_data, new_data, source, triggering_commit_txid)
    VALUES
        (NEW.address,
         CASE WHEN TG_OP = 'UPDATE' THEN OLD.data ELSE NULL END,
         NEW.data,
         src,
         commit_txid_bytes);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER accounts_history_trigger
    AFTER INSERT OR UPDATE ON accounts
    FOR EACH ROW
    EXECUTE FUNCTION account_history_capture();

-- ===========================================================================
-- 7. username_claim_log: every claim attempt, success or reject
-- ===========================================================================
--
-- The `usernames` table holds only the successful claims. Rejected
-- claims (squat attempts, malformed signatures, taken names) currently
-- return a 4xx and leave no trace. This table captures the attempt
-- itself for abuse forensics.

CREATE TABLE username_claim_log (
    id                  BIGSERIAL    PRIMARY KEY,
    attempted_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    requested_username  TEXT         NOT NULL,
    normalized_username TEXT         NOT NULL,
    address             BYTEA        NOT NULL,
    signature           BYTEA        NOT NULL,
    success             BOOLEAN      NOT NULL,
    reject_reason       TEXT,
    request_log_id      BIGINT       REFERENCES request_log (id) ON DELETE SET NULL
);

CREATE INDEX username_claim_log_username_idx ON username_claim_log (normalized_username, attempted_at DESC);
CREATE INDEX username_claim_log_attempted_at_idx ON username_claim_log (attempted_at DESC);

-- ===========================================================================
-- 8. tx_mining_log: reveal-txid prefix-mining attempts
-- ===========================================================================
--
-- The publisher mines a reveal txid until it ends with the inscription
-- marker prefix (today `4242`). Today the only record of this work is
-- the stdout line "Tried N nonces…". This table records the per-mint
-- effort so the operator can spot a mining hang or a prefix change.

CREATE TABLE tx_mining_log (
    id            BIGSERIAL    PRIMARY KEY,
    mined_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    target_prefix TEXT         NOT NULL,
    nonces_tried  BIGINT       NOT NULL,
    duration_us   BIGINT       NOT NULL,
    final_nonce   BIGINT,
    final_txid    BYTEA        NOT NULL,
    commit_txid   BYTEA
);

CREATE INDEX tx_mining_log_mined_at_idx ON tx_mining_log (mined_at DESC);

-- ===========================================================================
-- 9. coin_proof_store: persisted view of the in-memory ProofStore
-- ===========================================================================
--
-- `ProofStore` lives in memory with a TTL; a crash between `/api/send`
-- (which generates the proof) and the client's matching `/api/commit`
-- (which references the proof by id) loses the proof and the client
-- has to retry. Persisting the proof bytes makes that recoverable.
--
-- This migration creates the schema; the in-memory `ProofStore`
-- bootstrap is a follow-up — the table can be populated incrementally
-- without breaking the existing in-memory path.

CREATE TABLE coin_proof_store (
    id                       BIGSERIAL    PRIMARY KEY,
    proof_id                 BIGINT       NOT NULL UNIQUE,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at               TIMESTAMPTZ  NOT NULL,
    consumed_at              TIMESTAMPTZ,
    consumed_by_commit_txid  BYTEA,
    proof_blob               BYTEA        NOT NULL
);

CREATE INDEX coin_proof_store_expires_at_idx ON coin_proof_store (expires_at);

-- ===========================================================================
-- 10. boot_log: server lifecycle events
-- ===========================================================================
--
-- Captures the events that happen *before* the HTTP server starts
-- accepting requests (migration run, state load, vault sync, scanner
-- bootstrap) and the matching shutdown / panic events. Today these are
-- stdout-only; if a service flapped overnight the `received_at` of the
-- next successful boot is the only timestamp left.

CREATE TABLE boot_log (
    id         BIGSERIAL    PRIMARY KEY,
    event_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    event_type TEXT         NOT NULL,
    message    TEXT         NOT NULL,
    metadata   JSONB
);

CREATE INDEX boot_log_event_at_idx ON boot_log (event_at DESC);
