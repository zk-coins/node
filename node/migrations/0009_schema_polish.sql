-- Schema polish on the 0006/0007/0008 stack.
--
-- Closes the semantic / consistency gaps surfaced by the post-#118
-- schema review:
--
--   1. `pending_inscriptions.reveal_txid` was nullable for defensive
--      reasons but every code path now sets it; ALTER it NOT NULL so
--      `loaders` can drop the `Option<>` and the schema reflects the
--      invariant.
--   2. `block_log.received_at` and `processed_at` were both set to
--      `NOW()` in the same INSERT — one of them is dead weight. Drop
--      `received_at`, keep `processed_at NOT NULL DEFAULT NOW()` as
--      the single timestamp. WS-frame-receive logging (separate
--      event) is a future addition.
--   3. `state_update_log.trigger` collides with Postgres trigger
--      vocabulary at every read; rename to `trigger_source`. No code
--      callers today so the rename is free.
--   4. `esplora_log` gains `triggering_request_log_id` analogous to
--      `error_log` — outbound Esplora chatter caused by an inbound
--      HTTP request can now be joined back to its `request_log` row.
--   5. `request_log` gains `client_ip` — the audit middleware now
--      surfaces the real client IP from `CF-Connecting-IP` /
--      `X-Forwarded-For` (everything zkcoins-node sees is behind a
--      Cloudflare Tunnel, so `remote_addr` is the tunnel endpoint,
--      not the client). `remote_addr` stays as the literal TCP peer
--      for transport-level forensics.
--   6. `account_history_capture()` trigger reads the optional
--      `zkcoins.request_log_id` GUC so callers that have an HTTP
--      request context (audit middleware) can thread it through to
--      `account_history.triggering_request_log_id` without
--      reimplementing the upsert in application code.
--
-- Closed test env stance unchanged: no backfill, no compat shims.

-- 1. pending_inscriptions.reveal_txid NOT NULL ---------------------------
--
-- All code paths fill reveal_txid since migration 0008; any row with
-- a NULL value can only come from a brief window between 0008's ADD
-- COLUMN landing and 0009 running. In the closed test env (see
-- `feedback_zkcoins_migrations_may_wipe`) such rows are throw-away:
-- wipe them explicitly so the SET NOT NULL never trips. New rows
-- start clean from the next publisher attempt.
DELETE FROM pending_inscriptions WHERE reveal_txid IS NULL;
ALTER TABLE pending_inscriptions
    ALTER COLUMN reveal_txid SET NOT NULL;

-- 2. block_log: single processed_at timestamp ----------------------------
DROP INDEX IF EXISTS block_log_received_at_idx;
ALTER TABLE block_log DROP COLUMN received_at;
ALTER TABLE block_log
    ALTER COLUMN processed_at SET DEFAULT NOW(),
    ALTER COLUMN processed_at SET NOT NULL;
CREATE INDEX block_log_processed_at_idx ON block_log (processed_at DESC);

-- 3. state_update_log column rename --------------------------------------
ALTER TABLE state_update_log RENAME COLUMN trigger TO trigger_source;

-- 4. esplora_log.triggering_request_log_id ------------------------------
ALTER TABLE esplora_log
    ADD COLUMN triggering_request_log_id BIGINT
        REFERENCES request_log (id) ON DELETE SET NULL;
CREATE INDEX esplora_log_triggering_request_idx
    ON esplora_log (triggering_request_log_id)
    WHERE triggering_request_log_id IS NOT NULL;

-- 5. request_log.client_ip ----------------------------------------------
ALTER TABLE request_log
    ADD COLUMN client_ip TEXT;
CREATE INDEX request_log_client_ip_idx
    ON request_log (client_ip, received_at DESC)
    WHERE client_ip IS NOT NULL;

-- 6. account_history_capture() reads optional request_log_id GUC -------
--
-- The trigger now consults TWO per-transaction GUCs:
--   * `zkcoins.account_source` (already supported)         — text source
--   * `zkcoins.account_commit_txid` (already supported)    — hex bytea
--   * `zkcoins.request_log_id` (NEW)                       — request_log.id
--
-- All three are read with `current_setting(..., TRUE)` so unset GUCs
-- silently fall back to the documented defaults (no error). Each
-- caller sets only the GUCs it knows about; the trigger captures
-- whatever is in scope.

CREATE OR REPLACE FUNCTION account_history_capture() RETURNS TRIGGER AS $$
DECLARE
    src TEXT := COALESCE(NULLIF(current_setting('zkcoins.account_source', TRUE), ''), 'scanner');
    commit_txid_hex TEXT := NULLIF(current_setting('zkcoins.account_commit_txid', TRUE), '');
    commit_txid_bytes BYTEA := NULL;
    req_log_id_text TEXT := NULLIF(current_setting('zkcoins.request_log_id', TRUE), '');
    req_log_id BIGINT := NULL;
BEGIN
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

    IF req_log_id_text IS NOT NULL THEN
        BEGIN
            req_log_id := req_log_id_text::BIGINT;
        EXCEPTION WHEN OTHERS THEN
            req_log_id := NULL;
        END;
    END IF;

    INSERT INTO account_history
        (address, prev_data, new_data, source, triggering_commit_txid, triggering_request_log_id)
    VALUES
        (NEW.address,
         CASE WHEN TG_OP = 'UPDATE' THEN OLD.data ELSE NULL END,
         NEW.data,
         src,
         commit_txid_bytes,
         req_log_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
