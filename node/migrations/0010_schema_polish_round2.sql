-- Second polish round on the persistence stack.
--
-- Closes the remaining gaps from the round-2 review:
--   * Length CHECKs on every BYTEA column whose contents have a
--     domain-fixed size (txid 32, address 32, pubkey 33, sig 64).
--   * `block_log.block_height` nullable (was: NOT NULL with magic
--     sentinel `-1` for unknown).
--   * `pending_inscriptions.reveal_txid` UNIQUE (was: only commit_txid).
--   * Drop the now-redundant `WHERE reveal_txid IS NOT NULL` partial
--     filter on the reveal_txid index — column is NOT NULL since 0009.
--   * `tx_mining_log.commit_txid` NOT NULL (was nullable, always set).
--   * Missing FK constraints to `pending_inscriptions.commit_txid`
--     for `tx_mining_log` + `coin_proof_store`.
--   * Logical-pair CHECKs (integrated ⇔ integrated_at, success ⇔
--     reject_reason, consumed_at ⇔ consumed_by_commit_txid, status=
--     'failed' ⇒ failure_reason).
--   * `created_at` columns on the pre-existing tables that only had
--     `updated_at` (accounts, latest_block, smt_state, mmr_state).
--   * Align `esplora_log.triggered_by` with `state_update_log
--     .trigger_source`: same name, same CHECK vocabulary.
--   * Performance indices on commonly-joined FK columns.
--   * `boot_log.event_type` + `tx_mining_log.target_prefix` CHECKs.
--   * Rename `account_history_capture()` → `accounts_history_capture()`
--     to match the trigger / table noun.
--   * `mmr_root_index.leaf_index` UNIQUE.
--
-- Per `feedback_zkcoins_migrations_may_wipe`: data is throw-away,
-- closed test env. Where a CHECK / NOT NULL could trip on legacy
-- rows we wipe them first.

-- ===========================================================================
-- 1. BYTEA length CHECKs
-- ===========================================================================

ALTER TABLE accounts
    ADD CONSTRAINT accounts_address_length CHECK (octet_length(address) = 32);

ALTER TABLE usernames
    ADD CONSTRAINT usernames_address_length CHECK (octet_length(address) = 32);

ALTER TABLE latest_block
    ADD CONSTRAINT latest_block_hash_length CHECK (octet_length(block_hash) = 32);

ALTER TABLE mmr_root_index
    ADD CONSTRAINT mmr_root_index_prev_root_length CHECK (octet_length(prev_mmr_root) = 32),
    ADD CONSTRAINT mmr_root_index_smt_root_length  CHECK (octet_length(smt_root) = 32);

ALTER TABLE pending_inscriptions
    ADD CONSTRAINT pending_inscriptions_commit_txid_length CHECK (octet_length(commit_txid) = 32),
    ADD CONSTRAINT pending_inscriptions_reveal_txid_length CHECK (octet_length(reveal_txid) = 32);

ALTER TABLE block_log
    ADD CONSTRAINT block_log_block_hash_length CHECK (octet_length(block_hash) = 32);

-- observed_inscriptions: block_hash is nullable, so guard the CHECK.
ALTER TABLE observed_inscriptions
    ADD CONSTRAINT observed_inscriptions_commit_txid_length CHECK (octet_length(commit_txid) = 32),
    ADD CONSTRAINT observed_inscriptions_block_hash_length  CHECK (block_hash IS NULL OR octet_length(block_hash) = 32),
    ADD CONSTRAINT observed_inscriptions_public_key_length  CHECK (octet_length(public_key) = 33);

-- state_update_log: commit_txid is nullable.
ALTER TABLE state_update_log
    ADD CONSTRAINT state_update_log_commit_txid_length CHECK (commit_txid IS NULL OR octet_length(commit_txid) = 32),
    ADD CONSTRAINT state_update_log_prev_mmr_root_length CHECK (octet_length(prev_mmr_root) = 32),
    ADD CONSTRAINT state_update_log_new_mmr_root_length  CHECK (octet_length(new_mmr_root) = 32),
    ADD CONSTRAINT state_update_log_smt_root_before_length CHECK (octet_length(smt_root_before) = 32),
    ADD CONSTRAINT state_update_log_smt_root_after_length  CHECK (octet_length(smt_root_after) = 32);

ALTER TABLE account_history
    ADD CONSTRAINT account_history_address_length CHECK (octet_length(address) = 32),
    ADD CONSTRAINT account_history_triggering_commit_txid_length
        CHECK (triggering_commit_txid IS NULL OR octet_length(triggering_commit_txid) = 32);

ALTER TABLE username_claim_log
    ADD CONSTRAINT username_claim_log_address_length CHECK (octet_length(address) = 32),
    ADD CONSTRAINT username_claim_log_signature_length CHECK (octet_length(signature) = 64);

ALTER TABLE tx_mining_log
    ADD CONSTRAINT tx_mining_log_final_txid_length CHECK (octet_length(final_txid) = 32);
-- tx_mining_log.commit_txid handled below (becomes NOT NULL + FK + length CHECK)

ALTER TABLE coin_proof_store
    ADD CONSTRAINT coin_proof_store_consumed_txid_length
        CHECK (consumed_by_commit_txid IS NULL OR octet_length(consumed_by_commit_txid) = 32);

-- ===========================================================================
-- 2. block_log.block_height nullable (drop sentinel `-1`)
-- ===========================================================================

UPDATE block_log SET block_height = NULL WHERE block_height = -1;
ALTER TABLE block_log ALTER COLUMN block_height DROP NOT NULL;

-- ===========================================================================
-- 3. pending_inscriptions.reveal_txid UNIQUE
-- ===========================================================================

ALTER TABLE pending_inscriptions
    ADD CONSTRAINT pending_inscriptions_reveal_txid_unique UNIQUE (reveal_txid);

-- The partial index from 0008 (`WHERE reveal_txid IS NOT NULL`) is now
-- redundant because reveal_txid is NOT NULL (0009) and UNIQUE adds
-- its own index. Drop the partial.
DROP INDEX IF EXISTS pending_inscriptions_reveal_txid_idx;

-- ===========================================================================
-- 4. tx_mining_log.commit_txid NOT NULL + length CHECK + FK
-- ===========================================================================

DELETE FROM tx_mining_log WHERE commit_txid IS NULL;
ALTER TABLE tx_mining_log
    ALTER COLUMN commit_txid SET NOT NULL,
    ADD CONSTRAINT tx_mining_log_commit_txid_length CHECK (octet_length(commit_txid) = 32),
    ADD CONSTRAINT tx_mining_log_commit_txid_fk
        FOREIGN KEY (commit_txid) REFERENCES pending_inscriptions (commit_txid) ON DELETE CASCADE;
CREATE INDEX tx_mining_log_commit_txid_idx ON tx_mining_log (commit_txid);

-- ===========================================================================
-- 5. coin_proof_store.consumed_by_commit_txid FK
-- ===========================================================================

ALTER TABLE coin_proof_store
    ADD CONSTRAINT coin_proof_store_consumed_txid_fk
        FOREIGN KEY (consumed_by_commit_txid) REFERENCES pending_inscriptions (commit_txid) ON DELETE SET NULL;

-- ===========================================================================
-- 6. Logical-pair CHECKs (mutually-exclusive flag/timestamp pairs)
-- ===========================================================================

ALTER TABLE observed_inscriptions ADD CONSTRAINT observed_inscriptions_integrated_consistency
    CHECK (
        (integrated = TRUE  AND integrated_at IS NOT NULL)
     OR (integrated = FALSE AND integrated_at IS NULL)
    );

ALTER TABLE username_claim_log ADD CONSTRAINT username_claim_log_outcome_consistency
    CHECK (
        (success = TRUE  AND reject_reason IS NULL)
     OR (success = FALSE AND reject_reason IS NOT NULL)
    );

ALTER TABLE coin_proof_store ADD CONSTRAINT coin_proof_store_consumption_consistency
    CHECK (
        (consumed_at IS NULL     AND consumed_by_commit_txid IS NULL)
     OR (consumed_at IS NOT NULL AND consumed_by_commit_txid IS NOT NULL)
    );

-- failure_reason is required whenever status = 'failed'; the inverse
-- direction (failure_reason set, status not 'failed') is permitted
-- because retries may leave a stale reason on an in-progress row.
ALTER TABLE pending_inscriptions ADD CONSTRAINT pending_inscriptions_failed_reason_required
    CHECK (status <> 'failed' OR failure_reason IS NOT NULL);

-- ===========================================================================
-- 7. Align esplora_log.triggered_by with state_update_log.trigger_source
-- ===========================================================================
--
-- Same name, same vocabulary. Existing rows with values outside the
-- vocabulary are wiped (closed test env).

DELETE FROM esplora_log
WHERE triggered_by IS NOT NULL
  AND triggered_by NOT IN ('mint', 'send', 'scanner', 'recovery', 'health', 'resume');

ALTER TABLE esplora_log RENAME COLUMN triggered_by TO trigger_source;
ALTER TABLE esplora_log ADD CONSTRAINT esplora_log_trigger_source_check
    CHECK (trigger_source IS NULL
        OR trigger_source IN ('mint', 'send', 'scanner', 'recovery', 'health', 'resume'));

-- ===========================================================================
-- 8. created_at on pre-existing singletons / state tables
-- ===========================================================================
--
-- The 0001 tables tracked only `updated_at`; this leaves "when was
-- this account first seen?" answerable only via `account_history`.
-- Adding a NOT NULL DEFAULT NOW() backfills existing rows with the
-- migration timestamp — close enough for closed test env, accurate
-- for everything written from now on.

ALTER TABLE accounts      ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE latest_block  ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE smt_state     ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE mmr_state     ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- ===========================================================================
-- 9. Performance indices
-- ===========================================================================

CREATE INDEX account_history_triggering_commit_txid_idx
    ON account_history (triggering_commit_txid, changed_at DESC)
    WHERE triggering_commit_txid IS NOT NULL;

CREATE INDEX pending_inscriptions_kind_idx
    ON pending_inscriptions (kind, created_at DESC);

CREATE INDEX pending_inscriptions_failed_idx
    ON pending_inscriptions (updated_at DESC)
    WHERE status = 'failed';

-- ===========================================================================
-- 10. boot_log.event_type + tx_mining_log.target_prefix CHECKs
-- ===========================================================================

ALTER TABLE boot_log ADD CONSTRAINT boot_log_event_type_check
    CHECK (event_type IN ('startup', 'shutdown', 'migration', 'state_load', 'vault_sync'));

-- target_prefix is always a lowercase hex string. Keep the column
-- flexible (the marker may change) but validate the shape.
ALTER TABLE tx_mining_log ADD CONSTRAINT tx_mining_log_target_prefix_shape
    CHECK (target_prefix ~ '^[0-9a-f]+$');

-- ===========================================================================
-- 11. Trigger function rename (cosmetic — match table noun)
-- ===========================================================================

DROP TRIGGER accounts_history_trigger ON accounts;
DROP FUNCTION account_history_capture();

CREATE OR REPLACE FUNCTION accounts_history_capture() RETURNS TRIGGER AS $$
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

CREATE TRIGGER accounts_history_trigger
    AFTER INSERT OR UPDATE ON accounts
    FOR EACH ROW
    EXECUTE FUNCTION accounts_history_capture();

-- ===========================================================================
-- 12. mmr_root_index.leaf_index UNIQUE
-- ===========================================================================
--
-- leaf_index is monotonic by construction (mmr.leaf_count()), so a
-- duplicate value is a code-side bug. UNIQUE turns that bug into a
-- constraint violation at insert time.

ALTER TABLE mmr_root_index
    ADD CONSTRAINT mmr_root_index_leaf_index_unique UNIQUE (leaf_index);
