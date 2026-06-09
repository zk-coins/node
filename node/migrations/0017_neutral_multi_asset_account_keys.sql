-- Neutral, permissionless multi-asset account keys (Milestone 2).
--
-- ## What changes
--
-- The protocol becomes fully neutral and permissionless: there is no
-- native/official coin and no central minting authority. Accounts are
-- now keyed per `(owner_address, asset_id)` (Model B) instead of per
-- owner address alone. The in-memory `AccountNode` keys by the tuple;
-- on disk the `accounts.address` BYTEA column stores the 64-byte
-- composite key `owner(32) || asset_id(32)` (see
-- `account_node::account_key_bytes`).
--
-- ## Why a genesis reset
--
-- Same rationale as migrations 0015 / 0016: the Milestone 1 circuit
-- change (new `AccountState` layout with `asset_id`, new asset-id
-- derivation, issuer-mint gate) invalidates EVERY persisted proof at
-- once — each `account.proof`, every queued source proof — and the
-- global SMT/MMR are append-only and shared across accounts. They
-- cannot be partially unwound per account without the global-vs-account
-- mismatch that breaks soundness. The old single-balance account rows
-- are also keyed by 32-byte owner addresses, incompatible with the new
-- 64-byte composite key. A coordinated reset to genesis is the only
-- provably-consistent recovery.
--
-- ## Scope: DEV *and* PRD
--
-- Both are closed test environments (CONTRIBUTING § "Closed test
-- environment"); there is no data to preserve. sqlx applies a migration
-- once per database, so the reset fires exactly once per environment on
-- the first deploy that carries it.
--
-- ## Table set (mirrors `0016` / `reset_proof_dependent_state_tx`)

DELETE FROM accounts;
DELETE FROM smt_state;
DELETE FROM mmr_state;
DELETE FROM mmr_root_index;
DELETE FROM latest_block;
DELETE FROM circuit_digest_meta;

-- The `accounts.address` column now stores the 64-byte composite key
-- `owner(32) || asset_id(32)`. Relax the 0010 length CHECK from 32 to
-- 64. (Idempotent guards via IF EXISTS so a re-run after a manual fix
-- does not error.)
ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_address_length;
ALTER TABLE accounts
    ADD CONSTRAINT accounts_address_length CHECK (octet_length(address) = 64);

-- The `account_history` ledger stays keyed by the 32-byte OWNER address
-- (the human-facing handle the `/api/history` endpoint queries by), NOT
-- the 64-byte composite. Redefine the capture trigger to write only the
-- owner prefix of the composite `accounts.address` so the existing
-- 32-byte `account_history_address_length` CHECK still holds and the
-- history endpoint continues to resolve by owner.
--
-- NOTE on the function name: migration 0010 renamed this function
-- `account_history_capture()` → `accounts_history_capture()` (plural,
-- matching the table noun) and re-pointed the `accounts_history_trigger`
-- at the new name. The live trigger therefore executes
-- `accounts_history_capture()`; replacing the obsolete singular name
-- here would leave the live trigger writing `NEW.address` (the 64-byte
-- composite), which violates the 32-byte `account_history_address_length`
-- CHECK on every account upsert. We CREATE OR REPLACE the *plural*
-- function so the owner-prefix change actually takes effect, preserving
-- 0010's full body (the `zkcoins.request_log_id` GUC read +
-- `triggering_request_log_id` column) and only swapping `NEW.address`
-- for its 32-byte owner prefix.
CREATE OR REPLACE FUNCTION accounts_history_capture() RETURNS TRIGGER AS $$
DECLARE
    src TEXT := COALESCE(NULLIF(current_setting('zkcoins.account_source', TRUE), ''), 'scanner');
    commit_txid_hex TEXT := NULLIF(current_setting('zkcoins.account_commit_txid', TRUE), '');
    commit_txid_bytes BYTEA := NULL;
    req_log_id_text TEXT := NULLIF(current_setting('zkcoins.request_log_id', TRUE), '');
    req_log_id BIGINT := NULL;
    owner_address BYTEA := substring(NEW.address FROM 1 FOR 32);
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
        (owner_address,
         CASE WHEN TG_OP = 'UPDATE' THEN OLD.data ELSE NULL END,
         NEW.data,
         src,
         commit_txid_bytes,
         req_log_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
