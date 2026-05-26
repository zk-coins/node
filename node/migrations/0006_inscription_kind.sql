-- Distinguish mint inscriptions from user-send (`/api/commit`) inscriptions
-- so the DB alone answers "what kind of operation was this?" without
-- having to grep container logs or re-derive the minting account's
-- pubkey-at-index-N. The previous schema persisted the bincode
-- `Commitment` blob only — semantically opaque without state context.
--
-- Closed test environment (see CONTRIBUTING.md and the project memo
-- `feedback_zkcoins_closed_test_env`): existing rows are crash-recovery
-- state for the publisher's commit/reveal pair, expected to be
-- `complete` and empty on a healthy server. Wiping them is the
-- documented "alt raus, neu rein" pattern — no backfill, no transition
-- shim.

DELETE FROM pending_inscriptions;

ALTER TABLE pending_inscriptions
    ADD COLUMN kind TEXT NOT NULL
    CHECK (kind IN ('mint', 'send'));
