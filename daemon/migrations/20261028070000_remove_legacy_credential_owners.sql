-- Owner UIDs and their MAC compatibility format are no longer supported.
-- Discard records using that format rather than attempting to rewrite MACs
-- whose key is kept outside SQLite.
DELETE FROM credential_metadata;
DROP INDEX credential_metadata_owner_rp_discoverable_idx;
DROP INDEX credential_metadata_user_id_idx;
ALTER TABLE credential_metadata DROP COLUMN user_id;
