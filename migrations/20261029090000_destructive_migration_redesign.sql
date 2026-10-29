-- Breaking migration-key redesign: credentials and old recovery/default-policy
-- state cannot be safely transformed to the new public-key envelope format.
-- Keep client_pin_state intact so the existing CTAP client PIN survives.
DELETE FROM credential_metadata;
DELETE FROM daemon_config WHERE key IN (
    'recovery_encryption',
    'default_pcr_policy',
    'migration_encryption',
    'default_migration_policy'
);

ALTER TABLE credential_metadata ADD COLUMN local_id INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX credential_metadata_local_id_idx
    ON credential_metadata(local_id);
