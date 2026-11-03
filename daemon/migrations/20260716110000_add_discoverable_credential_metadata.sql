ALTER TABLE credential_metadata
    ADD COLUMN discoverable INTEGER NOT NULL DEFAULT 1 CHECK (discoverable IN (0, 1));

CREATE INDEX credential_metadata_owner_rp_discoverable_idx
    ON credential_metadata(user_id, rp_id, discoverable);
