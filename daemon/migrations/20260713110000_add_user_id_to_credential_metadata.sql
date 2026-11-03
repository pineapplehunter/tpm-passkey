ALTER TABLE credential_metadata ADD COLUMN user_id INTEGER;
CREATE INDEX credential_metadata_user_id_idx ON credential_metadata(user_id);
