ALTER TABLE credential_keyslots ADD COLUMN policy_ref BLOB;
ALTER TABLE credential_keyslots ADD COLUMN authority_name BLOB;
ALTER TABLE credential_keyslots ADD COLUMN authority_signature BLOB;
ALTER TABLE credential_keyslots ADD COLUMN policy_version INTEGER NOT NULL DEFAULT 1;
