-- Migration-authority slot labels are an implementation detail, but their
-- persisted name should match the public migration terminology. Rebuild both
-- related tables to update the SQLite CHECK constraint while preserving rows.
CREATE TABLE credential_keyslots_new (
    keyslot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id BLOB NOT NULL REFERENCES credential_metadata(credential_id) ON DELETE CASCADE,
    slot_kind TEXT NOT NULL CHECK (slot_kind IN ('primary', 'migration')),
    slot_label TEXT,
    policy_selection TEXT,
    policy_digest BLOB,
    policy_ref BLOB,
    authority_name BLOB,
    authority_signature BLOB,
    policy_version INTEGER NOT NULL DEFAULT 1,
    tpm_key BLOB NOT NULL,
    public_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (credential_id, slot_kind)
);

INSERT INTO credential_keyslots_new (
    keyslot_id, credential_id, slot_kind, slot_label, policy_selection,
    policy_digest, policy_ref, authority_name, authority_signature,
    policy_version, tpm_key, public_key, created_at, updated_at
)
SELECT keyslot_id, credential_id,
       CASE slot_kind WHEN 'recovery' THEN 'migration' ELSE slot_kind END,
       slot_label, policy_selection, policy_digest, policy_ref, authority_name,
       authority_signature, policy_version, tpm_key, public_key, created_at, updated_at
FROM credential_keyslots;

CREATE TABLE credential_tokens_new (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyslot_id INTEGER NOT NULL REFERENCES credential_keyslots_new(keyslot_id) ON DELETE CASCADE,
    token_type TEXT NOT NULL CHECK (token_type IN ('passphrase')),
    label TEXT,
    encrypted_auth BLOB NOT NULL,
    last_used TEXT,
    used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (keyslot_id, token_type)
);
INSERT INTO credential_tokens_new
SELECT token_id, keyslot_id, token_type, label, encrypted_auth, last_used,
       used_count, created_at, updated_at
FROM credential_tokens;

DROP TABLE credential_tokens;
DROP TABLE credential_keyslots;
ALTER TABLE credential_keyslots_new RENAME TO credential_keyslots;
ALTER TABLE credential_tokens_new RENAME TO credential_tokens;
CREATE INDEX credential_keyslots_credential_id_idx ON credential_keyslots(credential_id);
CREATE INDEX credential_tokens_keyslot_id_idx ON credential_tokens(keyslot_id);
